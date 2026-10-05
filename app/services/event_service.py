import json
import hashlib
from typing import Tuple, Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.models import Event, Delivery, Endpoint, EndpointSubscription, utc_now
from app.config import settings

class IdempotencyConflictError(Exception):
    """Raised when an idempotency key is reused with a different payload."""
    pass

class ProjectEndpointLimitExceeded(Exception):
    """Raised when project endpoint capacity is exceeded."""
    pass

def canonicalize_payload(data: dict) -> Tuple[str, str]:
    """
    Returns (canonical_json_str, sha256_hash).
    Uses stable separators and sorted keys so hash and byte representations are deterministic.
    """
    canonical_json = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    req_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return canonical_json, req_hash

def get_matching_endpoints(db: Session, project_id: str, event_type: str) -> List[Endpoint]:
    """Finds all enabled endpoints for a project matching event_type or wildcard *."""
    return (
        db.query(Endpoint)
        .join(EndpointSubscription, Endpoint.id == EndpointSubscription.endpoint_id)
        .filter(
            Endpoint.project_id == project_id,
            Endpoint.enabled == True,
            or_(
                EndpointSubscription.event_type == "*",
                EndpointSubscription.event_type == event_type
            )
        )
        .distinct()
        .all()
    )

def ingest_event(
    db: Session,
    project_id: str,
    event_type: str,
    payload_data: dict,
    idempotency_key: Optional[str] = None
) -> Tuple[Event, bool, int]:
    """
    Atomically ingests an event and creates pending delivery records for matching endpoints.
    
    Returns:
        (event: Event, is_duplicate: bool, delivery_count: int)
    """
    wire_payload, request_hash = canonicalize_payload(payload_data)

    # 1. Check idempotency
    if idempotency_key:
        idempotency_key = idempotency_key.strip()
        existing_event = (
            db.query(Event)
            .filter(
                Event.project_id == project_id,
                Event.idempotency_key == idempotency_key
            )
            .first()
        )
        if existing_event:
            if existing_event.request_hash == request_hash:
                delivery_count = len(existing_event.deliveries)
                return existing_event, True, delivery_count
            else:
                raise IdempotencyConflictError(
                    f"Idempotency key '{idempotency_key}' was previously used with different payload content."
                )

    # 2. Find matching endpoints
    matching_endpoints = get_matching_endpoints(db, project_id, event_type)

    # 3. Create Event and Deliveries in a single atomic transaction
    event = Event(
        project_id=project_id,
        event_type=event_type,
        payload_json=wire_payload,
        wire_payload=wire_payload,
        idempotency_key=idempotency_key,
        request_hash=request_hash,
        created_at=utc_now()
    )
    db.add(event)
    db.flush()  # Assign event.id

    now = utc_now()
    created_deliveries = []
    for ep in matching_endpoints:
        delivery = Delivery(
            event_id=event.id,
            endpoint_id=ep.id,
            target_url_snapshot=ep.url,
            status="PENDING",
            attempt_count=0,
            next_attempt_at=now,
            created_at=now
        )
        db.add(delivery)
        created_deliveries.append(delivery)

    db.commit()
    db.refresh(event)

    return event, False, len(created_deliveries)
