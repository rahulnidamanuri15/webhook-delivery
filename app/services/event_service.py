import hashlib
import json

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Delivery, Endpoint, EndpointSubscription, Event, generate_id, utc_now


class IdempotencyConflictError(Exception):
    """Raised when an idempotency key is reused with a different payload."""

    pass


def canonicalize_payload(arg1: str | dict, arg2: dict | None = None) -> tuple[str, str]:
    """
    Returns (canonical_data_json_str, sha256_hash).
    If called with (event_type, data), hashes f"{event_type}:{canonical_data}".
    If called with (data), hashes canonical_data.
    Uses stable separators and sorted keys so hash and byte representations are deterministic.
    """
    if arg2 is None and isinstance(arg1, dict):
        event_type = ""
        data = arg1
    else:
        event_type = str(arg1)
        data = arg2 or {}
    canonical_data = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    hash_input = f"{event_type}:{canonical_data}" if event_type else canonical_data
    req_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
    return canonical_data, req_hash


def _subscription_matches(pattern: str, event_type: str) -> bool:
    """Supports exact names, global ``*``, and prefix ``namespace.*``.

    - ``*`` matches everything.
    - ``order.*`` matches ``order.shipped`` (prefix + ".") but not ``order`` or ``orders.x``.
    - otherwise exact equality.
    """
    p = (pattern or "").strip()
    if p == "*" or p == event_type:
        return True
    if p.endswith(".*"):
        prefix = p[:-2].strip()
        if prefix and event_type.startswith(prefix + "."):
            return True
    return False


def get_matching_endpoints(db: Session, project_id: str, event_type: str) -> list[Endpoint]:
    """Finds all enabled endpoints for a project matching event_type.

    Matches exact names, ``*``, and ``prefix.*``. Filtering is done in Python
    (bounded by MAX_ENDPOINTS_PER_PROJECT) so prefix semantics stay exact
    across SQLite and PostgreSQL without LIKE escaping pitfalls.
    """
    from app.config import settings as _settings

    try:
        _limit = int(getattr(_settings, "MAX_ENDPOINTS_PER_PROJECT", 20) or 20)
    except Exception:
        _limit = 20
    candidates = (
        db.query(Endpoint)
        .join(EndpointSubscription, Endpoint.id == EndpointSubscription.endpoint_id)
        .filter(
            Endpoint.project_id == project_id,
            Endpoint.enabled == True,
        )
        .distinct()
        .limit(_limit)
        .all()
    )
    if not candidates:
        return []
    # Map endpoint -> its subscription patterns in one extra query.
    from collections import defaultdict

    ep_ids = [e.id for e in candidates]
    subs = (
        db.query(EndpointSubscription.endpoint_id, EndpointSubscription.event_type)
        .filter(EndpointSubscription.endpoint_id.in_(ep_ids))
        .all()
    )
    patterns: dict[str, list[str]] = defaultdict(list)
    for eid, etype in subs:
        patterns[eid].append(etype)
    return [e for e in candidates if any(_subscription_matches(p, event_type) for p in patterns.get(e.id, []))]


def ingest_event(
    db: Session,
    project_id: str,
    event_type: str,
    payload_data: dict,
    idempotency_key: str | None = None,
    endpoint_ids: list[str] | None = None,
) -> tuple[Event, bool, int]:
    """
    Atomically ingests an event and creates pending delivery records for matching endpoints.

    When ``endpoint_ids`` is given, fan-out is restricted to those endpoints
    (still intersected with enabled + event-type-subscribed matches, and the
    IDs must belong to this project). ``None`` keeps the default: all matches.

    Returns:
        (event: Event, is_duplicate: bool, delivery_count: int)
    """
    # Normalize inputs: empty/whitespace idempotency keys mean "no key"
    # (prevents unique-constraint collision on "" across key-less events).
    if isinstance(event_type, str):
        event_type = event_type.strip()
    if idempotency_key is not None:
        idempotency_key = idempotency_key.strip() if isinstance(idempotency_key, str) else None
        if not idempotency_key:
            idempotency_key = None
    if not event_type or len(event_type) > 255:
        raise ValueError("event_type must be 1..255 characters")
    import re as _re

    if not _re.match(r"^[A-Za-z0-9._*-]+$", event_type):
        raise ValueError("event_type contains invalid characters (allowed: A-Z a-z 0-9 . _ * -)")

    # Bound payload shape (CPU DoS): depth <= 16, total keys <= 1000.
    # 1 MB byte cap is enforced by callers; this caps sort/serialize cost.
    def _check_shape(obj, depth: int = 0) -> int:
        if depth > 16:
            raise ValueError("payload exceeds max nesting depth (16)")
        if isinstance(obj, dict):
            if len(obj) > 1000:
                raise ValueError("payload object exceeds max keys (1000)")
            total = len(obj)
            for v in obj.values():
                total += _check_shape(v, depth + 1)
                if total > 5000:
                    raise ValueError("payload exceeds max total nodes (5000)")
            return total
        if isinstance(obj, list):
            if len(obj) > 1000:
                raise ValueError("payload array exceeds max items (1000)")
            total = len(obj)
            for v in obj:
                total += _check_shape(v, depth + 1)
                if total > 5000:
                    raise ValueError("payload exceeds max total nodes (5000)")
            return total
        return 1

    if not isinstance(payload_data, dict):
        raise ValueError("payload data must be a JSON object")
    _check_shape(payload_data)

    canonical_data, request_hash = canonicalize_payload(event_type, payload_data)

    # 1. Check idempotency
    if idempotency_key:
        existing_event = (
            db.query(Event).filter(Event.project_id == project_id, Event.idempotency_key == idempotency_key).first()
        )
        if existing_event:
            if existing_event.request_hash == request_hash:
                delivery_count = len(existing_event.deliveries)
                return existing_event, True, delivery_count
            else:
                raise IdempotencyConflictError(
                    f"Idempotency key '{idempotency_key}' was previously used with different payload content or event type."
                )

    # 2. Find matching endpoints
    matching_endpoints = get_matching_endpoints(db, project_id, event_type)

    # 2b. Optional targeted delivery: restrict fan-out to selected endpoints.
    # Still intersected with enabled + subscribed matches so subscriptions
    # stay the routing contract; unknown IDs fail closed (no cross-org leak).
    if endpoint_ids is not None:
        selected: list[str] = []
        for _eid in endpoint_ids:
            _eid = (_eid or "").strip()[:64] if isinstance(_eid, str) else ""
            if _eid and _eid not in selected:
                selected.append(_eid)
        if not selected:
            raise ValueError("select at least one endpoint or send to all endpoints")
        try:
            from app.config import settings as _settings

            _cap = int(getattr(_settings, "MAX_ENDPOINTS_PER_PROJECT", 20) or 20)
        except Exception:
            _cap = 20
        if len(selected) > _cap:
            raise ValueError(f"too many endpoints selected (max {_cap})")
        _known_ids = {r[0] for r in db.query(Endpoint.id).filter(Endpoint.project_id == project_id).all()}
        _unknown = [e for e in selected if e not in _known_ids]
        if _unknown:
            raise ValueError("unknown endpoint(s) selected")
        _sel = set(selected)
        matching_endpoints = [e for e in matching_endpoints if e.id in _sel]

    # 3. Create Event and Deliveries in a single atomic transaction
    event_id = generate_id("evt")
    now = utc_now()
    envelope = {
        "id": event_id,
        "type": event_type,
        "created_at": now.isoformat(),
        "data": payload_data,
    }
    wire_payload = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    try:
        event = Event(
            id=event_id,
            project_id=project_id,
            event_type=event_type,
            payload_json=canonical_data,
            wire_payload=wire_payload,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            created_at=now,
        )
        db.add(event)
        db.flush()

        created_deliveries = []
        for ep in matching_endpoints:
            delivery = Delivery(
                event_id=event.id,
                endpoint_id=ep.id,
                target_url_snapshot=ep.url,
                status="PENDING",
                attempt_count=0,
                next_attempt_at=now,
                created_at=now,
            )
            db.add(delivery)
            created_deliveries.append(delivery)

        db.commit()
        db.refresh(event)

        return event, False, len(created_deliveries)
    except IntegrityError:
        db.rollback()
        # Handle concurrent insertion of the same (project_id, idempotency_key)
        if idempotency_key:
            existing_event = (
                db.query(Event).filter(Event.project_id == project_id, Event.idempotency_key == idempotency_key).first()
            )
            if existing_event:
                if existing_event.request_hash == request_hash:
                    return existing_event, True, len(existing_event.deliveries)
                else:
                    raise IdempotencyConflictError(
                        f"Idempotency key '{idempotency_key}' was previously used with different payload content or event type."
                    )
        raise
