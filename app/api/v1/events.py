import json

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_api_key
from app.config import settings
from app.db.session import get_db
from app.models import ApiKey, Delivery, Event, Project
from app.schemas.event import DeliveryResponse, EventIngestRequest, EventIngestResponse, EventResponse
from app.services.event_service import IdempotencyConflictError, ingest_event
from app.services.tracing import start_trace_span

router = APIRouter(prefix="/api/v1", tags=["Events & Deliveries"])

@router.post(
    "/events",
    response_model=EventIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Publish an event for webhook delivery"
)
def publish_event(
    payload: EventIngestRequest,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    auth: tuple[ApiKey, Project] = Depends(get_current_api_key),
    db: Session = Depends(get_db)
):
    """
    Ingests an event atomically and queues background deliveries for subscribed endpoints.
    Supports idempotent retries with the 'Idempotency-Key' header.
    """
    _, project = auth

    # Enforce maximum event payload size
    raw_payload_bytes = json.dumps(payload.data, ensure_ascii=False).encode("utf-8")
    if len(raw_payload_bytes) > settings.MAX_PAYLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Payload exceeds maximum allowed size of {settings.MAX_PAYLOAD_SIZE_BYTES} bytes."
        )

    # Rate limiting per project
    from app.services.rate_limiter import check_ingestion_rate_limit
    allowed, wait_time = check_ingestion_rate_limit(
        project.id,
        max_per_second=float(settings.INGESTION_RATE_LIMIT_PER_SECOND)
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Project event ingestion rate limit exceeded.",
            headers={"Retry-After": str(max(1, int(wait_time)))}
        )


    try:
        with start_trace_span("ingest.event", {"project.id": project.id, "event.type": payload.type}):
            event, is_duplicate, delivery_count = ingest_event(
                db=db,
                project_id=project.id,
                event_type=payload.type,
                payload_data=payload.data,
                idempotency_key=idempotency_key
            )
    except IdempotencyConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e)
        )

    return EventIngestResponse(
        event_id=event.id,
        status="accepted",
        delivery_count=delivery_count
    )

@router.get(
    "/events/{event_id}",
    response_model=EventResponse,
    summary="Get event details"
)
def get_event(
    event_id: str,
    auth: tuple[ApiKey, Project] = Depends(get_current_api_key),
    db: Session = Depends(get_db)
):
    _, project = auth
    event = (
        db.query(Event)
        .filter(Event.id == event_id, Event.project_id == project.id)
        .first()
    )
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")

    payload_dict = json.loads(event.payload_json)
    return EventResponse(
        id=event.id,
        project_id=event.project_id,
        event_type=event.event_type,
        payload=payload_dict,
        idempotency_key=event.idempotency_key,
        created_at=event.created_at,
        deliveries=event.deliveries
    )

@router.get(
    "/events/{event_id}/deliveries",
    response_model=list[DeliveryResponse],
    summary="List deliveries for an event"
)
def get_event_deliveries(
    event_id: str,
    auth: tuple[ApiKey, Project] = Depends(get_current_api_key),
    db: Session = Depends(get_db)
):
    _, project = auth
    event = (
        db.query(Event)
        .filter(Event.id == event_id, Event.project_id == project.id)
        .first()
    )
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")

    return event.deliveries

@router.get(
    "/deliveries/{delivery_id}",
    response_model=DeliveryResponse,
    summary="Get delivery details and attempt history"
)
def get_delivery(
    delivery_id: str,
    auth: tuple[ApiKey, Project] = Depends(get_current_api_key),
    db: Session = Depends(get_db)
):
    _, project = auth
    delivery = (
        db.query(Delivery)
        .join(Event, Delivery.event_id == Event.id)
        .filter(Delivery.id == delivery_id, Event.project_id == project.id)
        .first()
    )
    if not delivery:
        raise HTTPException(status_code=404, detail="Delivery not found.")

    return delivery
