from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class EventIngestRequest(BaseModel):
    type: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9._*-]+$",
        description="Event name, e.g. payment.succeeded",
    )
    data: dict[str, Any] = Field(description="Arbitrary event payload data")

class EventIngestResponse(BaseModel):
    event_id: str
    status: str = "accepted"
    delivery_count: int

class DeliveryAttemptResponse(BaseModel):
    id: str
    attempt_number: int
    started_at: datetime
    finished_at: datetime
    http_status: int | None = None
    duration_ms: int
    error_code: str | None = None
    response_excerpt: str | None = None
    outcome: str

    class Config:
        from_attributes = True

class DeliveryResponse(BaseModel):
    id: str
    event_id: str
    endpoint_id: str
    target_url_snapshot: str
    status: str
    attempt_count: int
    next_attempt_at: datetime
    replay_of_delivery_id: str | None = None
    created_at: datetime
    completed_at: datetime | None = None
    attempts: list[DeliveryAttemptResponse] = []

    class Config:
        from_attributes = True

class EventResponse(BaseModel):
    id: str
    project_id: str
    event_type: str
    payload: dict[str, Any]
    idempotency_key: str | None = None
    created_at: datetime
    deliveries: list[DeliveryResponse] = []

    class Config:
        from_attributes = True
