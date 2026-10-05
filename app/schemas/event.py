from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, Field

class EventIngestRequest(BaseModel):
    type: str = Field(description="Event name, e.g. payment.succeeded")
    data: Dict[str, Any] = Field(description="Arbitrary event payload data")

class EventIngestResponse(BaseModel):
    event_id: str
    status: str = "accepted"
    delivery_count: int

class DeliveryAttemptResponse(BaseModel):
    id: str
    attempt_number: int
    started_at: datetime
    finished_at: datetime
    http_status: Optional[int] = None
    duration_ms: int
    error_code: Optional[str] = None
    response_excerpt: Optional[str] = None
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
    replay_of_delivery_id: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    attempts: List[DeliveryAttemptResponse] = []

    class Config:
        from_attributes = True

class EventResponse(BaseModel):
    id: str
    project_id: str
    event_type: str
    payload: Dict[str, Any]
    idempotency_key: Optional[str] = None
    created_at: datetime
    deliveries: List[DeliveryResponse] = []

    class Config:
        from_attributes = True
