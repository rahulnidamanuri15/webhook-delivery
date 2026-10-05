from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field

class EndpointCreate(BaseModel):
    url: str = Field(description="Webhook receiver URL (https/http)")
    description: Optional[str] = Field(default=None, max_length=500)
    event_types: List[str] = Field(
        default=["*"],
        description="List of event types to subscribe to, e.g. ['payment.succeeded'] or ['*']"
    )
    rate_limit_per_second: int = Field(default=10, ge=1, le=100)

class EndpointResponse(BaseModel):
    id: str
    project_id: str
    url: str
    description: Optional[str] = None
    enabled: bool
    rate_limit_per_second: int
    created_at: datetime
    subscriptions: List[str] = []
    signing_secret: Optional[str] = None  # Decrypted when viewed in dashboard or endpoint response

    class Config:
        from_attributes = True

class EndpointUpdate(BaseModel):
    description: Optional[str] = None
    enabled: Optional[bool] = None
    event_types: Optional[List[str]] = None
    rate_limit_per_second: Optional[int] = None
