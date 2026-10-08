from datetime import datetime

from pydantic import BaseModel, Field


class EndpointCreate(BaseModel):
    url: str = Field(description="Webhook receiver URL (https/http)")
    description: str | None = Field(default=None, max_length=500)
    event_types: list[str] = Field(
        default=["*"], description="List of event types to subscribe to, e.g. ['payment.succeeded'] or ['*']"
    )
    rate_limit_per_second: int = Field(default=10, ge=1, le=100)


class EndpointResponse(BaseModel):
    id: str
    project_id: str
    url: str
    description: str | None = None
    enabled: bool
    rate_limit_per_second: int
    created_at: datetime
    subscriptions: list[str] = []
    signing_secret: str | None = None  # Decrypted when viewed in dashboard or endpoint response

    class Config:
        from_attributes = True


class EndpointUpdate(BaseModel):
    description: str | None = None
    enabled: bool | None = None
    event_types: list[str] | None = None
    rate_limit_per_second: int | None = None
