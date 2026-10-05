import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Text, Boolean, Integer, DateTime, ForeignKey,
    UniqueConstraint, Index
)
from sqlalchemy.orm import relationship
from app.db.session import Base

def generate_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"

    id = Column(String(32), primary_key=True, default=lambda: generate_id("usr"))
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    memberships = relationship("OrganizationMember", back_populates="user", cascade="all, delete-orphan")


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String(32), primary_key=True, default=lambda: generate_id("org"))
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    members = relationship("OrganizationMember", back_populates="organization", cascade="all, delete-orphan")
    projects = relationship("Project", back_populates="organization", cascade="all, delete-orphan")


class OrganizationMember(Base):
    __tablename__ = "organization_members"

    id = Column(String(32), primary_key=True, default=lambda: generate_id("mem"))
    organization_id = Column(String(32), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(String(32), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(32), nullable=False, default="owner")  # 'owner', 'member'
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    organization = relationship("Organization", back_populates="members")
    user = relationship("User", back_populates="memberships")

    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_org_member"),
    )


class Project(Base):
    __tablename__ = "projects"

    id = Column(String(32), primary_key=True, default=lambda: generate_id("prj"))
    organization_id = Column(String(32), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    organization = relationship("Organization", back_populates="projects")
    api_keys = relationship("ApiKey", back_populates="project", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="project", cascade="all, delete-orphan")
    events = relationship("Event", back_populates="project", cascade="all, delete-orphan")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(String(32), primary_key=True, default=lambda: generate_id("key"))
    project_id = Column(String(32), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    key_prefix = Column(String(32), nullable=False)
    key_hash = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    project = relationship("Project", back_populates="api_keys")

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(String(32), primary_key=True, default=lambda: generate_id("ep"))
    project_id = Column(String(32), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(String(2048), nullable=False)
    description = Column(String(500), nullable=True)
    encrypted_signing_secret = Column(Text, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    rate_limit_per_second = Column(Integer, default=10, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    project = relationship("Project", back_populates="endpoints")
    subscriptions = relationship("EndpointSubscription", back_populates="endpoint", cascade="all, delete-orphan")
    deliveries = relationship("Delivery", back_populates="endpoint", cascade="all, delete-orphan")


class EndpointSubscription(Base):
    __tablename__ = "endpoint_subscriptions"

    id = Column(String(32), primary_key=True, default=lambda: generate_id("sub"))
    endpoint_id = Column(String(32), ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(255), nullable=False)

    endpoint = relationship("Endpoint", back_populates="subscriptions")

    __table_args__ = (
        UniqueConstraint("endpoint_id", "event_type", name="uq_endpoint_event_type"),
    )


class Event(Base):
    __tablename__ = "events"

    id = Column(String(32), primary_key=True, default=lambda: generate_id("evt"))
    project_id = Column(String(32), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(255), nullable=False, index=True)
    payload_json = Column(Text, nullable=False)
    wire_payload = Column(Text, nullable=False)
    idempotency_key = Column(String(255), nullable=True)
    request_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    project = relationship("Project", back_populates="events")
    deliveries = relationship("Delivery", back_populates="event", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("project_id", "idempotency_key", name="uq_project_idempotency_key"),
        Index("ix_events_project_created", "project_id", "created_at"),
    )


class Delivery(Base):
    __tablename__ = "deliveries"

    id = Column(String(32), primary_key=True, default=lambda: generate_id("dlv"))
    event_id = Column(String(32), ForeignKey("events.id", ondelete="CASCADE"), nullable=False, index=True)
    endpoint_id = Column(String(32), ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True)
    target_url_snapshot = Column(String(2048), nullable=False)
    
    # State machine: PENDING, IN_FLIGHT, SUCCEEDED, RETRY_SCHEDULED, DEAD
    status = Column(String(32), default="PENDING", nullable=False, index=True)
    attempt_count = Column(Integer, default=0, nullable=False)
    next_attempt_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    
    # Leases for distributed worker crash recovery
    lease_token = Column(String(64), nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Replay tracking
    replay_of_delivery_id = Column(String(32), ForeignKey("deliveries.id", ondelete="SET NULL"), nullable=True)
    
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    event = relationship("Event", back_populates="deliveries")
    endpoint = relationship("Endpoint", back_populates="deliveries")
    attempts = relationship("DeliveryAttempt", back_populates="delivery", cascade="all, delete-orphan", order_by="DeliveryAttempt.attempt_number")
    replayed_from = relationship("Delivery", remote_side=[id])

    __table_args__ = (
        Index("ix_deliveries_status_next_attempt", "status", "next_attempt_at"),
        Index("ix_deliveries_endpoint_created", "endpoint_id", "created_at"),
    )


class DeliveryAttempt(Base):
    __tablename__ = "delivery_attempts"

    id = Column(String(32), primary_key=True, default=lambda: generate_id("att"))
    delivery_id = Column(String(32), ForeignKey("deliveries.id", ondelete="CASCADE"), nullable=False, index=True)
    attempt_number = Column(Integer, nullable=False)
    started_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    finished_at = Column(DateTime(timezone=True), nullable=False)
    http_status = Column(Integer, nullable=True)
    duration_ms = Column(Integer, default=0, nullable=False)
    error_code = Column(String(64), nullable=True)
    response_excerpt = Column(Text, nullable=True)
    outcome = Column(String(32), nullable=False)  # SUCCESS, RETRYABLE_ERROR, PERMANENT_ERROR

    delivery = relationship("Delivery", back_populates="attempts")

    __table_args__ = (
        UniqueConstraint("delivery_id", "attempt_number", name="uq_delivery_attempt_number"),
        Index("ix_attempts_delivery_started", "delivery_id", "started_at"),
    )

# Import AuditLog and OrganizationInvitation
from app.models.audit_log import AuditLog
from app.models.invitation import OrganizationInvitation
