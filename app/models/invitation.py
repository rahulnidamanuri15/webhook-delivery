import secrets
from datetime import datetime, timedelta, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, Index
from sqlalchemy.orm import relationship
from app.db.session import Base
from app.models import generate_id, utc_now

def generate_invitation_token() -> str:
    return secrets.token_urlsafe(32)

class OrganizationInvitation(Base):
    __tablename__ = "organization_invitations"

    id = Column(String(32), primary_key=True, default=lambda: generate_id("inv"))
    organization_id = Column(String(32), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    role = Column(String(32), nullable=False, default="member")  # 'admin', 'member'
    token = Column(String(64), unique=True, nullable=False, default=generate_invitation_token, index=True)
    status = Column(String(32), nullable=False, default="PENDING")  # 'PENDING', 'ACCEPTED', 'EXPIRED', 'REVOKED'
    invited_by_user_id = Column(String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, default=lambda: utc_now() + timedelta(days=7))
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    organization = relationship("Organization")
    invited_by = relationship("User")

    @property
    def is_valid(self) -> bool:
        if self.status != "PENDING":
            return False
        exp = self.expires_at.replace(tzinfo=timezone.utc) if self.expires_at.tzinfo is None else self.expires_at
        now = utc_now()
        now = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now
        return exp > now

    __table_args__ = (
        Index("ix_invitations_org_status", "organization_id", "status"),
    )
