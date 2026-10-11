import secrets
from datetime import UTC, timedelta

from sqlalchemy import Column, DateTime, ForeignKey, Index, String
from sqlalchemy.orm import relationship

from app.db.session import Base
from app.models import generate_id, utc_now


def generate_invitation_token() -> str:
    """Secure default: random 256-bit hash (hex) so raw tokens never hit the DB.

    Real invitation flow generates raw = token_urlsafe(32), stores
    hash_invitation_token(raw), and emails raw. This default is only for
    backward-compat (tests / direct ORM creates) and produces a hash-only
    value that is already safe at rest.
    """
    import hashlib as _hashlib

    raw = secrets.token_urlsafe(32)
    return _hashlib.sha256(raw.encode("utf-8")).hexdigest()


class OrganizationInvitation(Base):
    __tablename__ = "organization_invitations"

    id = Column(String(32), primary_key=True, default=lambda: generate_id("inv"))
    organization_id = Column(String(32), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    role = Column(String(32), nullable=False, default="member")  # 'admin', 'member'
    # Hash-only: 64-char hex digest. Default is a secure random hash so
    # legacy ORM creates without explicit token stay safe at rest.
    # Preferred: callers pass hash_invitation_token(raw_token) explicitly.
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
        exp = self.expires_at.replace(tzinfo=UTC) if self.expires_at.tzinfo is None else self.expires_at
        now = utc_now()
        now = now.replace(tzinfo=UTC) if now.tzinfo is None else now
        return exp > now

    __table_args__ = (Index("ix_invitations_org_status", "organization_id", "status"),)
