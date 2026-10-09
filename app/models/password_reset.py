from datetime import UTC

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String

from app.db.session import Base
from app.models import generate_id, utc_now


class PasswordResetOTP(Base):
    """One-time passcode for forgot-password flow.

    Only a SHA-256 hash of the OTP is stored. A row is single-use
    (``used``) and time-boxed (``expires_at``). Failed verifications
    increment ``attempts``; the row is invalidated after
    ``PASSWORD_RESET_OTP_MAX_ATTEMPTS`` failures.
    """

    __tablename__ = "password_reset_otps"

    id = Column(String(32), primary_key=True, default=lambda: generate_id("pwd"))
    user_id = Column(String(32), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    otp_hash = Column(String(64), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    attempts = Column(Integer, nullable=False, default=0)
    used = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    @property
    def is_expired(self) -> bool:
        exp = self.expires_at
        if exp is not None and getattr(exp, "tzinfo", None) is None:
            exp = exp.replace(tzinfo=UTC)
        now = utc_now()
        return exp <= now

    @property
    def is_valid(self) -> bool:
        return not self.used and not self.is_expired

    __table_args__ = (Index("ix_pwd_reset_user_created", "user_id", "created_at"),)
