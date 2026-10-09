"""Forgot-password OTP lifecycle (generation, verification, reset tokens).

Security properties:
- Only SHA-256 hashes of OTPs are stored (never plaintext).
- OTPs are single-use, time-boxed, and invalidated after N failed attempts.
- Only the newest valid OTP per user is usable; older rows are marked used.
- The post-OTP reset credential is a short-lived signed token
  (itsdangerous, purpose-bound salt) — not the OTP itself.
"""

import hashlib
import hmac
import logging
import secrets
import time
from datetime import timedelta

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from app.config import settings
from app.models import utc_now
from app.models.password_reset import PasswordResetOTP

logger = logging.getLogger("webhook.password_reset")

_reset_serializer = URLSafeTimedSerializer(settings.SECRET_KEY, salt="wh_pwd_reset_salt")


def generate_otp(length: int | None = None) -> str:
    """Cryptographically secure numeric OTP, zero-padded to ``length`` digits."""
    n = int(length or settings.PASSWORD_RESET_OTP_LENGTH or 6)
    n = max(4, min(10, n))
    return f"{secrets.randbelow(10**n):0{n}d}"


def hash_otp(otp: str) -> str:
    return hashlib.sha256((otp or "").strip().encode("utf-8")).hexdigest()


def _constant_time_compare(a: str, b: str) -> bool:
    try:
        return hmac.compare_digest(a.strip(), b.strip())
    except Exception:
        return False


def create_otp_for_user(db: Session, user_id: str, email: str) -> tuple[PasswordResetOTP, str]:
    """Invalidates previous live OTPs, creates a fresh OTP row, returns (row, plain_otp)."""
    # Invalidate older live OTPs for this user (only newest is usable).
    try:
        db.query(PasswordResetOTP).filter(
            PasswordResetOTP.user_id == user_id,
            PasswordResetOTP.used.is_(False),
        ).update({"used": True}, synchronize_session=False)
        db.flush()
    except Exception:
        db.rollback()

    plain_otp = generate_otp()
    expire_minutes = int(settings.PASSWORD_RESET_OTP_EXPIRE_MINUTES or 10)
    row = PasswordResetOTP(
        user_id=user_id,
        email=(email or "").strip().lower(),
        otp_hash=hash_otp(plain_otp),
        expires_at=utc_now() + timedelta(minutes=expire_minutes),
        attempts=0,
        used=False,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row, plain_otp


def get_latest_valid_otp(db: Session, user_id: str) -> PasswordResetOTP | None:
    return (
        db.query(PasswordResetOTP)
        .filter(PasswordResetOTP.user_id == user_id, PasswordResetOTP.used.is_(False))
        .order_by(PasswordResetOTP.created_at.desc())
        .first()
    )


def verify_otp(db: Session, user_id: str, otp: str) -> tuple[bool, str, PasswordResetOTP | None]:
    """Verifies ``otp`` against the latest live OTP row.

    Returns (ok, reason, row) where reason is one of:
    'ok' | 'missing' | 'expired' | 'locked' | 'invalid'.
    Failed attempts increment the counter; the row is locked (marked used)
    after PASSWORD_RESET_OTP_MAX_ATTEMPTS failures.
    """
    candidate = (otp or "").strip()
    if not candidate:
        return False, "missing", None
    row = get_latest_valid_otp(db, user_id)
    if row is None:
        return False, "missing", None
    if row.is_expired:
        try:
            row.used = True
            db.commit()
        except Exception:
            db.rollback()
        return False, "expired", row
    max_attempts = int(settings.PASSWORD_RESET_OTP_MAX_ATTEMPTS or 5)
    if int(row.attempts or 0) >= max_attempts:
        try:
            row.used = True
            db.commit()
        except Exception:
            db.rollback()
        return False, "locked", row
    if _constant_time_compare(hash_otp(candidate), row.otp_hash):
        return True, "ok", row
    # Wrong code: count attempt, lock on exhaustion.
    try:
        row.attempts = int(row.attempts or 0) + 1
        if int(row.attempts) >= max_attempts:
            row.used = True
        db.commit()
        remaining = max(0, max_attempts - int(row.attempts))
    except Exception:
        db.rollback()
        remaining = 0
    if remaining <= 0:
        return False, "locked", row
    return False, "invalid", row


def consume_otp(db: Session, row: PasswordResetOTP) -> None:
    """Marks an OTP row as used after successful verification."""
    try:
        row.used = True
        db.commit()
    except Exception:
        db.rollback()


def create_reset_token(user_id: str, otp_id: str) -> str:
    return _reset_serializer.dumps({"user_id": user_id, "otp_id": otp_id, "purpose": "forgot-password"})


# Server-side reset sessions. The browser only ever sees an opaque id in a
# short-lived cookie; the signed bearer stays here so it cannot land in a
# request URL, access log, proxy log, or browser history.
# Redis when available (shared across workers), else in-process.
_reset_sessions: dict[str, tuple[str, float]] = {}
_redis_reset = None
_redis_reset_checked = False


def _reset_session_ttl() -> int:
    return int(settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES or 15) * 60


def _get_reset_redis():
    global _redis_reset, _redis_reset_checked
    if _redis_reset_checked:
        return _redis_reset
    _redis_reset_checked = True
    try:
        import redis as _redis_mod

        client = _redis_mod.from_url(settings.REDIS_URL, socket_connect_timeout=0.3, socket_timeout=0.3)
        client.ping()
        _redis_reset = client
    except Exception:
        _redis_reset = None
    return _redis_reset


def _purge_expired_reset_sessions(now: float | None = None) -> None:
    now = time.time() if now is None else now
    expired = [sid for sid, (_token, exp) in _reset_sessions.items() if exp <= now]
    for sid in expired:
        _reset_sessions.pop(sid, None)


def issue_reset_session(token: str) -> str:
    """Stores ``token`` server-side and returns an opaque session id.

    The id carries no user, OTP, or signature material.
    """
    session_id = secrets.token_urlsafe(32)
    ttl = _reset_session_ttl()
    client = _get_reset_redis()
    if client is not None:
        try:
            client.setex(f"pwdreset_session:{session_id}", ttl, token)
            return session_id
        except Exception:
            logger.warning("Reset-session store unavailable; using in-process fallback")
    _purge_expired_reset_sessions()
    _reset_sessions[session_id] = (token, time.time() + ttl)
    return session_id


def lookup_reset_session(session_id: str) -> str | None:
    """Returns the signed token for a live session id, else None."""
    if not session_id:
        return None
    client = _get_reset_redis()
    if client is not None:
        try:
            raw = client.get(f"pwdreset_session:{session_id}")
            if raw is None:
                return None
            return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        except Exception:
            logger.warning("Reset-session lookup failed")
            return None
    _purge_expired_reset_sessions()
    entry = _reset_sessions.get(session_id)
    if entry is None:
        return None
    token, exp = entry
    if exp <= time.time():
        _reset_sessions.pop(session_id, None)
        return None
    return token


def consume_reset_session(session_id: str) -> None:
    """Forgets a reset session so its cookie cannot be replayed."""
    if not session_id:
        return
    client = _get_reset_redis()
    if client is not None:
        try:
            client.delete(f"pwdreset_session:{session_id}")
        except Exception:
            logger.warning("Reset-session consume failed")
    _reset_sessions.pop(session_id, None)


def verify_reset_token(token: str, max_age_seconds: int | None = None) -> dict | None:
    if not token:
        return None
    if max_age_seconds is None:
        max_age_seconds = int(settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES or 15) * 60
    try:
        data = _reset_serializer.loads(token, max_age=int(max_age_seconds))
    except (BadSignature, SignatureExpired, Exception):
        return None
    if not isinstance(data, dict) or data.get("purpose") != "forgot-password":
        return None
    if not data.get("user_id") or not data.get("otp_id"):
        return None
    return data


def validate_new_password(password: str) -> str | None:
    """Returns an error message if ``password`` violates policy, else None."""
    import re as _re

    pw = password or ""
    if len(pw) < 8 or len(pw) > 128:
        return "Password must be 8..128 characters long."
    classes = sum(
        [
            bool(_re.search(r"[A-Z]", pw)),
            bool(_re.search(r"[a-z]", pw)),
            bool(_re.search(r"[0-9]", pw)),
            bool(_re.search(r"[^A-Za-z0-9]", pw)),
        ]
    )
    if classes < 3:
        return "Password must include 3 of: uppercase, lowercase, digit, symbol."
    return None
