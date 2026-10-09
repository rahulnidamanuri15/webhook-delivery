from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import ApiKey, Project, User
from app.services.security import hash_api_key_candidates, verify_session_token

security = HTTPBearer(auto_error=False)


def get_current_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(security),
    db: Session = Depends(get_db),
) -> tuple[ApiKey, Project]:
    """Authenticates Bearer API keys for developer public endpoints."""
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Bearer authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Pre-auth IP throttle (before expensive DB lookup) to slow key guessing.
    try:
        from app.services.rate_limiter import check_api_auth_rate_limit
        from app.services.security import get_client_ip

        _ip = get_client_ip(request)
        _allowed, _wait = check_api_auth_rate_limit(_ip)
        if not _allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many authentication attempts.",
                headers={"Retry-After": str(max(1, int(_wait)))},
            )
    except HTTPException:
        raise
    except Exception:
        pass

    raw_token = credentials.credentials.strip()
    candidates = hash_api_key_candidates(raw_token)

    api_key = db.query(ApiKey).filter(ApiKey.key_hash.in_(candidates), ApiKey.revoked_at.is_(None)).first()

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return api_key, api_key.project


def _is_session_stale_from_pwd_change(token: str, password_changed_at) -> bool:
    if not password_changed_at:
        return False
    try:
        from app.services.security import serializer

        _, ts = serializer.loads(token, return_timestamp=True, max_age=86400 * 7)
        token_ts = ts.timestamp() if hasattr(ts, "timestamp") else float(ts)
        pwd_ts = (
            password_changed_at.timestamp() if hasattr(password_changed_at, "timestamp") else float(password_changed_at)
        )
        return token_ts < pwd_ts
    except Exception:
        return False


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Authenticates server-side session cookie for dashboard UI."""
    token = request.cookies.get("wh_session")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    data = verify_session_token(token)
    if not data or "user_id" not in data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid")

    user = db.query(User).filter(User.id == data["user_id"]).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    if _is_session_stale_from_pwd_change(token, user.password_changed_at):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session invalidated due to password reset. Please sign in again.",
        )

    return user


def get_optional_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    token = request.cookies.get("wh_session")
    if not token:
        return None
    data = verify_session_token(token)
    if not data or "user_id" not in data:
        return None
    user = db.query(User).filter(User.id == data["user_id"]).first()
    if not user:
        return None
    if _is_session_stale_from_pwd_change(token, user.password_changed_at):
        return None
    return user
