
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import ApiKey, Project, User
from app.services.security import hash_api_key_candidates, verify_session_token

security = HTTPBearer(auto_error=False)

def get_current_api_key(
    credentials: HTTPAuthorizationCredentials | None = Security(security),
    db: Session = Depends(get_db)
) -> tuple[ApiKey, Project]:
    """Authenticates Bearer API keys for developer public endpoints."""
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Bearer authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_token = credentials.credentials.strip()
    candidates = hash_api_key_candidates(raw_token)

    api_key = (
        db.query(ApiKey)
        .filter(ApiKey.key_hash.in_(candidates), ApiKey.revoked_at.is_(None))
        .first()
    )

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return api_key, api_key.project

def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Authenticates server-side session cookie for dashboard UI."""
    token = request.cookies.get("wh_session")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    data = verify_session_token(token)
    if not data or "user_id" not in data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid"
        )

    user = db.query(User).filter(User.id == data["user_id"]).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    return user

def get_optional_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    token = request.cookies.get("wh_session")
    if not token:
        return None
    data = verify_session_token(token)
    if not data or "user_id" not in data:
        return None
    return db.query(User).filter(User.id == data["user_id"]).first()
