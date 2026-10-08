import json
from typing import Any

from sqlalchemy.orm import Session

from app.models import utc_now
from app.models.audit_log import AuditLog


def log_audit_event(
    db: Session,
    organization_id: str,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    user_id: str | None = None,
    ip_address: str | None = None,
    details: dict[str, Any] | None = None,
    commit: bool = True
) -> AuditLog:
    """Creates an audit log entry for security and compliance tracking.

    Supports commit=False for committing atomically alongside the primary business action.
    """
    details_str = json.dumps(details) if details else None
    entry = AuditLog(
        organization_id=organization_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        details_json=details_str,
        created_at=utc_now()
    )
    db.add(entry)
    if commit:
        try:
            db.commit()
            db.refresh(entry)
        except Exception:
            db.rollback()
            raise
    return entry
