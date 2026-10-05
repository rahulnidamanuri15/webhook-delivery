import json
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.models.audit_log import AuditLog
from app.models import utc_now

def log_audit_event(
    db: Session,
    organization_id: str,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> AuditLog:
    """Creates an audit log entry for security and compliance tracking."""
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
    db.commit()
    db.refresh(entry)
    return entry
