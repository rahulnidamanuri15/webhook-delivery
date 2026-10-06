"""Data-retention purging for events, deliveries, attempts and audit logs.

Policy (see docs/SECURITY.md and .env.example):
  DATA_RETENTION_DAYS=N  -> delete terminal records older than N days.
  DATA_RETENTION_DAYS=0  -> automatic purging disabled (default for dev keeps data).

Only terminal deliveries (SUCCEEDED/DEAD) and their attempts are purged.
Events are removed once all their deliveries are terminal and old enough.
Audit logs older than the window are also trimmed.
"""
from datetime import timedelta
import logging
from sqlalchemy.orm import Session
from sqlalchemy import and_
from app.models import Event, Delivery, DeliveryAttempt, utc_now
from app.config import settings

logger = logging.getLogger("webhook.retention")


def purge_expired_data(db: Session, retention_days: int | None = None) -> dict:
    if retention_days is None:
        retention_days = settings.DATA_RETENTION_DAYS
    if not retention_days or retention_days <= 0:
        return {"purged_attempts": 0, "purged_deliveries": 0, "purged_events": 0, "purged_audit_logs": 0, "disabled": True}

    cutoff = utc_now() - timedelta(days=retention_days)

    # 1. Delete attempts belonging to old terminal deliveries
    old_terminal_delivery_ids = [
        r[0] for r in db.query(Delivery.id).filter(
            Delivery.status.in_(["SUCCEEDED", "DEAD"]),
            Delivery.created_at < cutoff,
        ).all()
    ]
    purged_attempts = 0
    purged_deliveries = 0
    purged_events = 0
    purged_audit = 0

    if old_terminal_delivery_ids:
        purged_attempts = db.query(DeliveryAttempt).filter(
            DeliveryAttempt.delivery_id.in_(old_terminal_delivery_ids)
        ).delete(synchronize_session=False)
        purged_deliveries = db.query(Delivery).filter(
            Delivery.id.in_(old_terminal_delivery_ids)
        ).delete(synchronize_session=False)

    # 2. Delete old events that no longer have deliveries (orphaned terminal events)
    # Events with remaining non-terminal deliveries are preserved.
    old_events = db.query(Event).filter(Event.created_at < cutoff).all()
    for evt in old_events:
        remaining = db.query(Delivery).filter(Delivery.event_id == evt.id).count()
        if remaining == 0:
            db.delete(evt)
            purged_events += 1

    # 3. Trim old audit logs
    try:
        from app.models.audit_log import AuditLog
        purged_audit = db.query(AuditLog).filter(AuditLog.created_at < cutoff).delete(synchronize_session=False)
    except Exception:
        purged_audit = 0

    db.commit()
    logger.info(
        "retention_purge",
        extra={"purged_attempts": purged_attempts, "purged_deliveries": purged_deliveries,
               "purged_events": purged_events, "purged_audit_logs": purged_audit, "cutoff": cutoff.isoformat()},
    )
    return {
        "purged_attempts": purged_attempts,
        "purged_deliveries": purged_deliveries,
        "purged_events": purged_events,
        "purged_audit_logs": purged_audit,
        "disabled": False,
    }
