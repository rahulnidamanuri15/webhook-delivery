"""Data-retention purging for events, deliveries, attempts and audit logs.

Policy (see docs/SECURITY.md and .env.example):
  DATA_RETENTION_DAYS=N  -> delete terminal records older than N days.
  DATA_RETENTION_DAYS=0  -> automatic purging disabled (default for dev keeps data).

Only terminal deliveries (SUCCEEDED/DEAD) and their attempts are purged.
Events are removed once all their deliveries are terminal and old enough.
Audit logs older than the window are also trimmed.
"""
import logging
from datetime import timedelta

from sqlalchemy.orm import Session

from app.config import settings
from app.models import Delivery, DeliveryAttempt, Event, utc_now

logger = logging.getLogger("webhook.retention")


def purge_expired_data(
    db: Session, retention_days: int | None = None, audit_retention_days: int | None = None, batch_size: int = 1000
) -> dict:
    if retention_days is None:
        retention_days = settings.DATA_RETENTION_DAYS
    if audit_retention_days is None:
        audit_retention_days = getattr(settings, "AUDIT_RETENTION_DAYS", 365)
    if not retention_days or retention_days <= 0:
        return {"purged_attempts": 0, "purged_deliveries": 0, "purged_events": 0, "purged_audit_logs": 0, "disabled": True}

    cutoff = utc_now() - timedelta(days=retention_days)
    audit_cutoff = utc_now() - timedelta(days=audit_retention_days) if audit_retention_days and audit_retention_days > 0 else None

    purged_attempts = 0
    purged_deliveries = 0
    purged_events = 0
    purged_audit = 0

    # 1. Batched delete: attempts then deliveries for old terminal deliveries.
    # Uses keyset batches (no unbounded IN list, short transactions).
    while True:
        batch_ids = [
            r[0]
            for r in db.query(Delivery.id)
            .filter(Delivery.status.in_(["SUCCEEDED", "DEAD"]), Delivery.created_at < cutoff)
            .limit(batch_size)
            .all()
        ]
        if not batch_ids:
            break
        purged_attempts += (
            db.query(DeliveryAttempt)
            .filter(DeliveryAttempt.delivery_id.in_(batch_ids))
            .delete(synchronize_session=False)
        )
        purged_deliveries += (
            db.query(Delivery).filter(Delivery.id.in_(batch_ids)).delete(synchronize_session=False)
        )
        db.commit()
        if len(batch_ids) < batch_size:
            break

    # 2. Delete old orphaned events in batches (anti-join, no N+1).
    while True:
        orphan_ids = [
            r[0]
            for r in db.query(Event.id)
            .outerjoin(Delivery, Delivery.event_id == Event.id)
            .filter(Event.created_at < cutoff, Delivery.id.is_(None))
            .limit(batch_size)
            .all()
        ]
        if not orphan_ids:
            break
        purged_events += (
            db.query(Event).filter(Event.id.in_(orphan_ids)).delete(synchronize_session=False)
        )
        db.commit()
        if len(orphan_ids) < batch_size:
            break

    # 3. Trim old audit logs (separate longer retention) in batches.
    try:
        from app.models.audit_log import AuditLog

        if audit_cutoff is not None:
            while True:
                audit_ids = [
                    r[0]
                    for r in db.query(AuditLog.id)
                    .filter(AuditLog.created_at < audit_cutoff)
                    .limit(batch_size)
                    .all()
                ]
                if not audit_ids:
                    break
                purged_audit += (
                    db.query(AuditLog).filter(AuditLog.id.in_(audit_ids)).delete(synchronize_session=False)
                )
                db.commit()
                if len(audit_ids) < batch_size:
                    break
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
