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


def get_legal_hold_ids(raw: str | set[str] | list[str] | None) -> set[str] | None:
    """Parses LEGAL_HOLD_PROJECT_IDS from settings or env into a set.

    Centralizes parsing so tasks.py / runner.py honor settings.LEGAL_HOLD_PROJECT_IDS
    (including *_FILE secrets) instead of reading os.getenv directly.
    """
    if raw is None:
        return None
    if isinstance(raw, (set, list, tuple)):
        hold = {str(p).strip() for p in raw if str(p).strip()}
        return hold or None
    hold = {p.strip() for p in str(raw or "").split(",") if p.strip()}
    return hold or None


def purge_expired_data(
    db: Session,
    retention_days: int | None = None,
    audit_retention_days: int | None = None,
    batch_size: int = 1000,
    legal_hold_project_ids: set[str] | list[str] | None = None,
) -> dict:
    if retention_days is None:
        retention_days = settings.DATA_RETENTION_DAYS
    if audit_retention_days is None:
        audit_retention_days = getattr(settings, "AUDIT_RETENTION_DAYS", 365)
    if not retention_days or retention_days <= 0:
        return {
            "purged_attempts": 0,
            "purged_deliveries": 0,
            "purged_events": 0,
            "purged_audit_logs": 0,
            "disabled": True,
        }

    cutoff = utc_now() - timedelta(days=retention_days)
    audit_cutoff = (
        utc_now() - timedelta(days=audit_retention_days) if audit_retention_days and audit_retention_days > 0 else None
    )

    purged_attempts = 0
    purged_deliveries = 0
    purged_events = 0
    purged_audit = 0

    hold_set = set(legal_hold_project_ids or [])

    # 1. Batched delete: attempts then deliveries for old terminal deliveries.
    # Uses keyset batches (no unbounded IN list, short transactions).
    # Uses completed_at (terminal time); legacy rows with NULL completed_at
    # fall back to created_at so they are still purged exactly once.
    from sqlalchemy import and_ as _and
    from sqlalchemy import or_ as _or

    while True:
        query = db.query(Delivery.id)
        if hold_set:
            query = query.join(Event, Delivery.event_id == Event.id).filter(Event.project_id.notin_(hold_set))
        batch_ids = [
            r[0]
            for r in query.filter(
                Delivery.status.in_(["SUCCEEDED", "DEAD"]),
                _or(
                    Delivery.completed_at < cutoff,
                    _and(Delivery.completed_at.is_(None), Delivery.created_at < cutoff),
                ),
            )
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
        purged_deliveries += db.query(Delivery).filter(Delivery.id.in_(batch_ids)).delete(synchronize_session=False)
        db.commit()
        if len(batch_ids) < batch_size:
            break

    # 2. Delete old orphaned events in batches (anti-join, no N+1).
    while True:
        eq = db.query(Event.id)
        if hold_set:
            eq = eq.filter(Event.project_id.notin_(hold_set))
        orphan_ids = [
            r[0]
            for r in eq.outerjoin(Delivery, Delivery.event_id == Event.id)
            .filter(Event.created_at < cutoff, Delivery.id.is_(None))
            .limit(batch_size)
            .all()
        ]
        if not orphan_ids:
            break
        purged_events += db.query(Event).filter(Event.id.in_(orphan_ids)).delete(synchronize_session=False)
        db.commit()
        if len(orphan_ids) < batch_size:
            break

    # 3. Trim old audit logs (separate longer retention) in batches.
    # Legal hold applies here too: audit rows for orgs containing held
    # projects are excluded. AuditLog is org-scoped, hold_set is project-scoped,
    # so resolve held org ids first.
    try:
        from app.models.audit_log import AuditLog

        hold_org_ids: set[str] = set()
        if hold_set:
            try:
                from app.models import Project as _Project

                rows = db.query(_Project.organization_id).filter(_Project.id.in_(list(hold_set))).all()
                hold_org_ids = {r[0] for r in rows if r[0]}
            except Exception:
                hold_org_ids = set()

        if audit_cutoff is not None:
            while True:
                _aq = db.query(AuditLog.id).filter(AuditLog.created_at < audit_cutoff)
                if hold_org_ids:
                    _aq = _aq.filter(AuditLog.organization_id.notin_(hold_org_ids))
                audit_ids = [r[0] for r in _aq.limit(batch_size).all()]
                if not audit_ids:
                    break
                purged_audit += db.query(AuditLog).filter(AuditLog.id.in_(audit_ids)).delete(synchronize_session=False)
                db.commit()
                if len(audit_ids) < batch_size:
                    break
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        purged_audit = 0

    db.commit()

    logger.info(
        "retention_purge",
        extra={
            "purged_attempts": purged_attempts,
            "purged_deliveries": purged_deliveries,
            "purged_events": purged_events,
            "purged_audit_logs": purged_audit,
            "cutoff": cutoff.isoformat(),
        },
    )
    return {
        "purged_attempts": purged_attempts,
        "purged_deliveries": purged_deliveries,
        "purged_events": purged_events,
        "purged_audit_logs": purged_audit,
        "disabled": False,
    }
