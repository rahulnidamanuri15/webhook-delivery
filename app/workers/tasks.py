"""Celery task definitions for background webhook execution and dispatching."""

import logging

from app.db.session import SessionLocal
from app.services.delivery_service import execute_delivery
from app.services.tracing import start_trace_span
from app.workers.celery_app import celery_app
from app.workers.dispatcher import get_due_delivery_ids
from app.workers.recovery import run_recovery_cycle

logger = logging.getLogger("webhook.tasks")


@celery_app.task(name="tasks.deliver_webhook")
def deliver_webhook_task(delivery_id: str) -> bool:
    """Executes a single webhook delivery using lease acquisition, HMAC signing, and backoff."""
    db = SessionLocal()
    try:
        with start_trace_span("delivery.execute", {"delivery.id": delivery_id}):
            return execute_delivery(db, delivery_id)
    except Exception as e:
        logger.error(f"Task delivery failed for {delivery_id}: {e}", exc_info=True)
        # Explicit rollback so the pooled connection is reusable after
        # OperationalError in claim_delivery (close() would roll back anyway).
        # Return False (acked): durability is owned by PG lease + recovery,
        # not Celery retry, so failures stay visible via attempts/DLQ.
        try:
            db.rollback()
        except Exception:
            pass
        return False
    finally:
        try:
            db.close()
        except Exception:
            pass
        # Release the pre-dispatch reservation so the next retry (e.g. +10s)
        # becomes visible on schedule instead of stalling until TTL.
        try:
            from app.workers.dispatcher import _release_dispatch_ids as _rel

            _rel([delivery_id])
        except Exception:
            pass


@celery_app.task(name="tasks.dispatch_due_deliveries")
def dispatch_due_deliveries_task(batch_size: int = 100) -> int:
    """Scans PostgreSQL for due deliveries and enqueues tasks to Celery workers."""
    from app.workers.dispatcher import _release_dispatch_ids

    db = SessionLocal()
    try:
        with start_trace_span("dispatch.cycle", {"batch.size": batch_size}):
            # Reclaim crashed leases without starving dispatch on recovery errors.
            try:
                run_recovery_cycle(db)
            except Exception as e:
                logger.error(f"Recovery failed, continuing to dispatch: {e}", exc_info=True)
                try:
                    db.rollback()
                except Exception:
                    pass

            # Enqueue due deliveries (mark_dispatched=True prevents beat stampedes)
            due_ids = get_due_delivery_ids(db, batch_size=batch_size, mark_dispatched=True)
            enqueued = 0
            failed: list[str] = []
            for dlv_id in due_ids:
                try:
                    deliver_webhook_task.delay(dlv_id)
                    enqueued += 1
                except Exception as e:
                    logger.error(f"Failed to enqueue {dlv_id}: {e}", exc_info=True)
                    failed.append(dlv_id)
            if failed:
                _release_dispatch_ids(failed)

            return enqueued
    except Exception as e:
        logger.error(f"Error in dispatch_due_deliveries_task: {e}", exc_info=True)
        try:
            db.rollback()
        except Exception:
            pass
        return 0
    finally:
        db.close()


@celery_app.task(name="tasks.recover_abandoned_leases")
def recover_abandoned_leases_task() -> int:
    """Periodic task to reconcile any abandoned IN_FLIGHT leases."""
    with start_trace_span("recovery.cycle"):
        return run_recovery_cycle()


@celery_app.task(name="tasks.purge_expired_data")
def purge_expired_data_task() -> dict:
    """Periodic retention purge (see DATA_RETENTION_DAYS). Honors legal hold."""
    from app.config import settings as _settings
    from app.services.retention import get_legal_hold_ids, purge_expired_data

    db = SessionLocal()
    try:
        with start_trace_span("retention.purge"):
            hold = get_legal_hold_ids(_settings.LEGAL_HOLD_PROJECT_IDS)
            return purge_expired_data(db, legal_hold_project_ids=hold)
    except Exception as e:
        logger.error(f"Retention purge failed: {e}", exc_info=True)
        return {"error": str(e)}
    finally:
        db.close()
