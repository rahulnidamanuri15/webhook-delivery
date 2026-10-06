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
        return False
    finally:
        db.close()


@celery_app.task(name="tasks.dispatch_due_deliveries")
def dispatch_due_deliveries_task(batch_size: int = 100) -> int:
    """Scans PostgreSQL for due deliveries and enqueues tasks to Celery workers."""
    db = SessionLocal()
    try:
        with start_trace_span("dispatch.cycle", {"batch.size": batch_size}):
            # Reclaim any crashed worker leases
            run_recovery_cycle(db)

            # Enqueue due deliveries
            due_ids = get_due_delivery_ids(db, batch_size=batch_size)
            for dlv_id in due_ids:
                deliver_webhook_task.delay(dlv_id)

            return len(due_ids)
    except Exception as e:
        logger.error(f"Error in dispatch_due_deliveries_task: {e}", exc_info=True)
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
    """Periodic retention purge (see DATA_RETENTION_DAYS)."""
    from app.services.retention import purge_expired_data
    db = SessionLocal()
    try:
        with start_trace_span("retention.purge"):
            return purge_expired_data(db)
    except Exception as e:
        logger.error(f"Retention purge failed: {e}", exc_info=True)
        return {"error": str(e)}
    finally:
        db.close()
