"""Delivery dispatcher module.

Finds due work in PostgreSQL according to the central architectural principle:
PostgreSQL owns delivery state, Redis transports work.
"""

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from sqlalchemy.orm import Session

from app.config import settings
from app.db.session import SessionLocal
from app.models import Delivery, utc_now
from app.services.delivery_service import execute_delivery
from app.services.tracing import start_trace_span
from app.workers.recovery import run_recovery_cycle

logger = logging.getLogger("webhook.dispatcher")

# Bound outbound concurrency so one slow endpoint cannot starve others.
# Each delivery gets its own DB session; threads only block on HTTP, not on each other.
DISPATCH_MAX_WORKERS = int(os.getenv("DISPATCH_MAX_WORKERS", "10"))


def get_due_delivery_ids(db: Session, batch_size: int = 50, mark_dispatched: bool = False) -> list[str]:
    """Queries deliveries in PENDING or RETRY_SCHEDULED status whose next_attempt_at <= now.

    Uses SELECT ... FOR UPDATE SKIP LOCKED on PostgreSQL so concurrent
    dispatchers do not fetch the same rows.
    When mark_dispatched=True (e.g. for Celery/Redis enqueuing), pushes
    next_attempt_at forward by LEASE_DURATION_SECONDS within the transaction
    to prevent duplicate enqueue stampedes while tasks wait in the queue.
    """
    now = utc_now()
    try:
        rows = (
            db.query(Delivery.id)
            .filter(
                Delivery.status.in_(["PENDING", "RETRY_SCHEDULED"]),
                Delivery.next_attempt_at <= now,
            )
            .order_by(Delivery.next_attempt_at.asc())
            .limit(batch_size)
            .with_for_update(skip_locked=True)
            .all()
        )
    except Exception:
        # Fallback for backends without SKIP LOCKED support.
        db.rollback()
        rows = (
            db.query(Delivery.id)
            .filter(
                Delivery.status.in_(["PENDING", "RETRY_SCHEDULED"]),
                Delivery.next_attempt_at <= now,
            )
            .order_by(Delivery.next_attempt_at.asc())
            .limit(batch_size)
            .all()
        )

    due_ids = [r[0] for r in rows]
    if mark_dispatched and due_ids:
        from datetime import timedelta

        dispatch_lease = timedelta(seconds=settings.LEASE_DURATION_SECONDS)
        db.query(Delivery).filter(Delivery.id.in_(due_ids)).update(
            {"next_attempt_at": now + dispatch_lease}, synchronize_session=False
        )
        db.commit()

    return due_ids


def _execute_single(delivery_id: str) -> bool:
    """Executes one delivery with its own DB session (thread-safe)."""
    db = SessionLocal()
    try:
        return bool(execute_delivery(db, delivery_id))
    except Exception as e:
        logger.error(f"Error executing delivery {delivery_id}: {e}", exc_info=True)
        return False
    finally:
        db.close()


def dispatch_batch(batch_size: int = 50, max_workers: int | None = None) -> int:
    """Dispatches a single batch of due deliveries.

    1. Recovers expired in-flight leases from crashed workers.
    2. Fetches due delivery IDs.
    3. Executes each delivery concurrently in a bounded thread pool so one
       slow/limited endpoint does not block all other endpoints.
    """
    db = SessionLocal()
    try:
        with start_trace_span("dispatch.recover"):
            run_recovery_cycle(db)
        with start_trace_span("dispatch.fetch_due", {"batch.size": batch_size}):
            due_ids = get_due_delivery_ids(db, batch_size=batch_size, mark_dispatched=settings.USE_CELERY)
    except Exception as e:
        logger.error(f"Error during dispatch batch: {e}", exc_info=True)
        try:
            db.close()
        except Exception:
            pass
        return 0
    finally:
        try:
            db.close()
        except Exception:
            pass
    if not due_ids:
        return 0

    if settings.USE_CELERY:
        from app.workers.tasks import deliver_webhook_task

        enqueued_count = 0
        with start_trace_span("dispatch.celery_enqueue", {"batch.size": len(due_ids)}):
            for dlv_id in due_ids:
                try:
                    deliver_webhook_task.delay(dlv_id)
                    enqueued_count += 1
                except Exception as e:
                    logger.error(f"Failed to enqueue Celery task for delivery {dlv_id}: {e}", exc_info=True)
        return enqueued_count

    workers = max(1, min(max_workers or DISPATCH_MAX_WORKERS, len(due_ids)))
    if workers == 1 or len(due_ids) == 1:
        count = 0
        for dlv_id in due_ids:
            try:
                _execute_single(dlv_id)
                count += 1
            except Exception:
                pass
        return count
    processed_count = 0
    with start_trace_span("dispatch.execute_batch", {"batch.size": len(due_ids), "workers": workers}):
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dispatch") as pool:
            futures = {pool.submit(_execute_single, dlv_id): dlv_id for dlv_id in due_ids}
            for fut in as_completed(futures):
                try:
                    fut.result()
                    processed_count += 1
                except Exception as e:
                    logger.error(f"Error executing delivery {futures[fut]}: {e}", exc_info=True)
    return processed_count
