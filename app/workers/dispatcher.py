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

# Redis key prefix for Celery pre-dispatch reservations (TTL = visibility window).
_DISPATCH_RESERVE_PREFIX = "dispatch:reserved:"

_redis_client = None


def _get_redis_client():
    """Shared Redis client (connection pool) — one per process, not per cycle."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        import redis as _redis_mod

        _redis_client = _redis_mod.from_url(
            settings.REDIS_URL, socket_timeout=2, socket_connect_timeout=2, max_connections=10
        )
        return _redis_client
    except Exception:
        return None


def _reserve_dispatch_ids(ids: list[str]) -> list[str]:
    """Best-effort Redis reservation for pre-dispatched deliveries.

    Returns the subset of ids that were newly reserved (not already reserved).
    When Redis is unavailable, returns all ids (no dedup): duplicate Celery
    tasks are still safe because claim_delivery() strictly enforces
    next_attempt_at eligibility, so a duplicate arriving before the retry time
    is rejected instead of bypassing backoff.
    """
    if not ids:
        return []
    try:
        client = _get_redis_client()
        if client is None:
            return list(ids)
        try:
            # Reservation TTL matches Celery visibility timeout so a queued-but-
            # slow task cannot expire its reservation and be re-enqueued while
            # the original is still waiting (queue amplification).
            # Must equal broker_transport_options.visibility_timeout
            # = max(LEASE*2, 120) in celery_app.py.
            ttl = max(int(settings.LEASE_DURATION_SECONDS * 2), 120)
        except Exception:
            ttl = 120
        pipe = client.pipeline(transaction=False)
        for did in ids:
            pipe.set(f"{_DISPATCH_RESERVE_PREFIX}{did}", "1", ex=ttl, nx=True)
        results = pipe.execute()
        return [did for did, ok in zip(ids, results) if ok]
    except Exception:
        return list(ids)


def _release_dispatch_ids(ids: list[str]) -> None:
    """Clears reservations for IDs that failed to enqueue or finished execution.

    Dispatcher reserves on enqueue; the Celery worker releases on completion
    (see tasks.deliver_webhook_task). Without release, RETRY_SCHEDULED rows
    with next_attempt in 10s stay reserved for the full TTL and retries stall.
    """
    if not ids:
        return
    try:
        client = _get_redis_client()
        if client is None:
            return
        pipe = client.pipeline(transaction=False)
        for did in ids:
            pipe.delete(f"{_DISPATCH_RESERVE_PREFIX}{did}")
        pipe.execute()
    except Exception:
        pass


def get_due_delivery_ids(db: Session, batch_size: int = 50, mark_dispatched: bool = False) -> list[str]:
    """Queries deliveries in PENDING or RETRY_SCHEDULED status whose next_attempt_at <= now.

    Uses SELECT ... FOR UPDATE SKIP LOCKED on PostgreSQL so concurrent
    dispatchers do not fetch the same rows.
    When mark_dispatched=True (e.g. for Celery/Redis enqueuing), reservations
    are recorded in Redis (TTL = visibility timeout) to prevent duplicate
    enqueue stampedes while tasks wait in the queue. Retry eligibility
    (next_attempt_at) is NEVER mutated here: pushing it forward would force
    claim_delivery() to accept future-scheduled deliveries, letting duplicate
    queued tasks bypass the normal retry backoff. Claim stays strict, so
    duplicates are safe even when Redis is unavailable (no dedup, just extra
    queue entries that the claim rejects).

    Locking: when mark_dispatched=True we fetch IDs WITHOUT row locks first,
    then reserve in Redis, so DB locks are never held across network I/O.
    In-process mode (mark_dispatched=False) keeps SKIP LOCKED since execution
    follows immediately in the same cycle.
    """
    now = utc_now()
    if mark_dispatched:
        # No row locks — avoids holding FOR UPDATE across Redis round-trip.
        try:
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
        except Exception:
            db.rollback()
            return []
        due_ids = [r[0] for r in rows]
        if due_ids:
            due_ids = _reserve_dispatch_ids(due_ids)
        try:
            db.rollback()
        except Exception:
            pass
        return due_ids

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
    # mark_dispatched=True returns early above; this path is in-process only
    # and holds no cross-network locks (locks released on session close).
    try:
        db.rollback()
    except Exception:
        pass

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
        # Recovery must never starve dispatch: isolate it so a recovery
        # failure still lets due deliveries flow this cycle.
        try:
            with start_trace_span("dispatch.recover"):
                run_recovery_cycle(db)
        except Exception as e:
            logger.error(f"Recovery failed, continuing to dispatch: {e}", exc_info=True)
            try:
                db.rollback()
            except Exception:
                pass
        try:
            with start_trace_span("dispatch.fetch_due", {"batch.size": batch_size}):
                due_ids = get_due_delivery_ids(db, batch_size=batch_size, mark_dispatched=settings.USE_CELERY)
        except Exception as e:
            logger.error(f"Error fetching due deliveries: {e}", exc_info=True)
            return 0
    except Exception as e:
        logger.error(f"Error during dispatch batch: {e}", exc_info=True)
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
        failed_ids: list[str] = []
        with start_trace_span("dispatch.celery_enqueue", {"batch.size": len(due_ids)}):
            for dlv_id in due_ids:
                try:
                    deliver_webhook_task.delay(dlv_id)
                    enqueued_count += 1
                except Exception as e:
                    logger.error(f"Failed to enqueue Celery task for delivery {dlv_id}: {e}", exc_info=True)
                    failed_ids.append(dlv_id)
        # Release reservations for failed enqueues so they are retryable next
        # cycle instead of stalling until TTL (30-60s blackout).
        if failed_ids:
            _release_dispatch_ids(failed_ids)
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
