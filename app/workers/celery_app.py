"""Celery application configuration and initialization."""

from celery import Celery

from app.config import settings

celery_app = Celery(
    "webhook_delivery",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_reject_on_worker_lost=True,
    broker_connection_retry_on_startup=True,
    # Unbounded reconnect for prod: a transient Redis restart must not kill
    # workers (previous max_retries=10 exited the process). None = retry forever.
    broker_connection_max_retries=None,
    broker_transport_options={
        "visibility_timeout": max(int(settings.LEASE_DURATION_SECONDS * 2), 120),
    },
    # Hard limit stays strictly below lease (30s) so SIGKILL races recovery less;
    # soft limit (HTTP+5) lets httpx errors surface as retryable first.
    task_time_limit=max(int(settings.LEASE_DURATION_SECONDS - 5), 20),
    task_soft_time_limit=int(settings.HTTP_TIMEOUT_SECONDS + 5),
    result_expires=3600,
    # Delivery/dispatch tasks only return bool/count for chaining; results would
    # otherwise pile in Redis (256MB prod) with no consumer.
    task_ignore_result=True,
    worker_cancel_long_running_tasks_on_connection_loss=True,
    beat_schedule={
        "dispatch-due-deliveries-every-2s": {
            "task": "tasks.dispatch_due_deliveries",
            "schedule": 2.0,
        },
        "recover-abandoned-leases-every-30s": {
            "task": "tasks.recover_abandoned_leases",
            "schedule": 30.0,
        },
        "purge-expired-data-hourly": {
            "task": "tasks.purge_expired_data",
            "schedule": 3600.0,
        },
    },
)


# Auto-import tasks to register them with the Celery app
import app.workers.tasks  # noqa: F401

# Prefork fork-safety: the SQLAlchemy engine is created at import time
# (app/db/session.py). After fork, child processes must not share the parent's
# pooled psycopg sockets. Dispose the pool in each worker child.
try:
    from celery.signals import worker_process_init as _wpi

    @_wpi.connect
    def _dispose_engine_on_fork(**kwargs):  # pragma: no cover - worker runtime only
        try:
            from app.db.session import engine as _eng

            _eng.dispose()
        except Exception:
            pass

except Exception:
    pass
