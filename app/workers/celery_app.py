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
    broker_connection_max_retries=10,
    broker_transport_options={
        "visibility_timeout": max(int(settings.LEASE_DURATION_SECONDS * 2), 60),
    },
    task_time_limit=settings.LEASE_DURATION_SECONDS,
    task_soft_time_limit=int(settings.HTTP_TIMEOUT_SECONDS + 5),
    result_expires=3600,
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
