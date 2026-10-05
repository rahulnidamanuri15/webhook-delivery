from celery import Celery
from app.config import settings
from app.db.session import SessionLocal
from app.services.delivery_service import execute_delivery, recover_abandoned_leases
from app.models import Delivery, utc_now

celery_app = Celery(
    "webhook_delivery",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)

@celery_app.task(name="tasks.deliver_webhook")
def deliver_webhook_task(delivery_id: str):
    """Executes a single webhook delivery."""
    db = SessionLocal()
    try:
        execute_delivery(db, delivery_id)
    finally:
        db.close()

@celery_app.task(name="tasks.dispatch_due_deliveries")
def dispatch_due_deliveries_task():
    """Scans for due deliveries and enqueues Celery delivery tasks."""
    db = SessionLocal()
    try:
        now = utc_now()
        due_deliveries = (
            db.query(Delivery.id)
            .filter(
                Delivery.status.in_(["PENDING", "RETRY_SCHEDULED"]),
                Delivery.next_attempt_at <= now
            )
            .limit(100)
            .all()
        )
        for (dlv_id,) in due_deliveries:
            deliver_webhook_task.delay(dlv_id)
            
        recover_abandoned_leases(db)
    finally:
        db.close()
