import time
import logging
import signal
import sys
import threading
from app.db.session import SessionLocal
from app.models import Delivery, utc_now
from app.services.delivery_service import execute_delivery, recover_abandoned_leases

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("webhook.dispatcher")

stop_requested = False

def handle_exit(sig, frame):
    global stop_requested
    logger.info("Shutdown signal received. Stopping worker loop...")
    stop_requested = True

def dispatch_once(batch_size: int = 50) -> int:
    """Finds due deliveries and recovers abandoned leases in one cycle."""
    db = SessionLocal()
    processed_count = 0
    try:
        # 1. Recover abandoned leases from crashed workers
        recovered = recover_abandoned_leases(db)
        if recovered > 0:
            logger.info(f"Crash recovery restored {recovered} abandoned deliveries.")

        # 2. Find eligible due deliveries
        now = utc_now()
        due_deliveries = (
            db.query(Delivery.id)
            .filter(
                Delivery.status.in_(["PENDING", "RETRY_SCHEDULED"]),
                Delivery.next_attempt_at <= now
            )
            .order_by(Delivery.next_attempt_at.asc())
            .limit(batch_size)
            .all()
        )

        for (dlv_id,) in due_deliveries:
            success = execute_delivery(db, dlv_id)
            processed_count += 1

    except Exception as e:
        logger.error(f"Error during dispatch cycle: {e}", exc_info=True)
    finally:
        db.close()

    return processed_count

def run_dispatcher_loop(poll_interval: float = 1.0):
    """Continuous polling loop for dispatching webhook deliveries."""
    logger.info("Starting reliable webhook delivery dispatcher loop...")
    try:
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGINT, handle_exit)
            signal.signal(signal.SIGTERM, handle_exit)
    except (ValueError, Exception):
        pass

    while not stop_requested:
        processed = dispatch_once()
        if processed == 0:
            time.sleep(poll_interval)
        else:
            time.sleep(0.1)  # small pause before next batch if busy

    logger.info("Webhook dispatcher stopped cleanly.")

if __name__ == "__main__":
    run_dispatcher_loop()
