"""Background runner loop for in-process or containerized dispatching."""
import time
import signal
import sys
import threading
from app.services.logging_util import setup_structured_logging
from app.services import tracing as _tracing  # noqa: F401 - configures OTel provider
from app.workers.dispatcher import dispatch_batch

setup_structured_logging()
import logging
logger = logging.getLogger("webhook.dispatcher")

stop_requested = False
_last_retention_run: float = 0.0
RETENTION_INTERVAL_SECONDS = 3600.0


def handle_exit(sig, frame):
    global stop_requested
    logger.info("Shutdown signal received. Stopping worker loop...")
    stop_requested = True


def dispatch_once(batch_size: int = 50) -> int:
    """Finds due deliveries and recovers abandoned leases in one cycle."""
    return dispatch_batch(batch_size=batch_size)


def _maybe_run_retention() -> None:
    """Time-based hourly purge (no drift when busy: wall-clock, not cycle count)."""
    global _last_retention_run
    now = time.monotonic()
    if (now - _last_retention_run) < RETENTION_INTERVAL_SECONDS:
        return
    _last_retention_run = now
    try:
        from app.db.session import SessionLocal
        from app.services.retention import purge_expired_data
        from app.services.tracing import start_trace_span as _span
        db = SessionLocal()
        try:
            with _span("retention.purge"):
                result = purge_expired_data(db)
            logger.info("retention_purge_completed", extra=result)
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Retention purge failed: {e}", exc_info=True)


def run_dispatcher_loop(poll_interval: float = 1.0):
    """Continuous polling loop for dispatching webhook deliveries."""
    from app.services.tracing import start_trace_span
    logger.info("Starting reliable webhook delivery dispatcher loop...", extra={"poll_interval": poll_interval})
    try:
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGINT, handle_exit)
            signal.signal(signal.SIGTERM, handle_exit)
    except (ValueError, Exception):
        pass

    while not stop_requested:
        with start_trace_span("dispatcher.loop_cycle"):
            processed = dispatch_once()
        _maybe_run_retention()
        if processed == 0:
            time.sleep(poll_interval)
        else:
            time.sleep(0.1)  # small pause before next batch if busy

    logger.info("Webhook dispatcher stopped cleanly.")


if __name__ == "__main__":
    run_dispatcher_loop()
