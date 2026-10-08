"""Lease recovery service for webhook workers.

Handles detecting and reconciling deliveries whose leases expired while IN_FLIGHT,
which indicates worker crashes, killed containers, or transient broker loss.
"""

import logging

from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.services.delivery_service import recover_abandoned_leases

logger = logging.getLogger("webhook.recovery")


def run_recovery_cycle(db: Session = None) -> int:
    """Scans and recovers abandoned leases in PostgreSQL.

    Returns the count of deliveries reclaimed.
    """
    should_close = False
    if db is None:
        db = SessionLocal()
        should_close = True

    try:
        recovered = recover_abandoned_leases(db)
        if recovered > 0:
            logger.warning(
                f"[Crash Recovery] Reclaimed {recovered} abandoned in-flight deliveries with expired leases."
            )
        return recovered
    finally:
        if should_close:
            db.close()
