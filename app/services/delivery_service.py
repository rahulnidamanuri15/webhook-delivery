import uuid
import time
import random
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import httpx
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from app.models import Delivery, DeliveryAttempt, Endpoint, Event, utc_now
from app.config import settings
from app.services.security import decrypt_secret
from app.services.signing import generate_webhook_headers
from app.services.ssrf import validate_webhook_url

logger = logging.getLogger("webhook.delivery")

def calculate_backoff_seconds(attempt_number: int, retry_after_header: Optional[str] = None) -> int:
    """Calculates backoff delay in seconds with jitter or honors Retry-After header."""
    if retry_after_header:
        try:
            delay = int(retry_after_header.strip())
            if 1 <= delay <= 3600:
                return delay
        except (ValueError, TypeError):
            pass

    intervals = (
        settings.DEMO_RETRY_INTERVALS
        if settings.USE_DEMO_RETRY_POLICY
        else settings.DEFAULT_RETRY_INTERVALS
    )
    
    idx = min(max(0, attempt_number - 1), len(intervals) - 1)
    base_interval = intervals[idx]
    
    # Add +/- 15% jitter to prevent thundering herd
    jitter_factor = random.uniform(0.85, 1.15)
    return max(1, int(base_interval * jitter_factor))

def is_retryable_http_status(status_code: int) -> bool:
    """HTTP 408 (Request Timeout), 429 (Too Many Requests), and 5xx are retryable."""
    return status_code in (408, 429) or (500 <= status_code <= 599)

def claim_delivery(db: Session, delivery_id: str) -> Optional[Tuple[Delivery, str]]:
    """
    Attempts to atomically acquire an execution lease on a delivery row.
    Returns (delivery, lease_token) if claimed, or None if already claimed/completed.
    """
    now = utc_now()
    delivery = (
        db.query(Delivery)
        .filter(
            Delivery.id == delivery_id,
            Delivery.status.in_(["PENDING", "RETRY_SCHEDULED"]),
            Delivery.next_attempt_at <= now
        )
        .with_for_update(skip_locked=True)
        .first()
    )

    if not delivery:
        return None

    lease_token = uuid.uuid4().hex
    delivery.status = "IN_FLIGHT"
    delivery.lease_token = lease_token
    delivery.lease_expires_at = now + timedelta(seconds=settings.LEASE_DURATION_SECONDS)
    delivery.attempt_count += 1
    
    db.commit()
    db.refresh(delivery)
    return delivery, lease_token

def execute_delivery(db: Session, delivery_id: str) -> bool:
    """
    Executes a single delivery:
    1. Claims the delivery with a lease.
    2. Performs the HTTP POST request OUTSIDE any database transaction.
    3. Verifies lease ownership and records attempt outcome.
    """
    claim_result = claim_delivery(db, delivery_id)
    if not claim_result:
        return False

    delivery, claimed_lease_token = claim_result
    event = delivery.event
    endpoint = delivery.endpoint

    # 1. Endpoint Rate Limiting (Phase 6 requirement: defer without consuming attempt budget)
    if endpoint and endpoint.rate_limit_per_second:
        from app.services.rate_limiter import check_endpoint_rate_limit
        allowed, wait_seconds = check_endpoint_rate_limit(endpoint.id, endpoint.rate_limit_per_second)
        if not allowed:
            # Defer without consuming attempt budget
            now = utc_now()
            delivery.status = "RETRY_SCHEDULED"
            delivery.attempt_count = max(0, delivery.attempt_count - 1)  # Restore attempt count
            delivery.next_attempt_at = now + timedelta(seconds=max(1.0, wait_seconds))
            delivery.lease_token = None
            delivery.lease_expires_at = None
            db.commit()
            logger.info(f"Delivery {delivery_id} deferred by {wait_seconds:.2f}s due to endpoint rate limit.")
            return False

    # 2. SSRF & DNS Rebinding Protection
    from app.services.ssrf import resolve_and_pin_destination
    is_safe, ssrf_err, target_connection_url, pinned_headers = resolve_and_pin_destination(delivery.target_url_snapshot)
    if not is_safe or not endpoint or not endpoint.enabled:
        reason = ssrf_err if not is_safe else "Endpoint disabled or deleted"
        _save_terminal_failure(db, delivery_id, claimed_lease_token, reason)
        return False

    # 3. Decrypt endpoint signing secret
    try:
        secret = decrypt_secret(endpoint.encrypted_signing_secret)
    except Exception as e:
        logger.error(f"Failed to decrypt endpoint secret for {endpoint.id}: {e}")
        _save_terminal_failure(db, delivery_id, claimed_lease_token, f"Secret decryption error: {e}")
        return False

    # 4. Generate headers with HMAC signature and fresh timestamp
    headers = generate_webhook_headers(
        secret=secret,
        event_id=event.id,
        delivery_id=delivery.id,
        payload=event.wire_payload
    )
    headers.update(pinned_headers)

    # 5. Outbound HTTP request executed safely outside DB transaction
    started_at = utc_now()
    start_time = time.perf_counter()
    http_status = None
    error_code = None
    response_excerpt = None
    retry_after = None
    outcome = "RETRYABLE_ERROR"

    try:
        with httpx.Client(timeout=settings.HTTP_TIMEOUT_SECONDS, follow_redirects=False) as client:
            resp = client.post(
                target_connection_url,
                content=event.wire_payload.encode("utf-8"),
                headers=headers
            )
            http_status = resp.status_code
            retry_after = resp.headers.get("retry-after")
            
            # Read bounded response excerpt
            raw_text = resp.text[:settings.RESPONSE_EXCERPT_MAX_BYTES]
            response_excerpt = raw_text

            if 200 <= http_status <= 299:
                outcome = "SUCCESS"
            elif is_retryable_http_status(http_status):
                outcome = "RETRYABLE_ERROR"
                error_code = f"HTTP_{http_status}"
            else:
                # 3xx, 4xx (except 408, 429) are considered permanent failures
                outcome = "PERMANENT_ERROR"
                error_code = f"HTTP_{http_status}"

    except httpx.ConnectTimeout:
        error_code = "CONNECT_TIMEOUT"
        outcome = "RETRYABLE_ERROR"
        response_excerpt = "Connection timed out"
    except httpx.ReadTimeout:
        error_code = "READ_TIMEOUT"
        outcome = "RETRYABLE_ERROR"
        response_excerpt = "Read timed out"
    except httpx.ConnectError as e:
        error_code = "CONNECT_ERROR"
        outcome = "RETRYABLE_ERROR"
        response_excerpt = f"Connection error: {str(e)[:250]}"
    except Exception as e:
        error_code = "REQUEST_FAILED"
        outcome = "RETRYABLE_ERROR"
        response_excerpt = f"Network failure: {str(e)[:250]}"

    duration_ms = int((time.perf_counter() - start_time) * 1000)
    finished_at = utc_now()

    # 5. Persist attempt record and update delivery status under verified lease
    return _record_attempt_and_update_state(
        db=db,
        delivery_id=delivery_id,
        lease_token=claimed_lease_token,
        attempt_number=delivery.attempt_count,
        started_at=started_at,
        finished_at=finished_at,
        http_status=http_status,
        duration_ms=duration_ms,
        error_code=error_code,
        response_excerpt=response_excerpt,
        outcome=outcome,
        retry_after=retry_after
    )

def _record_attempt_and_update_state(
    db: Session,
    delivery_id: str,
    lease_token: str,
    attempt_number: int,
    started_at: datetime,
    finished_at: datetime,
    http_status: Optional[int],
    duration_ms: int,
    error_code: Optional[str],
    response_excerpt: Optional[str],
    outcome: str,
    retry_after: Optional[str] = None
) -> bool:
    """Verifies lease ownership and updates the delivery and attempt records."""
    delivery = (
        db.query(Delivery)
        .filter(Delivery.id == delivery_id)
        .with_for_update()
        .first()
    )

    if not delivery or delivery.lease_token != lease_token:
        logger.warning(f"Delivery {delivery_id} lease token mismatch or expired. Dropping stale update.")
        db.rollback()
        return False

    # Insert attempt record
    attempt = DeliveryAttempt(
        delivery_id=delivery.id,
        attempt_number=attempt_number,
        started_at=started_at,
        finished_at=finished_at,
        http_status=http_status,
        duration_ms=duration_ms,
        error_code=error_code,
        response_excerpt=response_excerpt,
        outcome=outcome
    )
    db.add(attempt)

    # Transition state machine
    now = utc_now()
    delivery.lease_token = None
    delivery.lease_expires_at = None

    if outcome == "SUCCESS":
        delivery.status = "SUCCEEDED"
        delivery.completed_at = now
    elif outcome == "RETRYABLE_ERROR":
        if delivery.attempt_count < settings.MAX_DELIVERY_ATTEMPTS:
            backoff_secs = calculate_backoff_seconds(delivery.attempt_count, retry_after)
            delivery.status = "RETRY_SCHEDULED"
            delivery.next_attempt_at = now + timedelta(seconds=backoff_secs)
        else:
            delivery.status = "DEAD"
            delivery.completed_at = now
    else:  # PERMANENT_ERROR
        delivery.status = "DEAD"
        delivery.completed_at = now

    db.commit()
    return True

def _save_terminal_failure(db: Session, delivery_id: str, lease_token: str, error_reason: str):
    """Terminates delivery due to SSRF restriction or disabled endpoint."""
    delivery = db.query(Delivery).filter(Delivery.id == delivery_id).with_for_update().first()
    if not delivery or delivery.lease_token != lease_token:
        db.rollback()
        return

    now = utc_now()
    attempt = DeliveryAttempt(
        delivery_id=delivery.id,
        attempt_number=delivery.attempt_count,
        started_at=now,
        finished_at=now,
        http_status=None,
        duration_ms=0,
        error_code="SSRF_OR_CONFIG_ERROR",
        response_excerpt=error_reason[:settings.RESPONSE_EXCERPT_MAX_BYTES],
        outcome="PERMANENT_ERROR"
    )
    db.add(attempt)
    delivery.status = "DEAD"
    delivery.completed_at = now
    delivery.lease_token = None
    delivery.lease_expires_at = None
    db.commit()

def recover_abandoned_leases(db: Session) -> int:
    """
    Finds deliveries that have been IN_FLIGHT past their lease expiration
    (e.g., worker crashed or hung) and returns them to RETRY_SCHEDULED or DEAD.
    """
    now = utc_now()
    abandoned = (
        db.query(Delivery)
        .filter(
            Delivery.status == "IN_FLIGHT",
            Delivery.lease_expires_at <= now
        )
        .with_for_update(skip_locked=True)
        .all()
    )

    recovered_count = 0
    for dlv in abandoned:
        dlv.lease_token = None
        dlv.lease_expires_at = None
        if dlv.attempt_count < settings.MAX_DELIVERY_ATTEMPTS:
            dlv.status = "RETRY_SCHEDULED"
            dlv.next_attempt_at = now
        else:
            dlv.status = "DEAD"
            dlv.completed_at = now
        recovered_count += 1

    if recovered_count > 0:
        db.commit()
        logger.info(f"Recovered {recovered_count} abandoned delivery leases.")
    return recovered_count

def replay_delivery(db: Session, delivery_id: str) -> Optional[Delivery]:
    """
    Creates a new delivery for the same event and endpoint, linking it to the previous delivery.
    Preserves original attempt history while allocating a fresh attempt budget.
    """
    old_delivery = db.query(Delivery).filter(Delivery.id == delivery_id).first()
    if not old_delivery:
        return None

    endpoint = old_delivery.endpoint
    current_url = endpoint.url if endpoint else old_delivery.target_url_snapshot

    now = utc_now()
    new_delivery = Delivery(
        event_id=old_delivery.event_id,
        endpoint_id=old_delivery.endpoint_id,
        target_url_snapshot=current_url,
        status="PENDING",
        attempt_count=0,
        next_attempt_at=now,
        replay_of_delivery_id=old_delivery.id,
        created_at=now
    )
    db.add(new_delivery)
    db.commit()
    db.refresh(new_delivery)
    return new_delivery
