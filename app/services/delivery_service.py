import logging
import random
import time
import uuid
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Delivery, DeliveryAttempt, utc_now
from app.services.security import decrypt_secret
from app.services.signing import generate_webhook_headers
from app.services.tracing import inject_trace_headers, start_trace_span

logger = logging.getLogger("webhook.delivery")

# Hard cap on bytes read from a receiver response body. Prevents a malicious
# receiver from exhausting worker memory; the stored excerpt is still bounded
# separately by RESPONSE_EXCERPT_MAX_BYTES.
MAX_RESPONSE_READ_BYTES = 64 * 1024


def _build_timeout() -> "httpx.Timeout":
    """Separate connect vs total timeouts (total stays < lease duration)."""
    total = float(settings.HTTP_TIMEOUT_SECONDS)
    connect = float(getattr(settings, "HTTP_CONNECT_TIMEOUT_SECONDS", 3.0))
    connect = min(connect, max(1.0, total - 1.0))
    return httpx.Timeout(connect=connect, read=total, write=min(5.0, total), pool=connect)


def _read_bounded_excerpt(response: "httpx.Response") -> str:
    """Streams at most MAX_RESPONSE_READ_BYTES, then truncates to excerpt size."""
    chunks: list[bytes] = []
    total = 0
    truncated_wire = False
    try:
        for chunk in response.iter_bytes(chunk_size=4096):
            if not chunk:
                break
            remaining = MAX_RESPONSE_READ_BYTES - total
            if remaining <= 0:
                truncated_wire = True
                break
            if len(chunk) > remaining:
                chunks.append(chunk[:remaining])
                total += remaining
                truncated_wire = True
                break
            chunks.append(chunk)
            total += len(chunk)
            if total >= MAX_RESPONSE_READ_BYTES:
                truncated_wire = True
                break
        # Drain/close without reading unbounded remainder
        try:
            response.close()
        except Exception:
            pass
    except Exception as e:
        return f"[bounded-read error: {e}]"[: settings.RESPONSE_EXCERPT_MAX_BYTES]
    try:
        text = b"".join(chunks).decode("utf-8", errors="replace")
    except Exception:
        text = ""
    if len(text) > settings.RESPONSE_EXCERPT_MAX_BYTES:
        keep = max(0, settings.RESPONSE_EXCERPT_MAX_BYTES - len(" ... [truncated]"))
        text = text[:keep] + " ... [truncated]"
    elif truncated_wire and len(text) <= settings.RESPONSE_EXCERPT_MAX_BYTES:
        # Wire was cut but excerpt fits: still signal truncation happened upstream
        if len(text) + len(" ... [wire-truncated]") <= settings.RESPONSE_EXCERPT_MAX_BYTES:
            text = text + " ... [wire-truncated]"
    return text

def calculate_backoff_seconds(attempt_number: int, retry_after_header: str | None = None) -> int:
    """Calculates backoff delay in seconds with jitter or honors Retry-After header.

    Honors both delay-seconds (e.g. ``120``) and HTTP-date (IMF-fixdate,
    e.g. ``Wed, 21 Oct 2015 07:28:00 GMT``) forms, clamped to [1, 3600]s.
    Falls back to the configured retry intervals with +/-15% jitter.
    """
    if retry_after_header:
        raw = retry_after_header.strip()
        # 1) delay-seconds form
        try:
            delay = int(raw)
            if 1 <= delay <= 3600:
                return delay
        except (ValueError, TypeError):
            pass
        # 2) HTTP-date form (RFC 7231 §7.1.3)
        try:
            from email.utils import parsedate_to_datetime
            retry_dt = parsedate_to_datetime(raw)
            if retry_dt is not None:
                now_dt = datetime.now(UTC)
                if retry_dt.tzinfo is None:
                    retry_dt = retry_dt.replace(tzinfo=UTC)
                delay_s = int((retry_dt - now_dt).total_seconds())
                if delay_s < 1:
                    delay_s = 1
                return max(1, min(3600, delay_s))
        except Exception:
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

def claim_delivery(db: Session, delivery_id: str) -> tuple[Delivery, str] | None:
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
    # Propagate W3C trace-context so receivers can correlate (no-op if OTel off).
    try:
        inject_trace_headers(headers)
    except Exception:
        pass

    # 5. Outbound HTTP request executed safely outside DB transaction.
    # Timeouts: connect (short) vs total (HTTP_TIMEOUT_SECONDS) both < lease (30s).
    started_at = utc_now()
    start_time = time.perf_counter()
    http_status = None
    error_code = None
    response_excerpt = None
    retry_after = None
    outcome = "RETRYABLE_ERROR"

    try:
        with start_trace_span("delivery.http_post", {"delivery.id": delivery_id}):
            with httpx.Client(timeout=_build_timeout(), follow_redirects=False) as client:
                with client.stream(
                    "POST",
                    target_connection_url,
                    content=event.wire_payload.encode("utf-8"),
                    headers=headers,
                ) as resp:
                    http_status = resp.status_code
                    retry_after = resp.headers.get("retry-after")
                    # Bounded streaming read (never loads unbounded bodies)
                    response_excerpt = _read_bounded_excerpt(resp)

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
    except (httpx.WriteTimeout, httpx.PoolTimeout, httpx.TimeoutException) as e:
        error_code = "TIMEOUT"
        outcome = "RETRYABLE_ERROR"
        response_excerpt = f"Timeout: {str(e)[:250]}"
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
    http_status: int | None,
    duration_ms: int,
    error_code: str | None,
    response_excerpt: str | None,
    outcome: str,
    retry_after: str | None = None
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

    Writes a bounded DeliveryAttempt row for the orphaned lease so the timeline
    has no history hole: attempt_number reuses the already-incremented
    attempt_count from claim time, outcome is RETRYABLE_ERROR (or PERMANENT
    when the budget is exhausted), error_code LEASE_EXPIRED.
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
        # Close the history gap left by the crashed worker before it could record.
        try:
            terminal = dlv.attempt_count >= settings.MAX_DELIVERY_ATTEMPTS
            attempt = DeliveryAttempt(
                delivery_id=dlv.id,
                attempt_number=max(1, dlv.attempt_count),
                started_at=dlv.lease_expires_at - timedelta(seconds=settings.LEASE_DURATION_SECONDS) if dlv.lease_expires_at else now,
                finished_at=now,
                http_status=None,
                duration_ms=0,
                error_code="LEASE_EXPIRED",
                response_excerpt="Worker lease expired before result was recorded (crash or hang); rescheduled.",
                outcome="PERMANENT_ERROR" if terminal else "RETRYABLE_ERROR",
            )
            db.add(attempt)
        except Exception:
            pass
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

def replay_delivery(db: Session, delivery_id: str) -> Delivery | None:
    """
    Creates a new delivery for the same event and endpoint, linking it to the previous delivery.
    Preserves original attempt history while allocating a fresh attempt budget.

    Policy: only DEAD (dead-letter) deliveries may be replayed. Returns None
    otherwise so callers surface 400/404 instead of cloning live work.
    Target URL uses the endpoint's current URL when available (operator may have
    fixed a typo), falling back to the original snapshot when the endpoint was
    deleted. Security checks (SSRF, enabled) are still enforced at send time.
    """
    old_delivery = db.query(Delivery).filter(Delivery.id == delivery_id).first()
    if not old_delivery:
        return None
    if old_delivery.status != "DEAD":
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
