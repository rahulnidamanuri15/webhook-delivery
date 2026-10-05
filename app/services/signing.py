import hmac
import hashlib
import time
from typing import Dict, Tuple

def compute_signature(secret: str, event_id: str, timestamp: int, payload: str) -> str:
    """
    Computes HMAC-SHA256 signature according to specification:
    signing_input = event_id + "." + str(timestamp) + "." + payload
    signature = "v1=" + hmac_sha256(secret, signing_input).hexdigest()
    """
    signing_input = f"{event_id}.{timestamp}.{payload}".encode("utf-8")
    secret_bytes = secret.encode("utf-8")
    mac = hmac.new(secret_bytes, signing_input, hashlib.sha256)
    return f"v1={mac.hexdigest()}"

def generate_webhook_headers(secret: str, event_id: str, delivery_id: str, payload: str) -> Dict[str, str]:
    """Generates standard webhook delivery headers with fresh timestamp and HMAC-SHA256 signature."""
    timestamp = int(time.time())
    signature = compute_signature(secret, event_id, timestamp, payload)
    return {
        "Content-Type": "application/json",
        "User-Agent": "ReliableWebhookDelivery/1.0",
        "Webhook-Event-Id": event_id,
        "Webhook-Delivery-Id": delivery_id,
        "Webhook-Timestamp": str(timestamp),
        "Webhook-Signature": signature
    }

def verify_webhook_signature(
    secret: str,
    event_id: str,
    timestamp_str: str,
    payload: str,
    received_signature: str,
    tolerance_seconds: int = 300
) -> Tuple[bool, str]:
    """
    Verifies the webhook signature in constant time and checks timestamp freshness.
    Returns:
        (is_valid: bool, reason: str)
    """
    try:
        ts = int(timestamp_str)
    except (ValueError, TypeError):
        return False, "Invalid timestamp format"

    now = int(time.time())
    if abs(now - ts) > tolerance_seconds:
        return False, f"Timestamp is outside the {tolerance_seconds}s tolerance window (diff: {abs(now - ts)}s)"

    expected_signature = compute_signature(secret, event_id, ts, payload)
    
    # Constant-time comparison to prevent timing attacks
    if hmac.compare_digest(expected_signature, received_signature):
        return True, "Signature valid"
    
    return False, "Signature mismatch"
