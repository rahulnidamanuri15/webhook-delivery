import time

from app.services.signing import compute_signature, verify_webhook_signature


def test_signature_generation_and_verification():
    secret = "whsec_test_secret_12345"
    event_id = "evt_abc123"
    timestamp = int(time.time())
    payload = '{"amount":100,"currency":"INR"}'

    sig = compute_signature(secret, event_id, timestamp, payload)
    assert sig.startswith("v1=")

    # Successful verification
    is_valid, reason = verify_webhook_signature(
        secret=secret, event_id=event_id, timestamp_str=str(timestamp), payload=payload, received_signature=sig
    )
    assert is_valid is True
    assert reason == "Signature valid"


def test_tampered_payload_fails_verification():
    secret = "whsec_test_secret_12345"
    event_id = "evt_abc123"
    timestamp = int(time.time())
    original_payload = '{"amount":100}'
    tampered_payload = '{"amount":9999}'

    sig = compute_signature(secret, event_id, timestamp, original_payload)

    is_valid, reason = verify_webhook_signature(
        secret=secret, event_id=event_id, timestamp_str=str(timestamp), payload=tampered_payload, received_signature=sig
    )
    assert is_valid is False
    assert "mismatch" in reason


def test_expired_timestamp_fails_verification():
    secret = "whsec_test_secret_12345"
    event_id = "evt_abc123"
    # Timestamp from 10 minutes ago
    old_timestamp = int(time.time()) - 600
    payload = '{"amount":100}'

    sig = compute_signature(secret, event_id, old_timestamp, payload)

    is_valid, reason = verify_webhook_signature(
        secret=secret,
        event_id=event_id,
        timestamp_str=str(old_timestamp),
        payload=payload,
        received_signature=sig,
        tolerance_seconds=300,
    )
    assert is_valid is False
    assert "outside the 300s tolerance window" in reason
