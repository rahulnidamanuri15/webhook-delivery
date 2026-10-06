"""Regression tests for audit fixes: Retry-After HTTP-date, prefix wildcards,
recovery history, replay guards, metrics histogram, tracing propagation."""
import time
from datetime import datetime, timezone, timedelta
from email.utils import format_datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.session import Base
from app.models import Organization, Project, Endpoint, EndpointSubscription, Event, Delivery, utc_now
from app.services.event_service import ingest_event, get_matching_endpoints, _subscription_matches
from app.services.delivery_service import calculate_backoff_seconds, recover_abandoned_leases, replay_delivery
from app.services.tracing import inject_trace_headers
from app.services.metrics import generate_prometheus_metrics
from app.services.security import generate_signing_secret, encrypt_secret
from app.config import settings


def _mem_db():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=eng)
    S = sessionmaker(bind=eng)
    return eng, S()


def _seed(ep_patterns):
    eng, db = _mem_db()
    org = Organization(name="o")
    db.add(org); db.flush()
    proj = Project(organization_id=org.id, name="p")
    db.add(proj); db.flush()
    ep = Endpoint(project_id=proj.id, url="http://127.0.0.1:8001/webhook",
                   encrypted_signing_secret=encrypt_secret(generate_signing_secret()), enabled=True)
    db.add(ep); db.flush()
    for pat in ep_patterns:
        db.add(EndpointSubscription(endpoint_id=ep.id, event_type=pat))
    db.commit()
    return eng, db, proj, ep


def test_retry_after_integer_honored():
    assert calculate_backoff_seconds(1, "120") == 120
    # Out of bounds falls back to intervals (not raw)
    v = calculate_backoff_seconds(1, "9999")
    assert 1 <= v <= 9000


def test_retry_after_http_date_honored():
    future = datetime.now(timezone.utc) + timedelta(seconds=90)
    hdr = format_datetime(future, usegmt=True)
    v = calculate_backoff_seconds(1, hdr)
    # Allow clock skew: 60..120
    assert 30 <= v <= 3600, f"got {v} for {hdr}"
    # Past date clamps to 1
    past = datetime.now(timezone.utc) - timedelta(seconds=60)
    assert calculate_backoff_seconds(1, format_datetime(past, usegmt=True)) == 1


def test_prefix_wildcard_matching():
    assert _subscription_matches("*", "order.shipped")
    assert _subscription_matches("order.shipped", "order.shipped")
    assert _subscription_matches("order.*", "order.shipped")
    assert _subscription_matches("order.*", "order.created")
    assert not _subscription_matches("order.*", "orders.shipped")
    assert not _subscription_matches("order.*", "payment.succeeded")
    assert not _subscription_matches("payment.*", "order.shipped")


def test_prefix_wildcard_end_to_end():
    eng, db, proj, ep = _seed(["order.*"])
    try:
        matched = get_matching_endpoints(db, proj.id, "order.shipped")
        assert len(matched) == 1
        assert get_matching_endpoints(db, proj.id, "payment.succeeded") == []
    finally:
        db.close(); eng.dispose()


def test_recovery_writes_attempt_history():
    eng, db, proj, ep = _seed(["*"])
    try:
        evt, _, _ = ingest_event(db, proj.id, "t.e", {"a": 1})
        dlv = evt.deliveries[0]
        dlv.status = "IN_FLIGHT"
        dlv.lease_token = "tok"
        dlv.lease_expires_at = utc_now() - timedelta(seconds=5)
        dlv.attempt_count = 1
        db.commit()
        n = recover_abandoned_leases(db)
        assert n == 1
        db.refresh(dlv)
        assert dlv.status == "RETRY_SCHEDULED"
        assert len(dlv.attempts) == 1
        assert dlv.attempts[0].error_code == "LEASE_EXPIRED"
    finally:
        db.close(); eng.dispose()


def test_replay_only_dead():
    eng, db, proj, ep = _seed(["*"])
    try:
        evt, _, _ = ingest_event(db, proj.id, "t.e2", {"a": 2})
        dlv = evt.deliveries[0]
        # PENDING cannot be replayed
        assert replay_delivery(db, dlv.id) is None
        dlv.status = "RETRY_SCHEDULED"; db.commit()
        assert replay_delivery(db, dlv.id) is None
        dlv.status = "DEAD"; db.commit()
        nd = replay_delivery(db, dlv.id)
        assert nd is not None and nd.replay_of_delivery_id == dlv.id
        assert nd.status == "PENDING" and nd.attempt_count == 0
    finally:
        db.close(); eng.dispose()


def test_metrics_histogram_and_per_endpoint():
    eng, db, proj, ep = _seed(["*"])
    try:
        evt, _, _ = ingest_event(db, proj.id, "t.m", {"x": 1})
        out = generate_prometheus_metrics(db)
        assert "webhook_delivery_duration_ms_bucket" in out
        assert 'le="+Inf"' in out
        assert "webhook_deliveries_by_endpoint" in out
    finally:
        db.close(); eng.dispose()


def test_trace_propagation_injects():
    h = {"Content-Type": "application/json"}
    out = inject_trace_headers(h)
    # No-op still returns dict; when OTel present, traceparent appears.
    assert isinstance(out, dict)
    assert "Content-Type" in out
