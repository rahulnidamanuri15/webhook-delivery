import html
import logging
from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.db.session import Base
from app.main import app
from app.models import (
    Endpoint,
    EndpointSubscription,
    Organization,
    OrganizationMember,
    Project,
    User,
    utc_now,
)
from app.services.delivery_service import (
    claim_delivery,
    execute_delivery,
    _record_attempt_and_update_state,
)
from app.services.event_service import ingest_event
from app.services.security import (
    create_session_token,
    decrypt_secret,
    encrypt_secret,
    generate_signing_secret,
    hash_password,
)
from app.workers.dispatcher import dispatch_batch
from app.workers.recovery import run_recovery_cycle


@pytest.fixture
def scenario_db(tmp_path):
    db_file = tmp_path / "scenario.db"
    engine = create_engine(
        f"sqlite:///{db_file}",
        connect_args={"timeout": 30, "check_same_thread": False},
    )
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA journal_mode=WAL")
        conn.exec_driver_sql("PRAGMA busy_timeout=30000")

    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()

    org = Organization(name="Scenario Org")
    session.add(org)
    session.flush()

    user = User(email="test@scenario.com", password_hash=hash_password("password123"))
    session.add(user)
    session.flush()
    session.add(OrganizationMember(organization_id=org.id, user_id=user.id, role="owner"))

    project = Project(organization_id=org.id, name="Scenario Project")
    session.add(project)
    session.flush()

    ep_fast = Endpoint(
        project_id=project.id,
        url="http://127.0.0.1:8001/fast",
        encrypted_signing_secret=encrypt_secret(generate_signing_secret()),
        enabled=True,
    )
    session.add(ep_fast)

    ep_slow = Endpoint(
        project_id=project.id,
        url="http://127.0.0.1:8001/slow",
        encrypted_signing_secret=encrypt_secret(generate_signing_secret()),
        enabled=True,
    )
    session.add(ep_slow)
    session.flush()

    session.add(EndpointSubscription(endpoint_id=ep_fast.id, event_type="*"))
    session.add(EndpointSubscription(endpoint_id=ep_slow.id, event_type="*"))
    session.commit()

    yield session
    session.close()
    engine.dispose()


def _mock_fast_and_slow_stream():
    """Mock for httpx.Client that simulates fast vs slow responses based on URL."""

    def client_factory(*args, **kwargs):
        client = MagicMock()
        client.__enter__.return_value = client
        client.__exit__.return_value = False

        def stream_mock(method, url, *a, **kw):
            resp = MagicMock()
            if "slow" in str(url):
                resp.status_code = 504
                resp.iter_bytes.return_value = [b"Gateway Timeout"]
            else:
                resp.status_code = 200
                resp.iter_bytes.return_value = [b'{"status":"ok"}']
            resp.close.return_value = None
            ctx = MagicMock()
            ctx.__enter__.return_value = resp
            ctx.__exit__.return_value = False
            return ctx

        client.stream.side_effect = stream_mock
        return client

    return patch("httpx.Client", side_effect=client_factory)


# --- 1. Redis losing a queued task ---
def test_redis_losing_queued_task_recovered_by_scanner(scenario_db):
    """When a Redis task is dropped or worker crashes mid-flight, recovery scanner restores it."""
    project = scenario_db.query(Project).first()
    event, _, _ = ingest_event(scenario_db, project.id, "test.task_lost", {"data": 1})
    delivery = event.deliveries[0]

    # Simulate worker picked up task, set to IN_FLIGHT with lease, then Redis lost or worker died
    delivery.status = "IN_FLIGHT"
    delivery.lease_token = "lost_task_lease_token"
    delivery.lease_expires_at = utc_now() - timedelta(seconds=15)  # Expired
    scenario_db.commit()

    # Recovery cycle detects abandoned lease and transitions back to RETRY_SCHEDULED
    recovered = run_recovery_cycle(scenario_db)
    assert recovered == 1

    scenario_db.refresh(delivery)
    assert delivery.status == "RETRY_SCHEDULED"
    assert delivery.lease_token is None
    assert delivery.lease_expires_at is None


# --- 2. A slow endpoint does not block others ---
def test_slow_endpoint_does_not_block_fast_endpoint(scenario_db):
    """Outbound dispatch concurrency ensures slow/failing endpoints do not starve fast ones."""
    project = scenario_db.query(Project).first()
    event, _, count = ingest_event(scenario_db, project.id, "test.concurrency", {"msg": "hello"})
    assert count == 2

    session_maker = sessionmaker(bind=scenario_db.get_bind())
    with _mock_fast_and_slow_stream():
        with patch("app.workers.dispatcher.SessionLocal", side_effect=session_maker):
            # Dispatch both deliveries concurrently in thread pool
            processed = dispatch_batch(batch_size=10, max_workers=2)
            assert processed == 2

    deliveries = {d.target_url_snapshot: d for d in event.deliveries}
    fast_dlv = deliveries["http://127.0.0.1:8001/fast"]
    slow_dlv = deliveries["http://127.0.0.1:8001/slow"]

    scenario_db.refresh(fast_dlv)
    scenario_db.refresh(slow_dlv)

    assert fast_dlv.status == "SUCCEEDED"
    assert slow_dlv.status == "RETRY_SCHEDULED"  # 504 is retryable


# --- 3. Redis being unavailable ---
def test_redis_unavailable_handled_gracefully(scenario_db):
    """When Redis is down, dispatch_batch logs error and exits without crashing."""
    project = scenario_db.query(Project).first()
    event, _, _ = ingest_event(scenario_db, project.id, "test.redis_down", {"data": 1})
    delivery = event.deliveries[0]
    assert delivery.status == "PENDING"

    session_maker = sessionmaker(bind=scenario_db.get_bind())
    settings.USE_CELERY = True
    try:
        # Simulate Redis connection failure during Celery task enqueue
        with patch("app.workers.tasks.deliver_webhook_task.delay", side_effect=Exception("Redis connection refused")):
            with patch("app.workers.dispatcher.SessionLocal", side_effect=session_maker):
                count = dispatch_batch()
                # Enqueue errors are logged and count remains 0 without raising an unhandled exception
                assert count == 0
    finally:
        settings.USE_CELERY = False


# --- 4. Sensitive values absent from logs ---
def test_sensitive_values_absent_from_logs(scenario_db, caplog):
    """Secrets, decrypted keys, and passwords must never appear in log records."""
    caplog.set_level(logging.DEBUG)
    project = scenario_db.query(Project).first()
    endpoint = scenario_db.query(Endpoint).first()
    decrypted_secret = decrypt_secret(endpoint.encrypted_signing_secret)

    event, _, _ = ingest_event(scenario_db, project.id, "test.sensitive", {"secret_data": "secret_123"})
    delivery = event.deliveries[0]

    with _mock_fast_and_slow_stream():
        execute_delivery(scenario_db, delivery.id)

    log_text = " ".join([record.getMessage() for record in caplog.records])
    assert decrypted_secret not in log_text, "Decrypted signing secret found in logs!"
    assert settings.SIGNING_SECRET_ENCRYPTION_KEY not in log_text, "Encryption key found in logs!"
    assert "password123" not in log_text, "User password found in logs!"


# --- 5. Stale worker cannot overwrite state under concurrency ---
def test_stale_worker_cannot_overwrite_state_under_concurrency(scenario_db):
    """If worker A's lease expires and worker B takes over, worker A cannot overwrite state."""
    project = scenario_db.query(Project).first()
    event, _, _ = ingest_event(scenario_db, project.id, "test.stale_worker", {"n": 10})
    delivery = event.deliveries[0]

    # Worker A claims delivery
    claim_a = claim_delivery(scenario_db, delivery.id)
    assert claim_a is not None
    _, lease_token_a = claim_a

    # Simulate Worker A hanging while lease expires, recovery scanner runs, and Worker B claims it
    delivery.lease_expires_at = utc_now() - timedelta(seconds=1)
    scenario_db.commit()

    run_recovery_cycle(scenario_db)
    claim_b = claim_delivery(scenario_db, delivery.id)
    assert claim_b is not None
    _, lease_token_b = claim_b
    assert lease_token_a != lease_token_b

    # Now Worker A wakes up and attempts to record its result with the old lease token
    now = utc_now()
    updated = _record_attempt_and_update_state(
        db=scenario_db,
        delivery_id=delivery.id,
        lease_token=lease_token_a,  # Stale token
        attempt_number=1,
        started_at=now,
        finished_at=now,
        http_status=200,
        duration_ms=50,
        error_code=None,
        response_excerpt="Worker A output",
        outcome="SUCCESS",
    )
    # Must be rejected because lease_token_a does not match current lease_token_b
    assert updated is False

    scenario_db.refresh(delivery)
    assert delivery.lease_token == lease_token_b  # Still held by Worker B


# --- 6. Escaping of payloads in dashboard ---
def test_dashboard_escapes_xss_payloads(scenario_db):
    """Dashboard HTML templates safely escape malicious script payloads."""
    from app.db.session import get_db

    project = scenario_db.query(Project).first()
    user = scenario_db.query(User).first()
    org = scenario_db.query(Organization).first()

    xss_content = "<script>alert('xss_attack')</script>"
    event, _, _ = ingest_event(scenario_db, project.id, "xss.event", {"malicious": xss_content})

    app.dependency_overrides[get_db] = lambda: scenario_db
    try:
        client = TestClient(app)
        session_token = create_session_token(user.id, org_id=org.id, project_id=project.id)
        client.cookies.set("wh_session", session_token)
        client.cookies.set("wh_active_project_id", project.id)

        # 1. Event detail page
        resp = client.get(f"/dashboard/events/{event.id}")
        assert resp.status_code == 200
        # Must NOT render unescaped raw <script> tag
        assert "<script>alert('xss_attack')</script>" not in resp.text
        # Should be HTML-escaped or JSON-escaped in the pre block
        assert (
            html.escape(xss_content) in resp.text
            or "\\u003cscript\\u003e" in resp.text
            or "&lt;script&gt;" in resp.text
            or "alert(&#39;xss_attack&#39;)" in resp.text
        )
    finally:
        app.dependency_overrides.pop(get_db, None)
