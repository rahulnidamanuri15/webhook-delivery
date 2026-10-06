from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.db.session import Base
from app.models import Endpoint, EndpointSubscription, Organization, Project, utc_now
from app.services.delivery_service import execute_delivery, recover_abandoned_leases, replay_delivery
from app.services.event_service import ingest_event
from app.services.security import encrypt_secret, generate_signing_secret


def _mock_stream_response(status_code: int = 200, text: str = "", headers: dict | None = None):
    """Builds a mocked httpx.Client whose .stream() yields a bounded response."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = headers or {}
    body = (text or "").encode("utf-8")
    # Yield in 4096-byte chunks like the real streaming reader
    mock_resp.iter_bytes.return_value = [body[i:i+4096] for i in range(0, max(1, len(body)), 4096)] if body else [b""]
    mock_resp.close.return_value = None
    mock_stream_ctx = MagicMock()
    mock_stream_ctx.__enter__.return_value = mock_resp
    mock_stream_ctx.__exit__.return_value = False
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = False
    mock_client.stream.return_value = mock_stream_ctx
    # Legacy .post fallback (not used by current code, kept for compat)
    mock_post_resp = MagicMock()
    mock_post_resp.status_code = status_code
    mock_post_resp.text = text
    mock_post_resp.headers = headers or {}
    mock_client.post.return_value = mock_post_resp
    return patch("httpx.Client", return_value=mock_client)

@pytest.fixture
def delivery_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()

    org = Organization(name="Test Org")
    session.add(org)
    session.flush()

    project = Project(organization_id=org.id, name="Test Project")
    session.add(project)
    session.flush()

    endpoint = Endpoint(
        project_id=project.id,
        url="http://127.0.0.1:8001/webhook",
        encrypted_signing_secret=encrypt_secret(generate_signing_secret()),
        enabled=True
    )
    session.add(endpoint)
    session.flush()

    sub = EndpointSubscription(endpoint_id=endpoint.id, event_type="*")
    session.add(sub)
    session.commit()

    yield session
    session.close()

def test_successful_delivery(delivery_db):
    project = delivery_db.query(Project).first()
    event, _, _ = ingest_event(delivery_db, project.id, "order.created", {"order_id": "ord_101"})
    delivery = event.deliveries[0]
    assert delivery.status == "PENDING"

    with _mock_stream_response(200, '{"received": true}'):
        success = execute_delivery(delivery_db, delivery.id)
        assert success is True

    delivery_db.refresh(delivery)
    assert delivery.status == "SUCCEEDED"
    assert delivery.attempt_count == 1
    assert len(delivery.attempts) == 1
    assert delivery.attempts[0].outcome == "SUCCESS"
    assert delivery.attempts[0].http_status == 200
    assert delivery.completed_at is not None

def test_retryable_error_schedules_backoff(delivery_db):
    project = delivery_db.query(Project).first()
    event, _, _ = ingest_event(delivery_db, project.id, "order.created", {"order_id": "ord_102"})
    delivery = event.deliveries[0]

    with _mock_stream_response(500, 'Internal Server Error'):
        success = execute_delivery(delivery_db, delivery.id)
        assert success is True

    delivery_db.refresh(delivery)
    assert delivery.status == "RETRY_SCHEDULED"
    assert delivery.attempt_count == 1
    assert delivery.attempts[0].outcome == "RETRYABLE_ERROR"
    assert delivery.next_attempt_at > delivery.created_at

def test_permanent_error_marks_delivery_dead(delivery_db):
    project = delivery_db.query(Project).first()
    event, _, _ = ingest_event(delivery_db, project.id, "order.created", {"order_id": "ord_103"})
    delivery = event.deliveries[0]

    # 400 Bad Request is permanent client error
    with _mock_stream_response(400, 'Bad Request: invalid format'):
        execute_delivery(delivery_db, delivery.id)

    delivery_db.refresh(delivery)
    assert delivery.status == "DEAD"
    assert delivery.attempts[0].outcome == "PERMANENT_ERROR"
    assert delivery.completed_at is not None

def test_exhausted_retry_budget_marks_delivery_dead(delivery_db):
    project = delivery_db.query(Project).first()
    event, _, _ = ingest_event(delivery_db, project.id, "order.created", {"order_id": "ord_104"})
    delivery = event.deliveries[0]

    # Pre-set attempt count to max attempts - 1
    delivery.attempt_count = settings.MAX_DELIVERY_ATTEMPTS - 1
    delivery_db.commit()

    with _mock_stream_response(503, 'Service Unavailable'):
        execute_delivery(delivery_db, delivery.id)

    delivery_db.refresh(delivery)
    assert delivery.attempt_count == settings.MAX_DELIVERY_ATTEMPTS
    assert delivery.status == "DEAD"

def test_crash_recovery_for_abandoned_lease(delivery_db):
    project = delivery_db.query(Project).first()
    event, _, _ = ingest_event(delivery_db, project.id, "order.created", {"order_id": "ord_105"})
    delivery = event.deliveries[0]

    # Simulate a crashed worker: delivery stuck IN_FLIGHT with expired lease
    now = utc_now()
    delivery.status = "IN_FLIGHT"
    delivery.lease_token = "orphaned_worker_token_123"
    delivery.lease_expires_at = now - timedelta(seconds=10)  # expired in past
    delivery.attempt_count = 1
    delivery_db.commit()

    recovered_count = recover_abandoned_leases(delivery_db)
    assert recovered_count == 1

    delivery_db.refresh(delivery)
    assert delivery.status == "RETRY_SCHEDULED"
    assert delivery.lease_token is None
    assert delivery.lease_expires_at is None

def test_manual_replay_creates_linked_delivery(delivery_db):
    project = delivery_db.query(Project).first()
    event, _, _ = ingest_event(delivery_db, project.id, "order.created", {"order_id": "ord_106"})
    delivery = event.deliveries[0]

    # Set as dead
    delivery.status = "DEAD"
    delivery.attempt_count = 5
    delivery_db.commit()

    # User triggers manual replay
    new_delivery = replay_delivery(delivery_db, delivery.id)
    assert new_delivery is not None
    assert new_delivery.id != delivery.id
    assert new_delivery.event_id == delivery.event_id
    assert new_delivery.replay_of_delivery_id == delivery.id
    assert new_delivery.status == "PENDING"
    assert new_delivery.attempt_count == 0


def test_wall_clock_timeout_marks_delivery_retryable(delivery_db):
    import httpx
    project = delivery_db.query(Project).first()
    event, _, _ = ingest_event(delivery_db, project.id, "order.created", {"order_id": "ord_107"})
    delivery = event.deliveries[0]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {}
    mock_resp.iter_bytes.side_effect = httpx.TimeoutException("Total HTTP request deadline exceeded (10.0s)")
    mock_resp.close.return_value = None

    mock_stream_ctx = MagicMock()
    mock_stream_ctx.__enter__.return_value = mock_resp
    mock_stream_ctx.__exit__.return_value = False

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = False
    mock_client.stream.return_value = mock_stream_ctx

    with patch("httpx.Client", return_value=mock_client):
        execute_delivery(delivery_db, delivery.id)

    delivery_db.refresh(delivery)
    assert delivery.status == "RETRY_SCHEDULED"
    assert delivery.attempt_count == 1
    assert len(delivery.attempts) == 1
    attempt = delivery.attempts[0]
    assert attempt.outcome == "RETRYABLE_ERROR"
    assert attempt.error_code == "TIMEOUT"
    assert "deadline exceeded" in (attempt.response_excerpt or "")


def test_dispatcher_enqueues_to_celery_when_enabled(delivery_db):
    from app.workers.dispatcher import dispatch_batch
    project = delivery_db.query(Project).first()
    event, _, _ = ingest_event(delivery_db, project.id, "order.created", {"order_id": "ord_celery"})
    delivery = event.deliveries[0]
    assert delivery.status == "PENDING"

    settings.USE_CELERY = True
    try:
        with patch("app.workers.tasks.deliver_webhook_task.delay") as mock_delay:
            with patch("app.workers.dispatcher.SessionLocal", return_value=delivery_db):
                count = dispatch_batch()
                assert count >= 1
                mock_delay.assert_any_call(delivery.id)
    finally:
        settings.USE_CELERY = False


