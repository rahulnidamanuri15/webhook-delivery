import time
from datetime import timedelta
import pytest
import httpx
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.session import Base
from app.models import Organization, Project, Endpoint, EndpointSubscription, Event, Delivery, DeliveryAttempt, utc_now
from app.services.event_service import ingest_event
from app.services.delivery_service import (
    execute_delivery,
    recover_abandoned_leases,
    replay_delivery
)
from app.services.security import generate_signing_secret, encrypt_secret
from app.config import settings


def _mock_stream_response(status_code: int = 200, text: str = "", headers: dict | None = None):
    """Builds a mocked httpx.Client whose .stream() yields a bounded response."""
    from unittest.mock import MagicMock, patch
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
