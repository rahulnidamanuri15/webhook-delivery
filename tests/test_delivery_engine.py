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

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"received": true}'
    mock_resp.headers = {}

    with patch("httpx.Client.post", return_value=mock_resp):
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

    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = 'Internal Server Error'
    mock_resp.headers = {}

    with patch("httpx.Client.post", return_value=mock_resp):
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
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.text = 'Bad Request: invalid format'
    mock_resp.headers = {}

    with patch("httpx.Client.post", return_value=mock_resp):
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

    mock_resp = MagicMock()
    mock_resp.status_code = 503
    mock_resp.text = 'Service Unavailable'
    mock_resp.headers = {}

    with patch("httpx.Client.post", return_value=mock_resp):
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
