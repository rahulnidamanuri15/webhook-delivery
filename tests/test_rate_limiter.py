import time
from datetime import timedelta
import pytest
from app.services.rate_limiter import MemoryTokenBucket, check_endpoint_rate_limit, check_ingestion_rate_limit
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.session import Base
from app.models import Organization, Project, Endpoint, EndpointSubscription, Event, Delivery, utc_now
from app.services.event_service import ingest_event
from app.services.delivery_service import execute_delivery
from app.services.security import generate_signing_secret, encrypt_secret

def test_memory_token_bucket_limits():
    bucket = MemoryTokenBucket()
    # 2 tokens per second, capacity 2
    key = "test_ep_bucket_1"
    
    # 1st and 2nd should succeed immediately
    allowed1, wait1 = bucket.acquire(key, rate_per_second=2.0, capacity=2.0)
    assert allowed1 is True
    assert wait1 == 0.0

    allowed2, wait2 = bucket.acquire(key, rate_per_second=2.0, capacity=2.0)
    assert allowed2 is True
    assert wait2 == 0.0

    # 3rd should be denied
    allowed3, wait3 = bucket.acquire(key, rate_per_second=2.0, capacity=2.0)
    assert allowed3 is False
    assert wait3 > 0.0

def test_endpoint_rate_limit_defers_without_consuming_attempt():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()

    org = Organization(name="Rate Limit Org")
    session.add(org)
    session.flush()

    project = Project(organization_id=org.id, name="Rate Limit Project")
    session.add(project)
    session.flush()

    # Endpoint with limit of 1 per second
    endpoint = Endpoint(
        project_id=project.id,
        url="http://127.0.0.1:8001/webhook",
        encrypted_signing_secret=encrypt_secret(generate_signing_secret()),
        enabled=True,
        rate_limit_per_second=1
    )
    session.add(endpoint)
    session.flush()

    sub = EndpointSubscription(endpoint_id=endpoint.id, event_type="*")
    session.add(sub)
    session.commit()

    # Ingest 2 events
    event1, _, _ = ingest_event(session, project.id, "test.rate", {"idx": 1})
    event2, _, _ = ingest_event(session, project.id, "test.rate", {"idx": 2})

    dlv1 = event1.deliveries[0]
    dlv2 = event2.deliveries[0]

    # Exhaust rate limit bucket directly
    from app.services.rate_limiter import memory_bucket
    memory_bucket.acquire(f"endpoint:{endpoint.id}", rate_per_second=1.0, capacity=1.0)
    # Bucket is now empty for this endpoint

    # Attempt to execute dlv1
    executed = execute_delivery(session, dlv1.id)
    assert executed is False

    session.refresh(dlv1)
    # Crucial requirement: Delivery deferred without consuming attempt budget
    assert dlv1.status == "RETRY_SCHEDULED"
    assert dlv1.attempt_count == 0  # Attempt count not incremented!
    assert len(dlv1.attempts) == 0
    from datetime import timezone
    next_ts = dlv1.next_attempt_at.replace(tzinfo=timezone.utc) if dlv1.next_attempt_at.tzinfo is None else dlv1.next_attempt_at
    assert next_ts >= utc_now() - timedelta(seconds=2)
