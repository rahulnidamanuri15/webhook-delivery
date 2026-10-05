import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.session import Base
from app.models import User, Organization, OrganizationMember, Project, Endpoint, EndpointSubscription, Event, Delivery
from app.services.event_service import ingest_event, IdempotencyConflictError
from app.services.security import generate_signing_secret, encrypt_secret

@pytest.fixture
def db_session():
    # In-memory test database
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()
    
    # Seed org and project
    org = Organization(name="Test Org")
    session.add(org)
    session.flush()

    project = Project(organization_id=org.id, name="Test Project")
    session.add(project)
    session.flush()

    # Seed 2 endpoints:
    # Ep 1: Subscribed to 'payment.succeeded'
    ep1 = Endpoint(
        project_id=project.id,
        url="http://127.0.0.1:8001/webhook1",
        encrypted_signing_secret=encrypt_secret(generate_signing_secret()),
        enabled=True
    )
    session.add(ep1)
    session.flush()
    sub1 = EndpointSubscription(endpoint_id=ep1.id, event_type="payment.succeeded")
    session.add(sub1)

    # Ep 2: Subscribed to wildcard '*'
    ep2 = Endpoint(
        project_id=project.id,
        url="http://127.0.0.1:8001/webhook2",
        encrypted_signing_secret=encrypt_secret(generate_signing_secret()),
        enabled=True
    )
    session.add(ep2)
    session.flush()
    sub2 = EndpointSubscription(endpoint_id=ep2.id, event_type="*")
    session.add(sub2)

    # Ep 3: Subscribed to 'order.shipped' (should NOT receive payment.succeeded)
    ep3 = Endpoint(
        project_id=project.id,
        url="http://127.0.0.1:8001/webhook3",
        encrypted_signing_secret=encrypt_secret(generate_signing_secret()),
        enabled=True
    )
    session.add(ep3)
    session.flush()
    sub3 = EndpointSubscription(endpoint_id=ep3.id, event_type="order.shipped")
    session.add(sub3)

    # Ep 4: Disabled endpoint (should NOT receive anything)
    ep4 = Endpoint(
        project_id=project.id,
        url="http://127.0.0.1:8001/webhook4",
        encrypted_signing_secret=encrypt_secret(generate_signing_secret()),
        enabled=False
    )
    session.add(ep4)
    session.flush()
    sub4 = EndpointSubscription(endpoint_id=ep4.id, event_type="*")
    session.add(sub4)

    session.commit()
    yield session
    session.close()

def test_atomic_event_ingestion_and_delivery_matching(db_session):
    project = db_session.query(Project).first()
    payload = {"payment_id": "pay_1", "amount": 500}

    event, is_duplicate, delivery_count = ingest_event(
        db=db_session,
        project_id=project.id,
        event_type="payment.succeeded",
        payload_data=payload,
        idempotency_key="key-001"
    )

    assert is_duplicate is False
    # ep1 (payment.succeeded) and ep2 (*) should match = 2 deliveries
    # ep3 (order.shipped) and ep4 (disabled) should NOT match
    assert delivery_count == 2
    assert len(event.deliveries) == 2
    for dlv in event.deliveries:
        assert dlv.status == "PENDING"
        assert dlv.attempt_count == 0

def test_idempotent_event_deduplication(db_session):
    project = db_session.query(Project).first()
    payload = {"payment_id": "pay_2", "amount": 1000}

    event1, is_dup1, count1 = ingest_event(
        db=db_session,
        project_id=project.id,
        event_type="payment.succeeded",
        payload_data=payload,
        idempotency_key="idempotent-key-002"
    )
    assert is_dup1 is False

    # Second request with EXACT same key and payload
    event2, is_dup2, count2 = ingest_event(
        db=db_session,
        project_id=project.id,
        event_type="payment.succeeded",
        payload_data=payload,
        idempotency_key="idempotent-key-002"
    )
    assert is_dup2 is True
    assert event1.id == event2.id
    assert count1 == count2

def test_idempotency_conflict_raises_error(db_session):
    project = db_session.query(Project).first()
    payload1 = {"payment_id": "pay_3", "amount": 100}
    payload2 = {"payment_id": "pay_3", "amount": 9999}  # altered amount

    ingest_event(
        db=db_session,
        project_id=project.id,
        event_type="payment.succeeded",
        payload_data=payload1,
        idempotency_key="conflict-key-003"
    )

    # Reusing same idempotency key with differing payload must raise IdempotencyConflictError
    with pytest.raises(IdempotencyConflictError):
        ingest_event(
            db=db_session,
            project_id=project.id,
            event_type="payment.succeeded",
            payload_data=payload2,
            idempotency_key="conflict-key-003"
        )
