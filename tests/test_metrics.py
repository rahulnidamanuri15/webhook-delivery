from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models import Event, Organization, Project
from app.services.metrics import generate_prometheus_metrics
from app.services.tracing import start_trace_span


def test_prometheus_metrics_generation():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()

    org = Organization(name="Metrics Org")
    session.add(org)
    session.flush()

    project = Project(organization_id=org.id, name="Metrics Project")
    session.add(project)
    session.flush()

    event = Event(
        project_id=project.id, event_type="test.metrics", payload_json="{}", wire_payload="{}", request_hash="hash123"
    )
    session.add(event)
    session.commit()

    output = generate_prometheus_metrics(session)
    assert "webhook_events_total" in output
    assert "webhook_deliveries_total" in output
    assert "webhook_delivery_attempts_total" in output
    assert "webhook_backlog_total" in output
    assert "webhook_delivery_duration_ms" in output


def test_tracing_context_manager():
    # Context manager shouldn't raise errors
    with start_trace_span("test.span", {"key": "value"}) as span:
        assert span is not None
