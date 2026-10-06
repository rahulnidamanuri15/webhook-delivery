"""E2E: publish -> dispatch -> demo receiver (mocked HTTP)."""
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models import Endpoint, EndpointSubscription, Organization, Project
from app.services.delivery_service import execute_delivery
from app.services.event_service import ingest_event
from app.services.security import encrypt_secret, generate_signing_secret


def _mock200():
    m = MagicMock()
    m.status_code = 200
    m.headers = {}
    m.iter_bytes.return_value = [b'{"ok":true}']
    m.close.return_value = None
    ctx = MagicMock(); ctx.__enter__.return_value = m; ctx.__exit__.return_value = False
    c = MagicMock(); c.__enter__.return_value = c; c.__exit__.return_value = False
    c.stream.return_value = ctx
    return patch("httpx.Client", return_value=c)


def test_e2e_publish_deliver():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=eng)
    S = sessionmaker(bind=eng)
    db = S()
    try:
        org = Organization(name="e2e"); db.add(org); db.flush()
        proj = Project(organization_id=org.id, name="p"); db.add(proj); db.flush()
        ep = Endpoint(project_id=proj.id, url="http://127.0.0.1:8001/webhook",
                       encrypted_signing_secret=encrypt_secret(generate_signing_secret()), enabled=True)
        db.add(ep); db.flush()
        db.add(EndpointSubscription(endpoint_id=ep.id, event_type="payment.succeeded"))
        db.commit()
        evt, dup, cnt = ingest_event(db, proj.id, "payment.succeeded", {"pay": 1}, idempotency_key="e2e-1")
        assert cnt == 1 and not dup
        with _mock200():
            assert execute_delivery(db, evt.deliveries[0].id) is True
        db.refresh(evt.deliveries[0])
        assert evt.deliveries[0].status == "SUCCEEDED"
    finally:
        db.close(); eng.dispose()
