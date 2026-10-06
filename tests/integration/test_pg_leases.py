"""PG locking test: runs against real PostgreSQL in CI, skips locally on SQLite."""
import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models import Endpoint, EndpointSubscription, Organization, Project
from app.services.event_service import ingest_event
from app.services.security import encrypt_secret, generate_signing_secret
from app.workers.dispatcher import get_due_delivery_ids

needs_pg = pytest.mark.skipif(
    not os.getenv("DATABASE_URL", "").startswith("postgresql"),
    reason="Requires real PostgreSQL (CI DATABASE_URL) for SKIP LOCKED semantics",
)


@needs_pg
def test_pg_dispatcher_finds_due():
    url = os.getenv("DATABASE_URL")
    eng = create_engine(url)
    Base.metadata.create_all(bind=eng)
    S = sessionmaker(bind=eng)
    db = S()
    try:
        org = Organization(name="pg-org")
        db.add(org); db.flush()
        proj = Project(organization_id=org.id, name="pg-proj")
        db.add(proj); db.flush()
        ep = Endpoint(project_id=proj.id, url="http://127.0.0.1:8001/webhook",
                       encrypted_signing_secret=encrypt_secret(generate_signing_secret()), enabled=True)
        db.add(ep); db.flush()
        db.add(EndpointSubscription(endpoint_id=ep.id, event_type="*"))
        db.commit()
        evt, _, _ = ingest_event(db, proj.id, "pg.test", {"n": 1})
        ids = get_due_delivery_ids(db, batch_size=10)
        assert evt.deliveries[0].id in ids
    finally:
        db.close()
        eng.dispose()
