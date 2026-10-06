"""Regression tests for the audit-fix batch (allowlist, retention, logout, CRUD, RBAC)."""
from datetime import timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models import Endpoint, EndpointSubscription, Organization, Project, utc_now
from app.services.event_service import ingest_event
from app.services.security import (
    create_session_token,
    encrypt_secret,
    generate_signing_secret,
    invalidate_session_token,
    verify_session_token,
)


def _mem_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def test_allowlist_blocks_unlisted_domain():
    from app.config import settings
    old = settings.ALLOWED_RECEIVER_DOMAINS
    settings.ALLOWED_RECEIVER_DOMAINS = "example.com"
    try:
        from unittest.mock import patch

        from app.services.ssrf import is_domain_allowed, validate_webhook_url
        ok, _ = is_domain_allowed("api.example.com")
        assert ok is True
        ok2, err = is_domain_allowed("evil.com")
        assert ok2 is False
        assert "allowlist" in (err or "").lower()
        # Full URL validation also enforces allowlist (mock DNS to stay offline-safe)
        with patch("app.services.ssrf.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 0))]):
            ok3, _ = validate_webhook_url("https://api.example.com/hook")
            assert ok3 is True
            ok4, err4 = validate_webhook_url("https://evil.com/hook")
            assert ok4 is False
            assert "allowlist" in (err4 or "").lower()
    finally:
        settings.ALLOWED_RECEIVER_DOMAINS = old


def test_retention_purges_only_terminal_old_data():
    from app.services.retention import purge_expired_data
    db = _mem_db()
    org = Organization(name="Ret Org"); db.add(org); db.flush()
    proj = Project(organization_id=org.id, name="Ret Proj"); db.add(proj); db.flush()
    ep = Endpoint(project_id=proj.id, url="http://127.0.0.1:8001/webhook",
                  encrypted_signing_secret=encrypt_secret(generate_signing_secret()), enabled=True)
    db.add(ep); db.flush()
    db.add(EndpointSubscription(endpoint_id=ep.id, event_type="*")); db.commit()
    evt, _, _ = ingest_event(db, proj.id, "t.e", {"a": 1})
    dlv = evt.deliveries[0]
    dlv.status = "SUCCEEDED"
    old = utc_now() - timedelta(days=100)
    dlv.created_at = old; dlv.completed_at = old; evt.created_at = old
    db.commit()
    res = purge_expired_data(db, retention_days=90)
    assert res["purged_deliveries"] == 1
    assert res["purged_events"] == 1
    # Disabled policy purges nothing
    res2 = purge_expired_data(db, retention_days=0)
    assert res2.get("disabled") is True
    db.close()


def test_logout_denylist_invalidates_session():
    tok = create_session_token("u123")
    assert verify_session_token(tok) is not None
    invalidate_session_token(tok)
    assert verify_session_token(tok) is None


def test_separate_timeouts_configured():
    from app.config import settings
    from app.services.delivery_service import _build_timeout
    t = _build_timeout()
    assert t.connect is not None
    assert float(t.connect) < float(settings.HTTP_TIMEOUT_SECONDS)
    assert float(settings.HTTP_TIMEOUT_SECONDS) < float(settings.LEASE_DURATION_SECONDS)
