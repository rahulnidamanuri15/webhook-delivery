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


from sqlalchemy.pool import StaticPool


def _mem_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
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
    org = Organization(name="Ret Org")
    db.add(org)
    db.flush()
    proj = Project(organization_id=org.id, name="Ret Proj")
    db.add(proj)
    db.flush()
    ep = Endpoint(
        project_id=proj.id,
        url="http://127.0.0.1:8001/webhook",
        encrypted_signing_secret=encrypt_secret(generate_signing_secret()),
        enabled=True,
    )
    db.add(ep)
    db.flush()
    db.add(EndpointSubscription(endpoint_id=ep.id, event_type="*"))
    db.commit()
    evt, _, _ = ingest_event(db, proj.id, "t.e", {"a": 1})
    dlv = evt.deliveries[0]
    dlv.status = "SUCCEEDED"
    old = utc_now() - timedelta(days=100)
    dlv.created_at = old
    dlv.completed_at = old
    evt.created_at = old
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


def test_production_fails_on_demo_retry_policy():
    import pytest
    from app.config import Settings, validate_production_settings

    s = Settings(
        ENV="production",
        DEBUG=False,
        DATABASE_URL="postgresql+psycopg://user:strongpass@host/db",
        SECRET_KEY="A" * 64,
        SIGNING_SECRET_ENCRYPTION_KEY="B" * 43 + "=",
        API_KEY_PEPPER="pepper_is_long_enough",
        METRICS_API_KEY="metrics_key_is_long_enough",
        ALLOW_LOCAL_RECEIVERS=False,
        ALLOWED_RECEIVER_DOMAINS="example.com",
        USE_DEMO_RETRY_POLICY=True,
    )
    with pytest.raises(RuntimeError, match="USE_DEMO_RETRY_POLICY must be False in production"):
        validate_production_settings(s)

    s.USE_DEMO_RETRY_POLICY = False
    validate_production_settings(s)


def test_get_client_ip_headers():
    from unittest.mock import MagicMock
    from app.services.security import get_client_ip

    req1 = MagicMock()
    req1.headers = {"x-forwarded-for": "203.0.113.195, 70.41.3.18, 150.172.238.178"}
    assert get_client_ip(req1) == "203.0.113.195"

    req2 = MagicMock()
    req2.headers = {"x-real-ip": "198.51.100.22"}
    assert get_client_ip(req2) == "198.51.100.22"

    req3 = MagicMock()
    req3.headers = {}
    req3.client.host = "192.0.2.1"
    assert get_client_ip(req3) == "192.0.2.1"


def test_safe_back_redirect_same_origin():
    from unittest.mock import MagicMock
    from app.dashboard.views import safe_back_redirect

    req = MagicMock()
    req.headers = {
        "host": "mywebhook.example.com",
        "referer": "https://mywebhook.example.com/dashboard/endpoints/ep_123?page=2",
    }
    url = safe_back_redirect(req)
    assert url == "/dashboard/endpoints/ep_123?page=2"

    req_cross = MagicMock()
    req_cross.headers = {"host": "mywebhook.example.com", "referer": "https://evil.com/dashboard/endpoints/ep_123"}
    assert safe_back_redirect(req_cross) == "/dashboard/endpoints"


def test_invitation_account_takeover_prevention():
    import re
    from fastapi.testclient import TestClient
    from app.main import app
    from app.db.session import get_db
    from app.models import Organization, User
    from app.models.invitation import OrganizationInvitation
    from app.services.security import hash_password

    client = TestClient(app)
    db = _mem_db()

    org = Organization(name="Invite Org")
    db.add(org)
    db.flush()
    existing_user = User(email="existing@example.com", password_hash=hash_password("Secret1234!"))
    db.add(existing_user)
    db.flush()
    inv = OrganizationInvitation(organization_id=org.id, email="existing@example.com", role="member")
    db.add(inv)
    db.commit()

    def _override_get_db():
        yield db

    app.dependency_overrides[get_db] = _override_get_db
    try:
        resp = client.get(f"/auth/invitations/{inv.token}")
        assert resp.status_code == 200
        assert "Account Password" in resp.text

        csrf_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', resp.text)
        assert csrf_match is not None
        csrf_token = csrf_match.group(1)

        # Submitting with wrong password fails
        resp_wrong_pw = client.post(
            f"/auth/invitations/{inv.token}/accept", data={"password": "WrongPassword!", "csrf_token": csrf_token}
        )
        assert resp_wrong_pw.status_code == 400
        assert "already exists" in resp_wrong_pw.text

        # Re-extract csrf_token if rotated, or reuse
        csrf_match2 = re.search(r'name="csrf_token"\s+value="([^"]+)"', resp_wrong_pw.text)
        token_to_use = csrf_match2.group(1) if csrf_match2 else csrf_token

        # Submitting with correct password succeeds and issues session
        resp_correct_pw = client.post(
            f"/auth/invitations/{inv.token}/accept",
            data={"password": "Secret1234!", "csrf_token": token_to_use},
            follow_redirects=False,
        )
        assert resp_correct_pw.status_code == 303
        assert "wh_session" in resp_correct_pw.cookies
    finally:
        app.dependency_overrides.clear()
        db.close()
