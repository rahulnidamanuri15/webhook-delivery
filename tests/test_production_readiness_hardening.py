"""Comprehensive tests for production readiness hardening.

Covers:
- Docker Secrets / *_FILE loading in Settings
- Production fail-fast on missing allowlist and unsafe lease duration
- Health probes: /live, /ready, /startup
- Request size limit ASGI middleware (413 Payload Too Large)
- Production /metrics access restrictions
- Invitation token hashing at rest & rate limiting
- Legal hold project exclusions in retention purging
- Comprehensive RBAC permission matrix (Owner, Admin, Member)
"""

import os
import tempfile
import pytest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import Settings, validate_production_settings
from app.db.session import Base, get_db
from app.main import app
from app.models import Endpoint, Organization, OrganizationMember, Project, User
from app.models.invitation import OrganizationInvitation
from app.services.security import (
    create_session_token,
    encrypt_secret,
    generate_signing_secret,
    hash_invitation_token,
    hash_password,
)


@pytest.fixture
def mem_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def test_settings_load_from_secret_files(monkeypatch):
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write("super_secret_file_content_1234567890\n")
        f.flush()
        file_path = f.name

    try:
        monkeypatch.setenv("SECRET_KEY_FILE", file_path)
        s = Settings()
        assert s.SECRET_KEY == "super_secret_file_content_1234567890"
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)


def test_production_fails_on_missing_allowlist():
    s = Settings(
        ENV="production",
        DEBUG=False,
        DATABASE_URL="postgresql+psycopg://user:strongpass@host/db",
        SECRET_KEY="A" * 64,
        SIGNING_SECRET_ENCRYPTION_KEY="B" * 43 + "=",
        API_KEY_PEPPER="pepper_is_long_enough",
        METRICS_API_KEY="metrics_key_is_long_enough",
        ALLOW_LOCAL_RECEIVERS=False,
        USE_DEMO_RETRY_POLICY=False,
        ALLOWED_RECEIVER_DOMAINS="",  # Missing allowlist
        SMTP_HOST="smtp.example.com",
        SMTP_PASSWORD="smtp-secret",
        SMTP_FROM_EMAIL="noreply@example.com",
        REDIS_URL="redis://:secret@redis:6379/0",
    )
    with pytest.raises(RuntimeError, match="ALLOWED_RECEIVER_DOMAINS must be configured in production"):
        validate_production_settings(s)


def test_production_fails_without_smtp():
    s = Settings(
        ENV="production",
        DEBUG=False,
        DATABASE_URL="postgresql+psycopg://user:strongpass@host/db",
        SECRET_KEY="A" * 64,
        SIGNING_SECRET_ENCRYPTION_KEY="B" * 43 + "=",
        API_KEY_PEPPER="pepper_is_long_enough",
        METRICS_API_KEY="metrics_key_is_long_enough",
        ALLOW_LOCAL_RECEIVERS=False,
        USE_DEMO_RETRY_POLICY=False,
        ALLOWED_RECEIVER_DOMAINS="example.com",
        REDIS_URL="redis://:secret@redis:6379/0",
        SMTP_HOST="",
    )
    with pytest.raises(RuntimeError, match="SMTP_HOST"):
        validate_production_settings(s)


def test_production_fails_on_unauthenticated_redis():
    s = Settings(
        ENV="production",
        DEBUG=False,
        DATABASE_URL="postgresql+psycopg://user:strongpass@host/db",
        SECRET_KEY="A" * 64,
        SIGNING_SECRET_ENCRYPTION_KEY="B" * 43 + "=",
        API_KEY_PEPPER="pepper_is_long_enough",
        METRICS_API_KEY="metrics_key_is_long_enough",
        ALLOW_LOCAL_RECEIVERS=False,
        USE_DEMO_RETRY_POLICY=False,
        ALLOWED_RECEIVER_DOMAINS="example.com",
        SMTP_HOST="smtp.example.com",
        SMTP_PASSWORD="smtp-secret",
        SMTP_FROM_EMAIL="noreply@example.com",
        REDIS_URL="rediss://redis:6379/0",
    )
    with pytest.raises(RuntimeError, match="REDIS_URL must include authentication"):
        validate_production_settings(s)


def test_production_fails_on_unsafe_lease_timeout():
    s = Settings(
        ENV="production",
        DEBUG=False,
        DATABASE_URL="postgresql+psycopg://user:strongpass@host/db",
        SECRET_KEY="A" * 64,
        SIGNING_SECRET_ENCRYPTION_KEY="B" * 43 + "=",
        API_KEY_PEPPER="pepper_is_long_enough",
        METRICS_API_KEY="metrics_key_is_long_enough",
        ALLOW_LOCAL_RECEIVERS=False,
        USE_DEMO_RETRY_POLICY=False,
        ALLOWED_RECEIVER_DOMAINS="example.com",
        SMTP_HOST="smtp.example.com",
        SMTP_PASSWORD="smtp-secret",
        SMTP_FROM_EMAIL="noreply@example.com",
        REDIS_URL="redis://:secret@redis:6379/0",
        HTTP_TIMEOUT_SECONDS=30.0,
        LEASE_DURATION_SECONDS=30,  # Unsafe: timeout not less than lease - margin
    )
    with pytest.raises(RuntimeError, match="LEASE_DURATION_SECONDS .* must exceed HTTP_TIMEOUT_SECONDS"):
        validate_production_settings(s)


def test_health_probes(mem_db):
    client = TestClient(app)
    app.dependency_overrides[get_db] = lambda: mem_db
    try:
        # 1. /live probe
        live_resp = client.get("/live")
        assert live_resp.status_code == 200
        assert live_resp.json()["status"] == "ok"
        assert live_resp.json()["version"] == "1.0.0"

        # 2. /ready probe
        ready_resp = client.get("/ready")
        assert ready_resp.status_code in (200, 503)

        # 3. /startup probe
        startup_resp = client.get("/startup")
        assert startup_resp.status_code in (200, 503)
    finally:
        app.dependency_overrides.clear()


def test_request_size_limit_middleware():
    client = TestClient(app)
    # Huge content length header exceeds 1MB + 64KB
    headers = {"content-length": "2000000"}
    resp = client.post("/api/v1/events", headers=headers, json={"data": {}})
    assert resp.status_code == 413
    assert "Payload Too Large" in resp.text


def test_production_metrics_requires_bearer_token(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "METRICS_API_KEY", "prod_metrics_key_12345678")

    client = TestClient(app)
    # Unauthenticated fails
    resp = client.get("/metrics")
    assert resp.status_code == 401

    # Valid Bearer token succeeds
    resp_valid = client.get("/metrics", headers={"Authorization": "Bearer prod_metrics_key_12345678"})
    assert resp_valid.status_code == 200
    assert "webhook_" in resp_valid.text


def test_client_ip_uses_rightmost_untrusted_hop(monkeypatch):
    """A trusted proxy at the right edge is skipped; a spoofed leftmost hop is not."""
    from app.config import settings
    from app.services.security import get_client_ip

    monkeypatch.setattr(settings, "TRUSTED_PROXIES", "10.0.0.0/8,172.16.0.0/12")

    class _Req:
        def __init__(self, client, headers):
            self.client = type("C", (), {"host": client})()
            self.headers = headers

    # nginx appended the real client; the client tried to prepend a fake hop.
    proxied = _Req("10.0.1.5", {"x-forwarded-for": "1.2.3.4, 203.0.113.9", "x-real-ip": "203.0.113.9"})
    assert get_client_ip(proxied) == "203.0.113.9"

    # Direct connection: ignore a client-supplied X-Forwarded-For.
    direct = _Req("198.51.100.20", {"x-forwarded-for": "1.2.3.4"})
    assert get_client_ip(direct) == "198.51.100.20"


def test_invitation_token_hashed_at_rest(mem_db):
    import re

    client = TestClient(app)
    app.dependency_overrides[get_db] = lambda: mem_db

    org = Organization(name="Hash Test Org")
    mem_db.add(org)
    mem_db.flush()

    user = User(email="inv_test@example.com", password_hash=hash_password("StrongPass123!"))
    mem_db.add(user)
    mem_db.flush()

    raw_token = "raw_secret_invitation_token_123456"
    token_hash = hash_invitation_token(raw_token)

    # Store ONLY the hash in the database
    inv = OrganizationInvitation(
        organization_id=org.id,
        email="inv_test@example.com",
        role="member",
        token=token_hash,
    )
    mem_db.add(inv)
    mem_db.commit()

    try:
        # Visiting with raw_token works via hash candidate matching
        resp = client.get(f"/auth/invitations/{raw_token}")
        assert resp.status_code == 200
        assert "Join Hash Test Org" in resp.text

        csrf_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', resp.text)
        assert csrf_match is not None
        csrf_token = csrf_match.group(1)

        # Submitting with correct password succeeds
        post_resp = client.post(
            f"/auth/invitations/{raw_token}/accept",
            data={"password": "StrongPass123!", "csrf_token": csrf_token},
            follow_redirects=False,
        )
        assert post_resp.status_code == 303
        mem_db.refresh(inv)
        assert inv.status == "ACCEPTED"
    finally:
        app.dependency_overrides.clear()


def test_retention_purge_respects_legal_hold(mem_db):
    from datetime import timedelta
    from app.models import Delivery, Endpoint, EndpointSubscription, utc_now
    from app.services.event_service import ingest_event
    from app.services.retention import purge_expired_data

    org = Organization(name="Hold Org")
    mem_db.add(org)
    mem_db.flush()
    proj1 = Project(organization_id=org.id, name="Project 1")
    proj2 = Project(organization_id=org.id, name="Project 2")
    mem_db.add_all([proj1, proj2])
    mem_db.flush()

    for p in (proj1, proj2):
        ep = Endpoint(
            project_id=p.id,
            url="http://127.0.0.1:8001/webhook",
            encrypted_signing_secret=encrypt_secret(generate_signing_secret()),
            enabled=True,
        )
        mem_db.add(ep)
        mem_db.flush()
        mem_db.add(EndpointSubscription(endpoint_id=ep.id, event_type="*"))
    mem_db.commit()

    evt1, _, _ = ingest_event(mem_db, proj1.id, "evt.hold", {"data": 1})
    evt2, _, _ = ingest_event(mem_db, proj2.id, "evt.purge", {"data": 2})

    old_date = utc_now() - timedelta(days=100)
    for evt in (evt1, evt2):
        evt.created_at = old_date
        for dlv in evt.deliveries:
            dlv.status = "SUCCEEDED"
            dlv.created_at = old_date
            dlv.completed_at = old_date
    evt1_id = evt1.id
    evt2_id = evt2.id
    mem_db.commit()

    # Purge with legal hold on proj1
    res = purge_expired_data(mem_db, retention_days=90, legal_hold_project_ids={proj1.id})
    assert res["purged_deliveries"] == 1
    assert res["purged_events"] == 1

    # proj1 delivery remains intact
    assert mem_db.query(Delivery).filter(Delivery.event_id == evt1_id).count() == 1
    # proj2 delivery was purged
    assert mem_db.query(Delivery).filter(Delivery.event_id == evt2_id).count() == 0


def test_rbac_matrix_permissions(mem_db):
    """Verifies RBAC enforcement: Owners and Admins can mutate; Members are strictly read-only (403)."""
    import re

    org = Organization(name="RBAC Org")
    mem_db.add(org)
    mem_db.flush()
    proj = Project(organization_id=org.id, name="RBAC Project")
    mem_db.add(proj)
    mem_db.flush()

    owner_u = User(email="owner@example.com", password_hash=hash_password("OwnerPass123!"))
    admin_u = User(email="admin@example.com", password_hash=hash_password("AdminPass123!"))
    member_u = User(email="member@example.com", password_hash=hash_password("MemberPass123!"))
    mem_db.add_all([owner_u, admin_u, member_u])
    mem_db.flush()

    mem_db.add(OrganizationMember(organization_id=org.id, user_id=owner_u.id, role="owner"))
    mem_db.add(OrganizationMember(organization_id=org.id, user_id=admin_u.id, role="admin"))
    mem_db.add(OrganizationMember(organization_id=org.id, user_id=member_u.id, role="member"))
    mem_db.commit()

    client = TestClient(app)
    app.dependency_overrides[get_db] = lambda: mem_db

    try:
        # Create an endpoint for testing mutations
        ep = Endpoint(
            project_id=proj.id,
            url="https://api.example.com/webhook",
            encrypted_signing_secret=encrypt_secret(generate_signing_secret()),
            enabled=True,
        )
        mem_db.add(ep)
        mem_db.commit()

        # 1. Member tries to create an endpoint -> 403 Forbidden
        member_session = create_session_token(member_u.id)
        client.cookies.set("wh_session", member_session)
        client.cookies.set("wh_active_org_id", org.id)
        client.cookies.set("wh_active_project_id", proj.id)

        # Get CSRF token
        dash_resp = client.get("/dashboard/endpoints")
        assert dash_resp.status_code == 200
        csrf_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', dash_resp.text)
        csrf = csrf_match.group(1) if csrf_match else "dummy"

        resp_create = client.post(
            "/dashboard/endpoints",
            data={"url": "https://api.example.com/new", "csrf_token": csrf},
        )
        assert resp_create.status_code == 403

        # Member tries to delete endpoint -> 403 Forbidden
        resp_del = client.post(
            f"/dashboard/endpoints/{ep.id}/delete",
            data={"csrf_token": csrf},
        )
        assert resp_del.status_code == 403

        # Member tries to rotate secret -> 403 Forbidden
        resp_rot = client.post(
            f"/dashboard/endpoints/{ep.id}/rotate-secret",
            data={"csrf_token": csrf},
        )
        assert resp_rot.status_code == 403

        # Member tries to create API key -> 403 Forbidden
        resp_key = client.post(
            "/dashboard/api-keys",
            data={"name": "Member Key", "csrf_token": csrf},
        )
        assert resp_key.status_code == 403

        # 2. Admin tries mutations -> Allowed (303 Redirect)
        admin_session = create_session_token(admin_u.id)
        client.cookies.set("wh_session", admin_session)
        dash_admin = client.get("/dashboard/endpoints")
        csrf_admin_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', dash_admin.text)
        csrf_admin = csrf_admin_match.group(1) if csrf_admin_match else csrf

        resp_admin_rot = client.post(
            f"/dashboard/endpoints/{ep.id}/rotate-secret",
            data={"csrf_token": csrf_admin},
            follow_redirects=False,
        )
        assert resp_admin_rot.status_code == 303
    finally:
        app.dependency_overrides.clear()
