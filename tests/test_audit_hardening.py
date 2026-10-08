"""Tests for deployment hardening, RBAC masking, input bounds, and fail-fast validation."""

from unittest.mock import MagicMock
import uuid
import pytest
from fastapi.testclient import TestClient

from app.config import Settings, validate_production_settings
from app.db.session import SessionLocal
from app.main import app
from app.models import Endpoint, Organization, OrganizationMember, Project, User
from app.services.security import (
    create_session_token,
    encrypt_secret,
    generate_signing_secret,
    get_csrf_token_for_request,
    hash_password,
)


def _get_csrf_for_token(session_token: str) -> str:
    mock_req = MagicMock()
    mock_req.cookies = {"wh_session": session_token}
    csrf_token, _ = get_csrf_token_for_request(mock_req)
    return csrf_token


def test_config_production_failfast():
    # Production with sqlite:// should raise RuntimeError
    with pytest.raises(RuntimeError, match="must be PostgreSQL in production"):
        s = Settings(
            ENV="production",
            DEBUG=False,
            DATABASE_URL="sqlite:///test.db",
            SECRET_KEY="A" * 64,
            SIGNING_SECRET_ENCRYPTION_KEY="B" * 43 + "=",
            API_KEY_PEPPER="pepper_is_long_enough",
            METRICS_API_KEY="metrics_key_is_long_enough",
            ALLOW_LOCAL_RECEIVERS=False,
        )
        validate_production_settings(s)

    # Production with DEBUG=True should raise RuntimeError
    with pytest.raises(RuntimeError, match="DEBUG must be False in production"):
        s = Settings(
            ENV="Production",  # Case-insensitive
            DEBUG=True,
            DATABASE_URL="postgresql+psycopg://user:strongpass@host/db",
            SECRET_KEY="A" * 64,
            SIGNING_SECRET_ENCRYPTION_KEY="B" * 43 + "=",
            API_KEY_PEPPER="pepper_is_long_enough",
            METRICS_API_KEY="metrics_key_is_long_enough",
            ALLOW_LOCAL_RECEIVERS=False,
        )
        validate_production_settings(s)


def test_rbac_endpoint_secret_masking():
    db = SessionLocal()
    client = TestClient(app)
    uid = uuid.uuid4().hex[:6]

    try:
        org = Organization(name=f"Masking Org {uid}")
        db.add(org)
        db.flush()

        user_owner = User(email=f"owner_{uid}@example.com", password_hash=hash_password("OwnerPassword123!"))
        user_member = User(email=f"member_{uid}@example.com", password_hash=hash_password("MemberPassword123!"))
        db.add_all([user_owner, user_member])
        db.flush()

        mem_owner = OrganizationMember(organization_id=org.id, user_id=user_owner.id, role="owner")
        mem_member = OrganizationMember(organization_id=org.id, user_id=user_member.id, role="member")
        db.add_all([mem_owner, mem_member])
        db.flush()

        proj = Project(organization_id=org.id, name=f"Masking Proj {uid}")
        db.add(proj)
        db.flush()

        raw_secret = generate_signing_secret()
        ep = Endpoint(
            project_id=proj.id,
            url="https://example.com/webhook",
            encrypted_signing_secret=encrypt_secret(raw_secret),
            enabled=True,
        )
        db.add(ep)
        db.commit()

        # 1. Owner can view decrypted secret
        owner_token = create_session_token(user_owner.id, org_id=org.id, project_id=proj.id)
        res_owner = client.get(
            f"/dashboard/endpoints/{ep.id}", cookies={"wh_session": owner_token, "wh_active_project_id": proj.id}
        )
        assert res_owner.status_code == 200
        assert raw_secret in res_owner.text

        # 2. Member cannot view decrypted secret (masked)
        member_token = create_session_token(user_member.id, org_id=org.id, project_id=proj.id)
        res_member = client.get(
            f"/dashboard/endpoints/{ep.id}", cookies={"wh_session": member_token, "wh_active_project_id": proj.id}
        )
        assert res_member.status_code == 200
        assert raw_secret not in res_member.text
        assert "whsec_••••••••" in res_member.text
    finally:
        db.close()


def test_invite_token_masked_for_members():
    from app.models.invitation import OrganizationInvitation

    db = SessionLocal()
    client = TestClient(app)
    uid = uuid.uuid4().hex[:6]

    try:
        org = Organization(name=f"Invite Org {uid}")
        db.add(org)
        db.flush()

        user_member = User(email=f"mem_{uid}@example.com", password_hash=hash_password("Pass1234!"))
        db.add(user_member)
        db.flush()

        mem = OrganizationMember(organization_id=org.id, user_id=user_member.id, role="member")
        db.add(mem)

        proj = Project(organization_id=org.id, name=f"Invite Proj {uid}")
        db.add(proj)
        db.flush()

        inv = OrganizationInvitation(
            organization_id=org.id,
            email=f"pending_{uid}@example.com",
            role="member",
            token=f"super_secret_invite_token_{uid}",
        )
        db.add(inv)
        db.commit()

        member_token = create_session_token(user_member.id, org_id=org.id, project_id=proj.id)
        res = client.get("/dashboard/team", cookies={"wh_session": member_token, "wh_active_project_id": proj.id})
        assert res.status_code == 200
        # Token must not leak to read-only members
        assert f"super_secret_invite_token_{uid}" not in res.text
    finally:
        db.close()


def test_project_name_bounds():
    db = SessionLocal()
    client = TestClient(app)
    uid = uuid.uuid4().hex[:6]

    try:
        org = Organization(name=f"Bounds Org {uid}")
        user = User(email=f"bounds_{uid}@example.com", password_hash=hash_password("Pass1234!"))
        db.add_all([org, user])
        db.flush()
        mem = OrganizationMember(organization_id=org.id, user_id=user.id, role="owner")
        proj = Project(organization_id=org.id, name="Default")
        db.add_all([mem, proj])
        db.commit()

        token = create_session_token(user.id, org_id=org.id, project_id=proj.id)
        csrf = _get_csrf_for_token(token)
        cookies = {"wh_session": token, "wh_active_project_id": proj.id}

        # Empty name rejected
        res_empty = client.post("/dashboard/projects", data={"name": "   ", "csrf_token": csrf}, cookies=cookies)
        assert res_empty.status_code == 400

        # Overly long name (>100 chars) rejected
        res_long = client.post("/dashboard/projects", data={"name": "x" * 101, "csrf_token": csrf}, cookies=cookies)
        assert res_long.status_code == 400

        # Valid name accepted
        res_ok = client.post(
            "/dashboard/projects",
            data={"name": f"Valid {uid}", "csrf_token": csrf},
            cookies=cookies,
            follow_redirects=False,
        )
        assert res_ok.status_code in (200, 302, 303)
    finally:
        db.close()


def test_api_key_name_bounds():
    db = SessionLocal()
    client = TestClient(app)
    uid = uuid.uuid4().hex[:6]

    try:
        org = Organization(name=f"Key Org {uid}")
        user = User(email=f"key_{uid}@example.com", password_hash=hash_password("Pass1234!"))
        db.add_all([org, user])
        db.flush()
        mem = OrganizationMember(organization_id=org.id, user_id=user.id, role="owner")
        proj = Project(organization_id=org.id, name="KeyProj")
        db.add_all([mem, proj])
        db.commit()

        token = create_session_token(user.id, org_id=org.id, project_id=proj.id)
        csrf = _get_csrf_for_token(token)
        cookies = {"wh_session": token, "wh_active_project_id": proj.id}

        # Name >100 chars rejected with 400
        res_long = client.post("/dashboard/api-keys", data={"name": "k" * 101, "csrf_token": csrf}, cookies=cookies)
        assert res_long.status_code == 400
        assert "between 1 and 100 characters" in res_long.text
    finally:
        db.close()


def test_email_validation():
    client = TestClient(app)
    anon_csrf_id = "test_anon_csrf_id"
    mock_req = MagicMock()
    mock_req.cookies = {"wh_csrf_id": anon_csrf_id}
    csrf_tok, _ = get_csrf_token_for_request(mock_req)

    # Register with invalid email
    res = client.post(
        "/auth/register",
        data={"email": "not-an-email", "password": "Password123!", "csrf_token": csrf_tok},
        cookies={"wh_csrf_id": anon_csrf_id},
    )
    assert res.status_code == 400
    assert "Invalid email address format" in res.text


def test_demo_receiver_config_validation():
    from demo_receiver.app import app as demo_app

    demo_client = TestClient(demo_app)

    # Invalid mode
    res_mode = demo_client.post("/config", json={"mode": "invalid_mode"})
    assert res_mode.status_code == 400

    # Invalid status code
    res_sc = demo_client.post("/config", json={"mode": "status_code", "status_code": 9999})
    assert res_sc.status_code == 400
