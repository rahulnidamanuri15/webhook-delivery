"""Tests for registration approval queue (pending -> approve/reject by superadmin)."""

import uuid
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from app.config import settings as _s
from app.db.session import SessionLocal
from app.main import app
from app.models import Organization, OrganizationMember, Project, User
from app.services.security import create_session_token, get_csrf_token_for_request, hash_password


def _anon_csrf():
    anon_id = f"anon_{uuid.uuid4().hex[:8]}"
    mock_req = MagicMock()
    mock_req.cookies = {"wh_csrf_id": anon_id}
    tok, _ = get_csrf_token_for_request(mock_req)
    return tok, anon_id


def _authed_csrf(session_token: str):
    mock_req = MagicMock()
    mock_req.cookies = {"wh_session": session_token}
    tok, _ = get_csrf_token_for_request(mock_req)
    return tok


def _make_superadmin(db, uid: str) -> tuple[User, str]:
    admin = User(
        email=f"super_{uid}@example.com", password_hash=hash_password("SuperPassword123!"), status="approved"
    )
    admin.is_superadmin = True
    db.add(admin)
    db.flush()
    org = Organization(name=f"Admin Org {uid}")
    db.add(org)
    db.flush()
    db.add(OrganizationMember(organization_id=org.id, user_id=admin.id, role="owner"))
    db.add(Project(organization_id=org.id, name="Admin Project"))
    db.commit()
    tok = create_session_token(admin.id, org_id=org.id)
    return admin, tok


def test_pending_register_then_approve(monkeypatch):
    monkeypatch.setattr(_s, "ALLOW_OPEN_REGISTRATION", False)
    monkeypatch.setattr(_s, "ALLOW_PENDING_REGISTRATION", True)
    db = SessionLocal()
    client = TestClient(app)
    uid = uuid.uuid4().hex[:8]
    email = f"pending_{uid}@example.com"
    try:
        tok, anon_id = _anon_csrf()
        res = client.post(
            "/auth/register",
            data={"email": email, "password": "Password123!", "project_name": "Default Project", "csrf_token": tok},
            cookies={"wh_csrf_id": anon_id},
        )
        assert res.status_code == 200
        assert "Application received" in res.text

        pending = db.query(User).filter(User.email == email).first()
        assert pending is not None
        assert pending.status == "pending"
        assert db.query(OrganizationMember).filter(OrganizationMember.user_id == pending.id).first() is None

        # Login blocked while pending
        tok2, anon2 = _anon_csrf()
        login = client.post(
            "/auth/login",
            data={"email": email, "password": "Password123!", "csrf_token": tok2},
            cookies={"wh_csrf_id": anon2},
        )
        assert login.status_code == 400
        assert "awaiting admin approval" in login.text

        # Superadmin approves
        _, admin_tok = _make_superadmin(db, uid)
        csrf = _authed_csrf(admin_tok)
        page = client.get("/dashboard/admin/pending", cookies={"wh_session": admin_tok})
        assert page.status_code == 200
        assert email in page.text
        appr = client.post(
            "/dashboard/admin/approve",
            data={"user_id": pending.id, "csrf_token": csrf},
            cookies={"wh_session": admin_tok},
            follow_redirects=False,
        )
        assert appr.status_code == 303
        db.expire_all()
        approved = db.query(User).filter(User.email == email).first()
        assert approved.status == "approved"
        assert db.query(OrganizationMember).filter(OrganizationMember.user_id == approved.id).first() is not None

        # Login works after approval
        tok3, anon3 = _anon_csrf()
        login2 = client.post(
            "/auth/login",
            data={"email": email, "password": "Password123!", "csrf_token": tok3},
            cookies={"wh_csrf_id": anon3},
            follow_redirects=False,
        )
        assert login2.status_code == 303
    finally:
        db.close()
        monkeypatch.setattr(_s, "ALLOW_PENDING_REGISTRATION", False)


def test_pending_register_then_reject(monkeypatch):
    monkeypatch.setattr(_s, "ALLOW_OPEN_REGISTRATION", False)
    monkeypatch.setattr(_s, "ALLOW_PENDING_REGISTRATION", True)
    db = SessionLocal()
    client = TestClient(app)
    uid = uuid.uuid4().hex[:8]
    email = f"reject_{uid}@example.com"
    try:
        tok, anon_id = _anon_csrf()
        res = client.post(
            "/auth/register",
            data={"email": email, "password": "Password123!", "project_name": "Default Project", "csrf_token": tok},
            cookies={"wh_csrf_id": anon_id},
        )
        assert res.status_code == 200
        pending = db.query(User).filter(User.email == email).first()
        _, admin_tok = _make_superadmin(db, uid)
        csrf = _authed_csrf(admin_tok)
        rej = client.post(
            "/dashboard/admin/reject",
            data={"user_id": pending.id, "csrf_token": csrf},
            cookies={"wh_session": admin_tok},
            follow_redirects=False,
        )
        assert rej.status_code == 303
        db.expire_all()
        assert db.query(User).filter(User.email == email).first().status == "rejected"
        tok2, anon2 = _anon_csrf()
        login = client.post(
            "/auth/login",
            data={"email": email, "password": "Password123!", "csrf_token": tok2},
            cookies={"wh_csrf_id": anon2},
        )
        assert login.status_code == 400
        assert "not approved" in login.text
    finally:
        db.close()
        monkeypatch.setattr(_s, "ALLOW_PENDING_REGISTRATION", False)


def test_admin_queue_requires_superadmin(monkeypatch):
    db = SessionLocal()
    client = TestClient(app)
    uid = uuid.uuid4().hex[:8]
    try:
        plain = User(email=f"plain_{uid}@example.com", password_hash=hash_password("Password123!"), status="approved")
        db.add(plain)
        db.flush()
        org = Organization(name=f"Plain Org {uid}")
        db.add(org)
        db.flush()
        db.add(OrganizationMember(organization_id=org.id, user_id=plain.id, role="member"))
        db.commit()
        tok = create_session_token(plain.id, org_id=org.id)
        page = client.get("/dashboard/admin/pending", cookies={"wh_session": tok})
        assert page.status_code == 403
    finally:
        db.close()
