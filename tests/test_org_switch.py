"""Tests for org switching (invited members) and audit actor role pills."""

import uuid
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from app.db.session import SessionLocal
from app.main import app
from app.models import Organization, OrganizationMember, Project, User
from app.services.security import create_session_token, get_csrf_token_for_request, hash_password


def _authed_csrf(session_token: str):
    mock_req = MagicMock()
    mock_req.cookies = {"wh_session": session_token}
    tok, _ = get_csrf_token_for_request(mock_req)
    return tok


def _user_with_org(db, email: str, org_name: str, role: str = "owner", superadmin: bool = False):
    u = User(email=email, password_hash=hash_password("Password123!"), status="approved")
    u.is_superadmin = superadmin
    db.add(u)
    db.flush()
    org = Organization(name=org_name)
    db.add(org)
    db.flush()
    db.add(OrganizationMember(organization_id=org.id, user_id=u.id, role=role))
    db.add(Project(organization_id=org.id, name="Default Project"))
    db.commit()
    return u, org


def test_invited_member_can_switch_org():
    db = SessionLocal()
    client = TestClient(app)
    uid = uuid.uuid4().hex[:8]
    try:
        owner, org_a = _user_with_org(db, f"own_{uid}@example.com", f"Org A {uid}")
        member, org_b = _user_with_org(db, f"mem_{uid}@example.com", f"Org B {uid}")
        # Invite member into owner's org as admin
        db.add(OrganizationMember(organization_id=org_a.id, user_id=member.id, role="admin"))
        db.commit()

        tok = create_session_token(member.id, org_id=org_b.id)
        # Projects page lists both workspaces
        page = client.get("/dashboard/projects", cookies={"wh_session": tok})
        assert page.status_code == 200
        assert f"Org A {uid}" in page.text
        assert f"Org B {uid}" in page.text

        # Switch workspace to owner's org
        csrf = _authed_csrf(tok)
        sw = client.post(
            "/dashboard/orgs/switch",
            data={"organization_id": org_a.id, "csrf_token": csrf},
            cookies={"wh_session": tok},
            follow_redirects=False,
        )
        assert sw.status_code == 303
        # Switch to foreign org without membership is 404
        outsider, _ = _user_with_org(db, f"out_{uid}@example.com", f"Org C {uid}")
        tok_out = create_session_token(outsider.id)
        csrf_out = _authed_csrf(tok_out)
        bad = client.post(
            "/dashboard/orgs/switch",
            data={"organization_id": org_a.id, "csrf_token": csrf_out},
            cookies={"wh_session": tok_out},
            follow_redirects=False,
        )
        assert bad.status_code == 404
    finally:
        db.close()


def test_audit_log_shows_superadmin_pill():
    from app.services.audit import log_audit_event

    db = SessionLocal()
    client = TestClient(app)
    uid = uuid.uuid4().hex[:8]
    try:
        admin, org = _user_with_org(db, f"sa_{uid}@example.com", f"Org SA {uid}", superadmin=True)
        log_audit_event(
            db,
            organization_id=org.id,
            user_id=admin.id,
            action="user.approved",
            resource_type="user",
            resource_id="usr_test",
        )
        tok = create_session_token(admin.id, org_id=org.id)
        page = client.get("/dashboard/audit-logs", cookies={"wh_session": tok})
        assert page.status_code == 200
        assert "Superadmin" in page.text
    finally:
        db.close()
