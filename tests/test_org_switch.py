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
        # Superadmin actor email is hidden (only pill); footer shows it once.
        assert page.text.count(admin.email) == 1
    finally:
        db.close()


def test_audit_logs_require_manager():
    db = SessionLocal()
    client = TestClient(app)
    uid = uuid.uuid4().hex[:8]
    try:
        owner, org = _user_with_org(db, f"own2_{uid}@example.com", f"Org Own {uid}")
        plain = User(email=f"mem2_{uid}@example.com", password_hash=hash_password("Password123!"), status="approved")
        db.add(plain)
        db.flush()
        db.add(OrganizationMember(organization_id=org.id, user_id=plain.id, role="member"))
        db.commit()
        tok = create_session_token(plain.id, org_id=org.id)
        page = client.get("/dashboard/audit-logs", cookies={"wh_session": tok})
        assert page.status_code == 403
        # Settings link hidden for plain members
        dash = client.get("/dashboard", cookies={"wh_session": tok})
        assert "/dashboard/audit-logs" not in dash.text
    finally:
        db.close()


def test_event_table_fragment_scoped_by_event_id():
    from app.models import Delivery, Event

    db = SessionLocal()
    client = TestClient(app)
    uid = uuid.uuid4().hex[:8]
    try:
        owner, org = _user_with_org(db, f"ev_{uid}@example.com", f"Org Ev {uid}")
        proj = db.query(Project).filter(Project.organization_id == org.id).first()
        e1 = Event(
            id=f"evt_{uid}a",
            project_id=proj.id,
            event_type="t.a",
            payload_json="{}",
            wire_payload="{}",
            request_hash="h1",
        )
        e2 = Event(
            id=f"evt_{uid}b",
            project_id=proj.id,
            event_type="t.b",
            payload_json="{}",
            wire_payload="{}",
            request_hash="h2",
        )
        db.add_all([e1, e2])
        db.flush()
        db.add(Delivery(event_id=e1.id, target_url_snapshot="https://x.example/1", status="PENDING", attempt_count=0))
        db.add(Delivery(event_id=e2.id, target_url_snapshot="https://x.example/2", status="PENDING", attempt_count=0))
        db.commit()
        tok = create_session_token(owner.id, org_id=org.id)
        r = client.get(f"/dashboard/deliveries/table?event_id={e1.id}", cookies={"wh_session": tok})
        assert r.status_code == 200
        assert "x.example/1" in r.text
        assert "x.example/2" not in r.text
        detail = client.get(f"/dashboard/events/{e1.id}", cookies={"wh_session": tok})
        assert detail.status_code == 200
        assert "event-deliveries-live" in detail.text
        assert "every 3s" in detail.text
    finally:
        db.close()
