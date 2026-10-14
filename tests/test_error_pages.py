"""Error pages: dashboard routes render branded HTML, API routes keep JSON."""

import uuid
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from app.db.session import SessionLocal
from app.main import app
from app.models import Organization, OrganizationMember, Project, User
from app.services.security import create_session_token, get_csrf_token_for_request, hash_password


def _member_client(role: str = "member"):
    db = SessionLocal()
    uid = uuid.uuid4().hex[:8]
    u = User(email=f"err_{uid}@example.com", password_hash=hash_password("Password123!"), status="approved")
    db.add(u)
    db.flush()
    o = Organization(name=f"Err Org {uid}")
    db.add(o)
    db.flush()
    db.add(OrganizationMember(organization_id=o.id, user_id=u.id, role=role))
    p = Project(organization_id=o.id, name="P")
    db.add(p)
    db.commit()
    proj_id = p.id
    tok = create_session_token(u.id, org_id=o.id)
    mock_req = MagicMock()
    mock_req.cookies = {"wh_session": tok}
    csrf, _ = get_csrf_token_for_request(mock_req)
    db.close()
    return TestClient(app, raise_server_exceptions=False), tok, csrf, proj_id


def test_dashboard_forbidden_renders_page_not_json():
    client, tok, csrf, _proj = _member_client()
    r = client.post("/dashboard/api-keys", data={"name": "x", "csrf_token": csrf}, cookies={"wh_session": tok})
    assert r.status_code == 403
    assert "text/html" in r.headers["content-type"]
    assert not r.text.lstrip().startswith("{")
    assert "Back to dashboard" in r.text


def test_api_errors_stay_json():
    client = TestClient(app, raise_server_exceptions=False)
    r = client.post("/api/v1/events", content=b"{}", headers={"Content-Type": "application/json"})
    assert r.status_code == 401
    assert "application/json" in r.headers["content-type"]


def test_api_key_create_redirect_shows_once():
    from app.models import ApiKey as _ApiKey

    client, tok, csrf, proj_id = _member_client(role="owner")
    r = client.post(
        "/dashboard/api-keys",
        data={"name": "prod", "csrf_token": csrf},
        cookies={"wh_session": tok},
        follow_redirects=False,
    )
    assert r.status_code == 303
    loc = r.headers["location"]
    assert "new_key=" in loc
    first = client.get(loc, cookies={"wh_session": tok})
    assert first.status_code == 200
    assert "Save Your Secret API Key" in first.text
    # Reloading the landing URL must not re-show the key nor mint another.
    db = SessionLocal()
    try:
        second = client.get(loc, cookies={"wh_session": tok})
        assert "Save Your Secret API Key" not in second.text
        assert db.query(_ApiKey).filter(_ApiKey.project_id == proj_id, _ApiKey.name == "prod").count() == 1
    finally:
        db.close()
