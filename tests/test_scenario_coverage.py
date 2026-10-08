import concurrent.futures
import uuid
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db.session import SessionLocal
from app.main import app
from app.models import (
    ApiKey,
    Delivery,
    Endpoint,
    EndpointSubscription,
    Event,
    Organization,
    OrganizationMember,
    Project,
    User,
)
from app.services.delivery_service import execute_delivery
from app.services.event_service import ingest_event
from app.services.security import (
    create_session_token,
    encrypt_secret,
    generate_api_key,
    generate_signing_secret,
    get_csrf_token_for_request,
    hash_password,
)


def _mock_stream_response(status_code: int = 200, text: str = "", headers: dict | None = None):
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = headers or {}
    body = (text or "").encode("utf-8")
    mock_resp.iter_bytes.return_value = (
        [body[i : i + 4096] for i in range(0, max(1, len(body)), 4096)] if body else [b""]
    )
    mock_resp.close.return_value = None
    mock_stream_ctx = MagicMock()
    mock_stream_ctx.__enter__.return_value = mock_resp
    mock_stream_ctx.__exit__.return_value = False
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = False
    mock_client.stream.return_value = mock_stream_ctx
    return patch("httpx.Client", return_value=mock_client)


client = TestClient(app)


@pytest.fixture
def test_setup():
    db = SessionLocal()
    uid = uuid.uuid4().hex[:8]

    # Create Organization A & Project A & User A
    org_a = Organization(name=f"Org Alpha {uid}")
    db.add(org_a)
    db.flush()

    user_a = User(email=f"alice_{uid}@alpha.com", password_hash=hash_password("password123"))
    db.add(user_a)
    db.flush()

    db.add(OrganizationMember(organization_id=org_a.id, user_id=user_a.id, role="owner"))

    proj_a = Project(organization_id=org_a.id, name=f"Project Alpha {uid}")
    db.add(proj_a)
    db.flush()

    full_key_a, prefix_a, hash_a = generate_api_key()
    api_key_a = ApiKey(project_id=proj_a.id, name="Key A", key_prefix=prefix_a, key_hash=hash_a)
    db.add(api_key_a)

    ep_a = Endpoint(
        project_id=proj_a.id,
        url=f"http://127.0.0.1:8001/webhook-a-{uid}",
        encrypted_signing_secret=encrypt_secret(generate_signing_secret()),
        enabled=True,
    )
    db.add(ep_a)
    db.flush()
    db.add(EndpointSubscription(endpoint_id=ep_a.id, event_type="*"))

    # Create Organization B & Project B & User B
    org_b = Organization(name=f"Org Beta {uid}")
    db.add(org_b)
    db.flush()

    user_b = User(email=f"bob_{uid}@beta.com", password_hash=hash_password("password123"))
    db.add(user_b)
    db.flush()

    db.add(OrganizationMember(organization_id=org_b.id, user_id=user_b.id, role="owner"))

    proj_b = Project(organization_id=org_b.id, name=f"Project Beta {uid}")
    db.add(proj_b)
    db.flush()

    full_key_b, prefix_b, hash_b = generate_api_key()
    api_key_b = ApiKey(project_id=proj_b.id, name="Key B", key_prefix=prefix_b, key_hash=hash_b)
    db.add(api_key_b)

    db.commit()

    session_token_a = create_session_token(user_a.id, org_id=org_a.id)
    session_token_b = create_session_token(user_b.id, org_id=org_b.id)

    data = {
        "user_a_id": user_a.id,
        "org_a_id": org_a.id,
        "proj_a_id": proj_a.id,
        "key_a": full_key_a,
        "session_a": session_token_a,
        "endpoint_a_id": ep_a.id,
        "user_b_id": user_b.id,
        "org_b_id": org_b.id,
        "proj_b_id": proj_b.id,
        "key_b": full_key_b,
        "session_b": session_token_b,
    }
    yield data
    db.close()


def test_cross_tenant_isolation_on_replay_and_api(test_setup):
    db = SessionLocal()
    try:
        # Create an event and dead delivery in Project Alpha
        event_a, is_dup, count = ingest_event(db, test_setup["proj_a_id"], "payment.succeeded", {"invoice": "inv_001"})
        assert count >= 1
        dlv_a = event_a.deliveries[0]
        dlv_a.status = "DEAD"
        db.commit()
        delivery_id = dlv_a.id

        # 1. API: User B tries to read Alpha's event and delivery -> 404
        headers_b = {"Authorization": f"Bearer {test_setup['key_b']}"}
        resp = client.get(f"/api/v1/events/{event_a.id}", headers=headers_b)
        assert resp.status_code == 404

        resp = client.get(f"/api/v1/events/{event_a.id}/deliveries", headers=headers_b)
        assert resp.status_code == 404

        # 2. Dashboard: User B tries to replay Project Alpha's delivery
        bob_client = TestClient(app)
        bob_client.cookies.set("wh_session", test_setup["session_b"])
        bob_client.cookies.set("wh_active_project_id", test_setup["proj_b_id"])

        mock_req = MagicMock()
        mock_req.cookies = {"wh_session": test_setup["session_b"]}
        bob_csrf, _ = get_csrf_token_for_request(mock_req)

        replay_resp = bob_client.post(
            f"/dashboard/deliveries/{delivery_id}/replay",
            data={"csrf_token": bob_csrf},
            follow_redirects=False,
        )
        # Cross-tenant replay is denied (redirects with error or returns 404)
        if replay_resp.status_code == 303:
            loc = replay_resp.headers.get("location", "")
            assert "error" in loc or "not+found" in loc
        else:
            assert replay_resp.status_code in (403, 404)

        # Confirm in DB that no replayed delivery exists for Project Beta
        beta_deliveries = db.query(Delivery).filter(Delivery.replay_of_delivery_id == delivery_id).all()
        assert len(beta_deliveries) == 0

    finally:
        db.close()


def test_concurrent_ingestion_race_condition(test_setup):
    """Verifies that simultaneous ingestion requests with identical (project_id, idempotency_key)
    are handled safely without unhandled crashes or duplicate records."""
    db = SessionLocal()
    proj_id = test_setup["proj_a_id"]
    idempotency_key = f"race-key-{uuid.uuid4().hex}"
    payload = {"account": "acc_777", "amount": 500}

    results = []

    def run_ingest():
        local_db = SessionLocal()
        try:
            evt, is_dup, count = ingest_event(
                local_db,
                project_id=proj_id,
                event_type="test.race",
                payload_data=payload,
                idempotency_key=idempotency_key,
            )
            return (evt.id, is_dup, None)
        except Exception as e:
            return (None, False, e)
        finally:
            local_db.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(run_ingest) for _ in range(4)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    # Verify no unhandled exceptions occurred
    for evt_id, is_dup, exc in results:
        assert exc is None, f"Concurrent ingestion raised exception: {exc}"

    # Verify only 1 primary ingestion (is_dup=False) and the rest are deduplicated (is_dup=True)
    first_seen = [r for r in results if r[1] is False]
    duplicates = [r for r in results if r[1] is True]
    assert len(first_seen) == 1
    assert len(duplicates) == 3

    # Verify database has exactly 1 event record
    matching_events = (
        db.query(Event).filter(Event.project_id == proj_id, Event.idempotency_key == idempotency_key).all()
    )
    assert len(matching_events) == 1
    db.close()


def test_bounded_response_excerpt_truncation(test_setup):
    """Verifies that large receiver response bodies are bounded to RESPONSE_EXCERPT_MAX_BYTES."""
    db = SessionLocal()
    try:
        event, is_dup, count = ingest_event(db, test_setup["proj_a_id"], "test.large_response", {"test": True})
        delivery = event.deliveries[0]

        # Generate a 50,000 character response body
        huge_text = "X" * 50000

        with _mock_stream_response(200, huge_text):
            success = execute_delivery(db, delivery.id)
            assert success is True

        db.refresh(delivery)
        attempt = delivery.attempts[0]
        assert attempt.response_excerpt is not None
        # Must be capped at settings.RESPONSE_EXCERPT_MAX_BYTES
        assert len(attempt.response_excerpt) <= settings.RESPONSE_EXCERPT_MAX_BYTES
        assert "... [truncated]" in attempt.response_excerpt

    finally:
        db.close()


def test_csrf_protection_enforcement(test_setup):
    """Verifies that state-changing dashboard forms reject requests without valid CSRF tokens."""
    auth_client = TestClient(app)
    auth_client.cookies.set("wh_session", test_setup["session_a"])

    # 1. State-changing POST without CSRF token -> 403 Forbidden
    resp_no_csrf = auth_client.post(
        "/dashboard/projects",
        data={"name": "Forbidden Project"},
    )
    assert resp_no_csrf.status_code == 403
    assert "CSRF" in resp_no_csrf.json().get("detail", "")

    # 2. State-changing POST with invalid CSRF token -> 403 Forbidden
    resp_invalid_csrf = auth_client.post(
        "/dashboard/projects",
        data={"name": "Forbidden Project", "csrf_token": "tampered-token-12345"},
    )
    assert resp_invalid_csrf.status_code == 403

    # 3. State-changing POST with valid CSRF token -> 303 Redirect Success
    mock_req = MagicMock()
    mock_req.cookies = {"wh_session": test_setup["session_a"]}
    valid_csrf, _ = get_csrf_token_for_request(mock_req)

    resp_valid = auth_client.post(
        "/dashboard/projects",
        data={"name": f"Authorized Project {uuid.uuid4().hex[:6]}", "csrf_token": valid_csrf},
        follow_redirects=False,
    )
    assert resp_valid.status_code == 303


def test_payload_size_limit_enforcement(test_setup):
    """Verifies that public API rejects event payloads exceeding 1MB (HTTP 413)."""
    headers = {
        "Authorization": f"Bearer {test_setup['key_a']}",
        "Content-Type": "application/json",
    }
    # Create payload exceeding 1MB
    large_payload = {
        "type": "large.blob",
        "data": {"junk": "A" * (settings.MAX_PAYLOAD_SIZE_BYTES + 1024)},
    }
    resp = client.post("/api/v1/events", json=large_payload, headers=headers)
    assert resp.status_code == 413
    assert "Payload exceeds maximum allowed size" in resp.json().get("detail", "")


def test_dedicated_disable_endpoint_route(test_setup):
    """Verifies POST /dashboard/endpoints/{id}/disable explicitly disables an endpoint."""
    db = SessionLocal()
    ep_id = test_setup["endpoint_a_id"]
    try:
        ep = db.query(Endpoint).filter(Endpoint.id == ep_id).first()
        ep.enabled = True
        db.commit()

        auth_client = TestClient(app)
        auth_client.cookies.set("wh_session", test_setup["session_a"])

        mock_req = MagicMock()
        mock_req.cookies = {"wh_session": test_setup["session_a"]}
        valid_csrf, _ = get_csrf_token_for_request(mock_req)

        resp = auth_client.post(
            f"/dashboard/endpoints/{ep_id}/disable",
            data={"csrf_token": valid_csrf},
            follow_redirects=False,
        )
        assert resp.status_code == 303

        db.refresh(ep)
        assert ep.enabled is False

        # Calling disable again maintains disabled state
        resp2 = auth_client.post(
            f"/dashboard/endpoints/{ep_id}/disable",
            data={"csrf_token": valid_csrf},
            follow_redirects=False,
        )
        assert resp2.status_code == 303
        db.refresh(ep)
        assert ep.enabled is False
    finally:
        db.close()


def test_max_endpoints_per_project_limit(test_setup):
    """Verifies that creating more than MAX_ENDPOINTS_PER_PROJECT endpoints is rejected."""
    db = SessionLocal()
    try:
        proj_id = test_setup["proj_b_id"]
        current_count = db.query(Endpoint).filter(Endpoint.project_id == proj_id).count()
        original_limit = settings.MAX_ENDPOINTS_PER_PROJECT
        settings.MAX_ENDPOINTS_PER_PROJECT = current_count + 1

        auth_client = TestClient(app)
        auth_client.cookies.set("wh_session", test_setup["session_b"])
        auth_client.cookies.set("wh_active_project_id", proj_id)

        mock_req = MagicMock()
        mock_req.cookies = {"wh_session": test_setup["session_b"]}
        valid_csrf, _ = get_csrf_token_for_request(mock_req)

        uid = uuid.uuid4().hex[:6]
        # 1st creation succeeds (reaches limit)
        resp1 = auth_client.post(
            "/dashboard/endpoints",
            data={
                "url": f"http://127.0.0.1:8001/wh-limit-1-{uid}",
                "event_types": "*",
                "rate_limit_per_second": 10,
                "csrf_token": valid_csrf,
            },
            follow_redirects=False,
        )
        assert resp1.status_code == 303

        # 2nd creation exceeds limit -> returns 400 with message
        resp2 = auth_client.post(
            "/dashboard/endpoints",
            data={
                "url": f"http://127.0.0.1:8001/wh-limit-2-{uid}",
                "event_types": "*",
                "rate_limit_per_second": 10,
                "csrf_token": valid_csrf,
            },
            follow_redirects=False,
        )
        assert resp2.status_code == 400
        assert "limit reached" in resp2.text.lower()

        # Restore setting
        settings.MAX_ENDPOINTS_PER_PROJECT = original_limit
    finally:
        db.close()
