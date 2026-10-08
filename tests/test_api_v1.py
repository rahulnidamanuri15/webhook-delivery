import pytest
from fastapi.testclient import TestClient

from app.db.session import SessionLocal
from app.main import app
from app.models import ApiKey, Endpoint, EndpointSubscription, Organization, Project
from app.services.security import encrypt_secret, generate_api_key, generate_signing_secret

client = TestClient(app)


@pytest.fixture(scope="module")
def api_test_data():
    db = SessionLocal()
    # Create org & project
    org = Organization(name="API Test Org")
    db.add(org)
    db.flush()

    project = Project(organization_id=org.id, name="API Test Project")
    db.add(project)
    db.flush()

    # Generate API key
    full_key, key_prefix, key_hash = generate_api_key()
    api_key_obj = ApiKey(project_id=project.id, name="Ingestion Key", key_prefix=key_prefix, key_hash=key_hash)
    db.add(api_key_obj)
    db.flush()

    # Endpoint subscribed to payment events
    endpoint = Endpoint(
        project_id=project.id,
        url="http://127.0.0.1:8001/webhook",
        encrypted_signing_secret=encrypt_secret(generate_signing_secret()),
        enabled=True,
    )
    db.add(endpoint)
    db.flush()

    sub = EndpointSubscription(endpoint_id=endpoint.id, event_type="payment.succeeded")
    db.add(sub)
    db.commit()

    yield {"api_key": full_key, "project_id": project.id, "endpoint_id": endpoint.id}
    db.close()


def test_healthcheck():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_unauthorized_event_publish():
    resp = client.post("/api/v1/events", json={"type": "payment.succeeded", "data": {"amount": 100}})
    assert resp.status_code == 401


def test_publish_event_and_inspect(api_test_data):
    headers = {"Authorization": f"Bearer {api_test_data['api_key']}", "Idempotency-Key": "api-test-key-501"}
    payload = {"type": "payment.succeeded", "data": {"payment_id": "pay_501", "amount_minor": 19900, "currency": "INR"}}

    # 1. Publish event
    resp = client.post("/api/v1/events", json=payload, headers=headers)
    assert resp.status_code == 202
    res_data = resp.json()
    assert res_data["status"] == "accepted"
    event_id = res_data["event_id"]
    assert res_data["delivery_count"] == 1

    # 2. Get event details
    event_resp = client.get(f"/api/v1/events/{event_id}", headers=headers)
    assert event_resp.status_code == 200
    event_detail = event_resp.json()
    assert event_detail["id"] == event_id
    assert event_detail["payload"]["payment_id"] == "pay_501"
    assert len(event_detail["deliveries"]) == 1

    delivery_id = event_detail["deliveries"][0]["id"]

    # 3. Get delivery details
    dlv_resp = client.get(f"/api/v1/deliveries/{delivery_id}", headers=headers)
    assert dlv_resp.status_code == 200
    dlv_detail = dlv_resp.json()
    assert dlv_detail["id"] == delivery_id
    assert dlv_detail["event_id"] == event_id


def test_idempotency_conflict_via_api(api_test_data):
    headers = {"Authorization": f"Bearer {api_test_data['api_key']}", "Idempotency-Key": "conflict-test-key-777"}

    # First request
    resp1 = client.post("/api/v1/events", json={"type": "payment.succeeded", "data": {"id": 1}}, headers=headers)
    assert resp1.status_code == 202

    # Second request with SAME key but DIFFERENT body -> 409 Conflict
    resp2 = client.post("/api/v1/events", json={"type": "payment.succeeded", "data": {"id": 999}}, headers=headers)
    assert resp2.status_code == 409
    assert "Idempotency key" in resp2.json()["detail"]
