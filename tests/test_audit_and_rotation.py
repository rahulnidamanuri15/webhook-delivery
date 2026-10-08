from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models import Organization, User
from app.models.audit_log import AuditLog
from app.services.audit import log_audit_event
from app.services.security import decrypt_secret, encrypt_secret, generate_signing_secret


def test_audit_log_creation():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()

    org = Organization(name="Audit Test Org")
    session.add(org)
    session.flush()

    user = User(email="auditor@example.com", password_hash="dummy")
    session.add(user)
    session.flush()

    log_entry = log_audit_event(
        db=session,
        organization_id=org.id,
        user_id=user.id,
        action="api_key.create",
        resource_type="api_key",
        resource_id="key_12345",
        ip_address="192.0.2.1",
        details={"name": "Test Key"},
    )

    assert log_entry.id.startswith("aud_")
    assert log_entry.action == "api_key.create"
    assert "Test Key" in log_entry.details_json

    # Query from DB
    retrieved = session.query(AuditLog).filter(AuditLog.id == log_entry.id).first()
    assert retrieved is not None
    assert retrieved.user_id == user.id


def test_endpoint_secret_rotation():
    secret_v1 = generate_signing_secret()
    encrypted_v1 = encrypt_secret(secret_v1)
    assert decrypt_secret(encrypted_v1) == secret_v1

    secret_v2 = generate_signing_secret()
    assert secret_v2 != secret_v1

    encrypted_v2 = encrypt_secret(secret_v2)
    assert decrypt_secret(encrypted_v2) == secret_v2


def test_multi_fernet_fallback_and_rotation(monkeypatch):
    from cryptography.fernet import Fernet
    from app.config import settings
    from app.services.security import (
        SecretDecryptionError,
        decrypt_secret,
        encrypt_secret,
        rotate_secret_ciphertext,
    )
    import pytest

    key_primary = Fernet.generate_key().decode()
    key_old = Fernet.generate_key().decode()
    key_unrelated = Fernet.generate_key().decode()

    # Encrypt secret with old key
    f_old = Fernet(key_old.encode())
    raw_secret = "whsec_test_fallback_12345678"
    token_old = f_old.encrypt(raw_secret.encode()).decode()

    # Configure primary and fallback keys
    monkeypatch.setattr(settings, "SIGNING_SECRET_ENCRYPTION_KEY", key_primary)
    monkeypatch.setattr(settings, "SIGNING_SECRET_ENCRYPTION_KEYS_FALLBACK", key_old)

    # Decrypt should succeed via fallback
    decrypted = decrypt_secret(token_old)
    assert decrypted == raw_secret

    # Encrypt should use primary key
    f_primary = Fernet(key_primary.encode())
    new_token = encrypt_secret(raw_secret)
    assert f_primary.decrypt(new_token.encode()).decode() == raw_secret

    # Rotate ciphertext from old key to primary key
    rotated_ct, was_rotated = rotate_secret_ciphertext(token_old)
    assert was_rotated is True
    assert f_primary.decrypt(rotated_ct.encode()).decode() == raw_secret

    # Running rotate again should be a no-op
    rotated_again, was_rotated_2 = rotate_secret_ciphertext(rotated_ct)
    assert was_rotated_2 is False

    # Unrelated key should raise SecretDecryptionError with informative message
    f_unrelated = Fernet(key_unrelated.encode())
    token_unrelated = f_unrelated.encrypt(b"secret_from_other_key").decode()
    with pytest.raises(SecretDecryptionError) as exc_info:
        decrypt_secret(token_unrelated)
    assert "Failed to decrypt signing secret" in str(exc_info.value)
    assert "key mismatch" in str(exc_info.value)


def test_delivery_secret_decryption_failure_records_descriptive_error():
    from app.models import Delivery, Endpoint, EndpointSubscription, Organization, Project
    from app.services.delivery_service import execute_delivery
    from app.services.event_service import ingest_event

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()

    org = Organization(name="Decryption Error Org")
    session.add(org)
    session.flush()

    project = Project(organization_id=org.id, name="Decryption Error Project")
    session.add(project)
    session.flush()

    # Endpoint with invalid/corrupt encrypted secret
    endpoint = Endpoint(
        project_id=project.id,
        url="http://127.0.0.1:8001/webhook",
        encrypted_signing_secret="gAAAAABcorrupt_ciphertext_cannot_be_decrypted",
        enabled=True,
    )
    session.add(endpoint)
    session.flush()

    sub = EndpointSubscription(endpoint_id=endpoint.id, event_type="*")
    session.add(sub)
    session.commit()

    event, _, _ = ingest_event(session, project.id, "payment.failed", {"id": 1})
    delivery = session.query(Delivery).filter(Delivery.event_id == event.id).first()

    success = execute_delivery(session, delivery.id)
    assert success is False

    session.refresh(delivery)
    assert delivery.status == "DEAD"
    assert len(delivery.attempts) == 1
    attempt = delivery.attempts[0]
    assert attempt.outcome == "PERMANENT_ERROR"
    assert attempt.error_code == "SSRF_OR_CONFIG_ERROR"
    assert "Secret decryption error:" in attempt.response_excerpt
    assert "Failed to decrypt signing secret" in attempt.response_excerpt
    assert len(attempt.response_excerpt.strip()) > 30


def test_endpoint_detail_view_handles_corrupt_secret_without_crash():
    import uuid
    from fastapi.testclient import TestClient
    from app.main import app
    from app.models import Endpoint, Organization, OrganizationMember, Project, User
    from app.services.security import create_session_token, hash_password
    from app.db.session import SessionLocal

    db = SessionLocal()
    uid = uuid.uuid4().hex[:8]
    org = Organization(name=f"UI Secret Test Org {uid}")
    db.add(org)
    db.flush()

    user = User(email=f"mgr_{uid}@secret-test.com", password_hash=hash_password("pw123"))
    db.add(user)
    db.flush()
    db.add(OrganizationMember(organization_id=org.id, user_id=user.id, role="owner"))

    project = Project(organization_id=org.id, name=f"UI Secret Test Project {uid}")
    db.add(project)
    db.flush()

    # Endpoint with invalid/corrupt secret
    endpoint = Endpoint(
        project_id=project.id,
        url="http://127.0.0.1:8001/webhook-bad-secret",
        encrypted_signing_secret="gAAAAABbad_secret_token_here",
        enabled=True,
    )
    db.add(endpoint)
    db.commit()

    token = create_session_token(user_id=user.id, org_id=org.id, project_id=project.id)
    client = TestClient(app)
    client.cookies.set("wh_session", token)

    # Must return 200 OK without crashing with 500
    resp = client.get(f"/dashboard/endpoints/{endpoint.id}")
    assert resp.status_code == 200
    html = resp.text
    assert "Signing Secret Decryption Error" in html
    assert "Regenerate / Rotate Secret Now" in html

    # Now simulate clicking rotate secret with valid CSRF token
    from app.services.security import generate_csrf_token

    csrf_token = generate_csrf_token(token)
    rotate_resp = client.post(
        f"/dashboard/endpoints/{endpoint.id}/rotate-secret",
        data={"csrf_token": csrf_token},
        follow_redirects=True,
    )
    assert rotate_resp.status_code == 200

    # Refresh DB and verify secret is now decryptable!
    db.refresh(endpoint)
    assert decrypt_secret(endpoint.encrypted_signing_secret).startswith("whsec_")
    db.close()
