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
        details={"name": "Test Key"}
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

    secret_v2 = generate_signing_secret()
    assert secret_v2 != secret_v1

    encrypted_v2 = encrypt_secret(secret_v2)
    assert decrypt_secret(encrypted_v2) == secret_v2
