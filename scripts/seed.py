"""Database seeding script for local development and demonstration."""
import os
import sys

# Add root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.session import Base, SessionLocal, engine
from app.models import (
    ApiKey,
    Endpoint,
    EndpointSubscription,
    Organization,
    OrganizationMember,
    Project,
    User,
)
from app.services.event_service import ingest_event
from app.services.security import encrypt_secret, hash_api_key, hash_password


def seed():
    print("Creating database tables if not existing...")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        # Check if user already exists
        existing_user = db.query(User).filter(User.email == "demo@example.com").first()
        if existing_user:
            print("Database already seeded with demo user demo@example.com.")
            return

        print("Seeding demo user, organization, project, endpoint, and events...")

        # 1. User
        user = User(
            email="demo@example.com",
            password_hash=hash_password("Password123!")
        )
        db.add(user)
        db.flush()

        # 2. Organization & Membership
        org = Organization(name="Acme Payments Org")
        db.add(org)
        db.flush()

        member = OrganizationMember(
            organization_id=org.id,
            user_id=user.id,
            role="owner"
        )
        db.add(member)

        # 3. Project
        project = Project(
            organization_id=org.id,
            name="Production Storefront"
        )
        db.add(project)
        db.flush()

        # 4. API Key
        raw_key = "wh_live_demo1234567890abcdef123456"
        key_prefix = raw_key[:16]
        key_hash = hash_api_key(raw_key)
        api_key = ApiKey(
            project_id=project.id,
            name="Main Server Key",
            key_prefix=key_prefix,
            key_hash=key_hash
        )
        db.add(api_key)

        # 5. Endpoint (pointing to controllable demo receiver)
        signing_secret = "whsec_demosecret1234567890abcdef"
        encrypted_secret = encrypt_secret(signing_secret)
        receiver_url = "http://demo_receiver:8001/webhook" if "postgres" in os.getenv("DATABASE_URL", "") else "http://127.0.0.1:8001/webhook"
        endpoint = Endpoint(
            project_id=project.id,
            url=receiver_url,
            description="Controllable Local Demo Receiver",
            encrypted_signing_secret=encrypted_secret,
            enabled=True,
            rate_limit_per_second=10
        )
        db.add(endpoint)
        db.flush()

        sub1 = EndpointSubscription(endpoint_id=endpoint.id, event_type="*")
        db.add(sub1)
        db.commit()

        # 6. Seed a sample event
        sample_payload = {
            "payment_id": "pay_live_99214",
            "order_id": "order_381",
            "amount_minor": 149900,
            "currency": "INR",
            "status": "succeeded"
        }
        event, _, _ = ingest_event(
            db=db,
            project_id=project.id,
            event_type="payment.succeeded",
            payload_data=sample_payload,
            idempotency_key="seed-payment-init-001"
        )

        print("Seeding completed successfully!")
        print("\n--- DEMO CREDENTIALS ---")
        print("Login URL:     http://127.0.0.1:8080/auth/login")
        print("Email:         demo@example.com")
        print("Password:      Password123!")
        print("API Key:       " + raw_key)
        print("Endpoint URL:  http://127.0.0.1:8001/webhook")
        print("Secret:        " + signing_secret)
        print("------------------------\n")

    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    seed()
