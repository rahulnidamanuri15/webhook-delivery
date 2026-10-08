import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models import Organization, OrganizationMember, User
from app.models.invitation import OrganizationInvitation


@pytest.fixture
def team_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()

    org = Organization(name="Acme Team Org")
    session.add(org)
    session.flush()

    owner = User(email="owner@example.com", password_hash="dummyhash")
    session.add(owner)
    session.flush()

    owner_mem = OrganizationMember(organization_id=org.id, user_id=owner.id, role="owner")
    session.add(owner_mem)
    session.commit()

    yield session, org, owner
    session.close()


def test_invitation_creation_and_acceptance(team_db):
    session, org, owner = team_db

    # 1. Create invitation
    inv = OrganizationInvitation(
        organization_id=org.id, email="newuser@example.com", role="admin", invited_by_user_id=owner.id
    )
    session.add(inv)
    session.commit()

    assert inv.id.startswith("inv_")
    assert inv.is_valid is True
    assert inv.status == "PENDING"
    assert len(inv.token) > 20

    # 2. Accept invitation
    new_user = User(email="newuser@example.com", password_hash="hash123")
    session.add(new_user)
    session.flush()

    new_mem = OrganizationMember(organization_id=inv.organization_id, user_id=new_user.id, role=inv.role)
    session.add(new_mem)
    inv.status = "ACCEPTED"
    session.commit()

    # Verify membership
    mem = (
        session.query(OrganizationMember)
        .filter(OrganizationMember.organization_id == org.id, OrganizationMember.user_id == new_user.id)
        .first()
    )
    assert mem is not None
    assert mem.role == "admin"
    assert inv.is_valid is False  # No longer pending


def test_invitation_revocation(team_db):
    session, org, owner = team_db

    inv = OrganizationInvitation(
        organization_id=org.id, email="revokeme@example.com", role="member", invited_by_user_id=owner.id
    )
    session.add(inv)
    session.commit()

    inv.status = "REVOKED"
    session.commit()

    assert inv.is_valid is False
