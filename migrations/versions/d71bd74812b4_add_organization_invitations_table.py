"""Add organization invitations table

Revision ID: d71bd74812b4
Revises: a6e091b054d7
Create Date: 2026-10-05 22:03:01.054055

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd71bd74812b4'
down_revision: Union[str, Sequence[str], None] = 'a6e091b054d7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('organization_invitations',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('organization_id', sa.String(length=32), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('role', sa.String(length=32), nullable=False),
    sa.Column('token', sa.String(length=64), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('invited_by_user_id', sa.String(length=32), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['invited_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token')
    )
    op.create_index(op.f('ix_organization_invitations_email'), 'organization_invitations', ['email'], unique=False)
    op.create_index(op.f('ix_organization_invitations_organization_id'), 'organization_invitations', ['organization_id'], unique=False)
    op.create_index(op.f('ix_organization_invitations_token'), 'organization_invitations', ['token'], unique=True)
    op.create_index('ix_invitations_org_status', 'organization_invitations', ['organization_id', 'status'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_invitations_org_status', table_name='organization_invitations')
    op.drop_index(op.f('ix_organization_invitations_token'), table_name='organization_invitations')
    op.drop_index(op.f('ix_organization_invitations_organization_id'), table_name='organization_invitations')
    op.drop_index(op.f('ix_organization_invitations_email'), table_name='organization_invitations')
    op.drop_table('organization_invitations')
