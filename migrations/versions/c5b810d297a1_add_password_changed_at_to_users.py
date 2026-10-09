"""Add password_changed_at to users table

Revision ID: c5b810d297a1
Revises: b3f1c9e2a4d8
Create Date: 2026-10-09

Tracks password changes to invalidate pre-existing session tokens.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c5b810d297a1'
down_revision: Union[str, Sequence[str], None] = 'b3f1c9e2a4d8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('users', sa.Column('password_changed_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('users', 'password_changed_at')
