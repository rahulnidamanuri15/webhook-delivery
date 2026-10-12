"""Add user approval queue (status + superadmin)

Revision ID: b8c3f1a2d4e6
Revises: f5a1c9d3e7b2
Create Date: 2026-10-12

- users.status: 'approved' (legacy default), 'pending', 'rejected'.
- users.is_superadmin: superadmin dashboard gate for approve/reject.
- Backfill: existing users -> approved; earliest user -> superadmin.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b8c3f1a2d4e6'
down_revision: Union[str, Sequence[str], None] = 'f5a1c9d3e7b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('status', sa.String(16), nullable=False, server_default='approved'))
    op.add_column('users', sa.Column('is_superadmin', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.execute(sa.text("CREATE INDEX IF NOT EXISTS ix_users_status ON users (status)"))
    # Earliest registered user becomes superadmin (first owner holds approval rights).
    op.execute(
        sa.text(
            "UPDATE users SET is_superadmin = TRUE WHERE id = "
            "(SELECT id FROM users ORDER BY created_at ASC LIMIT 1)"
        )
    )


def downgrade() -> None:
    op.execute(sa.text("DROP INDEX IF EXISTS ix_users_status"))
    op.drop_column('users', 'is_superadmin')
    op.drop_column('users', 'status')
