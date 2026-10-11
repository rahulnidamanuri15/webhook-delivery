"""Add active-replay guard + lease recovery index

Revision ID: f5a1c9d3e7b2
Revises: e4f2a1c9d3b5
Create Date: 2026-10-11

- Partial unique index prevents concurrent replay duplicates: only one
  non-terminal replay per source delivery.
- Composite (status, lease_expires_at) index speeds crash-recovery scan
  (IN_FLIGHT + lease_expires <= now ORDER BY lease_expires).
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f5a1c9d3e7b2'
down_revision: Union[str, Sequence[str], None] = 'e4f2a1c9d3b5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Partial unique: one active (non-terminal) replay per source delivery.
    # Terminal replays (DEAD/SUCCEEDED) may accumulate for audit.
    op.execute(
        sa.text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_active_replay_per_delivery "
            "ON deliveries (replay_of_delivery_id) "
            "WHERE replay_of_delivery_id IS NOT NULL AND status NOT IN ('DEAD', 'SUCCEEDED')"
        )
    )
    op.execute(
        sa.text(
            "CREATE INDEX IF NOT EXISTS ix_deliveries_status_lease_expires "
            "ON deliveries (status, lease_expires_at)"
        )
    )


def downgrade() -> None:
    op.execute(sa.text("DROP INDEX IF EXISTS uq_active_replay_per_delivery"))
    op.execute(sa.text("DROP INDEX IF EXISTS ix_deliveries_status_lease_expires"))
