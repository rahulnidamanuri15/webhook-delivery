"""Preserve delivery history on endpoint delete

Revision ID: e4f2a1c9d3b5
Revises: c5b810d297a1
Create Date: 2026-10-10

Endpoint deletion must not hard-delete delivery history (audit requirement,
documented in delete_endpoint_post). Change deliveries.endpoint_id FK to
ON DELETE SET NULL + nullable, matching the ORM relationship change
(Endpoint.deliveries no longer cascades).
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e4f2a1c9d3b5'
down_revision: Union[str, Sequence[str], None] = 'c5b810d297a1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Drop CASCADE FK, allow NULL, re-create with SET NULL.
    op.drop_constraint('deliveries_endpoint_id_fkey', 'deliveries', type_='foreignkey')
    op.alter_column('deliveries', 'endpoint_id', existing_type=sa.String(length=32), nullable=True)
    op.create_foreign_key(
        'deliveries_endpoint_id_fkey',
        'deliveries',
        'endpoints',
        ['endpoint_id'],
        ['id'],
        ondelete='SET NULL',
    )


def downgrade() -> None:
    """Downgrade schema."""
    # Restore CASCADE + NOT NULL. Refuses to run while preserved history
    # (NULL endpoint_id rows kept by the upgrade) exists: those deliveries
    # are precisely the audit history saved from endpoint deletion, and
    # their attempt records cascade-delete with them. Silently deleting them
    # here would destroy the history this migration was created to preserve.
    # An operator who really wants the destructive rollback must reassign or
    # explicitly purge those rows first (a separate, deliberate decision),
    # then re-run the downgrade.
    conn = op.get_bind()
    preserved = conn.execute(sa.text("SELECT COUNT(*) FROM deliveries WHERE endpoint_id IS NULL")).scalar()
    if preserved:
        raise RuntimeError(
            f"Refusing downgrade: {preserved} preserved deliverie(s) with NULL endpoint_id exist "
            "(history kept after endpoint deletion). Reassign or explicitly delete them first; "
            "this downgrade will not silently destroy audit history."
        )
    op.drop_constraint('deliveries_endpoint_id_fkey', 'deliveries', type_='foreignkey')
    op.alter_column('deliveries', 'endpoint_id', existing_type=sa.String(length=32), nullable=False)
    op.create_foreign_key(
        'deliveries_endpoint_id_fkey',
        'deliveries',
        'endpoints',
        ['endpoint_id'],
        ['id'],
        ondelete='CASCADE',
    )
