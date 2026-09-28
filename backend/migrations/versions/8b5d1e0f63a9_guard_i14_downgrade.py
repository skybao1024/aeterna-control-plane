"""guard destructive i14 downgrade

Revision ID: 8b5d1e0f63a9
Revises: 7a4c0d9e52f8
Create Date: 2026-09-27
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "8b5d1e0f63a9"
down_revision: Union[str, None] = "7a4c0d9e52f8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """The guard is enforced when leaving the I14 migration chain."""


def downgrade() -> None:
    connection = op.get_bind()
    i14_rows = connection.execute(
        sa.text(
            "SELECT "
            "(SELECT count(*) FROM aeterna_owner_recovery_requests) + "
            "(SELECT count(*) FROM aeterna_recovery_rotations) + "
            "(SELECT count(*) FROM aeterna_recovery_rotation_devices)"
        )
    ).scalar_one()
    multi_epoch_accounts = connection.execute(
        sa.text(
            "SELECT count(*) FROM ("
            "SELECT account_id FROM account_policies "
            "WHERE account_id IS NOT NULL GROUP BY account_id HAVING count(*) > 1"
            ") AS multi_epoch"
        )
    ).scalar_one()
    if i14_rows or multi_epoch_accounts:
        raise RuntimeError(
            "I14 downgrade refused: archive Owner recovery and rotation rows and "
            "resolve immutable multi-epoch policy history before downgrade"
        )
