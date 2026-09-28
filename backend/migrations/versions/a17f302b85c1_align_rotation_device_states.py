"""align rotation device states

Revision ID: a17f302b85c1
Revises: 9c6e2f1a74b0
Create Date: 2026-09-27
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a17f302b85c1"
down_revision: Union[str, None] = "9c6e2f1a74b0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint(
        "ck_aeterna_rotation_device_state",
        "aeterna_recovery_rotation_devices",
        type_="check",
    )
    op.execute(
        "UPDATE aeterna_recovery_rotation_devices "
        "SET state = 'excluded' WHERE state = 'revoked'"
    )
    op.create_check_constraint(
        "ck_aeterna_rotation_device_state",
        "aeterna_recovery_rotation_devices",
        "state IN ('pending', 'not_enrolled', 'complete', 'excluded')",
    )


def downgrade() -> None:
    unsupported = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT count(*) FROM aeterna_recovery_rotation_devices "
                "WHERE state IN ('not_enrolled', 'excluded')"
            )
        )
        .scalar_one()
    )
    if unsupported:
        raise RuntimeError(
            "Downgrade refused: rotation device state would lose meaning"
        )
    op.drop_constraint(
        "ck_aeterna_rotation_device_state",
        "aeterna_recovery_rotation_devices",
        type_="check",
    )
    op.create_check_constraint(
        "ck_aeterna_rotation_device_state",
        "aeterna_recovery_rotation_devices",
        "state IN ('pending', 'complete', 'revoked')",
    )
