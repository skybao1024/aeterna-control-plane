"""bind rotation records per device

Revision ID: b28a413c96d2
Revises: a17f302b85c1
Create Date: 2026-09-27
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b28a413c96d2"
down_revision: Union[str, None] = "a17f302b85c1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "aeterna_recovery_rotation_devices",
        sa.Column("recovery_id", sa.UUID(), nullable=True),
    )
    op.create_foreign_key(
        "fk_aeterna_rotation_devices_recovery_record",
        "aeterna_recovery_rotation_devices",
        "aeterna_recovery_records",
        ["recovery_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_unique_constraint(
        "uq_aeterna_rotation_device_recovery",
        "aeterna_recovery_rotation_devices",
        ["recovery_id"],
    )
    op.execute(
        "UPDATE aeterna_recovery_rotation_devices AS rotation_device "
        "SET recovery_id = rotation.recovery_id "
        "FROM aeterna_recovery_rotations AS rotation "
        "WHERE rotation_device.rotation_id = rotation.id "
        "AND rotation_device.device_id = rotation.initiating_device_id"
    )
    op.create_index(
        "uq_aeterna_recovery_rotations_live_account",
        "aeterna_recovery_rotations",
        ["account_id"],
        unique=True,
        postgresql_where=sa.text("state IN ('preparing', 'active')"),
    )


def downgrade() -> None:
    rotation_count = (
        op.get_bind()
        .execute(sa.text("SELECT count(*) FROM aeterna_recovery_rotations"))
        .scalar_one()
    )
    if rotation_count:
        raise RuntimeError(
            "Downgrade refused: per-device rotation record bindings must be retained"
        )
    op.drop_index(
        "uq_aeterna_recovery_rotations_live_account",
        table_name="aeterna_recovery_rotations",
    )
    op.drop_constraint(
        "uq_aeterna_rotation_device_recovery",
        "aeterna_recovery_rotation_devices",
        type_="unique",
    )
    op.drop_constraint(
        "fk_aeterna_rotation_devices_recovery_record",
        "aeterna_recovery_rotation_devices",
        type_="foreignkey",
    )
    op.drop_column("aeterna_recovery_rotation_devices", "recovery_id")
