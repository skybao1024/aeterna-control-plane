"""add signed heartbeat and multi-device aggregation

Revision ID: d0a10e27b5c4
Revises: b7e19a09c4d2
Create Date: 2026-09-27 12:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d0a10e27b5c4"
down_revision: Union[str, None] = "b7e19a09c4d2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add latest-only heartbeat state and active-device aggregation."""
    op.add_column(
        "aeterna_accounts",
        sa.Column("last_activity_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )

    op.add_column(
        "aeterna_devices",
        sa.Column(
            "heartbeat_authorized_at", sa.TIMESTAMP(timezone=True), nullable=True
        ),
    )
    op.execute(
        "UPDATE aeterna_devices SET heartbeat_authorized_at = bound_at "
        "WHERE heartbeat_authorized_at IS NULL"
    )
    op.alter_column("aeterna_devices", "heartbeat_authorized_at", nullable=False)
    op.add_column(
        "aeterna_devices",
        sa.Column("last_sequence", sa.BigInteger(), server_default="0", nullable=False),
    )
    op.add_column(
        "aeterna_devices",
        sa.Column("last_seen_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "aeterna_devices",
        sa.Column("last_heartbeat_request_id", sa.UUID(), nullable=True),
    )
    op.add_column(
        "aeterna_devices",
        sa.Column("last_heartbeat_request_digest", sa.LargeBinary(), nullable=True),
    )
    op.create_check_constraint(
        "ck_aeterna_devices_last_sequence_range",
        "aeterna_devices",
        "last_sequence >= 0 AND last_sequence <= 9007199254740991",
    )
    op.create_check_constraint(
        "ck_aeterna_devices_heartbeat_request_pair",
        "aeterna_devices",
        "(last_heartbeat_request_id IS NULL) = "
        "(last_heartbeat_request_digest IS NULL)",
    )
    op.create_check_constraint(
        "ck_aeterna_devices_heartbeat_digest_length",
        "aeterna_devices",
        "last_heartbeat_request_digest IS NULL OR "
        "octet_length(last_heartbeat_request_digest) = 32",
    )
    op.drop_constraint("ck_aeterna_devices_status", "aeterna_devices", type_="check")
    op.create_check_constraint(
        "ck_aeterna_devices_status",
        "aeterna_devices",
        "status IN ('active', 'dormant', 'lost', 'revoked')",
    )

    op.drop_constraint(
        "uq_aeterna_device_bindings_account_device",
        "aeterna_device_bindings",
        type_="unique",
    )
    op.create_index(
        "uq_aeterna_device_bindings_pending_account_device",
        "aeterna_device_bindings",
        ["account_id", "proposed_device_id"],
        unique=True,
        postgresql_where=sa.text("state = 'pending'"),
    )

    op.drop_constraint(
        "ck_aeterna_security_audit_event_type",
        "aeterna_security_audit",
        type_="check",
    )
    op.create_check_constraint(
        "ck_aeterna_security_audit_event_type",
        "aeterna_security_audit",
        "event_type IN ('account.created', 'device.binding_requested', "
        "'device.bound', 'device.binding_cancelled', 'device.dormant', "
        "'device.lost', 'device.revoked', 'device.reverified')",
    )


def downgrade() -> None:
    """Remove I10 after verifying no repeated bindings or I10-only states exist."""
    op.drop_constraint(
        "ck_aeterna_security_audit_event_type",
        "aeterna_security_audit",
        type_="check",
    )
    op.create_check_constraint(
        "ck_aeterna_security_audit_event_type",
        "aeterna_security_audit",
        "event_type IN ('account.created', 'device.binding_requested', "
        "'device.bound', 'device.binding_cancelled')",
    )

    op.drop_index(
        "uq_aeterna_device_bindings_pending_account_device",
        table_name="aeterna_device_bindings",
    )
    op.create_unique_constraint(
        "uq_aeterna_device_bindings_account_device",
        "aeterna_device_bindings",
        ["account_id", "proposed_device_id"],
    )

    op.drop_constraint("ck_aeterna_devices_status", "aeterna_devices", type_="check")
    op.create_check_constraint(
        "ck_aeterna_devices_status",
        "aeterna_devices",
        "status IN ('active', 'revoked')",
    )
    op.drop_constraint(
        "ck_aeterna_devices_heartbeat_digest_length",
        "aeterna_devices",
        type_="check",
    )
    op.drop_constraint(
        "ck_aeterna_devices_heartbeat_request_pair",
        "aeterna_devices",
        type_="check",
    )
    op.drop_constraint(
        "ck_aeterna_devices_last_sequence_range",
        "aeterna_devices",
        type_="check",
    )
    op.drop_column("aeterna_devices", "last_heartbeat_request_digest")
    op.drop_column("aeterna_devices", "last_heartbeat_request_id")
    op.drop_column("aeterna_devices", "last_seen_at")
    op.drop_column("aeterna_devices", "last_sequence")
    op.drop_column("aeterna_devices", "heartbeat_authorized_at")
    op.drop_column("aeterna_accounts", "last_activity_at")
