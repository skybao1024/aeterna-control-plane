"""add I11 policy state machine and transactional outbox

Revision ID: 6b8f7d4a91c2
Revises: d0a10e27b5c4
Create Date: 2026-09-27 16:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "6b8f7d4a91c2"
down_revision: Union[str, None] = "d0a10e27b5c4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _timestamps() -> tuple[sa.Column, sa.Column]:
    return (
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )


def upgrade() -> None:
    """Bind policies to accounts and add durable queue idempotency records."""
    op.add_column(
        "account_policies",
        sa.Column("account_id", sa.UUID(), nullable=True),
    )
    op.create_foreign_key(
        "fk_account_policies_account_id_aeterna_accounts",
        "account_policies",
        "aeterna_accounts",
        ["account_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_unique_constraint(
        "uq_account_policies_account_id",
        "account_policies",
        ["account_id"],
    )
    op.create_index(
        "ix_account_policies_account_id",
        "account_policies",
        ["account_id"],
        unique=False,
    )

    op.drop_constraint("ck_account_policies_state", "account_policies", type_="check")
    op.drop_constraint(
        "ck_account_policies_inactivity_window_positive",
        "account_policies",
        type_="check",
    )
    op.drop_constraint(
        "ck_account_policies_warning_window_valid",
        "account_policies",
        type_="check",
    )
    op.drop_constraint(
        "ck_account_policies_grace_window_positive",
        "account_policies",
        type_="check",
    )
    op.create_check_constraint(
        "ck_account_policies_state",
        "account_policies",
        "state IN ('ACTIVE', 'PRE_WARNING', 'GRACE_PERIOD', 'RELEASED', "
        "'DISABLED', 'DELETED')",
    )
    op.create_check_constraint(
        "ck_account_policies_version_nonnegative",
        "account_policies",
        "version >= 0",
    )
    op.create_check_constraint(
        "ck_account_policies_inactivity_window_range",
        "account_policies",
        "inactivity_window_seconds >= 1209600 "
        "AND inactivity_window_seconds <= 31536000",
    )
    op.create_check_constraint(
        "ck_account_policies_warning_window_range",
        "account_policies",
        "warning_window_seconds >= 259200 "
        "AND warning_window_seconds <= 2592000 "
        "AND warning_window_seconds < inactivity_window_seconds",
    )
    op.create_check_constraint(
        "ck_account_policies_grace_window_minimum",
        "account_policies",
        "grace_window_seconds >= 259200",
    )

    op.execute(
        "UPDATE account_policy_outbox_events "
        "SET status = 'acknowledged' WHERE status = 'processed'"
    )
    op.drop_constraint(
        "ck_account_policy_outbox_events_status",
        "account_policy_outbox_events",
        type_="check",
    )
    op.add_column(
        "account_policy_outbox_events",
        sa.Column("notification_type", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "account_policy_outbox_events",
        sa.Column("delivery_idempotency_key", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "account_policy_outbox_events",
        sa.Column(
            "attempt_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
    )
    op.add_column(
        "account_policy_outbox_events",
        sa.Column("queued_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "account_policy_outbox_events",
        sa.Column("acknowledged_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "account_policy_outbox_events",
        sa.Column("cancelled_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.alter_column(
        "account_policy_outbox_events",
        "attempt_count",
        server_default=None,
    )
    op.create_unique_constraint(
        "uq_account_policy_outbox_events_delivery_idempotency_key",
        "account_policy_outbox_events",
        ["delivery_idempotency_key"],
    )
    op.create_check_constraint(
        "ck_account_policy_outbox_events_status",
        "account_policy_outbox_events",
        "status IN ('pending', 'queued', 'acknowledged', 'cancelled')",
    )
    op.create_check_constraint(
        "ck_account_policy_outbox_events_notification_delivery_pair",
        "account_policy_outbox_events",
        "(notification_type IS NULL) = (delivery_idempotency_key IS NULL)",
    )
    op.create_check_constraint(
        "ck_account_policy_outbox_events_attempt_count_nonnegative",
        "account_policy_outbox_events",
        "attempt_count >= 0",
    )
    op.create_index(
        "ix_account_policy_outbox_events_delivery_scan",
        "account_policy_outbox_events",
        ["status", "scheduled_at"],
        unique=False,
    )

    op.create_table(
        "account_policy_outbox_attempts",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("outbox_event_id", sa.UUID(), nullable=False),
        sa.Column("task_idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("delivery_idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("prepared_at", sa.TIMESTAMP(timezone=True), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "status = 'prepared'",
            name="ck_account_policy_outbox_attempts_status",
        ),
        sa.ForeignKeyConstraint(
            ["outbox_event_id"],
            ["account_policy_outbox_events.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "task_idempotency_key",
            name="uq_account_policy_outbox_attempts_task_idempotency_key",
        ),
    )
    op.create_index(
        "ix_account_policy_outbox_attempts_outbox_event_id",
        "account_policy_outbox_attempts",
        ["outbox_event_id"],
        unique=False,
    )

    op.create_table(
        "account_policy_outbox_callbacks",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("outbox_event_id", sa.UUID(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("received_at", sa.TIMESTAMP(timezone=True), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "outcome IN ('dispatch-accepted', 'dispatch-failed')",
            name="ck_account_policy_outbox_callbacks_outcome",
        ),
        sa.ForeignKeyConstraint(
            ["outbox_event_id"],
            ["account_policy_outbox_events.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "idempotency_key",
            name="uq_account_policy_outbox_callbacks_idempotency_key",
        ),
    )
    op.create_index(
        "ix_account_policy_outbox_callbacks_outbox_event_id",
        "account_policy_outbox_callbacks",
        ["outbox_event_id"],
        unique=False,
    )


def downgrade() -> None:
    """Remove I11 queue records and restore the I03 policy constraints."""
    op.drop_index(
        "ix_account_policy_outbox_callbacks_outbox_event_id",
        table_name="account_policy_outbox_callbacks",
    )
    op.drop_table("account_policy_outbox_callbacks")
    op.drop_index(
        "ix_account_policy_outbox_attempts_outbox_event_id",
        table_name="account_policy_outbox_attempts",
    )
    op.drop_table("account_policy_outbox_attempts")

    op.drop_index(
        "ix_account_policy_outbox_events_delivery_scan",
        table_name="account_policy_outbox_events",
    )
    op.drop_constraint(
        "ck_account_policy_outbox_events_attempt_count_nonnegative",
        "account_policy_outbox_events",
        type_="check",
    )
    op.drop_constraint(
        "ck_account_policy_outbox_events_notification_delivery_pair",
        "account_policy_outbox_events",
        type_="check",
    )
    op.drop_constraint(
        "ck_account_policy_outbox_events_status",
        "account_policy_outbox_events",
        type_="check",
    )
    op.drop_constraint(
        "uq_account_policy_outbox_events_delivery_idempotency_key",
        "account_policy_outbox_events",
        type_="unique",
    )
    op.execute(
        "UPDATE account_policy_outbox_events SET status = 'processed' "
        "WHERE status IN ('queued', 'acknowledged', 'cancelled')"
    )
    op.drop_column("account_policy_outbox_events", "cancelled_at")
    op.drop_column("account_policy_outbox_events", "acknowledged_at")
    op.drop_column("account_policy_outbox_events", "queued_at")
    op.drop_column("account_policy_outbox_events", "attempt_count")
    op.drop_column("account_policy_outbox_events", "delivery_idempotency_key")
    op.drop_column("account_policy_outbox_events", "notification_type")
    op.create_check_constraint(
        "ck_account_policy_outbox_events_status",
        "account_policy_outbox_events",
        "status IN ('pending', 'processed')",
    )

    op.drop_constraint(
        "ck_account_policies_grace_window_minimum",
        "account_policies",
        type_="check",
    )
    op.drop_constraint(
        "ck_account_policies_warning_window_range",
        "account_policies",
        type_="check",
    )
    op.drop_constraint(
        "ck_account_policies_inactivity_window_range",
        "account_policies",
        type_="check",
    )
    op.drop_constraint(
        "ck_account_policies_version_nonnegative",
        "account_policies",
        type_="check",
    )
    op.drop_constraint("ck_account_policies_state", "account_policies", type_="check")
    op.create_check_constraint(
        "ck_account_policies_state",
        "account_policies",
        "state IN ('ACTIVE', 'PRE_WARNING', 'GRACE_PERIOD', 'RELEASED')",
    )
    op.create_check_constraint(
        "ck_account_policies_inactivity_window_positive",
        "account_policies",
        "inactivity_window_seconds > 0",
    )
    op.create_check_constraint(
        "ck_account_policies_warning_window_valid",
        "account_policies",
        "warning_window_seconds > 0 "
        "AND warning_window_seconds < inactivity_window_seconds",
    )
    op.create_check_constraint(
        "ck_account_policies_grace_window_positive",
        "account_policies",
        "grace_window_seconds > 0",
    )

    op.drop_index("ix_account_policies_account_id", table_name="account_policies")
    op.drop_constraint(
        "uq_account_policies_account_id",
        "account_policies",
        type_="unique",
    )
    op.drop_constraint(
        "fk_account_policies_account_id_aeterna_accounts",
        "account_policies",
        type_="foreignkey",
    )
    op.drop_column("account_policies", "account_id")
