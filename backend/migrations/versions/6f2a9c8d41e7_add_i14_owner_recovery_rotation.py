"""add i14 owner recovery rotation

Revision ID: 6f2a9c8d41e7
Revises: 350391c65e38
Create Date: 2026-09-27
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "6f2a9c8d41e7"
down_revision: Union[str, None] = "350391c65e38"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "aeterna_accounts",
        sa.Column(
            "current_policy_epoch", sa.Integer(), server_default="1", nullable=False
        ),
    )
    op.add_column(
        "aeterna_accounts",
        sa.Column(
            "current_recovery_generation",
            sa.Integer(),
            server_default="1",
            nullable=False,
        ),
    )
    op.add_column(
        "aeterna_devices",
        sa.Column("policy_epoch", sa.Integer(), server_default="1", nullable=False),
    )
    op.drop_constraint(
        "uq_account_policies_account_id", "account_policies", type_="unique"
    )
    op.add_column(
        "account_policies",
        sa.Column("epoch", sa.Integer(), server_default="1", nullable=False),
    )
    op.add_column(
        "account_policies",
        sa.Column("retired_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.create_unique_constraint(
        "uq_account_policies_account_epoch",
        "account_policies",
        ["account_id", "epoch"],
    )
    op.create_index(
        "uq_account_policies_current_account",
        "account_policies",
        ["account_id"],
        unique=True,
        postgresql_where=sa.text("retired_at IS NULL"),
    )

    op.drop_index(
        "uq_aeterna_recovery_records_live_device_vault",
        table_name="aeterna_recovery_records",
    )
    op.drop_constraint(
        "ck_aeterna_recovery_records_state",
        "aeterna_recovery_records",
        type_="check",
    )
    op.drop_constraint(
        "ck_aeterna_recovery_records_state_timestamps",
        "aeterna_recovery_records",
        type_="check",
    )
    op.add_column(
        "aeterna_recovery_records",
        sa.Column("policy_epoch", sa.Integer(), server_default="1", nullable=False),
    )
    op.add_column(
        "aeterna_recovery_records",
        sa.Column(
            "recovery_generation", sa.Integer(), server_default="1", nullable=False
        ),
    )
    op.create_check_constraint(
        "ck_aeterna_recovery_records_state",
        "aeterna_recovery_records",
        "state IN ('pending_confirmation', 'sealed', 'abandoned', 'expired', 'revoked')",
    )
    op.create_check_constraint(
        "ck_aeterna_recovery_records_state_timestamps",
        "aeterna_recovery_records",
        "(state = 'pending_confirmation' AND wrapper_digest IS NULL "
        "AND confirmed_at IS NULL AND abandoned_at IS NULL) OR "
        "(state = 'sealed' AND wrapper_digest IS NOT NULL "
        "AND confirmed_at IS NOT NULL AND abandoned_at IS NULL) OR "
        "(state IN ('abandoned', 'expired', 'revoked') AND abandoned_at IS NOT NULL)",
    )
    op.create_index(
        "uq_aeterna_recovery_records_live_device_vault",
        "aeterna_recovery_records",
        [
            "account_id",
            "device_id",
            "vault_id",
            "policy_epoch",
            "recovery_generation",
        ],
        unique=True,
        postgresql_where=sa.text("state IN ('pending_confirmation', 'sealed')"),
    )

    op.drop_constraint(
        "ck_aeterna_recovery_audit_event_type",
        "aeterna_recovery_audit",
        type_="check",
    )
    op.create_check_constraint(
        "ck_aeterna_recovery_audit_event_type",
        "aeterna_recovery_audit",
        "event_type IN ('record.provisioned', 'record.confirmed', "
        "'record.abandoned', 'grant.created', 'claim.started', 'claim.verified', "
        "'secret.released', 'owner.started', 'owner.verified', 'owner.cancelled', "
        "'owner.released', 'owner.completed', 'rotation.provisioned', "
        "'rotation.activated', 'rotation.device_completed', 'rotation.completed')",
    )

    op.create_table(
        "aeterna_owner_recovery_requests",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("account_id", sa.UUID(), nullable=False),
        sa.Column("device_id", sa.UUID(), nullable=False),
        sa.Column("recovery_id", sa.UUID(), nullable=False),
        sa.Column("vault_id", sa.UUID(), nullable=False),
        sa.Column("policy_epoch", sa.Integer(), nullable=False),
        sa.Column("recovery_generation", sa.Integer(), nullable=False),
        sa.Column("wrapper_digest", sa.LargeBinary(), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("start_request_id", sa.UUID(), nullable=False),
        sa.Column("start_request_digest", sa.LargeBinary(), nullable=False),
        sa.Column("challenge_id", sa.UUID(), nullable=False),
        sa.Column("otp_verifier", sa.LargeBinary(), nullable=False),
        sa.Column("otp_key_version", sa.Integer(), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("challenge_expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("ready_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("verified_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("released_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.TIMESTAMP(timezone=True), nullable=True),
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
        sa.CheckConstraint(
            "state IN ('pending_email', 'cooling_down', 'material_released', "
            "'completed', 'cancelled', 'expired')",
            name="ck_aeterna_owner_recovery_state",
        ),
        sa.CheckConstraint(
            "octet_length(start_request_digest) = 32 AND "
            "octet_length(wrapper_digest) = 32 AND octet_length(otp_verifier) = 32",
            name="ck_aeterna_owner_recovery_digest_lengths",
        ),
        sa.CheckConstraint(
            "attempt_count BETWEEN 0 AND 5 AND otp_key_version > 0",
            name="ck_aeterna_owner_recovery_otp_bounds",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"], ["aeterna_accounts.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["aeterna_devices.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["recovery_id"], ["aeterna_recovery_records.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("challenge_id"),
        sa.UniqueConstraint(
            "start_request_id", name="uq_aeterna_owner_recovery_start_request"
        ),
    )
    op.create_index(
        op.f("ix_aeterna_owner_recovery_requests_account_id"),
        "aeterna_owner_recovery_requests",
        ["account_id"],
    )
    op.create_index(
        op.f("ix_aeterna_owner_recovery_requests_device_id"),
        "aeterna_owner_recovery_requests",
        ["device_id"],
    )
    op.create_index(
        "uq_aeterna_owner_recovery_live_account",
        "aeterna_owner_recovery_requests",
        ["account_id"],
        unique=True,
        postgresql_where=sa.text(
            "state IN ('pending_email', 'cooling_down', 'material_released')"
        ),
    )

    op.create_table(
        "aeterna_recovery_rotations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("account_id", sa.UUID(), nullable=False),
        sa.Column("initiating_device_id", sa.UUID(), nullable=False),
        sa.Column("recovery_id", sa.UUID(), nullable=False),
        sa.Column("owner_recovery_id", sa.UUID(), nullable=True),
        sa.Column("vault_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=24), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("source_policy_epoch", sa.Integer(), nullable=False),
        sa.Column("target_policy_epoch", sa.Integer(), nullable=False),
        sa.Column("source_generation", sa.Integer(), nullable=False),
        sa.Column("target_generation", sa.Integer(), nullable=False),
        sa.Column("provision_request_id", sa.UUID(), nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("activated_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
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
        sa.CheckConstraint(
            "kind IN ('erc_rotation', 'post_compromise')",
            name="ck_aeterna_recovery_rotation_kind",
        ),
        sa.CheckConstraint(
            "state IN ('preparing', 'active', 'complete', 'cancelled')",
            name="ck_aeterna_recovery_rotation_state",
        ),
        sa.CheckConstraint(
            "target_generation = source_generation + 1 AND "
            "target_policy_epoch >= source_policy_epoch",
            name="ck_aeterna_recovery_rotation_targets",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"], ["aeterna_accounts.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["initiating_device_id"], ["aeterna_devices.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["recovery_id"], ["aeterna_recovery_records.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["owner_recovery_id"],
            ["aeterna_owner_recovery_requests.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "provision_request_id", name="uq_aeterna_recovery_rotation_request"
        ),
    )
    op.create_index(
        op.f("ix_aeterna_recovery_rotations_account_id"),
        "aeterna_recovery_rotations",
        ["account_id"],
    )

    op.create_table(
        "aeterna_recovery_rotation_devices",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("rotation_id", sa.UUID(), nullable=False),
        sa.Column("device_id", sa.UUID(), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("wrapper_digest", sa.LargeBinary(), nullable=True),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
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
        sa.CheckConstraint(
            "state IN ('pending', 'complete', 'revoked')",
            name="ck_aeterna_rotation_device_state",
        ),
        sa.CheckConstraint(
            "wrapper_digest IS NULL OR octet_length(wrapper_digest) = 32",
            name="ck_aeterna_rotation_device_wrapper_digest",
        ),
        sa.ForeignKeyConstraint(
            ["rotation_id"], ["aeterna_recovery_rotations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["aeterna_devices.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "rotation_id", "device_id", name="uq_aeterna_rotation_device"
        ),
    )
    op.create_index(
        op.f("ix_aeterna_recovery_rotation_devices_rotation_id"),
        "aeterna_recovery_rotation_devices",
        ["rotation_id"],
    )
    op.create_index(
        op.f("ix_aeterna_recovery_rotation_devices_device_id"),
        "aeterna_recovery_rotation_devices",
        ["device_id"],
    )

    op.add_column(
        "aeterna_email_outbox_events",
        sa.Column("owner_recovery_id", sa.UUID(), nullable=True),
    )
    op.create_foreign_key(
        "fk_aeterna_email_outbox_events_owner_recovery",
        "aeterna_email_outbox_events",
        "aeterna_owner_recovery_requests",
        ["owner_recovery_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.drop_constraint(
        "ck_aeterna_email_outbox_events_event_type",
        "aeterna_email_outbox_events",
        type_="check",
    )
    op.create_check_constraint(
        "ck_aeterna_email_outbox_events_event_type",
        "aeterna_email_outbox_events",
        "event_type IN ('owner-pre-warning', 'owner-grace-period-started', "
        "'owner-warning-required', 'owner-release-authorized', "
        "'contact-invitation', 'contact-test', 'recovery-claim-link', "
        "'recovery-otp', 'recovery-claimed-owner', 'recovery-claimed-contact', "
        "'owner-recovery-otp', 'owner-recovery-cooling-down', "
        "'owner-recovery-cancelled', 'owner-recovery-material-released')",
    )
    op.create_check_constraint(
        "ck_aeterna_email_outbox_events_owner_recovery_reference",
        "aeterna_email_outbox_events",
        "(event_type LIKE 'owner-recovery-%' AND owner_recovery_id IS NOT NULL) "
        "OR (event_type NOT LIKE 'owner-recovery-%' AND owner_recovery_id IS NULL)",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_aeterna_email_outbox_events_owner_recovery_reference",
        "aeterna_email_outbox_events",
        type_="check",
    )
    op.drop_constraint(
        "ck_aeterna_email_outbox_events_event_type",
        "aeterna_email_outbox_events",
        type_="check",
    )
    op.create_check_constraint(
        "ck_aeterna_email_outbox_events_event_type",
        "aeterna_email_outbox_events",
        "event_type IN ('owner-pre-warning', 'owner-grace-period-started', "
        "'owner-warning-required', 'owner-release-authorized', "
        "'contact-invitation', 'contact-test', 'recovery-claim-link', "
        "'recovery-otp', 'recovery-claimed-owner', 'recovery-claimed-contact')",
    )
    op.drop_constraint(
        "fk_aeterna_email_outbox_events_owner_recovery",
        "aeterna_email_outbox_events",
        type_="foreignkey",
    )
    op.drop_column("aeterna_email_outbox_events", "owner_recovery_id")
    op.drop_table("aeterna_recovery_rotation_devices")
    op.drop_table("aeterna_recovery_rotations")
    op.drop_table("aeterna_owner_recovery_requests")
    op.drop_constraint(
        "ck_aeterna_recovery_audit_event_type",
        "aeterna_recovery_audit",
        type_="check",
    )
    op.create_check_constraint(
        "ck_aeterna_recovery_audit_event_type",
        "aeterna_recovery_audit",
        "event_type IN ('record.provisioned', 'record.confirmed', "
        "'record.abandoned', 'grant.created', 'claim.started', "
        "'claim.verified', 'secret.released')",
    )
    op.drop_index(
        "uq_aeterna_recovery_records_live_device_vault",
        table_name="aeterna_recovery_records",
    )
    op.drop_constraint(
        "ck_aeterna_recovery_records_state_timestamps",
        "aeterna_recovery_records",
        type_="check",
    )
    op.drop_constraint(
        "ck_aeterna_recovery_records_state",
        "aeterna_recovery_records",
        type_="check",
    )
    op.drop_column("aeterna_recovery_records", "recovery_generation")
    op.drop_column("aeterna_recovery_records", "policy_epoch")
    op.create_check_constraint(
        "ck_aeterna_recovery_records_state",
        "aeterna_recovery_records",
        "state IN ('pending_confirmation', 'sealed', 'abandoned', 'expired')",
    )
    op.create_check_constraint(
        "ck_aeterna_recovery_records_state_timestamps",
        "aeterna_recovery_records",
        "(state = 'pending_confirmation' AND wrapper_digest IS NULL "
        "AND confirmed_at IS NULL AND abandoned_at IS NULL) OR "
        "(state = 'sealed' AND wrapper_digest IS NOT NULL "
        "AND confirmed_at IS NOT NULL AND abandoned_at IS NULL) OR "
        "(state IN ('abandoned', 'expired') AND abandoned_at IS NOT NULL)",
    )
    op.create_index(
        "uq_aeterna_recovery_records_live_device_vault",
        "aeterna_recovery_records",
        ["account_id", "device_id", "vault_id"],
        unique=True,
        postgresql_where=sa.text("state IN ('pending_confirmation', 'sealed')"),
    )
    op.drop_index("uq_account_policies_current_account", table_name="account_policies")
    op.drop_constraint(
        "uq_account_policies_account_epoch", "account_policies", type_="unique"
    )
    op.drop_column("account_policies", "retired_at")
    op.drop_column("account_policies", "epoch")
    op.create_unique_constraint(
        "uq_account_policies_account_id", "account_policies", ["account_id"]
    )
    op.drop_column("aeterna_devices", "policy_epoch")
    op.drop_column("aeterna_accounts", "current_recovery_generation")
    op.drop_column("aeterna_accounts", "current_policy_epoch")
