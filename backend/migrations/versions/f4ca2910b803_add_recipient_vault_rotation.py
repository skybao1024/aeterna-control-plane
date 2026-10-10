"""Add durable Vault-scoped recipient rotations without Owner account rearm."""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "f4ca2910b803"
down_revision: Union[str, None] = "d81b53aa672e"
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None

OLD_AUDIT_EVENTS = (
    "'record.provisioned', 'record.confirmed', 'record.abandoned', 'grant.created', "
    "'claim.started', 'claim.verified', 'secret.released', 'owner.started', "
    "'owner.verified', 'owner.cancelled', 'owner.released', 'owner.completed', "
    "'rotation.provisioned', 'rotation.activated', 'rotation.device_completed', "
    "'rotation.completed'"
)
RECIPIENT_AUDIT_EVENTS = (
    "'recipient.reserved', 'recipient.provisioned', 'recipient.prepared', "
    "'recipient.completed', 'recipient.abandoned'"
)


def upgrade() -> None:
    op.add_column(
        "aeterna_recovery_otp_challenges",
        sa.Column(
            "scope", sa.String(32), server_default="recovery.srs.read", nullable=False
        ),
    )
    op.create_check_constraint(
        "ck_aeterna_recovery_otp_challenges_scope",
        "aeterna_recovery_otp_challenges",
        "scope IN ('recovery.srs.read', 'recovery.recipient.rotate')",
    )
    op.create_table(
        "aeterna_recipient_recovery_rotations",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column(
            "account_id",
            sa.UUID(),
            sa.ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "contact_id",
            sa.UUID(),
            sa.ForeignKey("aeterna_contacts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "grant_id",
            sa.UUID(),
            sa.ForeignKey("aeterna_recovery_grants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "device_id",
            sa.UUID(),
            sa.ForeignKey("aeterna_devices.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "source_recovery_id",
            sa.UUID(),
            sa.ForeignKey("aeterna_recovery_records.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("vault_id", sa.UUID(), nullable=False),
        sa.Column("source_policy_epoch", sa.Integer(), nullable=False),
        sa.Column("source_generation", sa.Integer(), nullable=False),
        sa.Column("source_wrapper_digest", sa.LargeBinary(), nullable=False),
        sa.Column("target_recovery_id", sa.UUID(), nullable=True),
        sa.Column("target_generation", sa.Integer(), nullable=False),
        sa.Column("erc_commitment", sa.LargeBinary(), nullable=True),
        sa.Column("target_wrapper_digest", sa.LargeBinary(), nullable=True),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("encrypted_srs", sa.LargeBinary(), nullable=True),
        sa.Column("kms_provider", sa.String(32), nullable=True),
        sa.Column("kms_key_arn", sa.String(512), nullable=True),
        sa.Column("kms_key_material_id", sa.String(512), nullable=True),
        sa.Column("secret_request_id", sa.UUID(), nullable=False),
        sa.Column("secret_request_digest", sa.LargeBinary(), nullable=False),
        sa.Column("prepared_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("abandoned_at", sa.TIMESTAMP(timezone=True), nullable=True),
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
        sa.UniqueConstraint(
            "target_recovery_id", name="uq_aeterna_recipient_rotation_target"
        ),
        sa.UniqueConstraint(
            "secret_request_id", name="uq_aeterna_recipient_rotation_secret_request"
        ),
        sa.CheckConstraint(
            "state IN ('reserved', 'provisioned', 'prepared', 'complete', 'abandoned')",
            name="ck_aeterna_recipient_rotation_state",
        ),
        sa.CheckConstraint(
            "source_policy_epoch > 0 AND source_generation > 0 AND target_generation = 1",
            name="ck_aeterna_recipient_rotation_generations",
        ),
        sa.CheckConstraint(
            "octet_length(source_wrapper_digest) = 32 AND octet_length(secret_request_digest) = 32 "
            "AND (erc_commitment IS NULL OR octet_length(erc_commitment) = 32) "
            "AND (target_wrapper_digest IS NULL OR octet_length(target_wrapper_digest) = 32)",
            name="ck_aeterna_recipient_rotation_digests",
        ),
        sa.CheckConstraint(
            "encrypted_srs IS NULL OR octet_length(encrypted_srs) BETWEEN 1 AND 8192",
            name="ck_aeterna_recipient_rotation_ciphertext",
        ),
        sa.CheckConstraint(
            "(state = 'reserved' AND target_recovery_id IS NULL AND encrypted_srs IS NULL "
            "AND erc_commitment IS NULL AND target_wrapper_digest IS NULL) OR "
            "(state = 'provisioned' AND target_recovery_id IS NOT NULL AND encrypted_srs IS NOT NULL "
            "AND erc_commitment IS NOT NULL AND target_wrapper_digest IS NULL) OR "
            "(state IN ('prepared', 'complete') AND target_recovery_id IS NOT NULL "
            "AND encrypted_srs IS NOT NULL AND erc_commitment IS NOT NULL "
            "AND target_wrapper_digest IS NOT NULL AND prepared_at IS NOT NULL) OR "
            "(state = 'abandoned' AND abandoned_at IS NOT NULL)",
            name="ck_aeterna_recipient_rotation_material_state",
        ),
        sa.CheckConstraint(
            "(state = 'complete' AND completed_at IS NOT NULL) OR "
            "(state <> 'complete' AND completed_at IS NULL)",
            name="ck_aeterna_recipient_rotation_completed_at",
        ),
    )
    op.create_index(
        "ix_aeterna_recipient_recovery_rotations_account_id",
        "aeterna_recipient_recovery_rotations",
        ["account_id"],
    )
    op.create_index(
        "ix_aeterna_recipient_recovery_rotations_source_recovery_id",
        "aeterna_recipient_recovery_rotations",
        ["source_recovery_id"],
    )
    op.create_index(
        "uq_aeterna_recipient_rotation_live_source",
        "aeterna_recipient_recovery_rotations",
        ["source_recovery_id"],
        unique=True,
        postgresql_where=sa.text("state <> 'abandoned'"),
    )
    op.drop_constraint(
        "ck_aeterna_recovery_claim_tokens_scope",
        "aeterna_recovery_claim_tokens",
        type_="check",
    )
    op.create_check_constraint(
        "ck_aeterna_recovery_claim_tokens_scope",
        "aeterna_recovery_claim_tokens",
        "scope IN ('recovery.srs.read', 'recovery.recipient.rotate')",
    )
    op.drop_constraint(
        "ck_aeterna_recovery_audit_event_type", "aeterna_recovery_audit", type_="check"
    )
    op.create_check_constraint(
        "ck_aeterna_recovery_audit_event_type",
        "aeterna_recovery_audit",
        f"event_type IN ({OLD_AUDIT_EVENTS}, {RECIPIENT_AUDIT_EVENTS})",
    )


def downgrade() -> None:
    connection = op.get_bind()
    rows = connection.execute(
        sa.text(
            "SELECT (SELECT count(*) FROM aeterna_recipient_recovery_rotations) + "
            "(SELECT count(*) FROM aeterna_recovery_claim_tokens WHERE scope = 'recovery.recipient.rotate') + "
            "(SELECT count(*) FROM aeterna_recovery_otp_challenges WHERE scope = 'recovery.recipient.rotate') + "
            "(SELECT count(*) FROM aeterna_recovery_audit WHERE event_type LIKE 'recipient.%')"
        )
    ).scalar_one()
    if rows:
        raise RuntimeError(
            "Recipient recovery downgrade refused: archive durable successor material "
            "and recipient authorization history before downgrade"
        )
    op.drop_constraint(
        "ck_aeterna_recovery_claim_tokens_scope",
        "aeterna_recovery_claim_tokens",
        type_="check",
    )
    op.create_check_constraint(
        "ck_aeterna_recovery_claim_tokens_scope",
        "aeterna_recovery_claim_tokens",
        "scope = 'recovery.srs.read'",
    )
    op.drop_constraint(
        "ck_aeterna_recovery_audit_event_type", "aeterna_recovery_audit", type_="check"
    )
    op.create_check_constraint(
        "ck_aeterna_recovery_audit_event_type",
        "aeterna_recovery_audit",
        f"event_type IN ({OLD_AUDIT_EVENTS})",
    )
    op.drop_table("aeterna_recipient_recovery_rotations")
    op.drop_constraint(
        "ck_aeterna_recovery_otp_challenges_scope",
        "aeterna_recovery_otp_challenges",
        type_="check",
    )
    op.drop_column("aeterna_recovery_otp_challenges", "scope")
