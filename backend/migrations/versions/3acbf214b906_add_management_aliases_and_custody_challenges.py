"""Add successful-recipient mailbox authority and custody replay receipts."""

import sqlalchemy as sa
from alembic import op

revision = "3acbf214b906"
down_revision = "f4ca2910b803"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "aeterna_management_aliases",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column(
            "account_id",
            sa.UUID(),
            sa.ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "rotation_id",
            sa.UUID(),
            sa.ForeignKey(
                "aeterna_recipient_recovery_rotations.id", ondelete="RESTRICT"
            ),
            nullable=False,
        ),
        sa.Column("email_lookup", sa.LargeBinary(), nullable=False),
        sa.Column("email_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("email_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("email_key_version", sa.Integer(), nullable=False),
        sa.Column("is_primary", sa.Boolean(), nullable=False),
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
            "account_id", "email_lookup", name="uq_aeterna_management_alias_mailbox"
        ),
        sa.CheckConstraint(
            "octet_length(email_lookup) = 32 AND octet_length(email_nonce) = 12 AND email_key_version > 0",
            name="ck_aeterna_management_email",
        ),
    )
    op.add_column(
        "aeterna_recipient_recovery_rotations",
        sa.Column("management_alias_id", sa.UUID(), nullable=True),
    )
    op.create_foreign_key(
        "fk_aeterna_recipient_rotation_management_alias",
        "aeterna_recipient_recovery_rotations",
        "aeterna_management_aliases",
        ["management_alias_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index(
        "ix_aeterna_management_aliases_account_id",
        "aeterna_management_aliases",
        ["account_id"],
    )
    op.create_index(
        "uq_aeterna_management_primary",
        "aeterna_management_aliases",
        ["account_id"],
        unique=True,
        postgresql_where=sa.text("is_primary"),
    )
    op.create_table(
        "aeterna_custody_challenges",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column(
            "account_id",
            sa.UUID(),
            sa.ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "device_id",
            sa.UUID(),
            sa.ForeignKey("aeterna_devices.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("vault_id", sa.UUID(), nullable=False),
        sa.Column("recovery_id", sa.UUID(), nullable=False),
        sa.Column("wrapper_digest", sa.LargeBinary(), nullable=False),
        sa.Column("challenge", sa.LargeBinary(), nullable=False),
        sa.Column("request_id", sa.UUID(), nullable=False),
        sa.Column("request_digest", sa.LargeBinary(), nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("verified_request_id", sa.UUID(), nullable=True),
        sa.Column("verified_digest", sa.LargeBinary(), nullable=True),
        sa.Column("verified", sa.Boolean(), nullable=True),
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
        sa.UniqueConstraint("request_id", name="uq_aeterna_custody_challenge_request"),
        sa.UniqueConstraint(
            "verified_request_id", name="uq_aeterna_custody_verified_request"
        ),
        sa.CheckConstraint(
            "octet_length(challenge) = 32 AND octet_length(wrapper_digest) = 32 AND octet_length(request_digest) = 32",
            name="ck_aeterna_custody_challenge_digests",
        ),
        sa.CheckConstraint(
            "(consumed_at IS NULL AND verified_request_id IS NULL AND verified_digest IS NULL AND verified IS NULL) OR (consumed_at IS NOT NULL AND verified_request_id IS NOT NULL AND verified_digest IS NOT NULL AND octet_length(verified_digest) = 32 AND verified IS NOT NULL)",
            name="ck_aeterna_custody_consumed",
        ),
    )
    op.create_index(
        "ix_aeterna_custody_challenges_account_id",
        "aeterna_custody_challenges",
        ["account_id"],
    )
    op.create_index(
        "ix_aeterna_custody_challenges_expires_at",
        "aeterna_custody_challenges",
        ["expires_at"],
    )


def downgrade():
    if (
        op.get_bind()
        .execute(sa.text("SELECT count(*) FROM aeterna_management_aliases"))
        .scalar_one()
    ):
        raise RuntimeError(
            "Management authority downgrade refused: preserve mailbox aliases before downgrade"
        )
    op.drop_table("aeterna_custody_challenges")
    op.drop_constraint(
        "fk_aeterna_recipient_rotation_management_alias",
        "aeterna_recipient_recovery_rotations",
        type_="foreignkey",
    )
    op.drop_column("aeterna_recipient_recovery_rotations", "management_alias_id")
    op.drop_table("aeterna_management_aliases")
