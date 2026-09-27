"""add Aeterna identity protocol v1 persistence

Revision ID: b7e19a09c4d2
Revises: 3f9e0e028cab
Create Date: 2026-09-27 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b7e19a09c4d2"
down_revision: Union[str, None] = "3f9e0e028cab"
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
    """Create isolated UUID account and device-binding tables."""
    op.create_table(
        "aeterna_accounts",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("email_lookup", sa.LargeBinary(), nullable=False),
        sa.Column("email_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("email_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("email_key_version", sa.Integer(), nullable=False),
        sa.Column("first_device_bound_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "octet_length(email_lookup) = 32",
            name="ck_aeterna_accounts_email_lookup_length",
        ),
        sa.CheckConstraint(
            "octet_length(email_nonce) = 12",
            name="ck_aeterna_accounts_email_nonce_length",
        ),
        sa.CheckConstraint(
            "email_key_version > 0",
            name="ck_aeterna_accounts_email_key_version_positive",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email_lookup", name="uq_aeterna_accounts_email_lookup"),
    )

    op.create_table(
        "aeterna_devices",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("account_id", sa.UUID(), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("label", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("bound_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        *_timestamps(),
        sa.CheckConstraint(
            "octet_length(public_key) = 32",
            name="ck_aeterna_devices_public_key_length",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'revoked')",
            name="ck_aeterna_devices_status",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"], ["aeterna_accounts.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "account_id",
            "public_key",
            name="uq_aeterna_devices_account_public_key",
        ),
    )
    op.create_index(
        op.f("ix_aeterna_devices_account_id"),
        "aeterna_devices",
        ["account_id"],
        unique=False,
    )

    op.create_table(
        "aeterna_device_bindings",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("account_id", sa.UUID(), nullable=False),
        sa.Column("proposed_device_id", sa.UUID(), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("label", sa.String(length=64), nullable=True),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("challenge", sa.LargeBinary(), nullable=True),
        sa.Column("challenge_consumed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("not_before", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("activated_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("request_id", sa.UUID(), nullable=False),
        sa.Column("request_digest", sa.LargeBinary(), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "octet_length(public_key) = 32",
            name="ck_aeterna_device_bindings_public_key_length",
        ),
        sa.CheckConstraint(
            "challenge IS NULL OR octet_length(challenge) = 32",
            name="ck_aeterna_device_bindings_challenge_length",
        ),
        sa.CheckConstraint(
            "octet_length(request_digest) = 32",
            name="ck_aeterna_device_bindings_request_digest_length",
        ),
        sa.CheckConstraint(
            "state IN ('active', 'pending', 'cancelled', 'expired')",
            name="ck_aeterna_device_bindings_state",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"], ["aeterna_accounts.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "account_id",
            "proposed_device_id",
            name="uq_aeterna_device_bindings_account_device",
        ),
        sa.UniqueConstraint("request_id", name="uq_aeterna_device_bindings_request_id"),
    )
    op.create_index(
        op.f("ix_aeterna_device_bindings_account_id"),
        "aeterna_device_bindings",
        ["account_id"],
        unique=False,
    )

    op.create_table(
        "aeterna_account_challenges",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("request_id", sa.UUID(), nullable=False),
        sa.Column("request_digest", sa.LargeBinary(), nullable=False),
        sa.Column("purpose", sa.String(length=64), nullable=False),
        sa.Column("account_id", sa.UUID(), nullable=True),
        sa.Column("binding_id", sa.UUID(), nullable=True),
        sa.Column("email_lookup", sa.LargeBinary(), nullable=False),
        sa.Column("email_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("email_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("email_key_version", sa.Integer(), nullable=False),
        sa.Column("otp_verifier", sa.LargeBinary(), nullable=False),
        sa.Column("ip_lookup", sa.LargeBinary(), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("resend_after", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("delivery_status", sa.String(length=16), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "purpose IN ('account_onboarding', 'device_binding', "
            "'device_binding_cancellation', 'device_binding_delayed_confirmation')",
            name="ck_aeterna_account_challenges_purpose",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'consumed', 'exhausted', 'expired')",
            name="ck_aeterna_account_challenges_status",
        ),
        sa.CheckConstraint(
            "delivery_status IN ('pending', 'sent', 'failed')",
            name="ck_aeterna_account_challenges_delivery_status",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0 AND attempt_count <= 5",
            name="ck_aeterna_account_challenges_attempt_count",
        ),
        sa.CheckConstraint(
            "octet_length(email_lookup) = 32",
            name="ck_aeterna_account_challenges_email_lookup_length",
        ),
        sa.CheckConstraint(
            "octet_length(email_nonce) = 12",
            name="ck_aeterna_account_challenges_email_nonce_length",
        ),
        sa.CheckConstraint(
            "octet_length(otp_verifier) = 32",
            name="ck_aeterna_account_challenges_otp_verifier_length",
        ),
        sa.CheckConstraint(
            "octet_length(ip_lookup) = 32",
            name="ck_aeterna_account_challenges_ip_lookup_length",
        ),
        sa.CheckConstraint(
            "octet_length(request_digest) = 32",
            name="ck_aeterna_account_challenges_request_digest_length",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"], ["aeterna_accounts.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["binding_id"], ["aeterna_device_bindings.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "request_id", name="uq_aeterna_account_challenges_request_id"
        ),
    )
    for column_name in ("account_id", "binding_id", "email_lookup", "ip_lookup"):
        op.create_index(
            op.f(f"ix_aeterna_account_challenges_{column_name}"),
            "aeterna_account_challenges",
            [column_name],
            unique=False,
        )

    op.create_table(
        "aeterna_binding_grants",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("challenge_id", sa.UUID(), nullable=False),
        sa.Column("account_id", sa.UUID(), nullable=False),
        sa.Column("purpose", sa.String(length=64), nullable=False),
        sa.Column("binding_id", sa.UUID(), nullable=True),
        sa.Column("token_digest", sa.LargeBinary(), nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        *_timestamps(),
        sa.CheckConstraint(
            "purpose IN ('account_onboarding', 'device_binding', "
            "'device_binding_cancellation', 'device_binding_delayed_confirmation')",
            name="ck_aeterna_binding_grants_purpose",
        ),
        sa.CheckConstraint(
            "octet_length(token_digest) = 32",
            name="ck_aeterna_binding_grants_token_digest_length",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"], ["aeterna_accounts.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["binding_id"], ["aeterna_device_bindings.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["challenge_id"], ["aeterna_account_challenges.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "challenge_id", name="uq_aeterna_binding_grants_challenge_id"
        ),
        sa.UniqueConstraint(
            "token_digest", name="uq_aeterna_binding_grants_token_digest"
        ),
    )
    op.create_index(
        op.f("ix_aeterna_binding_grants_account_id"),
        "aeterna_binding_grants",
        ["account_id"],
        unique=False,
    )

    op.create_table(
        "aeterna_protocol_idempotency",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("account_id", sa.UUID(), nullable=False),
        sa.Column("operation", sa.String(length=64), nullable=False),
        sa.Column("request_id", sa.UUID(), nullable=False),
        sa.Column("request_digest", sa.LargeBinary(), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=False),
        sa.Column("response_data", sa.JSON(), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "octet_length(request_digest) = 32",
            name="ck_aeterna_protocol_idempotency_request_digest_length",
        ),
        sa.CheckConstraint(
            "http_status >= 200 AND http_status <= 599",
            name="ck_aeterna_protocol_idempotency_http_status",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"], ["aeterna_accounts.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "operation",
            "request_id",
            name="uq_aeterna_protocol_idempotency_operation_request",
        ),
    )
    op.create_index(
        op.f("ix_aeterna_protocol_idempotency_account_id"),
        "aeterna_protocol_idempotency",
        ["account_id"],
        unique=False,
    )

    op.create_table(
        "aeterna_security_audit",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("account_id", sa.UUID(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("request_id", sa.UUID(), nullable=False),
        sa.Column("binding_id", sa.UUID(), nullable=True),
        sa.Column("device_id", sa.UUID(), nullable=True),
        *_timestamps(),
        sa.CheckConstraint(
            "event_type IN ('account.created', 'device.binding_requested', "
            "'device.bound', 'device.binding_cancelled')",
            name="ck_aeterna_security_audit_event_type",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"], ["aeterna_accounts.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_aeterna_security_audit_account_id"),
        "aeterna_security_audit",
        ["account_id"],
        unique=False,
    )


def downgrade() -> None:
    """Remove only the isolated I09 tables."""
    op.drop_index(
        op.f("ix_aeterna_security_audit_account_id"),
        table_name="aeterna_security_audit",
    )
    op.drop_table("aeterna_security_audit")
    op.drop_index(
        op.f("ix_aeterna_protocol_idempotency_account_id"),
        table_name="aeterna_protocol_idempotency",
    )
    op.drop_table("aeterna_protocol_idempotency")
    op.drop_index(
        op.f("ix_aeterna_binding_grants_account_id"),
        table_name="aeterna_binding_grants",
    )
    op.drop_table("aeterna_binding_grants")
    for column_name in ("ip_lookup", "email_lookup", "binding_id", "account_id"):
        op.drop_index(
            op.f(f"ix_aeterna_account_challenges_{column_name}"),
            table_name="aeterna_account_challenges",
        )
    op.drop_table("aeterna_account_challenges")
    op.drop_index(
        op.f("ix_aeterna_device_bindings_account_id"),
        table_name="aeterna_device_bindings",
    )
    op.drop_table("aeterna_device_bindings")
    op.drop_index(op.f("ix_aeterna_devices_account_id"), table_name="aeterna_devices")
    op.drop_table("aeterna_devices")
    op.drop_table("aeterna_accounts")
