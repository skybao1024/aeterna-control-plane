"""Persistence models for Aeterna account and device identity protocol v1."""

import uuid

from sqlalchemy import (
    JSON,
    TIMESTAMP,
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import UUID

from .base import BaseModel


class AeternaAccount(BaseModel):
    """An Aeterna account whose mailbox identity is encrypted at rest."""

    __tablename__ = "aeterna_accounts"
    __table_args__ = (
        UniqueConstraint("email_lookup", name="uq_aeterna_accounts_email_lookup"),
        CheckConstraint(
            "octet_length(email_lookup) = 32",
            name="ck_aeterna_accounts_email_lookup_length",
        ),
        CheckConstraint(
            "octet_length(email_nonce) = 12",
            name="ck_aeterna_accounts_email_nonce_length",
        ),
        CheckConstraint(
            "email_key_version > 0",
            name="ck_aeterna_accounts_email_key_version_positive",
        ),
        CheckConstraint(
            "(erc_commitment IS NULL AND erc_commitment_epoch IS NULL "
            "AND erc_commitment_generation IS NULL) OR "
            "(erc_commitment IS NOT NULL AND erc_commitment_epoch IS NOT NULL "
            "AND erc_commitment_generation IS NOT NULL "
            "AND octet_length(erc_commitment) = 32 AND erc_commitment_epoch > 0 "
            "AND erc_commitment_generation > 0)",
            name="ck_aeterna_accounts_erc_commitment",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_lookup = Column(LargeBinary, nullable=False)
    email_ciphertext = Column(LargeBinary, nullable=False)
    email_nonce = Column(LargeBinary, nullable=False)
    email_key_version = Column(Integer, nullable=False, default=1)
    first_device_bound_at = Column(TIMESTAMP(timezone=True), nullable=True)
    last_activity_at = Column(TIMESTAMP(timezone=True), nullable=True)
    current_policy_epoch = Column(Integer, nullable=False, default=1)
    current_recovery_generation = Column(Integer, nullable=False, default=1)
    erc_commitment = Column(LargeBinary, nullable=True)
    erc_commitment_epoch = Column(Integer, nullable=True)
    erc_commitment_generation = Column(Integer, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)


class AeternaDevice(BaseModel):
    """A bound public signing key and its latest heartbeat eligibility state."""

    __tablename__ = "aeterna_devices"
    __table_args__ = (
        UniqueConstraint(
            "account_id", "public_key", name="uq_aeterna_devices_account_public_key"
        ),
        CheckConstraint(
            "octet_length(public_key) = 32",
            name="ck_aeterna_devices_public_key_length",
        ),
        CheckConstraint(
            "status IN ('active', 'dormant', 'lost', 'revoked')",
            name="ck_aeterna_devices_status",
        ),
        CheckConstraint(
            "last_sequence >= 0 AND last_sequence <= 9007199254740991",
            name="ck_aeterna_devices_last_sequence_range",
        ),
        CheckConstraint(
            "(last_heartbeat_request_id IS NULL) = "
            "(last_heartbeat_request_digest IS NULL)",
            name="ck_aeterna_devices_heartbeat_request_pair",
        ),
        CheckConstraint(
            "last_heartbeat_request_digest IS NULL OR "
            "octet_length(last_heartbeat_request_digest) = 32",
            name="ck_aeterna_devices_heartbeat_digest_length",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True)
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    public_key = Column(LargeBinary, nullable=False)
    label = Column(String(64), nullable=True)
    status = Column(String(16), nullable=False, default="active")
    bound_at = Column(TIMESTAMP(timezone=True), nullable=False)
    heartbeat_authorized_at = Column(TIMESTAMP(timezone=True), nullable=False)
    policy_epoch = Column(Integer, nullable=False, default=1)
    last_sequence = Column(BigInteger, nullable=False, default=0)
    last_seen_at = Column(TIMESTAMP(timezone=True), nullable=True)
    last_heartbeat_request_id = Column(UUID(as_uuid=True), nullable=True)
    last_heartbeat_request_digest = Column(LargeBinary, nullable=True)
    revoked_at = Column(TIMESTAMP(timezone=True), nullable=True)


class AeternaDeviceBinding(BaseModel):
    """One proposed-device binding and its terminal-state evidence."""

    __tablename__ = "aeterna_device_bindings"
    __table_args__ = (
        Index(
            "uq_aeterna_device_bindings_pending_account_device",
            "account_id",
            "proposed_device_id",
            unique=True,
            postgresql_where=text("state = 'pending'"),
        ),
        UniqueConstraint("request_id", name="uq_aeterna_device_bindings_request_id"),
        CheckConstraint(
            "octet_length(public_key) = 32",
            name="ck_aeterna_device_bindings_public_key_length",
        ),
        CheckConstraint(
            "challenge IS NULL OR octet_length(challenge) = 32",
            name="ck_aeterna_device_bindings_challenge_length",
        ),
        CheckConstraint(
            "octet_length(request_digest) = 32",
            name="ck_aeterna_device_bindings_request_digest_length",
        ),
        CheckConstraint(
            "state IN ('active', 'pending', 'cancelled', 'expired')",
            name="ck_aeterna_device_bindings_state",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    proposed_device_id = Column(UUID(as_uuid=True), nullable=False)
    public_key = Column(LargeBinary, nullable=False)
    label = Column(String(64), nullable=True)
    state = Column(String(16), nullable=False)
    challenge = Column(LargeBinary, nullable=True)
    challenge_consumed_at = Column(TIMESTAMP(timezone=True), nullable=True)
    not_before = Column(TIMESTAMP(timezone=True), nullable=True)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    activated_at = Column(TIMESTAMP(timezone=True), nullable=True)
    cancelled_at = Column(TIMESTAMP(timezone=True), nullable=True)
    request_id = Column(UUID(as_uuid=True), nullable=False)
    request_digest = Column(LargeBinary, nullable=False)


class AeternaAccountChallenge(BaseModel):
    """A single mailbox-control challenge without plaintext mailbox storage."""

    __tablename__ = "aeterna_account_challenges"
    __table_args__ = (
        UniqueConstraint("request_id", name="uq_aeterna_account_challenges_request_id"),
        CheckConstraint(
            "purpose IN ('account_onboarding', 'device_binding', "
            "'device_binding_cancellation', 'device_binding_delayed_confirmation')",
            name="ck_aeterna_account_challenges_purpose",
        ),
        CheckConstraint(
            "status IN ('pending', 'consumed', 'exhausted', 'expired')",
            name="ck_aeterna_account_challenges_status",
        ),
        CheckConstraint(
            "delivery_status IN ('pending', 'sent', 'failed')",
            name="ck_aeterna_account_challenges_delivery_status",
        ),
        CheckConstraint(
            "attempt_count >= 0 AND attempt_count <= 5",
            name="ck_aeterna_account_challenges_attempt_count",
        ),
        CheckConstraint(
            "octet_length(email_lookup) = 32",
            name="ck_aeterna_account_challenges_email_lookup_length",
        ),
        CheckConstraint(
            "octet_length(email_nonce) = 12",
            name="ck_aeterna_account_challenges_email_nonce_length",
        ),
        CheckConstraint(
            "octet_length(otp_verifier) = 32",
            name="ck_aeterna_account_challenges_otp_verifier_length",
        ),
        CheckConstraint(
            "octet_length(ip_lookup) = 32",
            name="ck_aeterna_account_challenges_ip_lookup_length",
        ),
        CheckConstraint(
            "octet_length(request_digest) = 32",
            name="ck_aeterna_account_challenges_request_digest_length",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_id = Column(UUID(as_uuid=True), nullable=False)
    request_digest = Column(LargeBinary, nullable=False)
    purpose = Column(String(64), nullable=False)
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    binding_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_device_bindings.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    email_lookup = Column(LargeBinary, nullable=False, index=True)
    email_ciphertext = Column(LargeBinary, nullable=False)
    email_nonce = Column(LargeBinary, nullable=False)
    email_key_version = Column(Integer, nullable=False, default=1)
    otp_verifier = Column(LargeBinary, nullable=False)
    ip_lookup = Column(LargeBinary, nullable=False, index=True)
    attempt_count = Column(Integer, nullable=False, default=0)
    status = Column(String(16), nullable=False, default="pending")
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    resend_after = Column(TIMESTAMP(timezone=True), nullable=False)
    delivery_status = Column(String(16), nullable=False, default="pending")


class AeternaBindingGrant(BaseModel):
    """A short-lived one-use capability issued after mailbox verification."""

    __tablename__ = "aeterna_binding_grants"
    __table_args__ = (
        UniqueConstraint("challenge_id", name="uq_aeterna_binding_grants_challenge_id"),
        UniqueConstraint("token_digest", name="uq_aeterna_binding_grants_token_digest"),
        CheckConstraint(
            "purpose IN ('account_onboarding', 'device_binding', "
            "'device_binding_cancellation', 'device_binding_delayed_confirmation')",
            name="ck_aeterna_binding_grants_purpose",
        ),
        CheckConstraint(
            "octet_length(token_digest) = 32",
            name="ck_aeterna_binding_grants_token_digest_length",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    challenge_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_account_challenges.id", ondelete="CASCADE"),
        nullable=False,
    )
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    purpose = Column(String(64), nullable=False)
    binding_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_device_bindings.id", ondelete="CASCADE"),
        nullable=True,
    )
    token_digest = Column(LargeBinary, nullable=False)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    consumed_at = Column(TIMESTAMP(timezone=True), nullable=True)


class AeternaProtocolIdempotency(BaseModel):
    """A redacted replay record for an authenticated protocol mutation."""

    __tablename__ = "aeterna_protocol_idempotency"
    __table_args__ = (
        UniqueConstraint(
            "operation",
            "request_id",
            name="uq_aeterna_protocol_idempotency_operation_request",
        ),
        CheckConstraint(
            "octet_length(request_digest) = 32",
            name="ck_aeterna_protocol_idempotency_request_digest_length",
        ),
        CheckConstraint(
            "http_status >= 200 AND http_status <= 599",
            name="ck_aeterna_protocol_idempotency_http_status",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    operation = Column(String(64), nullable=False)
    request_id = Column(UUID(as_uuid=True), nullable=False)
    request_digest = Column(LargeBinary, nullable=False)
    http_status = Column(Integer, nullable=False)
    response_data = Column(JSON, nullable=False)


class AeternaSecurityAudit(BaseModel):
    """A redacted account/device security event."""

    __tablename__ = "aeterna_security_audit"
    __table_args__ = (
        CheckConstraint(
            "event_type IN ('account.created', 'device.binding_requested', "
            "'device.bound', 'device.binding_cancelled', 'device.dormant', "
            "'device.lost', 'device.revoked', 'device.reverified')",
            name="ck_aeterna_security_audit_event_type",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type = Column(String(64), nullable=False)
    request_id = Column(UUID(as_uuid=True), nullable=False)
    binding_id = Column(UUID(as_uuid=True), nullable=True)
    device_id = Column(UUID(as_uuid=True), nullable=True)
