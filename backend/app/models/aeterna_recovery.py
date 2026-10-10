"""Persistent delayed-recovery records and one-time claim capabilities."""

import uuid

from sqlalchemy import (
    TIMESTAMP,
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


class AeternaRecoveryRecord(BaseModel):
    """One device-bound encrypted SRS and confirmed local-wrapper binding."""

    __tablename__ = "aeterna_recovery_records"
    __table_args__ = (
        Index(
            "uq_aeterna_recovery_records_live_device_vault",
            "account_id",
            "device_id",
            "vault_id",
            "policy_epoch",
            "recovery_generation",
            unique=True,
            postgresql_where=text("state IN ('pending_confirmation', 'sealed')"),
        ),
        UniqueConstraint(
            "provision_request_id",
            name="uq_aeterna_recovery_records_provision_request",
        ),
        CheckConstraint(
            "state IN ('pending_confirmation', 'sealed', 'abandoned', 'expired', "
            "'revoked')",
            name="ck_aeterna_recovery_records_state",
        ),
        CheckConstraint(
            "octet_length(encrypted_srs) BETWEEN 1 AND 8192",
            name="ck_aeterna_recovery_records_ciphertext_length",
        ),
        CheckConstraint(
            "octet_length(provision_request_digest) = 32",
            name="ck_aeterna_recovery_records_request_digest_length",
        ),
        CheckConstraint(
            "wrapper_digest IS NULL OR octet_length(wrapper_digest) = 32",
            name="ck_aeterna_recovery_records_wrapper_digest_length",
        ),
        CheckConstraint(
            "erc_commitment IS NULL OR octet_length(erc_commitment) = 32",
            name="ck_aeterna_recovery_records_erc_commitment_length",
        ),
        CheckConstraint(
            "kms_context_version = 1 AND crypto_format_version = 1 "
            "AND recovery_context_version = 1",
            name="ck_aeterna_recovery_records_versions",
        ),
        CheckConstraint(
            "(state = 'pending_confirmation' AND wrapper_digest IS NULL "
            "AND confirmed_at IS NULL AND abandoned_at IS NULL) OR "
            "(state = 'sealed' AND wrapper_digest IS NOT NULL "
            "AND confirmed_at IS NOT NULL AND abandoned_at IS NULL) OR "
            "(state IN ('abandoned', 'expired', 'revoked') "
            "AND abandoned_at IS NOT NULL)",
            name="ck_aeterna_recovery_records_state_timestamps",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True)
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    vault_id = Column(UUID(as_uuid=True), nullable=False)
    policy_epoch = Column(Integer, nullable=False, default=1)
    recovery_generation = Column(Integer, nullable=False, default=1)
    state = Column(String(24), nullable=False)
    encrypted_srs = Column(LargeBinary, nullable=False)
    kms_provider = Column(String(32), nullable=False)
    kms_key_arn = Column(String(512), nullable=False)
    kms_key_material_id = Column(String(512), nullable=False)
    kms_context_version = Column(Integer, nullable=False)
    crypto_format_version = Column(Integer, nullable=False)
    recovery_context_version = Column(Integer, nullable=False)
    wrapper_digest = Column(LargeBinary, nullable=True)
    erc_commitment = Column(LargeBinary, nullable=True)
    provision_request_id = Column(UUID(as_uuid=True), nullable=False)
    provision_request_digest = Column(LargeBinary, nullable=False)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    confirmed_at = Column(TIMESTAMP(timezone=True), nullable=True)
    abandoned_at = Column(TIMESTAMP(timezone=True), nullable=True)


class AeternaRecoveryGrant(BaseModel):
    """Independent one-time authority for one verified recovery contact."""

    __tablename__ = "aeterna_recovery_grants"
    __table_args__ = (
        UniqueConstraint(
            "recovery_id",
            "contact_id",
            name="uq_aeterna_recovery_grants_record_contact",
        ),
        CheckConstraint(
            "state IN ('available', 'claimed', 'revoked')",
            name="ck_aeterna_recovery_grants_state",
        ),
        CheckConstraint(
            "(state = 'claimed' AND claimed_at IS NOT NULL) OR "
            "(state <> 'claimed' AND claimed_at IS NULL)",
            name="ck_aeterna_recovery_grants_claimed_at",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    recovery_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_recovery_records.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    contact_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_contacts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    state = Column(String(16), nullable=False)
    released_at = Column(TIMESTAMP(timezone=True), nullable=False)
    claimed_at = Column(TIMESTAMP(timezone=True), nullable=True)


class AeternaRecoveryClaimLink(BaseModel):
    """Digest-only, fragment-carried contact claim link."""

    __tablename__ = "aeterna_recovery_claim_links"
    __table_args__ = (
        UniqueConstraint(
            "token_digest", name="uq_aeterna_recovery_claim_links_token_digest"
        ),
        CheckConstraint(
            "octet_length(token_digest) = 32",
            name="ck_aeterna_recovery_claim_links_token_digest_length",
        ),
        CheckConstraint(
            "status IN ('active', 'consumed', 'expired', 'revoked')",
            name="ck_aeterna_recovery_claim_links_status",
        ),
        CheckConstraint(
            "token_key_version > 0",
            name="ck_aeterna_recovery_claim_links_key_version",
        ),
        CheckConstraint(
            "(status = 'active' AND consumed_at IS NULL) OR "
            "(status <> 'active' AND consumed_at IS NOT NULL)",
            name="ck_aeterna_recovery_claim_links_consumed_at",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    grant_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_recovery_grants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_digest = Column(LargeBinary, nullable=False)
    token_key_version = Column(Integer, nullable=False)
    status = Column(String(16), nullable=False)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    consumed_at = Column(TIMESTAMP(timezone=True), nullable=True)


class AeternaRecoveryOtpChallenge(BaseModel):
    """Keyed OTP verifier scoped to one live claim link."""

    __tablename__ = "aeterna_recovery_otp_challenges"
    __table_args__ = (
        CheckConstraint(
            "octet_length(otp_verifier) = 32",
            name="ck_aeterna_recovery_otp_challenges_verifier_length",
        ),
        CheckConstraint(
            "status IN ('active', 'verified', 'expired', 'locked')",
            name="ck_aeterna_recovery_otp_challenges_status",
        ),
        CheckConstraint(
            "attempt_count BETWEEN 0 AND 5",
            name="ck_aeterna_recovery_otp_challenges_attempt_count",
        ),
        CheckConstraint(
            "otp_key_version > 0",
            name="ck_aeterna_recovery_otp_challenges_key_version",
        ),
        CheckConstraint(
            "scope IN ('recovery.srs.read', 'recovery.recipient.rotate')",
            name="ck_aeterna_recovery_otp_challenges_scope",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    link_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_recovery_claim_links.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    otp_verifier = Column(LargeBinary, nullable=False)
    otp_key_version = Column(Integer, nullable=False)
    scope = Column(
        String(32),
        nullable=False,
        default="recovery.srs.read",
        server_default="recovery.srs.read",
    )
    attempt_count = Column(Integer, nullable=False, default=0)
    status = Column(String(16), nullable=False)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    resend_after = Column(TIMESTAMP(timezone=True), nullable=False)
    verified_at = Column(TIMESTAMP(timezone=True), nullable=True)


class AeternaRecoveryClaimToken(BaseModel):
    """Digest-only short-lived capability for a bound recovery operation."""

    __tablename__ = "aeterna_recovery_claim_tokens"
    __table_args__ = (
        UniqueConstraint(
            "token_digest", name="uq_aeterna_recovery_claim_tokens_token_digest"
        ),
        CheckConstraint(
            "octet_length(token_digest) = 32",
            name="ck_aeterna_recovery_claim_tokens_digest_length",
        ),
        CheckConstraint(
            "octet_length(wrapper_digest) = 32",
            name="ck_aeterna_recovery_claim_tokens_wrapper_digest_length",
        ),
        CheckConstraint(
            "scope IN ('recovery.srs.read', 'recovery.recipient.rotate')",
            name="ck_aeterna_recovery_claim_tokens_scope",
        ),
        CheckConstraint(
            "status IN ('active', 'consumed', 'expired')",
            name="ck_aeterna_recovery_claim_tokens_status",
        ),
        CheckConstraint(
            "(status = 'active' AND consumed_at IS NULL) OR "
            "(status <> 'active' AND consumed_at IS NOT NULL)",
            name="ck_aeterna_recovery_claim_tokens_consumed_at",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    grant_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_recovery_grants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=False,
    )
    contact_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_contacts.id", ondelete="CASCADE"),
        nullable=False,
    )
    recovery_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_recovery_records.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_devices.id", ondelete="CASCADE"),
        nullable=False,
    )
    vault_id = Column(UUID(as_uuid=True), nullable=False)
    wrapper_digest = Column(LargeBinary, nullable=False)
    token_digest = Column(LargeBinary, nullable=False)
    scope = Column(String(32), nullable=False)
    status = Column(String(16), nullable=False)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    consumed_at = Column(TIMESTAMP(timezone=True), nullable=True)


class AeternaRecoveryAudit(BaseModel):
    """Immutable redacted recovery authorization event."""

    __tablename__ = "aeterna_recovery_audit"
    __table_args__ = (
        CheckConstraint(
            "event_type IN ('record.provisioned', 'record.confirmed', "
            "'record.abandoned', 'grant.created', 'claim.started', "
            "'claim.verified', 'secret.released', 'owner.started', "
            "'owner.verified', 'owner.cancelled', 'owner.released', "
            "'owner.completed', 'rotation.provisioned', 'rotation.activated', "
            "'rotation.device_completed', 'rotation.completed', "
            "'recipient.reserved', 'recipient.provisioned', 'recipient.prepared', "
            "'recipient.completed', 'recipient.abandoned')",
            name="ck_aeterna_recovery_audit_event_type",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    recovery_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    contact_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    grant_id = Column(UUID(as_uuid=True), nullable=True)
    request_id = Column(UUID(as_uuid=True), nullable=True)
    event_type = Column(String(32), nullable=False)
    status = Column(String(24), nullable=False)


class AeternaOwnerRecoveryRequest(BaseModel):
    """Email-verified owner recovery with a cancellable cooldown."""

    __tablename__ = "aeterna_owner_recovery_requests"
    __table_args__ = (
        UniqueConstraint(
            "start_request_id", name="uq_aeterna_owner_recovery_start_request"
        ),
        CheckConstraint(
            "state IN ('pending_email', 'cooling_down', 'material_released', "
            "'completed', 'cancelled', 'expired')",
            name="ck_aeterna_owner_recovery_state",
        ),
        CheckConstraint(
            "octet_length(start_request_digest) = 32 AND "
            "octet_length(wrapper_digest) = 32 AND octet_length(otp_verifier) = 32",
            name="ck_aeterna_owner_recovery_digest_lengths",
        ),
        CheckConstraint(
            "attempt_count BETWEEN 0 AND 5 AND otp_key_version > 0",
            name="ck_aeterna_owner_recovery_otp_bounds",
        ),
        Index(
            "uq_aeterna_owner_recovery_live_account",
            "account_id",
            unique=True,
            postgresql_where=text(
                "state IN ('pending_email', 'cooling_down', 'material_released')"
            ),
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    recovery_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_recovery_records.id", ondelete="CASCADE"),
        nullable=False,
    )
    vault_id = Column(UUID(as_uuid=True), nullable=False)
    policy_epoch = Column(Integer, nullable=False)
    recovery_generation = Column(Integer, nullable=False)
    rekey_required = Column(Boolean, nullable=False, default=False)
    wrapper_digest = Column(LargeBinary, nullable=False)
    state = Column(String(24), nullable=False)
    start_request_id = Column(UUID(as_uuid=True), nullable=False)
    start_request_digest = Column(LargeBinary, nullable=False)
    challenge_id = Column(UUID(as_uuid=True), nullable=False, unique=True)
    otp_verifier = Column(LargeBinary, nullable=False)
    otp_key_version = Column(Integer, nullable=False)
    attempt_count = Column(Integer, nullable=False, default=0)
    challenge_expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    ready_at = Column(TIMESTAMP(timezone=True), nullable=True)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    verified_at = Column(TIMESTAMP(timezone=True), nullable=True)
    released_at = Column(TIMESTAMP(timezone=True), nullable=True)
    completed_at = Column(TIMESTAMP(timezone=True), nullable=True)
    cancelled_at = Column(TIMESTAMP(timezone=True), nullable=True)


class AeternaRecoveryRotation(BaseModel):
    """One generation or post-compromise policy-epoch rotation."""

    __tablename__ = "aeterna_recovery_rotations"
    __table_args__ = (
        UniqueConstraint(
            "provision_request_id", name="uq_aeterna_recovery_rotation_request"
        ),
        CheckConstraint(
            "kind IN ('erc_rotation', 'post_compromise')",
            name="ck_aeterna_recovery_rotation_kind",
        ),
        CheckConstraint(
            "state IN ('preparing', 'active', 'complete', 'cancelled')",
            name="ck_aeterna_recovery_rotation_state",
        ),
        CheckConstraint(
            "target_generation = source_generation + 1 AND "
            "target_policy_epoch >= source_policy_epoch",
            name="ck_aeterna_recovery_rotation_targets",
        ),
        Index(
            "uq_aeterna_recovery_rotations_live_account",
            "account_id",
            unique=True,
            postgresql_where=text("state IN ('preparing', 'active')"),
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True)
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    initiating_device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_devices.id", ondelete="CASCADE"),
        nullable=False,
    )
    recovery_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_recovery_records.id", ondelete="CASCADE"),
        nullable=False,
    )
    owner_recovery_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_owner_recovery_requests.id", ondelete="RESTRICT"),
        nullable=True,
    )
    vault_id = Column(UUID(as_uuid=True), nullable=False)
    kind = Column(String(24), nullable=False)
    state = Column(String(16), nullable=False)
    source_policy_epoch = Column(Integer, nullable=False)
    target_policy_epoch = Column(Integer, nullable=False)
    source_generation = Column(Integer, nullable=False)
    target_generation = Column(Integer, nullable=False)
    provision_request_id = Column(UUID(as_uuid=True), nullable=False)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    activated_at = Column(TIMESTAMP(timezone=True), nullable=True)
    completed_at = Column(TIMESTAMP(timezone=True), nullable=True)


class AeternaRecoveryRotationDevice(BaseModel):
    """Per-device wrapper completion state for a recovery rotation."""

    __tablename__ = "aeterna_recovery_rotation_devices"
    __table_args__ = (
        UniqueConstraint("rotation_id", "device_id", name="uq_aeterna_rotation_device"),
        UniqueConstraint("recovery_id", name="uq_aeterna_rotation_device_recovery"),
        CheckConstraint(
            "state IN ('pending', 'not_enrolled', 'complete', 'excluded')",
            name="ck_aeterna_rotation_device_state",
        ),
        CheckConstraint(
            "wrapper_digest IS NULL OR octet_length(wrapper_digest) = 32",
            name="ck_aeterna_rotation_device_wrapper_digest",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rotation_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_recovery_rotations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    recovery_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_recovery_records.id", ondelete="RESTRICT"),
        nullable=True,
    )
    state = Column(String(16), nullable=False)
    wrapper_digest = Column(LargeBinary, nullable=True)
    completed_at = Column(TIMESTAMP(timezone=True), nullable=True)
