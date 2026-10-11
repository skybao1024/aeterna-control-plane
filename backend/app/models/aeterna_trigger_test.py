"""Independent test resources never confer production policy or recovery authority."""

import uuid

from sqlalchemy import (
    JSON,
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


class AeternaTriggerTest(BaseModel):
    """A bounded session owns timing, isolated factors, capabilities and evidence."""

    __tablename__ = "aeterna_trigger_tests"
    __table_args__ = (
        UniqueConstraint("create_request_id", name="uq_trigger_test_create_request"),
        Index(
            "uq_trigger_test_active_device",
            "account_id",
            "device_id",
            unique=True,
            postgresql_where=text("state NOT IN ('COMPLETE', 'STOPPED', 'EXPIRED')"),
        ),
        CheckConstraint(
            "state IN ('PREPARING', 'ACTIVE', 'PRE_WARNING', 'GRACE_PERIOD', "
            "'RELEASED', 'COMPLETE', 'STOPPED', 'EXPIRED')",
            name="ck_trigger_test_state",
        ),
        CheckConstraint("locale IN ('en', 'zh-CN')", name="ck_trigger_test_locale"),
        CheckConstraint("version >= 0", name="ck_trigger_test_version"),
        CheckConstraint(
            "octet_length(create_request_digest) = 32", name="ck_trigger_test_digest"
        ),
        CheckConstraint(
            "(source_ciphertext IS NULL) = (source_nonce IS NULL)",
            name="ck_trigger_test_source_pair",
        ),
        CheckConstraint(
            "(target_ciphertext IS NULL) = (target_nonce IS NULL)",
            name="ck_trigger_test_target_pair",
        ),
    )
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    device_id = Column(UUID(as_uuid=True), nullable=False)
    contact_id = Column(UUID(as_uuid=True), nullable=True)
    locale = Column(String(16), nullable=False)
    include_recovery = Column(Boolean, nullable=False)
    state = Column(String(24), nullable=False)
    version = Column(Integer, nullable=False, default=0)
    create_request_id = Column(UUID(as_uuid=True), nullable=False)
    create_request_digest = Column(LargeBinary, nullable=False)
    operation_receipts = Column(JSON, nullable=False, default=dict)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    started_at = Column(TIMESTAMP(timezone=True), nullable=True)
    due_at = Column(TIMESTAMP(timezone=True), nullable=True)
    warning_started_at = Column(TIMESTAMP(timezone=True), nullable=True)
    owner_warning_proven_at = Column(TIMESTAMP(timezone=True), nullable=True)
    grace_started_at = Column(TIMESTAMP(timezone=True), nullable=True)
    released_at = Column(TIMESTAMP(timezone=True), nullable=True)
    stopped_at = Column(TIMESTAMP(timezone=True), nullable=True)
    stop_reason = Column(String(24), nullable=True)
    activity_resumed_at = Column(TIMESTAMP(timezone=True), nullable=True)
    recipient_verified_at = Column(TIMESTAMP(timezone=True), nullable=True)
    sample_rotated_at = Column(TIMESTAMP(timezone=True), nullable=True)
    completed_at = Column(TIMESTAMP(timezone=True), nullable=True)
    sample_vault_id = Column(UUID(as_uuid=True), nullable=True)
    source_recovery_id = Column(UUID(as_uuid=True), nullable=True)
    source_wrapper_digest = Column(LargeBinary, nullable=True)
    source_ciphertext = Column(LargeBinary, nullable=True)
    source_nonce = Column(LargeBinary, nullable=True)
    target_recovery_id = Column(UUID(as_uuid=True), nullable=True)
    target_wrapper_digest = Column(LargeBinary, nullable=True)
    target_ciphertext = Column(LargeBinary, nullable=True)
    target_nonce = Column(LargeBinary, nullable=True)
    factor_key_version = Column(Integer, nullable=True)
    owner_ciphertext = Column(LargeBinary, nullable=False)
    owner_nonce = Column(LargeBinary, nullable=False)
    recipient_ciphertext = Column(LargeBinary, nullable=False)
    recipient_nonce = Column(LargeBinary, nullable=False)
    email_key_version = Column(Integer, nullable=False)
    notice_verifier = Column(LargeBinary, nullable=True)
    notice_ciphertext = Column(LargeBinary, nullable=True)
    notice_nonce = Column(LargeBinary, nullable=True)
    claim_verifier = Column(LargeBinary, nullable=True)
    claim_expires_at = Column(TIMESTAMP(timezone=True), nullable=True)


class AeternaTriggerTestChallenge(BaseModel):
    """Purpose-bound mailbox proof that cannot authorize any production operation."""

    __tablename__ = "aeterna_trigger_test_challenges"
    __table_args__ = (
        CheckConstraint(
            "purpose IN ('warning', 'recipient')",
            name="ck_trigger_test_challenge_purpose",
        ),
        CheckConstraint(
            "status IN ('pending', 'verified', 'expired', 'locked')",
            name="ck_trigger_test_challenge_status",
        ),
        CheckConstraint(
            "attempt_count BETWEEN 0 AND 5", name="ck_trigger_test_challenge_attempts"
        ),
        CheckConstraint(
            "octet_length(verifier) = 32 AND octet_length(code_nonce) = 12",
            name="ck_trigger_test_challenge_material",
        ),
    )
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    test_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_trigger_tests.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    purpose = Column(String(16), nullable=False)
    status = Column(String(16), nullable=False)
    verifier = Column(LargeBinary, nullable=False)
    code_ciphertext = Column(LargeBinary, nullable=False)
    code_nonce = Column(LargeBinary, nullable=False)
    key_version = Column(Integer, nullable=False)
    attempt_count = Column(Integer, nullable=False, default=0)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    verified_at = Column(TIMESTAMP(timezone=True), nullable=True)


class AeternaTriggerTestMail(BaseModel):
    """Disjoint test mail authority and honest durable provider outcomes."""

    __tablename__ = "aeterna_trigger_test_mail"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_trigger_test_mail_key"),
        CheckConstraint(
            "kind IN ('warning', 'notice', 'warning-code', 'recipient-code')",
            name="ck_trigger_test_mail_kind",
        ),
        CheckConstraint(
            "status IN ('queued', 'sending', 'provider_accepted', 'failed', 'ambiguous', 'cancelled')",
            name="ck_trigger_test_mail_status",
        ),
        CheckConstraint(
            "attempt_count BETWEEN 0 AND 3", name="ck_trigger_test_mail_attempts"
        ),
    )
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    test_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_trigger_tests.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    challenge_id = Column(UUID(as_uuid=True), nullable=True)
    kind = Column(String(24), nullable=False)
    status = Column(String(24), nullable=False)
    idempotency_key = Column(String(128), nullable=False)
    attempt_count = Column(Integer, nullable=False, default=0)
    sending_at = Column(TIMESTAMP(timezone=True), nullable=True)
    accepted_at = Column(TIMESTAMP(timezone=True), nullable=True)
    last_error_code = Column(String(64), nullable=True)
    provider_name = Column(String(64), nullable=True)
    provider_message_id = Column(String(256), nullable=True)
