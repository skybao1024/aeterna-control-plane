"""Vault-scoped recipient rotations, separate from Owner policy generations."""

from sqlalchemy import (
    TIMESTAMP,
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

from app.models.base import BaseModel


class AeternaRecipientRecoveryRotation(BaseModel):
    """Durable encrypted successor material for one historical source Vault."""

    __tablename__ = "aeterna_recipient_recovery_rotations"
    __table_args__ = (
        Index(
            "uq_aeterna_recipient_rotation_live_source",
            "source_recovery_id",
            unique=True,
            postgresql_where=text("state <> 'abandoned'"),
        ),
        UniqueConstraint(
            "target_recovery_id", name="uq_aeterna_recipient_rotation_target"
        ),
        UniqueConstraint(
            "secret_request_id", name="uq_aeterna_recipient_rotation_secret_request"
        ),
        CheckConstraint(
            "state IN ('reserved', 'provisioned', 'prepared', 'complete', 'abandoned')",
            name="ck_aeterna_recipient_rotation_state",
        ),
        CheckConstraint(
            "source_policy_epoch > 0 AND source_generation > 0 "
            "AND target_generation = 1",
            name="ck_aeterna_recipient_rotation_generations",
        ),
        CheckConstraint(
            "octet_length(source_wrapper_digest) = 32 "
            "AND octet_length(secret_request_digest) = 32 "
            "AND (erc_commitment IS NULL OR octet_length(erc_commitment) = 32) "
            "AND (target_wrapper_digest IS NULL "
            "OR octet_length(target_wrapper_digest) = 32)",
            name="ck_aeterna_recipient_rotation_digests",
        ),
        CheckConstraint(
            "encrypted_srs IS NULL OR octet_length(encrypted_srs) BETWEEN 1 AND 8192",
            name="ck_aeterna_recipient_rotation_ciphertext",
        ),
        CheckConstraint(
            "(state = 'reserved' AND target_recovery_id IS NULL "
            "AND encrypted_srs IS NULL AND erc_commitment IS NULL "
            "AND target_wrapper_digest IS NULL) OR "
            "(state = 'provisioned' AND target_recovery_id IS NOT NULL "
            "AND encrypted_srs IS NOT NULL AND erc_commitment IS NOT NULL "
            "AND target_wrapper_digest IS NULL) OR "
            "(state IN ('prepared', 'complete') AND target_recovery_id IS NOT NULL "
            "AND encrypted_srs IS NOT NULL AND erc_commitment IS NOT NULL "
            "AND target_wrapper_digest IS NOT NULL AND prepared_at IS NOT NULL) OR "
            "(state = 'abandoned' AND abandoned_at IS NOT NULL)",
            name="ck_aeterna_recipient_rotation_material_state",
        ),
        CheckConstraint(
            "(state = 'complete' AND completed_at IS NOT NULL) OR "
            "(state <> 'complete' AND completed_at IS NULL)",
            name="ck_aeterna_recipient_rotation_completed_at",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True)
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    contact_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_contacts.id", ondelete="CASCADE"),
        nullable=False,
    )
    grant_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_recovery_grants.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_devices.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_recovery_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_recovery_records.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    vault_id = Column(UUID(as_uuid=True), nullable=False)
    source_policy_epoch = Column(Integer, nullable=False)
    source_generation = Column(Integer, nullable=False)
    source_wrapper_digest = Column(LargeBinary, nullable=False)
    target_recovery_id = Column(UUID(as_uuid=True), nullable=True)
    target_generation = Column(Integer, nullable=False, default=1)
    erc_commitment = Column(LargeBinary, nullable=True)
    target_wrapper_digest = Column(LargeBinary, nullable=True)
    state = Column(String(16), nullable=False)
    encrypted_srs = Column(LargeBinary, nullable=True)
    kms_provider = Column(String(32), nullable=True)
    kms_key_arn = Column(String(512), nullable=True)
    kms_key_material_id = Column(String(512), nullable=True)
    secret_request_id = Column(UUID(as_uuid=True), nullable=False)
    secret_request_digest = Column(LargeBinary, nullable=False)
    prepared_at = Column(TIMESTAMP(timezone=True), nullable=True)
    management_alias_id = Column(
        UUID(as_uuid=True),
        ForeignKey(
            "aeterna_management_aliases.id",
            ondelete="RESTRICT",
            use_alter=True,
            name="fk_aeterna_recipient_rotation_management_alias",
        ),
        nullable=True,
    )
    completed_at = Column(TIMESTAMP(timezone=True), nullable=True)
    abandoned_at = Column(TIMESTAMP(timezone=True), nullable=True)
