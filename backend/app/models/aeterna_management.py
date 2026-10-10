"""Encrypted successful-recipient mailbox aliases and custody freshness."""

from sqlalchemy import (
    TIMESTAMP,
    Boolean,
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import UUID

from app.models.base import BaseModel


class AeternaManagementAlias(BaseModel):
    """A durable mailbox snapshot authorizing one transferred account."""

    __tablename__ = "aeterna_management_aliases"
    __table_args__ = (
        UniqueConstraint(
            "account_id", "email_lookup", name="uq_aeterna_management_alias_mailbox"
        ),
        Index(
            "uq_aeterna_management_primary",
            "account_id",
            unique=True,
            postgresql_where=text("is_primary"),
        ),
        CheckConstraint(
            "octet_length(email_lookup) = 32 AND octet_length(email_nonce) = 12 AND email_key_version > 0",
            name="ck_aeterna_management_email",
        ),
    )
    id = Column(UUID(as_uuid=True), primary_key=True)
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    rotation_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_recipient_recovery_rotations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    email_lookup = Column(LargeBinary, nullable=False)
    email_ciphertext = Column(LargeBinary, nullable=False)
    email_nonce = Column(LargeBinary, nullable=False)
    email_key_version = Column(Integer, nullable=False)
    is_primary = Column(Boolean, nullable=False)


class AeternaCustodyChallenge(BaseModel):
    """A five-minute exact-binding challenge and successful replay receipt."""

    __tablename__ = "aeterna_custody_challenges"
    __table_args__ = (
        UniqueConstraint("request_id", name="uq_aeterna_custody_challenge_request"),
        UniqueConstraint(
            "verified_request_id", name="uq_aeterna_custody_verified_request"
        ),
        CheckConstraint(
            "octet_length(challenge) = 32 AND octet_length(wrapper_digest) = 32 AND octet_length(request_digest) = 32",
            name="ck_aeterna_custody_challenge_digests",
        ),
        CheckConstraint(
            "(consumed_at IS NULL AND verified_request_id IS NULL AND verified_digest IS NULL AND verified IS NULL) OR (consumed_at IS NOT NULL AND verified_request_id IS NOT NULL AND verified_digest IS NOT NULL AND octet_length(verified_digest) = 32 AND verified IS NOT NULL)",
            name="ck_aeterna_custody_consumed",
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
    )
    vault_id = Column(UUID(as_uuid=True), nullable=False)
    recovery_id = Column(UUID(as_uuid=True), nullable=False)
    wrapper_digest = Column(LargeBinary, nullable=False)
    challenge = Column(LargeBinary, nullable=False)
    request_id = Column(UUID(as_uuid=True), nullable=False)
    request_digest = Column(LargeBinary, nullable=False)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False, index=True)
    consumed_at = Column(TIMESTAMP(timezone=True), nullable=True)
    verified_request_id = Column(UUID(as_uuid=True), nullable=True)
    verified_digest = Column(LargeBinary, nullable=True)
    verified = Column(Boolean, nullable=True)
