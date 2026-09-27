"""Encrypted contacts and redacted email-delivery persistence for Aeterna."""

import uuid

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

from .base import BaseModel


class AeternaContact(BaseModel):
    """An encrypted notification target with an explicit consent boundary."""

    __tablename__ = "aeterna_contacts"
    __table_args__ = (
        Index(
            "uq_aeterna_contacts_active_account_email",
            "account_id",
            "email_lookup",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        CheckConstraint(
            "octet_length(email_lookup) = 32",
            name="ck_aeterna_contacts_email_lookup_length",
        ),
        CheckConstraint(
            "octet_length(email_nonce) = 12",
            name="ck_aeterna_contacts_email_nonce_length",
        ),
        CheckConstraint(
            "email_key_version > 0",
            name="ck_aeterna_contacts_email_key_version_positive",
        ),
        CheckConstraint(
            "disclosure_mode IN ('CONFIRM_NOW', 'PRIVATE_UNTIL_RELEASE')",
            name="ck_aeterna_contacts_disclosure_mode",
        ),
        CheckConstraint(
            "consent_status IN ('NOT_REQUESTED', 'INVITED', 'ACCEPTED', 'DECLINED')",
            name="ck_aeterna_contacts_consent_status",
        ),
        CheckConstraint(
            "(consent_status = 'ACCEPTED' AND accepted_at IS NOT NULL "
            "AND verified_at IS NOT NULL AND declined_at IS NULL) OR "
            "(consent_status = 'DECLINED' AND declined_at IS NOT NULL "
            "AND accepted_at IS NULL AND verified_at IS NULL) OR "
            "(consent_status IN ('NOT_REQUESTED', 'INVITED') "
            "AND accepted_at IS NULL AND declined_at IS NULL "
            "AND verified_at IS NULL)",
            name="ck_aeterna_contacts_consent_timestamps",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    email_lookup = Column(LargeBinary, nullable=False)
    email_ciphertext = Column(LargeBinary, nullable=False)
    email_nonce = Column(LargeBinary, nullable=False)
    email_key_version = Column(Integer, nullable=False, default=1)
    disclosure_mode = Column(String(32), nullable=False)
    consent_status = Column(String(24), nullable=False)
    invitation_sent_at = Column(TIMESTAMP(timezone=True), nullable=True)
    accepted_at = Column(TIMESTAMP(timezone=True), nullable=True)
    declined_at = Column(TIMESTAMP(timezone=True), nullable=True)
    verified_at = Column(TIMESTAMP(timezone=True), nullable=True)
    bounced_at = Column(TIMESTAMP(timezone=True), nullable=True)
    deleted_at = Column(TIMESTAMP(timezone=True), nullable=True)


class AeternaNotificationTemplate(BaseModel):
    """Bounded owner and confirmed-contact text encrypted at rest."""

    __tablename__ = "aeterna_notification_templates"
    __table_args__ = (
        CheckConstraint(
            "octet_length(owner_message_nonce) = 12 "
            "AND octet_length(contact_message_nonce) = 12",
            name="ck_aeterna_notification_templates_nonce_lengths",
        ),
        CheckConstraint(
            "owner_message_key_version > 0 AND contact_message_key_version > 0",
            name="ck_aeterna_notification_templates_key_versions",
        ),
        CheckConstraint(
            "version > 0",
            name="ck_aeterna_notification_templates_version_positive",
        ),
    )

    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        primary_key=True,
    )
    owner_message_ciphertext = Column(LargeBinary, nullable=False)
    owner_message_nonce = Column(LargeBinary, nullable=False)
    owner_message_key_version = Column(Integer, nullable=False)
    contact_message_ciphertext = Column(LargeBinary, nullable=False)
    contact_message_nonce = Column(LargeBinary, nullable=False)
    contact_message_key_version = Column(Integer, nullable=False)
    version = Column(Integer, nullable=False, default=1)


class AeternaContactInvitation(BaseModel):
    """A single-purpose invitation represented only by a token verifier."""

    __tablename__ = "aeterna_contact_invitations"
    __table_args__ = (
        UniqueConstraint(
            "token_digest",
            name="uq_aeterna_contact_invitations_token_digest",
        ),
        CheckConstraint(
            "octet_length(token_digest) = 32",
            name="ck_aeterna_contact_invitations_token_digest_length",
        ),
        CheckConstraint(
            "token_key_version > 0",
            name="ck_aeterna_contact_invitations_token_key_version",
        ),
        CheckConstraint(
            "status IN ('pending', 'accepted', 'declined', 'expired', 'revoked')",
            name="ck_aeterna_contact_invitations_status",
        ),
        CheckConstraint(
            "(status = 'pending' AND consumed_at IS NULL) OR "
            "(status <> 'pending' AND consumed_at IS NOT NULL)",
            name="ck_aeterna_contact_invitations_consumption",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    contact_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_contacts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_digest = Column(LargeBinary, nullable=False)
    token_key_version = Column(Integer, nullable=False)
    status = Column(String(16), nullable=False, default="pending")
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    consumed_at = Column(TIMESTAMP(timezone=True), nullable=True)


class AeternaEmailOutboxEvent(BaseModel):
    """One provider-neutral email intent without plaintext recipient or body."""

    __tablename__ = "aeterna_email_outbox_events"
    __table_args__ = (
        UniqueConstraint(
            "idempotency_key",
            name="uq_aeterna_email_outbox_events_idempotency_key",
        ),
        CheckConstraint(
            "recipient_kind IN ('owner', 'contact')",
            name="ck_aeterna_email_outbox_events_recipient_kind",
        ),
        CheckConstraint(
            "event_type IN ('owner-pre-warning', 'owner-grace-period-started', "
            "'owner-warning-required', 'owner-release-authorized', "
            "'contact-invitation', 'contact-test', 'recovery-claim-link', "
            "'recovery-otp', 'recovery-claimed-owner', "
            "'recovery-claimed-contact')",
            name="ck_aeterna_email_outbox_events_event_type",
        ),
        CheckConstraint(
            "status IN ('queued', 'sending', 'retry_pending', "
            "'provider_accepted', 'delivered', 'bounced', 'complained', 'ambiguous', "
            "'failed', 'cancelled')",
            name="ck_aeterna_email_outbox_events_status",
        ),
        CheckConstraint(
            "attempt_count >= 0",
            name="ck_aeterna_email_outbox_events_attempt_count_nonnegative",
        ),
        CheckConstraint(
            "(recipient_kind = 'owner' AND contact_id IS NULL "
            "AND invitation_id IS NULL AND recovery_link_id IS NULL "
            "AND recovery_challenge_id IS NULL) OR "
            "(recipient_kind = 'contact' AND contact_id IS NOT NULL)",
            name="ck_aeterna_email_outbox_events_recipient_reference",
        ),
        CheckConstraint(
            "(event_type = 'contact-invitation' AND invitation_id IS NOT NULL) OR "
            "(event_type <> 'contact-invitation' AND invitation_id IS NULL)",
            name="ck_aeterna_email_outbox_events_invitation_reference",
        ),
        CheckConstraint(
            "(event_type = 'recovery-claim-link' AND recovery_link_id IS NOT NULL) OR "
            "(event_type <> 'recovery-claim-link' AND recovery_link_id IS NULL)",
            name="ck_aeterna_email_outbox_events_recovery_link_reference",
        ),
        CheckConstraint(
            "(event_type = 'recovery-otp' AND recovery_challenge_id IS NOT NULL) OR "
            "(event_type <> 'recovery-otp' AND recovery_challenge_id IS NULL)",
            name="ck_aeterna_email_outbox_events_recovery_challenge_reference",
        ),
        Index(
            "ix_aeterna_email_outbox_events_dispatch",
            "status",
            "next_attempt_at",
        ),
        Index(
            "uq_aeterna_email_outbox_events_provider_message",
            "provider_name",
            "provider_message_id",
            unique=True,
            postgresql_where=text("provider_message_id IS NOT NULL"),
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    contact_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_contacts.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    invitation_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_contact_invitations.id", ondelete="CASCADE"),
        nullable=True,
    )
    recovery_link_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_recovery_claim_links.id", ondelete="CASCADE"),
        nullable=True,
    )
    recovery_challenge_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_recovery_otp_challenges.id", ondelete="CASCADE"),
        nullable=True,
    )
    source_policy_outbox_id = Column(
        UUID(as_uuid=True),
        ForeignKey("account_policy_outbox_events.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    recipient_kind = Column(String(16), nullable=False)
    event_type = Column(String(64), nullable=False)
    idempotency_key = Column(String(255), nullable=False)
    status = Column(String(24), nullable=False, default="queued")
    next_attempt_at = Column(TIMESTAMP(timezone=True), nullable=False)
    attempt_count = Column(Integer, nullable=False, default=0)
    provider_name = Column(String(64), nullable=True)
    provider_message_id = Column(String(255), nullable=True)
    provider_accepted_at = Column(TIMESTAMP(timezone=True), nullable=True)
    delivered_at = Column(TIMESTAMP(timezone=True), nullable=True)
    bounced_at = Column(TIMESTAMP(timezone=True), nullable=True)
    failed_at = Column(TIMESTAMP(timezone=True), nullable=True)
    cancelled_at = Column(TIMESTAMP(timezone=True), nullable=True)
    last_error_code = Column(String(64), nullable=True)


class AeternaEmailDeliveryAttempt(BaseModel):
    """A redacted external-send attempt using the event's stable provider key."""

    __tablename__ = "aeterna_email_delivery_attempts"
    __table_args__ = (
        UniqueConstraint(
            "outbox_event_id",
            "attempt_number",
            name="uq_aeterna_email_delivery_attempts_event_number",
        ),
        CheckConstraint(
            "status IN ('sending', 'retryable_failure', 'ambiguous_failure', "
            "'failed', 'provider_accepted')",
            name="ck_aeterna_email_delivery_attempts_status",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    outbox_event_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_email_outbox_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    attempt_number = Column(Integer, nullable=False)
    provider_name = Column(String(64), nullable=False)
    status = Column(String(24), nullable=False)
    provider_message_id = Column(String(255), nullable=True)
    error_code = Column(String(64), nullable=True)
    started_at = Column(TIMESTAMP(timezone=True), nullable=False)
    completed_at = Column(TIMESTAMP(timezone=True), nullable=True)


class AeternaEmailDeliveryCallback(BaseModel):
    """An idempotent authenticated provider callback without read inference."""

    __tablename__ = "aeterna_email_delivery_callbacks"
    __table_args__ = (
        UniqueConstraint(
            "provider_name",
            "callback_id",
            name="uq_aeterna_email_delivery_callbacks_provider_callback",
        ),
        CheckConstraint(
            "callback_type IN ('provider_accepted', 'delivered', 'bounced', "
            "'complained', 'rejected')",
            name="ck_aeterna_email_delivery_callbacks_type",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    outbox_event_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_email_outbox_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider_name = Column(String(64), nullable=False)
    callback_id = Column(String(255), nullable=False)
    callback_type = Column(String(32), nullable=False)
    occurred_at = Column(TIMESTAMP(timezone=True), nullable=False)
    received_at = Column(TIMESTAMP(timezone=True), nullable=False)


class AeternaRecipientSuppression(BaseModel):
    """A keyed recipient suppression without plaintext mailbox storage."""

    __tablename__ = "aeterna_recipient_suppressions"
    __table_args__ = (
        CheckConstraint(
            "octet_length(recipient_lookup) = 32",
            name="ck_aeterna_recipient_suppressions_lookup_length",
        ),
        CheckConstraint(
            "reason IN ('declined', 'hard_bounce', 'complaint', 'abuse')",
            name="ck_aeterna_recipient_suppressions_reason",
        ),
    )

    recipient_lookup = Column(LargeBinary, primary_key=True)
    reason = Column(String(24), nullable=False)


class AeternaNotificationAbuseEvent(BaseModel):
    """Keyed account, recipient, and IP evidence for bounded abuse checks."""

    __tablename__ = "aeterna_notification_abuse_events"
    __table_args__ = (
        CheckConstraint(
            "recipient_lookup IS NULL OR octet_length(recipient_lookup) = 32",
            name="ck_aeterna_notification_abuse_events_recipient_length",
        ),
        CheckConstraint(
            "ip_lookup IS NULL OR octet_length(ip_lookup) = 32",
            name="ck_aeterna_notification_abuse_events_ip_length",
        ),
        CheckConstraint(
            "event_type IN ('contact_create', 'contact_invite', "
            "'contact_test', 'invitation_response')",
            name="ck_aeterna_notification_abuse_events_type",
        ),
        Index(
            "ix_aeterna_notification_abuse_account_time",
            "account_id",
            "created_at",
        ),
        Index(
            "ix_aeterna_notification_abuse_recipient_time",
            "recipient_lookup",
            "created_at",
        ),
        Index(
            "ix_aeterna_notification_abuse_ip_time",
            "ip_lookup",
            "created_at",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=True,
    )
    recipient_lookup = Column(LargeBinary, nullable=True)
    ip_lookup = Column(LargeBinary, nullable=True)
    event_type = Column(String(32), nullable=False)


class AeternaNotificationAudit(BaseModel):
    """A deliberately redacted contact and delivery audit record."""

    __tablename__ = "aeterna_notification_audit"
    __table_args__ = (
        CheckConstraint(
            "actor_kind IN ('owner', 'recipient', 'system', 'provider')",
            name="ck_aeterna_notification_audit_actor_kind",
        ),
        CheckConstraint(
            "event_type IN ('contact.created', 'contact.invited', "
            "'contact.accepted', 'contact.declined', 'contact.deleted', "
            "'contact.test_queued', 'template.updated', 'delivery.queued', "
            "'delivery.retry_scheduled', 'delivery.provider_accepted', "
            "'delivery.delivered', 'delivery.bounced', 'delivery.complained', "
            "'delivery.failed', "
            "'delivery.cancelled')",
            name="ck_aeterna_notification_audit_event_type",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id = Column(
        UUID(as_uuid=True),
        ForeignKey("aeterna_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    contact_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    outbox_event_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    actor_kind = Column(String(16), nullable=False)
    event_type = Column(String(64), nullable=False)
    status = Column(String(32), nullable=True)
    reason_code = Column(String(64), nullable=True)
