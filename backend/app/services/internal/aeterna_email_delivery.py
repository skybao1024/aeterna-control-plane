"""Idempotent provider delivery and callback state for Aeterna I12."""

from __future__ import annotations

import html
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.account_policy import AccountPolicy, AccountPolicyOutboxEvent
from app.models.aeterna_identity import AeternaAccount
from app.models.aeterna_notification import (
    AeternaContact,
    AeternaContactInvitation,
    AeternaEmailDeliveryAttempt,
    AeternaEmailDeliveryCallback,
    AeternaEmailOutboxEvent,
    AeternaNotificationAudit,
    AeternaNotificationTemplate,
    AeternaRecipientSuppression,
)
from app.models.aeterna_recovery import (
    AeternaOwnerRecoveryRequest,
    AeternaRecoveryClaimLink,
    AeternaRecoveryGrant,
    AeternaRecoveryOtpChallenge,
    AeternaRecoveryRecord,
)
from app.services.common.aeterna_email_adapter import (
    AeternaEmailAdapter,
    AeternaEmailEnvelope,
    EmailDeliveryFailure,
    UnavailableProductionEmailAdapter,
    get_aeterna_email_adapter,
)
from app.services.common.aeterna_management import (
    AeternaManagementAuthorityService,
    get_aeterna_management_authority_service,
)
from app.services.common.aeterna_security import (
    AeternaIdentityKeys,
    IdentityKeyUnavailable,
    decrypt_email,
    decrypt_private_text,
    derive_invitation_token,
    derive_recovery_link_token,
    derive_recovery_otp,
    get_identity_keys,
)
from app.services.common.email import EMAIL_APP_NAME

MAX_PROVIDER_NAME_BYTES = 64
MAX_PROVIDER_MESSAGE_ID_BYTES = 255
MAX_CALLBACK_ID_BYTES = 255
MAX_REASON_CODE_BYTES = 64


class DeliveryCallbackType(str, Enum):
    """Transport-only callback types; opens and human reading are excluded."""

    PROVIDER_ACCEPTED = "provider_accepted"
    DELIVERED = "delivered"
    BOUNCED = "bounced"
    COMPLAINED = "complained"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class DispatchResult:
    outbox_event_id: uuid.UUID
    status: str
    attempt_number: int


@dataclass(frozen=True, slots=True)
class CallbackResult:
    outbox_event_id: uuid.UUID
    status: str
    duplicate: bool


class AeternaEmailDeliveryService:
    """Render late, send once per durable authorization, and record transport truth."""

    def __init__(
        self,
        adapter: AeternaEmailAdapter | None = None,
        key_provider: Callable[[], AeternaIdentityKeys] = get_identity_keys,
        clock: Callable[[], datetime] | None = None,
        management_service: AeternaManagementAuthorityService | None = None,
    ):
        self.adapter = adapter or get_aeterna_email_adapter()
        self.key_provider = key_provider
        self.management = (
            management_service or get_aeterna_management_authority_service()
        )
        self.clock = clock or (lambda: datetime.now(UTC))

    async def dispatch_event(
        self, db: AsyncSession, event_id: uuid.UUID
    ) -> DispatchResult:
        """Authorize one send before the external effect and never retry ambiguity."""

        prepared = await self._prepare_send(db, event_id)
        if isinstance(prepared, DispatchResult):
            return prepared
        event, attempt, envelope = prepared
        try:
            acceptance = await self.adapter.send(envelope, event.idempotency_key)
        except EmailDeliveryFailure as exc:
            return await self._record_failure(db, event.id, attempt.id, exc)
        except Exception:
            return await self._record_failure(
                db,
                event.id,
                attempt.id,
                EmailDeliveryFailure(
                    "provider-failure-ambiguous",
                    retryable=False,
                    ambiguous=True,
                ),
            )

        self._validate_provider_value(
            acceptance.provider_name, MAX_PROVIDER_NAME_BYTES, "provider name"
        )
        if acceptance.provider_name != self.adapter.provider_name:
            raise RuntimeError("Provider acceptance came from an unexpected adapter")
        self._validate_provider_value(
            acceptance.provider_message_id,
            MAX_PROVIDER_MESSAGE_ID_BYTES,
            "provider message identifier",
        )
        accepted_at = self._normalize_time(acceptance.accepted_at)
        async with db.begin():
            account = await db.scalar(
                select(AeternaAccount)
                .where(AeternaAccount.id == event.account_id)
                .with_for_update()
            )
            contact = None
            if event.contact_id is not None:
                contact = await db.scalar(
                    select(AeternaContact)
                    .where(AeternaContact.id == event.contact_id)
                    .with_for_update()
                )
            persisted = await db.scalar(
                select(AeternaEmailOutboxEvent)
                .where(AeternaEmailOutboxEvent.id == event.id)
                .with_for_update()
            )
            persisted_attempt = await db.scalar(
                select(AeternaEmailDeliveryAttempt)
                .where(AeternaEmailDeliveryAttempt.id == attempt.id)
                .with_for_update()
            )
            if account is None or persisted is None or persisted_attempt is None:
                raise RuntimeError("The prepared email delivery record was not found")
            if persisted.status != "sending":
                return DispatchResult(
                    outbox_event_id=persisted.id,
                    status=persisted.status,
                    attempt_number=persisted.attempt_count,
                )
            persisted.status = "provider_accepted"
            persisted.provider_name = acceptance.provider_name
            persisted.provider_message_id = acceptance.provider_message_id
            persisted.provider_accepted_at = accepted_at
            persisted.last_error_code = None
            persisted.updated_at = accepted_at
            persisted_attempt.status = "provider_accepted"
            persisted_attempt.provider_message_id = acceptance.provider_message_id
            persisted_attempt.completed_at = accepted_at
            persisted_attempt.updated_at = accepted_at
            if persisted.event_type == "contact-invitation":
                if contact is not None:
                    contact.invitation_sent_at = accepted_at
                    contact.updated_at = accepted_at
            self._audit(
                db,
                persisted,
                "provider",
                "delivery.provider_accepted",
                "provider_accepted",
            )
        return DispatchResult(
            outbox_event_id=event.id,
            status="provider_accepted",
            attempt_number=attempt.attempt_number,
        )

    async def record_callback(
        self,
        db: AsyncSession,
        *,
        provider_name: str,
        provider_message_id: str,
        callback_id: str,
        callback_type: DeliveryCallbackType,
        occurred_at: datetime,
        reason_code: str | None = None,
    ) -> CallbackResult:
        """Record an already authenticated callback without inferring readership."""

        self._validate_provider_value(
            provider_name, MAX_PROVIDER_NAME_BYTES, "provider name"
        )
        self._validate_provider_value(
            provider_message_id,
            MAX_PROVIDER_MESSAGE_ID_BYTES,
            "provider message identifier",
        )
        self._validate_provider_value(
            callback_id, MAX_CALLBACK_ID_BYTES, "callback identifier"
        )
        if reason_code is not None:
            self._validate_provider_value(
                reason_code, MAX_REASON_CODE_BYTES, "reason code"
            )
        occurred = self._normalize_time(occurred_at)
        now = self._now()
        existing = await db.scalar(
            select(AeternaEmailDeliveryCallback).where(
                AeternaEmailDeliveryCallback.provider_name == provider_name,
                AeternaEmailDeliveryCallback.callback_id == callback_id,
            )
        )
        if existing is not None:
            if existing.callback_type != callback_type.value:
                raise RuntimeError("Callback identifier conflicts with stored outcome")
            event = await db.get(AeternaEmailOutboxEvent, existing.outbox_event_id)
            if event is None:
                raise RuntimeError("Callback email event was not found")
            result = CallbackResult(event.id, event.status, True)
            await db.rollback()
            return result

        reference = (
            await db.execute(
                select(
                    AeternaEmailOutboxEvent.id,
                    AeternaEmailOutboxEvent.account_id,
                    AeternaEmailOutboxEvent.contact_id,
                ).where(
                    AeternaEmailOutboxEvent.provider_name == provider_name,
                    AeternaEmailOutboxEvent.provider_message_id == provider_message_id,
                )
            )
        ).one_or_none()
        if reference is None:
            raise RuntimeError("Provider callback does not match a delivery")
        reference_id = reference.id
        reference_account_id = reference.account_id
        reference_contact_id = reference.contact_id
        await db.rollback()

        async with db.begin():
            account = await db.scalar(
                select(AeternaAccount)
                .where(AeternaAccount.id == reference_account_id)
                .with_for_update()
            )
            concurrent_duplicate = await db.scalar(
                select(AeternaEmailDeliveryCallback).where(
                    AeternaEmailDeliveryCallback.provider_name == provider_name,
                    AeternaEmailDeliveryCallback.callback_id == callback_id,
                )
            )
            if concurrent_duplicate is not None:
                if concurrent_duplicate.callback_type != callback_type.value:
                    raise RuntimeError(
                        "Callback identifier conflicts with stored outcome"
                    )
                concurrent_event = await db.get(
                    AeternaEmailOutboxEvent,
                    concurrent_duplicate.outbox_event_id,
                )
                if concurrent_event is None:
                    raise RuntimeError("Callback email event was not found")
                return CallbackResult(
                    concurrent_event.id,
                    concurrent_event.status,
                    True,
                )
            contact = None
            if reference_contact_id is not None:
                contact = await db.scalar(
                    select(AeternaContact)
                    .where(AeternaContact.id == reference_contact_id)
                    .with_for_update()
                )
            event = await db.scalar(
                select(AeternaEmailOutboxEvent)
                .where(AeternaEmailOutboxEvent.id == reference_id)
                .with_for_update()
            )
            if account is None or event is None:
                raise RuntimeError("Provider callback delivery record disappeared")
            callback = AeternaEmailDeliveryCallback(
                id=uuid.uuid4(),
                outbox_event_id=event.id,
                provider_name=provider_name,
                callback_id=callback_id,
                callback_type=callback_type.value,
                occurred_at=occurred,
                received_at=now,
            )
            db.add(callback)
            audit_event = None
            if callback_type is DeliveryCallbackType.PROVIDER_ACCEPTED:
                if event.status in {"sending", "retry_pending", "queued"}:
                    event.status = "provider_accepted"
                if event.provider_accepted_at is None:
                    event.provider_accepted_at = occurred
                audit_event = "delivery.provider_accepted"
            elif callback_type is DeliveryCallbackType.DELIVERED:
                if event.status not in {
                    "bounced",
                    "complained",
                    "cancelled",
                    "failed",
                }:
                    event.status = "delivered"
                    event.delivered_at = occurred
                    if event.provider_accepted_at is None:
                        event.provider_accepted_at = occurred
                audit_event = "delivery.delivered"
            elif callback_type is DeliveryCallbackType.BOUNCED:
                if event.status not in {"cancelled", "complained"}:
                    event.status = "bounced"
                    event.bounced_at = occurred
                    event.last_error_code = reason_code or "provider-bounce"
                    if contact is not None:
                        contact.bounced_at = occurred
                        contact.updated_at = now
                        if reason_code == "hard-bounce":
                            suppression = await db.get(
                                AeternaRecipientSuppression, contact.email_lookup
                            )
                            if suppression is None:
                                db.add(
                                    AeternaRecipientSuppression(
                                        recipient_lookup=contact.email_lookup,
                                        reason="hard_bounce",
                                    )
                                )
                            else:
                                suppression.reason = "hard_bounce"
                                suppression.updated_at = now
                audit_event = "delivery.bounced"
            elif callback_type is DeliveryCallbackType.COMPLAINED:
                if event.status != "cancelled":
                    event.status = "complained"
                    event.last_error_code = reason_code or "provider-complaint"
                    if contact is not None:
                        suppression = await db.get(
                            AeternaRecipientSuppression, contact.email_lookup
                        )
                        if suppression is None:
                            db.add(
                                AeternaRecipientSuppression(
                                    recipient_lookup=contact.email_lookup,
                                    reason="complaint",
                                )
                            )
                        else:
                            suppression.reason = "complaint"
                            suppression.updated_at = now
                audit_event = "delivery.complained"
            else:
                if event.status not in {
                    "delivered",
                    "bounced",
                    "complained",
                    "cancelled",
                }:
                    event.status = "failed"
                    event.failed_at = occurred
                    event.last_error_code = reason_code or "provider-rejected"
                audit_event = "delivery.failed"
            event.updated_at = now
            self._audit(
                db,
                event,
                "provider",
                audit_event,
                event.status,
                reason_code=reason_code,
            )
        return CallbackResult(event.id, event.status, False)

    async def _prepare_send(
        self,
        db: AsyncSession,
        event_id: uuid.UUID,
    ) -> (
        tuple[
            AeternaEmailOutboxEvent, AeternaEmailDeliveryAttempt, AeternaEmailEnvelope
        ]
        | DispatchResult
    ):
        relation = (
            await db.execute(
                select(
                    AeternaEmailOutboxEvent.account_id,
                    AeternaEmailOutboxEvent.contact_id,
                ).where(AeternaEmailOutboxEvent.id == event_id)
            )
        ).one_or_none()
        if relation is None:
            raise RuntimeError("Email Outbox event was not found")
        relation_account_id = relation.account_id
        relation_contact_id = relation.contact_id
        await db.rollback()
        async with db.begin():
            account = await db.scalar(
                select(AeternaAccount)
                .where(AeternaAccount.id == relation_account_id)
                .with_for_update()
            )
            contact = None
            if relation_contact_id is not None:
                contact = await db.scalar(
                    select(AeternaContact)
                    .where(AeternaContact.id == relation_contact_id)
                    .with_for_update()
                )
            event = await db.scalar(
                select(AeternaEmailOutboxEvent)
                .where(AeternaEmailOutboxEvent.id == event_id)
                .with_for_update()
            )
            if account is None or event is None:
                raise RuntimeError("Email Outbox authorization record disappeared")
            if event.status not in {"queued", "retry_pending"}:
                return DispatchResult(event.id, event.status, event.attempt_count)
            now = self._now()
            if event.next_attempt_at > now:
                return DispatchResult(event.id, event.status, event.attempt_count)
            if event.source_policy_outbox_id is not None:
                source = await db.scalar(
                    select(AccountPolicyOutboxEvent).where(
                        AccountPolicyOutboxEvent.id == event.source_policy_outbox_id
                    )
                )
                if source is None or source.status == "cancelled":
                    event.status = "cancelled"
                    event.cancelled_at = now
                    event.updated_at = now
                    self._audit(
                        db,
                        event,
                        "system",
                        "delivery.cancelled",
                        "cancelled",
                    )
                    return DispatchResult(event.id, event.status, event.attempt_count)
            if contact is not None and (
                contact.deleted_at is not None or contact.consent_status == "DECLINED"
            ):
                event.status = "cancelled"
                event.cancelled_at = now
                event.updated_at = now
                self._audit(
                    db,
                    event,
                    "system",
                    "delivery.cancelled",
                    "cancelled",
                )
                return DispatchResult(event.id, event.status, event.attempt_count)
            if event.event_type in {
                "recovery-claim-link",
                "recovery-otp",
                "recovery-claimed-contact",
            } and (
                contact is None
                or contact.consent_status != "ACCEPTED"
                or contact.verified_at is None
                or contact.deleted_at is not None
            ):
                event.status = "cancelled"
                event.cancelled_at = now
                event.updated_at = now
                self._audit(db, event, "system", "delivery.cancelled", "cancelled")
                return DispatchResult(event.id, event.status, event.attempt_count)

            if event.event_type == "contact-invitation":
                invitation = await db.scalar(
                    select(AeternaContactInvitation)
                    .where(AeternaContactInvitation.id == event.invitation_id)
                    .with_for_update()
                )
                if (
                    invitation is None
                    or invitation.status != "pending"
                    or invitation.expires_at <= now
                ):
                    event.status = "cancelled"
                    event.cancelled_at = now
                    event.updated_at = now
                    self._audit(
                        db,
                        event,
                        "system",
                        "delivery.cancelled",
                        "cancelled",
                    )
                    return DispatchResult(event.id, event.status, event.attempt_count)
            if event.event_type == "recovery-claim-link":
                link = await db.scalar(
                    select(AeternaRecoveryClaimLink)
                    .where(AeternaRecoveryClaimLink.id == event.recovery_link_id)
                    .with_for_update()
                )
                if not await self._recovery_entry_available(db, link):
                    event.status = "cancelled"
                    event.cancelled_at = now
                    event.updated_at = now
                    self._audit(db, event, "system", "delivery.cancelled", "cancelled")
                    return DispatchResult(event.id, event.status, event.attempt_count)
            if event.event_type == "recovery-otp":
                challenge_link_id = await db.scalar(
                    select(AeternaRecoveryOtpChallenge.link_id).where(
                        AeternaRecoveryOtpChallenge.id == event.recovery_challenge_id
                    )
                )
                link = (
                    await db.scalar(
                        select(AeternaRecoveryClaimLink)
                        .where(AeternaRecoveryClaimLink.id == challenge_link_id)
                        .with_for_update()
                    )
                    if challenge_link_id is not None
                    else None
                )
                challenge = await db.scalar(
                    select(AeternaRecoveryOtpChallenge)
                    .where(
                        AeternaRecoveryOtpChallenge.id == event.recovery_challenge_id
                    )
                    .with_for_update()
                )
                if (
                    link is None
                    or link.status != "active"
                    or challenge is None
                    or (
                        link.expires_at <= now
                        and challenge.scope != "recovery.recipient.rotate"
                    )
                    or challenge.status != "active"
                    or challenge.expires_at <= now
                ):
                    event.status = "cancelled"
                    event.cancelled_at = now
                    event.updated_at = now
                    self._audit(db, event, "system", "delivery.cancelled", "cancelled")
                    return DispatchResult(event.id, event.status, event.attempt_count)

            keys = self._keys()
            envelope = await self._render(db, keys, account, contact, event, now)
            attempt_number = event.attempt_count + 1
            attempt = AeternaEmailDeliveryAttempt(
                id=uuid.uuid4(),
                outbox_event_id=event.id,
                attempt_number=attempt_number,
                provider_name=self.adapter.provider_name,
                status="sending",
                started_at=now,
            )
            db.add(attempt)
            event.status = "sending"
            event.attempt_count = attempt_number
            event.provider_name = self.adapter.provider_name
            event.updated_at = now
            await db.flush()
        return event, attempt, envelope

    async def _record_failure(
        self,
        db: AsyncSession,
        event_id: uuid.UUID,
        attempt_id: uuid.UUID,
        failure: EmailDeliveryFailure,
    ) -> DispatchResult:
        now = self._now()
        async with db.begin():
            event = await db.scalar(
                select(AeternaEmailOutboxEvent)
                .where(AeternaEmailOutboxEvent.id == event_id)
                .with_for_update()
            )
            attempt = await db.scalar(
                select(AeternaEmailDeliveryAttempt)
                .where(AeternaEmailDeliveryAttempt.id == attempt_id)
                .with_for_update()
            )
            if event is None or attempt is None:
                raise RuntimeError("The failed delivery record was not found")
            if failure.ambiguous:
                event.status = "ambiguous"
                event.failed_at = now
                attempt.status = "ambiguous_failure"
            elif failure.retryable and self.adapter.supports_idempotency:
                event.status = "retry_pending"
                event.next_attempt_at = now + timedelta(
                    minutes=min(60, 2 ** min(event.attempt_count, 5))
                )
                attempt.status = "retryable_failure"
            else:
                event.status = "failed"
                event.failed_at = now
                attempt.status = "failed"
            event.last_error_code = failure.code
            event.updated_at = now
            attempt.error_code = failure.code
            attempt.completed_at = now
            attempt.updated_at = now
            audit_event = (
                "delivery.retry_scheduled"
                if event.status == "retry_pending"
                else "delivery.failed"
            )
            self._audit(
                db,
                event,
                "provider",
                audit_event,
                event.status,
                reason_code=failure.code,
            )
        return DispatchResult(event.id, event.status, event.attempt_count)

    async def _recovery_entry_available(
        self, db: AsyncSession, link: AeternaRecoveryClaimLink | None
    ) -> bool:
        if link is None or link.status == "revoked":
            return False
        eligible = await db.scalar(
            select(AeternaRecoveryGrant.id)
            .join(
                AeternaRecoveryRecord,
                AeternaRecoveryRecord.id == AeternaRecoveryGrant.recovery_id,
            )
            .join(
                AccountPolicy,
                (AccountPolicy.account_id == AeternaRecoveryGrant.account_id)
                & (AccountPolicy.epoch == AeternaRecoveryRecord.policy_epoch),
            )
            .where(
                AeternaRecoveryGrant.id == link.grant_id,
                AeternaRecoveryGrant.state == "available",
                AeternaRecoveryRecord.state == "sealed",
                AccountPolicy.state == "RELEASED",
            )
        )
        return eligible is not None

    async def _render(
        self,
        db: AsyncSession,
        keys: AeternaIdentityKeys,
        account: AeternaAccount,
        contact: AeternaContact | None,
        event: AeternaEmailOutboxEvent,
        now: datetime,
    ) -> AeternaEmailEnvelope:
        owner_email = None
        if event.recipient_kind == "owner" or event.event_type == "contact-invitation":
            if event.owner_recovery_id is not None:
                owner_request = await db.get(
                    AeternaOwnerRecoveryRequest, event.owner_recovery_id
                )
                if owner_request is None:
                    raise RuntimeError("Owner recovery delivery is missing its request")
                owner_email = await self.management.preferred_mailbox(
                    db, keys, account, owner_request.device_id
                )
            else:
                owner_email = await self.management.mailbox(db, keys, account)
        custom_message = ""
        template = await db.get(AeternaNotificationTemplate, account.id)
        if event.recipient_kind == "owner":
            if owner_email is None:
                raise RuntimeError("Owner delivery is missing its recipient")
            recipient = owner_email
            if template is not None:
                custom_message = decrypt_private_text(
                    keys,
                    template.owner_message_ciphertext,
                    template.owner_message_nonce,
                    "owner-notification",
                    account.id,
                    template.owner_message_key_version,
                )
            if event.event_type == "owner-recovery-otp":
                recovery = await db.get(
                    AeternaOwnerRecoveryRequest, event.owner_recovery_id
                )
                if (
                    recovery is None
                    or recovery.state != "pending_email"
                    or recovery.challenge_expires_at <= now
                ):
                    raise EmailDeliveryFailure(
                        "owner-recovery-otp-unavailable", retryable=False
                    )
                code = derive_recovery_otp(
                    keys, recovery.challenge_id, recovery.otp_key_version
                )
                subject = f"{EMAIL_APP_NAME} owner recovery verification code"
                fixed_text = (
                    "Use this one-time code to verify an owner recovery request: "
                    f"{code}\n\nThe code expires in 10 minutes."
                )
                custom_message = ""
            else:
                subject, fixed_text = self._owner_copy(event.event_type)
        else:
            if contact is None:
                raise RuntimeError("Contact delivery is missing its contact")
            recipient = decrypt_email(
                keys,
                contact.email_ciphertext,
                contact.email_nonce,
                "contact",
                contact.id,
                contact.email_key_version,
            )
            if event.event_type == "contact-invitation":
                if owner_email is None:
                    raise RuntimeError("Invitation delivery is missing its owner")
                invitation = await db.scalar(
                    select(AeternaContactInvitation)
                    .where(AeternaContactInvitation.id == event.invitation_id)
                    .with_for_update()
                )
                if (
                    invitation is None
                    or invitation.status != "pending"
                    or invitation.expires_at <= now
                ):
                    raise EmailDeliveryFailure(
                        "invitation-unavailable", retryable=False
                    )
                token = derive_invitation_token(
                    keys, invitation.id, invitation.token_key_version
                )
                action_url = (
                    f"{settings.FRONTEND_URL.rstrip('/')}/contact-invitation"
                    f"#token={token}"
                )
                subject = f"{EMAIL_APP_NAME} recovery contact invitation"
                fixed_text = (
                    f"An {EMAIL_APP_NAME} owner has selected this email address as a "
                    f"recovery contact. Owner: {owner_email}\n\n"
                    "No recovery material or private message is included. You may "
                    "accept or decline the role using the link below.\n\n"
                    f"{action_url}"
                )
                custom_message = ""
            elif event.event_type == "contact-test":
                subject = f"{EMAIL_APP_NAME} recovery contact delivery test"
                fixed_text = (
                    "This is a delivery test for a recovery-contact role that this "
                    "email address previously accepted and verified."
                )
                if template is not None:
                    custom_message = decrypt_private_text(
                        keys,
                        template.contact_message_ciphertext,
                        template.contact_message_nonce,
                        "contact-notification",
                        account.id,
                        template.contact_message_key_version,
                    )
            elif event.event_type == "recovery-claim-link":
                link = await db.get(AeternaRecoveryClaimLink, event.recovery_link_id)
                if not await self._recovery_entry_available(db, link):
                    raise EmailDeliveryFailure(
                        "recovery-link-unavailable", retryable=False
                    )
                token = derive_recovery_link_token(
                    keys, link.id, link.token_key_version
                )
                action_url = (
                    f"{settings.FRONTEND_URL.rstrip('/')}/recovery-claim"
                    f"#token={token}"
                )
                subject = f"{EMAIL_APP_NAME} recovery access is available"
                fixed_text = (
                    "Recovery access is available to this verified recovery contact. "
                    "Open Aeterna on the computer that holds the Vault and paste this "
                    "email link into Emergency recovery. The app will send a separate "
                    "mailbox verification code, valid for 10 minutes. The entry link "
                    "can be used again while this recovery remains authorized.\n\n"
                    f"{action_url}"
                )
                custom_message = ""
            elif event.event_type == "recovery-otp":
                challenge = await db.get(
                    AeternaRecoveryOtpChallenge, event.recovery_challenge_id
                )
                if (
                    challenge is None
                    or challenge.status != "active"
                    or challenge.expires_at <= now
                ):
                    raise EmailDeliveryFailure(
                        "recovery-otp-unavailable", retryable=False
                    )
                code = derive_recovery_otp(
                    keys, challenge.id, challenge.otp_key_version
                )
                subject = f"{EMAIL_APP_NAME} recovery verification code"
                fixed_text = (
                    "Use this one-time code to continue the delayed-recovery "
                    f"claim: {code}\n\nThe code expires in 10 minutes."
                )
                custom_message = ""
            elif event.event_type == "recovery-claimed-contact":
                subject = f"{EMAIL_APP_NAME} recovery security notice"
                fixed_text = (
                    "Another verified recovery contact completed a one-time "
                    f"recovery-secret claim for this {EMAIL_APP_NAME} account."
                )
                custom_message = ""
            else:
                raise RuntimeError("Unsupported contact email event type")

        text_body = fixed_text
        if custom_message:
            text_body = f"{fixed_text}\n\nOwner-provided note:\n{custom_message}"
        html_body = "<p>" + html.escape(fixed_text).replace("\n", "<br>") + "</p>"
        if custom_message:
            html_body += (
                "<p><strong>Owner-provided note:</strong><br>"
                + html.escape(custom_message).replace("\n", "<br>")
                + "</p>"
            )
        return AeternaEmailEnvelope(recipient, subject, text_body, html_body)

    def _owner_copy(self, event_type: str) -> tuple[str, str]:
        messages = {
            "owner-pre-warning": (
                f"{EMAIL_APP_NAME} inactivity warning",
                f"Your {EMAIL_APP_NAME} account entered its pre-warning period. "
                "Open a bound device to review the account and submit valid activity "
                "if appropriate.",
            ),
            "owner-grace-period-started": (
                f"{EMAIL_APP_NAME} grace period started",
                f"Your {EMAIL_APP_NAME} account entered its grace period. "
                "Provider delivery does not confirm that you read this warning.",
            ),
            "owner-warning-required": (
                f"{EMAIL_APP_NAME} warning requires confirmation",
                f"{EMAIL_APP_NAME} recovered from an outage and restarted a complete "
                "grace period. Review and explicitly acknowledge the warning in "
                f"{EMAIL_APP_NAME}.",
            ),
            "owner-release-authorized": (
                f"{EMAIL_APP_NAME} release boundary reached",
                f"Your {EMAIL_APP_NAME} account reached its release boundary. "
                "This notice does not contain or authorize access to recovery material.",
            ),
            "recovery-claimed-owner": (
                f"{EMAIL_APP_NAME} recovery secret was claimed",
                "A verified recovery contact completed a one-time recovery-secret "
                "claim. This security notice contains no recovery material.",
            ),
            "owner-recovery-cooling-down": (
                f"{EMAIL_APP_NAME} owner recovery cooling-down started",
                "An owner recovery request passed email verification and entered "
                "a 24-hour cooling-down period. Any active bound device can cancel it.",
            ),
            "owner-recovery-cancelled": (
                f"{EMAIL_APP_NAME} owner recovery cancelled",
                "An active bound device cancelled the pending owner recovery request.",
            ),
            "owner-recovery-material-released": (
                f"{EMAIL_APP_NAME} owner recovery material released",
                "Recovery material was released to the initiating device after the "
                "cooling-down period. Access wrappers must now be replaced.",
            ),
            "owner-recovery-successor-authorized": (
                f"{EMAIL_APP_NAME} successor protection authorized",
                "A bound device and Owner mailbox verification authorized a "
                "post-compromise successor. No old recovery secret was released; "
                "the device must complete an atomic local rekey.",
            ),
        }
        try:
            return messages[event_type]
        except KeyError as exc:
            raise RuntimeError("Unsupported owner email event type") from exc

    def _audit(
        self,
        db: AsyncSession,
        event: AeternaEmailOutboxEvent,
        actor_kind: str,
        event_type: str,
        status: str,
        *,
        reason_code: str | None = None,
    ) -> None:
        db.add(
            AeternaNotificationAudit(
                id=uuid.uuid4(),
                account_id=event.account_id,
                contact_id=event.contact_id,
                outbox_event_id=event.id,
                actor_kind=actor_kind,
                event_type=event_type,
                status=status,
                reason_code=reason_code,
            )
        )

    def _keys(self) -> AeternaIdentityKeys:
        try:
            return self.key_provider()
        except IdentityKeyUnavailable:
            raise EmailDeliveryFailure(
                "notification-key-unavailable", retryable=False
            ) from None

    def _now(self) -> datetime:
        return self._normalize_time(self.clock())

    def _normalize_time(self, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise RuntimeError("Delivery time must be timezone-aware")
        return value.astimezone(UTC)

    def _validate_provider_value(self, value: str, limit: int, label: str) -> None:
        if (
            not value
            or len(value.encode("utf-8")) > limit
            or any(ord(character) < 33 or ord(character) == 127 for character in value)
        ):
            raise RuntimeError(f"Invalid {label}")


def get_aeterna_email_delivery_service() -> AeternaEmailDeliveryService:
    """Assemble the external email delivery dependency chain."""

    return AeternaEmailDeliveryService(
        adapter=get_aeterna_email_adapter(),
        management_service=get_aeterna_management_authority_service(),
    )


def get_aeterna_email_callback_service() -> AeternaEmailDeliveryService:
    """Build callback processing without initializing an outbound AWS client."""

    return AeternaEmailDeliveryService(
        adapter=UnavailableProductionEmailAdapter(),
        management_service=get_aeterna_management_authority_service(),
    )
