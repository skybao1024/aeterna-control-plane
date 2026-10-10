"""Transactional contact consent and email-intent service for Aeterna I12."""

from __future__ import annotations

import secrets
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidTag
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.models.account_policy import (
    AccountPolicy,
    AccountPolicyOutboxEvent,
    AccountPolicyState,
)
from app.models.aeterna_identity import (
    AeternaAccount,
    AeternaDevice,
    AeternaProtocolIdempotency,
)
from app.models.aeterna_notification import (
    AeternaContact,
    AeternaContactInvitation,
    AeternaEmailOutboxEvent,
    AeternaNotificationAbuseEvent,
    AeternaNotificationAudit,
    AeternaNotificationTemplate,
    AeternaRecipientSuppression,
)
from app.schemas.client.aeterna_notification import (
    ContactActionRequest,
    ContactCreateRequest,
    ContactInvitationResponseRequest,
    NotificationTemplateEditRequest,
    NotificationTemplateReadRequest,
    NotificationTemplateRequest,
    OwnerConfigurationRequest,
)
from app.services.client.aeterna_heartbeat import DEVICE_DORMANCY
from app.services.common.aeterna_management import (
    AeternaManagementAuthorityService,
    get_aeterna_management_authority_service,
)
from app.services.common.aeterna_security import (
    AeternaIdentityKeys,
    IdentityKeyUnavailable,
    InvalidEmail,
    decrypt_email,
    decrypt_private_text,
    derive_invitation_token,
    email_lookup,
    encrypt_email,
    encrypt_private_text,
    get_identity_keys,
    ip_lookup,
    normalize_email,
    private_request_digest,
    request_digest,
    token_digest,
    verify_signature,
)

INVITATION_LIFETIME = timedelta(days=7)
ABUSE_WINDOW = timedelta(days=1)
MAX_ACTIVE_CONTACTS = 10
MAX_ACCOUNT_ACTIONS_PER_DAY = 30
MAX_RECIPIENT_ACTIONS_PER_DAY = 5
MAX_IP_ACTIONS_PER_DAY = 40


def utc_now() -> datetime:
    return datetime.now(UTC)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class AeternaNotificationService:
    """Own consent, disclosure, encryption, abuse, and durable email intent rules."""

    def __init__(
        self,
        key_provider: Callable[[], AeternaIdentityKeys] = get_identity_keys,
        clock: Callable[[], datetime] = utc_now,
        uuid_factory: Callable[[], uuid.UUID] = uuid.uuid4,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
        management_service: AeternaManagementAuthorityService | None = None,
    ):
        self.key_provider = key_provider
        self.clock = clock
        self.uuid_factory = uuid_factory
        self.random_bytes = random_bytes
        self.management = (
            management_service or get_aeterna_management_authority_service()
        )

    async def create_contact(
        self,
        db: AsyncSession,
        payload: ContactCreateRequest,
        document: dict[str, Any],
        client_address: str,
    ) -> dict[str, Any]:
        keys = self._keys(payload.signed.request_id)
        signed = payload.signed
        try:
            normalized_email = normalize_email(signed.email)
        except InvalidEmail:
            raise AeternaProtocolException(
                400, "protocol.invalid_request", signed.request_id
            ) from None

        account, _device, replay = await self._authorize_owner(
            db, payload, document, private=True
        )
        if replay is not None:
            return replay
        now = self._now()
        recipient_lookup = email_lookup(keys, normalized_email)
        remote_lookup = ip_lookup(keys, client_address)
        await self._enforce_abuse_limits(
            db,
            now=now,
            account_id=account.id,
            recipient_lookup=recipient_lookup,
            remote_lookup=remote_lookup,
        )
        if await db.get(AeternaRecipientSuppression, recipient_lookup) is not None:
            raise AeternaProtocolException(
                400, "contact.recipient_unavailable", signed.request_id
            )

        active_count = await db.scalar(
            select(func.count(AeternaContact.id)).where(
                AeternaContact.account_id == account.id,
                AeternaContact.deleted_at.is_(None),
            )
        )
        if active_count is not None and active_count >= MAX_ACTIVE_CONTACTS:
            raise AeternaProtocolException(
                400, "contact.limit_reached", signed.request_id
            )
        duplicate = await db.scalar(
            select(AeternaContact.id).where(
                AeternaContact.account_id == account.id,
                AeternaContact.email_lookup == recipient_lookup,
                AeternaContact.deleted_at.is_(None),
            )
        )
        if duplicate is not None:
            raise AeternaProtocolException(
                409, "contact.already_exists", signed.request_id
            )

        contact_id = self.uuid_factory()
        ciphertext, nonce, key_version = encrypt_email(
            keys,
            normalized_email,
            "contact",
            contact_id,
            nonce_factory=self.random_bytes,
        )
        contact = AeternaContact(
            id=contact_id,
            account_id=account.id,
            email_lookup=recipient_lookup,
            email_ciphertext=ciphertext,
            email_nonce=nonce,
            email_key_version=key_version,
            disclosure_mode=signed.disclosure_mode,
            consent_status="NOT_REQUESTED",
        )
        db.add(contact)
        await db.flush()
        self._audit(db, account.id, contact.id, None, "owner", "contact.created")
        if signed.disclosure_mode == "CONFIRM_NOW":
            await self._queue_invitation(
                db,
                keys=keys,
                contact=contact,
                now=now,
                key_suffix=f"create:{signed.request_id}",
            )
        self._record_abuse(
            db,
            account.id,
            recipient_lookup,
            remote_lookup,
            "contact_create",
        )
        data = await self._contact_data(db, contact)
        self._record_idempotency(
            db,
            account.id,
            signed.operation,
            signed.request_id,
            private_request_digest(keys, document),
            data,
        )
        await db.commit()
        return data

    async def invite_contact(
        self,
        db: AsyncSession,
        payload: ContactActionRequest,
        document: dict[str, Any],
        client_address: str,
    ) -> dict[str, Any]:
        self._require_action(payload, "contact.invite")
        keys = self._keys(payload.signed.request_id)
        signed = payload.signed
        account, _device, replay = await self._authorize_owner(db, payload, document)
        if replay is not None:
            return replay
        contact = await self._locked_contact(
            db, account.id, signed.contact_id, signed.request_id
        )
        self._require_actionable_contact(contact, signed.request_id)
        if contact.consent_status == "ACCEPTED":
            raise AeternaProtocolException(
                409, "contact.already_verified", signed.request_id
            )
        if contact.disclosure_mode == "PRIVATE_UNTIL_RELEASE":
            policy_state = await db.scalar(
                select(AccountPolicy.state).where(
                    AccountPolicy.account_id == account.id,
                    AccountPolicy.retired_at.is_(None),
                )
            )
            if policy_state != AccountPolicyState.RELEASED.value:
                raise AeternaProtocolException(
                    403, "contact.disclosure_locked", signed.request_id
                )

        now = self._now()
        remote_lookup = ip_lookup(keys, client_address)
        await self._enforce_abuse_limits(
            db,
            now=now,
            account_id=account.id,
            recipient_lookup=contact.email_lookup,
            remote_lookup=remote_lookup,
        )
        if await db.get(AeternaRecipientSuppression, contact.email_lookup) is not None:
            raise AeternaProtocolException(
                400, "contact.recipient_unavailable", signed.request_id
            )
        await self._queue_invitation(
            db,
            keys=keys,
            contact=contact,
            now=now,
            key_suffix=f"manual:{signed.request_id}",
        )
        self._record_abuse(
            db,
            account.id,
            contact.email_lookup,
            remote_lookup,
            "contact_invite",
        )
        data = await self._contact_data(db, contact)
        self._record_idempotency(
            db,
            account.id,
            signed.operation,
            signed.request_id,
            request_digest(document),
            data,
        )
        await db.commit()
        return data

    async def queue_test_email(
        self,
        db: AsyncSession,
        payload: ContactActionRequest,
        document: dict[str, Any],
        client_address: str,
    ) -> dict[str, Any]:
        self._require_action(payload, "notification.test")
        keys = self._keys(payload.signed.request_id)
        signed = payload.signed
        account, _device, replay = await self._authorize_owner(db, payload, document)
        if replay is not None:
            return replay
        contact = await self._locked_contact(
            db, account.id, signed.contact_id, signed.request_id
        )
        if (
            contact.deleted_at is not None
            or contact.consent_status != "ACCEPTED"
            or contact.verified_at is None
        ):
            raise AeternaProtocolException(
                403, "contact.verification_required", signed.request_id
            )
        now = self._now()
        remote_lookup = ip_lookup(keys, client_address)
        await self._enforce_abuse_limits(
            db,
            now=now,
            account_id=account.id,
            recipient_lookup=contact.email_lookup,
            remote_lookup=remote_lookup,
        )
        event = self._queue_email_event(
            db,
            account_id=account.id,
            contact_id=contact.id,
            event_type="contact-test",
            idempotency_key=(
                f"contact-notification-test:{contact.id}:{signed.request_id}"
            ),
            now=now,
        )
        self._audit(
            db,
            account.id,
            contact.id,
            event.id,
            "owner",
            "contact.test_queued",
            status="queued",
        )
        self._record_abuse(
            db,
            account.id,
            contact.email_lookup,
            remote_lookup,
            "contact_test",
        )
        await db.flush()
        data = await self._contact_data(db, contact)
        self._record_idempotency(
            db,
            account.id,
            signed.operation,
            signed.request_id,
            request_digest(document),
            data,
        )
        await db.commit()
        return data

    async def delete_contact(
        self,
        db: AsyncSession,
        payload: ContactActionRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        self._require_action(payload, "contact.delete")
        signed = payload.signed
        account, _device, replay = await self._authorize_owner(db, payload, document)
        if replay is not None:
            return replay
        contact = await self._locked_contact(
            db, account.id, signed.contact_id, signed.request_id, include_deleted=True
        )
        if contact.deleted_at is None:
            await self._delete_contact_record(
                db,
                contact,
                now=self._now(),
                actor_kind="owner",
                audit_event="contact.deleted",
                suppress=False,
            )
        data = await self._contact_data(db, contact)
        self._record_idempotency(
            db,
            account.id,
            signed.operation,
            signed.request_id,
            request_digest(document),
            data,
        )
        await db.commit()
        return data

    async def contact_status(
        self,
        db: AsyncSession,
        payload: ContactActionRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        self._require_action(payload, "contact.status")
        signed = payload.signed
        account, _device, _replay = await self._authorize_owner(db, payload, document)
        contact = await self._locked_contact(
            db, account.id, signed.contact_id, signed.request_id, include_deleted=True
        )
        data = await self._contact_data(db, contact)
        await db.rollback()
        return data

    async def update_template(
        self,
        db: AsyncSession,
        payload: NotificationTemplateRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        keys = self._keys(payload.signed.request_id)
        signed = payload.signed
        account, _device, replay = await self._authorize_owner(
            db, payload, document, private=True
        )
        if replay is not None:
            return replay
        template = await db.scalar(
            select(AeternaNotificationTemplate)
            .where(AeternaNotificationTemplate.account_id == account.id)
            .with_for_update()
        )
        owner_ciphertext, owner_nonce, owner_key_version = encrypt_private_text(
            keys,
            signed.owner_message,
            "owner-notification",
            account.id,
            nonce_factory=self.random_bytes,
        )
        contact_ciphertext, contact_nonce, contact_key_version = encrypt_private_text(
            keys,
            signed.contact_message,
            "contact-notification",
            account.id,
            nonce_factory=self.random_bytes,
        )
        if template is None:
            template = AeternaNotificationTemplate(
                account_id=account.id,
                owner_message_ciphertext=owner_ciphertext,
                owner_message_nonce=owner_nonce,
                owner_message_key_version=owner_key_version,
                contact_message_ciphertext=contact_ciphertext,
                contact_message_nonce=contact_nonce,
                contact_message_key_version=contact_key_version,
                version=1,
            )
            db.add(template)
        else:
            template.owner_message_ciphertext = owner_ciphertext
            template.owner_message_nonce = owner_nonce
            template.owner_message_key_version = owner_key_version
            template.contact_message_ciphertext = contact_ciphertext
            template.contact_message_nonce = contact_nonce
            template.contact_message_key_version = contact_key_version
            template.version += 1
            template.updated_at = self._now()
        await db.flush()
        self._audit(
            db,
            account.id,
            None,
            None,
            "owner",
            "template.updated",
            status=f"v{template.version}",
        )
        data = {"account_id": str(account.id), "version": template.version}
        self._record_idempotency(
            db,
            account.id,
            signed.operation,
            signed.request_id,
            private_request_digest(keys, document),
            data,
        )
        await db.commit()
        return data

    async def read_owner_configuration(
        self,
        db: AsyncSession,
        payload: OwnerConfigurationRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        signed = payload.signed
        keys = self._keys(signed.request_id)
        account, _device, _replay = await self._authorize_owner(db, payload, document)
        contacts = []
        try:
            owner_email = await self.management.mailbox(db, keys, account)
            management_email = await self.management.preferred_mailbox(
                db, keys, account, _device.id
            )
            for contact_id in signed.contact_ids:
                contact = await self._locked_contact(
                    db, account.id, contact_id, signed.request_id, include_deleted=True
                )
                email = (
                    None
                    if contact.deleted_at is not None
                    else decrypt_email(
                        keys,
                        contact.email_ciphertext,
                        contact.email_nonce,
                        "contact",
                        contact.id,
                        contact.email_key_version,
                    )
                )
                contacts.append({"contact_id": contact_id, "email": email})
        except (IdentityKeyUnavailable, InvalidTag, UnicodeError):
            raise AeternaProtocolException(
                503, "service.temporarily_unavailable", signed.request_id
            ) from None
        data = {
            "account_id": str(account.id),
            "owner_email": owner_email,
            "management_email": management_email,
            "contacts": contacts,
        }
        await db.rollback()
        return data

    async def read_template(
        self,
        db: AsyncSession,
        payload: NotificationTemplateReadRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        signed = payload.signed
        keys = self._keys(signed.request_id)
        account, _device, _replay = await self._authorize_owner(db, payload, document)
        template = await db.scalar(
            select(AeternaNotificationTemplate)
            .where(AeternaNotificationTemplate.account_id == account.id)
            .with_for_update()
        )
        message = ""
        if template is not None:
            purpose = (
                "owner-notification"
                if signed.field == "owner_message"
                else "contact-notification"
            )
            try:
                message = decrypt_private_text(
                    keys,
                    getattr(template, f"{signed.field}_ciphertext"),
                    getattr(template, f"{signed.field}_nonce"),
                    purpose,
                    account.id,
                    getattr(template, f"{signed.field}_key_version"),
                )
            except (IdentityKeyUnavailable, InvalidTag, UnicodeError):
                raise AeternaProtocolException(
                    503, "service.temporarily_unavailable", signed.request_id
                ) from None
        data = {
            "account_id": str(account.id),
            "field": signed.field,
            "version": template.version if template is not None else 0,
            "message": message,
        }
        await db.rollback()
        return data

    async def edit_template(
        self,
        db: AsyncSession,
        payload: NotificationTemplateEditRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        signed = payload.signed
        keys = self._keys(signed.request_id)
        account, _device, replay = await self._authorize_owner(
            db, payload, document, private=True
        )
        if replay is not None:
            return replay
        template = await db.scalar(
            select(AeternaNotificationTemplate)
            .where(AeternaNotificationTemplate.account_id == account.id)
            .with_for_update()
        )
        version = template.version if template is not None else 0
        if version != signed.expected_version or version >= 2147483647:
            raise AeternaProtocolException(
                409, "notification.template_conflict", signed.request_id
            )
        if template is None:
            fields = {}
            for field, purpose in (
                ("owner_message", "owner-notification"),
                ("contact_message", "contact-notification"),
            ):
                ciphertext, nonce, key_version = encrypt_private_text(
                    keys,
                    signed.message if field == signed.field else "",
                    purpose,
                    account.id,
                    nonce_factory=self.random_bytes,
                )
                fields.update(
                    {
                        f"{field}_ciphertext": ciphertext,
                        f"{field}_nonce": nonce,
                        f"{field}_key_version": key_version,
                    }
                )
            template = AeternaNotificationTemplate(
                account_id=account.id, version=1, **fields
            )
            db.add(template)
        else:
            purpose = (
                "owner-notification"
                if signed.field == "owner_message"
                else "contact-notification"
            )
            ciphertext, nonce, key_version = encrypt_private_text(
                keys,
                signed.message,
                purpose,
                account.id,
                nonce_factory=self.random_bytes,
            )
            setattr(template, f"{signed.field}_ciphertext", ciphertext)
            setattr(template, f"{signed.field}_nonce", nonce)
            setattr(template, f"{signed.field}_key_version", key_version)
            template.version += 1
            template.updated_at = self._now()
        await db.flush()
        data = {"account_id": str(account.id), "version": template.version}
        self._audit(
            db,
            account.id,
            None,
            None,
            "owner",
            "template.updated",
            status=f"v{template.version}",
        )
        self._record_idempotency(
            db,
            account.id,
            signed.operation,
            signed.request_id,
            private_request_digest(keys, document),
            data,
        )
        await db.commit()
        return data

    async def respond_to_invitation(
        self,
        db: AsyncSession,
        payload: ContactInvitationResponseRequest,
        client_address: str,
    ) -> dict[str, bool]:
        keys = self._keys(payload.request_id)
        now = self._now()
        remote_lookup = ip_lookup(keys, client_address)
        if not await self._ip_limit_allows(db, now, remote_lookup):
            self._record_abuse(db, None, None, remote_lookup, "invitation_response")
            await db.commit()
            return {"processed": True}
        try:
            digest = token_digest(payload.token)
        except ValueError:
            digest = self.random_bytes(32)

        invitation_row = (
            await db.execute(
                select(AeternaContactInvitation.id, AeternaContact.account_id)
                .join(
                    AeternaContact,
                    AeternaContact.id == AeternaContactInvitation.contact_id,
                )
                .where(AeternaContactInvitation.token_digest == digest)
            )
        ).one_or_none()
        if invitation_row is None:
            self._record_abuse(db, None, None, remote_lookup, "invitation_response")
            await db.commit()
            return {"processed": True}

        invitation_id, account_id = invitation_row
        account = await db.scalar(
            select(AeternaAccount)
            .where(AeternaAccount.id == account_id, AeternaAccount.is_active.is_(True))
            .with_for_update()
        )
        if account is None:
            self._record_abuse(db, None, None, remote_lookup, "invitation_response")
            await db.commit()
            return {"processed": True}
        invitation = await db.scalar(
            select(AeternaContactInvitation)
            .where(AeternaContactInvitation.id == invitation_id)
            .with_for_update()
        )
        if invitation is None:
            self._record_abuse(db, None, None, remote_lookup, "invitation_response")
            await db.commit()
            return {"processed": True}
        contact = await db.scalar(
            select(AeternaContact)
            .where(
                AeternaContact.id == invitation.contact_id,
                AeternaContact.account_id == account.id,
            )
            .with_for_update()
        )
        if contact is None:
            self._record_abuse(db, None, None, remote_lookup, "invitation_response")
            await db.commit()
            return {"processed": True}

        allowed = await self._enforce_abuse_limits(
            db,
            now=now,
            account_id=account.id,
            recipient_lookup=contact.email_lookup,
            remote_lookup=remote_lookup,
            generic=True,
        )
        if not allowed:
            self._record_abuse(
                db,
                account.id,
                contact.email_lookup,
                remote_lookup,
                "invitation_response",
            )
            await db.commit()
            return {"processed": True}
        self._record_abuse(
            db,
            account.id,
            contact.email_lookup,
            remote_lookup,
            "invitation_response",
        )
        if (
            invitation.status != "pending"
            or invitation.expires_at <= now
            or contact.deleted_at is not None
        ):
            if invitation.status == "pending":
                invitation.status = "expired"
                invitation.consumed_at = now
            await db.commit()
            return {"processed": True}

        if payload.decision == "accept":
            invitation.status = "accepted"
            invitation.consumed_at = now
            contact.consent_status = "ACCEPTED"
            contact.accepted_at = now
            contact.verified_at = now
            contact.declined_at = None
            contact.updated_at = now
            await self._revoke_other_invitations(db, contact.id, invitation.id, now)
            self._audit(
                db,
                account.id,
                contact.id,
                None,
                "recipient",
                "contact.accepted",
                status="verified",
            )
        else:
            invitation.status = "declined"
            invitation.consumed_at = now
            await self._delete_contact_record(
                db,
                contact,
                now=now,
                actor_kind="recipient",
                audit_event="contact.declined",
                suppress=True,
            )
        await db.commit()
        return {"processed": True}

    async def materialize_policy_event(
        self,
        db: AsyncSession,
        event_id: uuid.UUID,
    ) -> list[uuid.UUID]:
        """Convert one I11 intent into redacted I12 email intents idempotently."""

        relation = (
            await db.execute(
                select(AccountPolicy.account_id, AccountPolicy.id)
                .join(
                    AccountPolicyOutboxEvent,
                    AccountPolicyOutboxEvent.account_policy_id == AccountPolicy.id,
                )
                .where(AccountPolicyOutboxEvent.id == event_id)
            )
        ).one_or_none()
        if relation is None or relation.account_id is None:
            return []
        account = await db.scalar(
            select(AeternaAccount)
            .where(AeternaAccount.id == relation.account_id)
            .with_for_update()
        )
        policy = await db.scalar(
            select(AccountPolicy)
            .where(AccountPolicy.id == relation.id)
            .with_for_update()
        )
        source = await db.scalar(
            select(AccountPolicyOutboxEvent)
            .where(AccountPolicyOutboxEvent.id == event_id)
            .with_for_update()
        )
        if (
            account is None
            or policy is None
            or source is None
            or source.status == "cancelled"
            or source.notification_type is None
            or source.delivery_idempotency_key is None
        ):
            return []

        now = self._now()
        created_ids: list[uuid.UUID] = []
        owner_key = f"{source.delivery_idempotency_key}:owner"
        owner_event = await db.scalar(
            select(AeternaEmailOutboxEvent).where(
                AeternaEmailOutboxEvent.idempotency_key == owner_key
            )
        )
        if owner_event is None:
            owner_event = self._queue_email_event(
                db,
                account_id=account.id,
                event_type=source.notification_type,
                idempotency_key=owner_key,
                now=now,
                source_policy_outbox_id=source.id,
            )
            created_ids.append(owner_event.id)

        if source.notification_type == "owner-release-authorized":
            contacts = list(
                (
                    await db.scalars(
                        select(AeternaContact)
                        .where(
                            AeternaContact.account_id == account.id,
                            AeternaContact.disclosure_mode == "PRIVATE_UNTIL_RELEASE",
                            AeternaContact.consent_status == "NOT_REQUESTED",
                            AeternaContact.deleted_at.is_(None),
                        )
                        .with_for_update()
                    )
                ).all()
            )
            keys = self._keys()
            for contact in contacts:
                if (
                    await db.get(AeternaRecipientSuppression, contact.email_lookup)
                    is not None
                ):
                    continue
                invitation_event = await self._queue_invitation(
                    db,
                    keys=keys,
                    contact=contact,
                    now=now,
                    key_suffix=f"release:{source.id}",
                    source_policy_outbox_id=source.id,
                )
                created_ids.append(invitation_event.id)
        await db.commit()
        return created_ids

    async def _authorize_owner(
        self,
        db: AsyncSession,
        payload,
        document: dict[str, Any],
        *,
        private: bool = False,
    ) -> tuple[AeternaAccount, AeternaDevice, dict[str, Any] | None]:
        signed = payload.signed
        account_id = uuid.UUID(signed.account_id)
        device_id = uuid.UUID(signed.authorizing_device_id)
        account = await db.scalar(
            select(AeternaAccount)
            .where(AeternaAccount.id == account_id, AeternaAccount.is_active.is_(True))
            .with_for_update()
        )
        device = await db.scalar(
            select(AeternaDevice)
            .where(
                AeternaDevice.id == device_id,
                AeternaDevice.account_id == account_id,
            )
            .with_for_update()
        )
        if (
            account is None
            or device is None
            or not verify_signature(
                device.public_key, document["signed"], payload.signature
            )
        ):
            raise AeternaProtocolException(
                401, "device.proof_invalid", signed.request_id
            )
        now = self._now()
        reference = device.last_seen_at or device.heartbeat_authorized_at
        if device.status != "active" or reference + DEVICE_DORMANCY <= now:
            raise AeternaProtocolException(403, "device.not_active", signed.request_id)

        keys = self._keys(signed.request_id)
        digest = (
            private_request_digest(keys, document)
            if private
            else request_digest(document)
        )
        replay = await self._idempotent_replay(
            db, account.id, signed.operation, signed.request_id, digest
        )
        return account, device, replay

    async def _idempotent_replay(
        self,
        db: AsyncSession,
        account_id: uuid.UUID,
        operation: str,
        request_id: str,
        digest: bytes,
    ) -> dict[str, Any] | None:
        record = await db.scalar(
            select(AeternaProtocolIdempotency).where(
                AeternaProtocolIdempotency.operation == operation,
                AeternaProtocolIdempotency.request_id == uuid.UUID(request_id),
            )
        )
        if record is None:
            return None
        if record.account_id != account_id or not secrets.compare_digest(
            record.request_digest, digest
        ):
            raise AeternaProtocolException(
                409, "request.idempotency_conflict", request_id
            )
        return record.response_data

    def _record_idempotency(
        self,
        db: AsyncSession,
        account_id: uuid.UUID,
        operation: str,
        request_id: str,
        digest: bytes,
        data: dict[str, Any],
    ) -> None:
        db.add(
            AeternaProtocolIdempotency(
                id=self.uuid_factory(),
                account_id=account_id,
                operation=operation,
                request_id=uuid.UUID(request_id),
                request_digest=digest,
                http_status=200,
                response_data=data,
            )
        )

    async def _locked_contact(
        self,
        db: AsyncSession,
        account_id: uuid.UUID,
        contact_id: str,
        request_id: str,
        *,
        include_deleted: bool = False,
    ) -> AeternaContact:
        conditions = [
            AeternaContact.id == uuid.UUID(contact_id),
            AeternaContact.account_id == account_id,
        ]
        if not include_deleted:
            conditions.append(AeternaContact.deleted_at.is_(None))
        contact = await db.scalar(
            select(AeternaContact).where(*conditions).with_for_update()
        )
        if contact is None:
            raise AeternaProtocolException(404, "contact.not_found", request_id)
        return contact

    def _require_actionable_contact(
        self, contact: AeternaContact, request_id: str
    ) -> None:
        if contact.deleted_at is not None or contact.consent_status == "DECLINED":
            raise AeternaProtocolException(404, "contact.not_found", request_id)

    async def _queue_invitation(
        self,
        db: AsyncSession,
        *,
        keys: AeternaIdentityKeys,
        contact: AeternaContact,
        now: datetime,
        key_suffix: str,
        source_policy_outbox_id: uuid.UUID | None = None,
    ) -> AeternaEmailOutboxEvent:
        await db.execute(
            update(AeternaContactInvitation)
            .where(
                AeternaContactInvitation.contact_id == contact.id,
                AeternaContactInvitation.status == "pending",
            )
            .values(status="revoked", consumed_at=now, updated_at=now)
            .execution_options(synchronize_session=False)
        )
        invitation_id = self.uuid_factory()
        token = derive_invitation_token(keys, invitation_id)
        invitation = AeternaContactInvitation(
            id=invitation_id,
            contact_id=contact.id,
            token_digest=token_digest(token),
            token_key_version=keys.version,
            status="pending",
            expires_at=now + INVITATION_LIFETIME,
        )
        db.add(invitation)
        contact.consent_status = "INVITED"
        contact.invitation_sent_at = None
        contact.accepted_at = None
        contact.declined_at = None
        contact.verified_at = None
        contact.updated_at = now
        event = self._queue_email_event(
            db,
            account_id=contact.account_id,
            contact_id=contact.id,
            invitation_id=invitation.id,
            event_type="contact-invitation",
            idempotency_key=f"contact-invitation:{contact.id}:{key_suffix}",
            now=now,
            source_policy_outbox_id=source_policy_outbox_id,
        )
        self._audit(
            db,
            contact.account_id,
            contact.id,
            event.id,
            "system",
            "contact.invited",
            status="queued",
        )
        await db.flush()
        return event

    def _queue_email_event(
        self,
        db: AsyncSession,
        *,
        account_id: uuid.UUID,
        event_type: str,
        idempotency_key: str,
        now: datetime,
        contact_id: uuid.UUID | None = None,
        invitation_id: uuid.UUID | None = None,
        source_policy_outbox_id: uuid.UUID | None = None,
    ) -> AeternaEmailOutboxEvent:
        event = AeternaEmailOutboxEvent(
            id=self.uuid_factory(),
            account_id=account_id,
            contact_id=contact_id,
            invitation_id=invitation_id,
            source_policy_outbox_id=source_policy_outbox_id,
            recipient_kind="contact" if contact_id is not None else "owner",
            event_type=event_type,
            idempotency_key=idempotency_key,
            status="queued",
            next_attempt_at=now,
            attempt_count=0,
        )
        db.add(event)
        self._audit(
            db,
            account_id,
            contact_id,
            event.id,
            "system",
            "delivery.queued",
            status="queued",
        )
        return event

    async def _delete_contact_record(
        self,
        db: AsyncSession,
        contact: AeternaContact,
        *,
        now: datetime,
        actor_kind: str,
        audit_event: str,
        suppress: bool,
    ) -> None:
        await db.execute(
            update(AeternaContactInvitation)
            .where(
                AeternaContactInvitation.contact_id == contact.id,
                AeternaContactInvitation.status == "pending",
            )
            .values(status="revoked", consumed_at=now, updated_at=now)
            .execution_options(synchronize_session=False)
        )
        cancelled_ids = list(
            (
                await db.scalars(
                    update(AeternaEmailOutboxEvent)
                    .where(
                        AeternaEmailOutboxEvent.contact_id == contact.id,
                        AeternaEmailOutboxEvent.status.in_({"queued", "retry_pending"}),
                    )
                    .values(status="cancelled", cancelled_at=now, updated_at=now)
                    .returning(AeternaEmailOutboxEvent.id)
                    .execution_options(synchronize_session=False)
                )
            ).all()
        )
        for event_id in cancelled_ids:
            self._audit(
                db,
                contact.account_id,
                contact.id,
                event_id,
                actor_kind,
                "delivery.cancelled",
                status="cancelled",
            )
        contact.consent_status = "DECLINED"
        contact.accepted_at = None
        contact.verified_at = None
        contact.declined_at = now
        contact.deleted_at = now
        contact.email_ciphertext = self.random_bytes(len(contact.email_ciphertext))
        contact.email_nonce = self.random_bytes(12)
        contact.updated_at = now
        if suppress:
            suppression = await db.get(
                AeternaRecipientSuppression, contact.email_lookup
            )
            if suppression is None:
                db.add(
                    AeternaRecipientSuppression(
                        recipient_lookup=contact.email_lookup,
                        reason="declined",
                    )
                )
            else:
                suppression.reason = "declined"
                suppression.updated_at = now
        self._audit(
            db,
            contact.account_id,
            contact.id,
            None,
            actor_kind,
            audit_event,
            status="deleted",
        )

    async def _revoke_other_invitations(
        self,
        db: AsyncSession,
        contact_id: uuid.UUID,
        accepted_invitation_id: uuid.UUID,
        now: datetime,
    ) -> None:
        await db.execute(
            update(AeternaContactInvitation)
            .where(
                AeternaContactInvitation.contact_id == contact_id,
                AeternaContactInvitation.id != accepted_invitation_id,
                AeternaContactInvitation.status == "pending",
            )
            .values(status="revoked", consumed_at=now, updated_at=now)
            .execution_options(synchronize_session=False)
        )

    async def _contact_data(
        self, db: AsyncSession, contact: AeternaContact
    ) -> dict[str, Any]:
        latest = await db.scalar(
            select(AeternaEmailOutboxEvent)
            .where(AeternaEmailOutboxEvent.contact_id == contact.id)
            .order_by(AeternaEmailOutboxEvent.created_at.desc())
            .limit(1)
        )
        return {
            "account_id": str(contact.account_id),
            "contact_id": str(contact.id),
            "disclosure_mode": contact.disclosure_mode,
            "consent_status": contact.consent_status,
            "is_recovery_contact": (
                contact.deleted_at is None
                and contact.consent_status == "ACCEPTED"
                and contact.verified_at is not None
            ),
            "deleted": contact.deleted_at is not None,
            "last_delivery_status": latest.status if latest is not None else None,
            "bounced_at": (
                format_timestamp(contact.bounced_at)
                if contact.bounced_at is not None
                else None
            ),
        }

    async def _enforce_abuse_limits(
        self,
        db: AsyncSession,
        *,
        now: datetime,
        account_id: uuid.UUID,
        recipient_lookup: bytes,
        remote_lookup: bytes | None,
        generic: bool = False,
    ) -> bool:
        since = now - ABUSE_WINDOW
        account_count = await db.scalar(
            select(func.count(AeternaNotificationAbuseEvent.id)).where(
                AeternaNotificationAbuseEvent.account_id == account_id,
                AeternaNotificationAbuseEvent.created_at >= since,
            )
        )
        recipient_count = await db.scalar(
            select(func.count(AeternaNotificationAbuseEvent.id)).where(
                AeternaNotificationAbuseEvent.recipient_lookup == recipient_lookup,
                AeternaNotificationAbuseEvent.created_at >= since,
            )
        )
        ip_count = 0
        if remote_lookup is not None:
            ip_count = (
                await db.scalar(
                    select(func.count(AeternaNotificationAbuseEvent.id)).where(
                        AeternaNotificationAbuseEvent.ip_lookup == remote_lookup,
                        AeternaNotificationAbuseEvent.created_at >= since,
                    )
                )
                or 0
            )
        if (
            (account_count or 0) >= MAX_ACCOUNT_ACTIONS_PER_DAY
            or (recipient_count or 0) >= MAX_RECIPIENT_ACTIONS_PER_DAY
            or ip_count >= MAX_IP_ACTIONS_PER_DAY
        ):
            if generic:
                return False
            raise AeternaProtocolException(
                429, "notification.rate_limited", retry_after_seconds=86_400
            )
        return True

    async def _ip_limit_allows(
        self, db: AsyncSession, now: datetime, remote_lookup: bytes
    ) -> bool:
        count = await db.scalar(
            select(func.count(AeternaNotificationAbuseEvent.id)).where(
                AeternaNotificationAbuseEvent.ip_lookup == remote_lookup,
                AeternaNotificationAbuseEvent.created_at >= now - ABUSE_WINDOW,
            )
        )
        return (count or 0) < MAX_IP_ACTIONS_PER_DAY

    def _record_abuse(
        self,
        db: AsyncSession,
        account_id: uuid.UUID | None,
        recipient_lookup: bytes | None,
        remote_lookup: bytes | None,
        event_type: str,
    ) -> None:
        db.add(
            AeternaNotificationAbuseEvent(
                id=self.uuid_factory(),
                account_id=account_id,
                recipient_lookup=recipient_lookup,
                ip_lookup=remote_lookup,
                event_type=event_type,
            )
        )

    def _audit(
        self,
        db: AsyncSession,
        account_id: uuid.UUID,
        contact_id: uuid.UUID | None,
        outbox_event_id: uuid.UUID | None,
        actor_kind: str,
        event_type: str,
        *,
        status: str | None = None,
        reason_code: str | None = None,
    ) -> None:
        db.add(
            AeternaNotificationAudit(
                id=self.uuid_factory(),
                account_id=account_id,
                contact_id=contact_id,
                outbox_event_id=outbox_event_id,
                actor_kind=actor_kind,
                event_type=event_type,
                status=status,
                reason_code=reason_code,
            )
        )

    def _keys(self, request_id: str | None = None) -> AeternaIdentityKeys:
        try:
            return self.key_provider()
        except IdentityKeyUnavailable:
            raise AeternaProtocolException(
                503, "service.temporarily_unavailable", request_id
            ) from None

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise RuntimeError("The notification clock must be timezone-aware")
        return value.astimezone(UTC)

    def _require_action(self, payload: ContactActionRequest, operation: str) -> None:
        if payload.signed.operation != operation:
            raise AeternaProtocolException(
                400, "protocol.invalid_request", payload.signed.request_id
            )


def get_aeterna_notification_service() -> AeternaNotificationService:
    """Assemble the contact and notification service dependency chain."""

    return AeternaNotificationService(
        management_service=get_aeterna_management_authority_service()
    )
