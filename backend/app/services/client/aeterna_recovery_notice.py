"""Read-only release discovery without granting activity or recovery authority."""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidTag
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.models.account_policy import AccountPolicy, AccountPolicyOutboxEvent
from app.models.aeterna_identity import AeternaAccount, AeternaDevice
from app.models.aeterna_notification import AeternaContact, AeternaEmailOutboxEvent
from app.models.aeterna_recovery import (
    AeternaRecoveryClaimLink,
    AeternaRecoveryGrant,
    AeternaRecoveryRecord,
)
from app.schemas.client.aeterna_recovery_notice import (
    RecoveryNoticeRequest,
    RecoveryNoticeResendRequest,
)
from app.services.common.aeterna_security import (
    AeternaIdentityKeys,
    IdentityKeyUnavailable,
    decrypt_email,
    get_identity_keys,
    normalize_email,
    verify_signature,
)

# At most 256 current recovery records times 10 contacts, plus release invitations.
MAX_NOTICE_EVENTS = 2_570
FAILURE_STATUSES = {"failed", "bounced", "complained", "cancelled"}
PENDING_STATUSES = {"queued", "sending", "retry_pending"}


def utc_now() -> datetime:
    return datetime.now(UTC)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class AeternaRecoveryNoticeService:
    """Expose only known recipients tied to the exact current RELEASED policy."""

    def __init__(
        self,
        key_provider: Callable[[], AeternaIdentityKeys] = get_identity_keys,
        clock: Callable[[], datetime] = utc_now,
    ):
        self.key_provider = key_provider
        self.clock = clock

    async def read(
        self,
        db: AsyncSession,
        payload: RecoveryNoticeRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        account, _device, policy = await self.authorize_device(db, payload, document)
        signed = payload.signed
        account_id = uuid.UUID(signed.account_id)
        state = policy.state if policy is not None else "NOT_CONFIGURED"
        observed_at = self.clock()
        data: dict[str, Any] = {
            "account_id": signed.account_id,
            "device_id": signed.authorizing_device_id,
            "observed_at": format_timestamp(observed_at),
            "state": state,
            "epoch": policy.epoch if policy is not None else None,
            "last_activity_at": (
                format_timestamp(policy.last_activity_at)
                if policy is not None
                else None
            ),
            "released_at": None,
            "recipients": [],
        }
        if state != "RELEASED":
            await db.rollback()
            return data
        if (
            policy is None
            or policy.released_at is None
            or policy.last_activity_at > policy.released_at
            or policy.released_at > observed_at
        ):
            raise AeternaProtocolException(
                503, "service.temporarily_unavailable", signed.request_id
            )
        data["released_at"] = format_timestamp(policy.released_at)
        contacts = list(
            (
                await db.scalars(
                    select(AeternaContact).where(
                        AeternaContact.account_id == account_id,
                        AeternaContact.id.in_(
                            [uuid.UUID(value) for value in signed.contact_ids]
                        ),
                    )
                )
            ).all()
        )
        if {str(contact.id) for contact in contacts} != set(signed.contact_ids):
            raise AeternaProtocolException(404, "contact.not_found", signed.request_id)

        release_events = await self._release_events(db, account, policy, contacts)
        invitation_events = await self._invitation_events(db, account, policy, contacts)
        if len(release_events) + len(invitation_events) > MAX_NOTICE_EVENTS:
            raise AeternaProtocolException(
                503, "service.temporarily_unavailable", signed.request_id
            )
        contacts_by_id = {str(contact.id): contact for contact in contacts}
        keys = None
        try:
            for contact_id in signed.contact_ids:
                contact = contacts_by_id[contact_id]
                if contact.deleted_at is not None:
                    continue
                events = [
                    event for event in release_events if event.contact_id == contact.id
                ]
                kind = "release"
                if not events:
                    events = [
                        event
                        for event in invitation_events
                        if event.contact_id == contact.id
                    ]
                    kind = "invitation"
                if not events:
                    continue
                if keys is None:
                    keys = self.key_provider()
                email = normalize_email(
                    decrypt_email(
                        keys,
                        contact.email_ciphertext,
                        contact.email_nonce,
                        "contact",
                        contact.id,
                        contact.email_key_version,
                    )
                )
                data["recipients"].append(
                    {
                        "contact_id": contact_id,
                        "email": email,
                        "kind": kind,
                        "status": self._delivery_status(events),
                    }
                )
        except (IdentityKeyUnavailable, InvalidTag, UnicodeError, ValueError):
            raise AeternaProtocolException(
                503, "service.temporarily_unavailable", signed.request_id
            ) from None
        await db.rollback()
        return data

    async def authorize_device(
        self,
        db: AsyncSession,
        payload: RecoveryNoticeRequest | RecoveryNoticeResendRequest,
        document: dict[str, Any],
    ) -> tuple[AeternaAccount, AeternaDevice, AccountPolicy | None]:
        signed = payload.signed
        account_id = uuid.UUID(signed.account_id)
        device_id = uuid.UUID(signed.authorizing_device_id)
        device = await db.scalar(
            select(AeternaDevice).where(
                AeternaDevice.id == device_id,
                AeternaDevice.account_id == account_id,
            )
        )
        if device is None or not verify_signature(
            device.public_key, document["signed"], payload.signature
        ):
            raise AeternaProtocolException(
                401, "device.proof_invalid", signed.request_id
            )

        # Authenticate before locking. The account lock serializes release,
        # reactivation and contact removal while this bounded snapshot is read.
        account = await db.scalar(
            select(AeternaAccount)
            .where(AeternaAccount.id == account_id, AeternaAccount.is_active.is_(True))
            .with_for_update()
        )
        device = await db.scalar(
            select(AeternaDevice)
            .where(
                AeternaDevice.id == device_id, AeternaDevice.account_id == account_id
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if (
            account is None
            or device is None
            or device.status not in {"active", "dormant"}
        ):
            raise AeternaProtocolException(403, "device.not_active", signed.request_id)
        policy = await db.scalar(
            select(AccountPolicy).where(
                AccountPolicy.account_id == account_id,
                AccountPolicy.epoch == account.current_policy_epoch,
                AccountPolicy.retired_at.is_(None),
            )
        )
        state = policy.state if policy is not None else "NOT_CONFIGURED"
        if device.status == "dormant" and state != "RELEASED":
            raise AeternaProtocolException(403, "device.not_active", signed.request_id)
        return account, device, policy

    async def _release_events(
        self,
        db: AsyncSession,
        account: AeternaAccount,
        policy: AccountPolicy,
        contacts: list[AeternaContact],
    ) -> list[AeternaEmailOutboxEvent]:
        return list(
            (
                await db.scalars(
                    select(AeternaEmailOutboxEvent)
                    .join(
                        AeternaRecoveryClaimLink,
                        AeternaEmailOutboxEvent.recovery_link_id
                        == AeternaRecoveryClaimLink.id,
                    )
                    .join(
                        AeternaRecoveryGrant,
                        AeternaRecoveryClaimLink.grant_id == AeternaRecoveryGrant.id,
                    )
                    .join(
                        AeternaRecoveryRecord,
                        AeternaRecoveryGrant.recovery_id == AeternaRecoveryRecord.id,
                    )
                    .where(
                        AeternaEmailOutboxEvent.account_id == account.id,
                        AeternaEmailOutboxEvent.recipient_kind == "contact",
                        AeternaEmailOutboxEvent.event_type == "recovery-claim-link",
                        AeternaEmailOutboxEvent.contact_id.in_(
                            [value.id for value in contacts]
                        ),
                        AeternaRecoveryGrant.account_id == account.id,
                        AeternaRecoveryGrant.contact_id
                        == AeternaEmailOutboxEvent.contact_id,
                        AeternaRecoveryRecord.account_id == account.id,
                        AeternaRecoveryRecord.policy_epoch == policy.epoch,
                        AeternaRecoveryRecord.recovery_generation
                        == account.current_recovery_generation,
                    )
                    .limit(MAX_NOTICE_EVENTS + 1)
                )
            ).all()
        )

    async def _invitation_events(
        self,
        db: AsyncSession,
        account: AeternaAccount,
        policy: AccountPolicy,
        contacts: list[AeternaContact],
    ) -> list[AeternaEmailOutboxEvent]:
        return list(
            (
                await db.scalars(
                    select(AeternaEmailOutboxEvent)
                    .join(
                        AccountPolicyOutboxEvent,
                        AeternaEmailOutboxEvent.source_policy_outbox_id
                        == AccountPolicyOutboxEvent.id,
                    )
                    .where(
                        AeternaEmailOutboxEvent.account_id == account.id,
                        AeternaEmailOutboxEvent.recipient_kind == "contact",
                        AeternaEmailOutboxEvent.event_type == "contact-invitation",
                        AeternaEmailOutboxEvent.contact_id.in_(
                            [value.id for value in contacts]
                        ),
                        AccountPolicyOutboxEvent.account_policy_id == policy.id,
                        AccountPolicyOutboxEvent.notification_type
                        == "owner-release-authorized",
                        AccountPolicyOutboxEvent.to_state == "RELEASED",
                    )
                    .limit(MAX_NOTICE_EVENTS + 1)
                )
            ).all()
        )

    def _delivery_status(self, events: list[AeternaEmailOutboxEvent]) -> str:
        eligible = [event for event in events if event.status not in FAILURE_STATUSES]
        if any(event.status == "delivered" for event in eligible):
            return "delivered"
        if any(event.status == "provider_accepted" for event in eligible):
            return "submitted"
        if any(event.status in PENDING_STATUSES for event in eligible):
            return "pending"
        if all(event.status in FAILURE_STATUSES for event in events):
            return "failed"
        return "unknown"


def get_aeterna_recovery_notice_service() -> AeternaRecoveryNoticeService:
    return AeternaRecoveryNoticeService()
