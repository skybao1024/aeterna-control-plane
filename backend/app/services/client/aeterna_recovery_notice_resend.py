"""Bounded explicit resend to an existing post-release notification target."""

import math
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.models.account_policy import AccountPolicyOutboxEvent
from app.models.aeterna_identity import AeternaProtocolIdempotency
from app.models.aeterna_notification import (
    AeternaContactInvitation,
    AeternaEmailOutboxEvent,
    AeternaNotificationAbuseEvent,
    AeternaRecipientSuppression,
)
from app.models.aeterna_recovery import AeternaRecoveryGrant, AeternaRecoveryRecord
from app.schemas.client.aeterna_recovery_notice import RecoveryNoticeResendRequest
from app.services.client.aeterna_notification import (
    AeternaNotificationService,
    get_aeterna_notification_service,
)
from app.services.client.aeterna_recovery import (
    AeternaRecoveryService,
    get_aeterna_recovery_service,
)
from app.services.client.aeterna_recovery_notice import (
    AeternaRecoveryNoticeService,
    format_timestamp,
    get_aeterna_recovery_notice_service,
    utc_now,
)
from app.services.common.aeterna_security import request_digest

RESEND_OPERATION = "recovery_notice.resend"
RESEND_COOLDOWN_SECONDS = 60
RESEND_DAY_SECONDS = 86_400
MAX_DEVICE_RESENDS_PER_DAY = 10


class AeternaRecoveryNoticeResendService:
    """Queue one existing-target email and its exact durable receipt atomically."""

    def __init__(
        self,
        *,
        notice_service: AeternaRecoveryNoticeService | None = None,
        notification_service: AeternaNotificationService | None = None,
        recovery_service: AeternaRecoveryService | None = None,
        clock: Callable[[], datetime] = utc_now,
    ):
        self.notice = notice_service or get_aeterna_recovery_notice_service()
        self.notifications = notification_service or get_aeterna_notification_service()
        self.recovery = recovery_service or get_aeterna_recovery_service()
        self.clock = clock

    async def resend(
        self,
        db: AsyncSession,
        payload: RecoveryNoticeResendRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        signed = payload.signed
        account, device, policy = await self.notice.authorize_device(
            db, payload, document
        )
        if policy is None or policy.state != "RELEASED":
            raise AeternaProtocolException(409, "policy.unavailable", signed.request_id)
        now = self._now()
        if (
            policy.released_at is None
            or policy.last_activity_at > policy.released_at
            or policy.released_at > now
        ):
            raise AeternaProtocolException(
                503, "service.temporarily_unavailable", signed.request_id
            )
        digest = request_digest(document)
        replay = await self.notifications._idempotent_replay(
            db, account.id, signed.operation, signed.request_id, digest
        )
        if replay is not None:
            await db.rollback()
            return replay
        contact = await self.notifications._locked_contact(
            db, account.id, signed.contact_id, signed.request_id
        )
        self.notifications._require_actionable_contact(contact, signed.request_id)
        if await db.get(AeternaRecipientSuppression, contact.email_lookup) is not None:
            raise AeternaProtocolException(
                400, "contact.recipient_unavailable", signed.request_id
            )
        await self._enforce_resend_limits(
            db, account.id, device.id, contact.id, now, signed.request_id
        )
        await self.notifications._enforce_abuse_limits(
            db,
            now=now,
            account_id=account.id,
            recipient_lookup=contact.email_lookup,
            remote_lookup=None,
        )
        keys = self.notifications._keys(signed.request_id)
        if contact.consent_status == "ACCEPTED" and contact.verified_at is not None:
            grant = await db.scalar(
                select(AeternaRecoveryGrant)
                .join(
                    AeternaRecoveryRecord,
                    AeternaRecoveryGrant.recovery_id == AeternaRecoveryRecord.id,
                )
                .where(
                    AeternaRecoveryGrant.account_id == account.id,
                    AeternaRecoveryGrant.contact_id == contact.id,
                    AeternaRecoveryGrant.state == "available",
                    AeternaRecoveryRecord.account_id == account.id,
                    AeternaRecoveryRecord.device_id == device.id,
                    AeternaRecoveryRecord.state == "sealed",
                    AeternaRecoveryRecord.policy_epoch == policy.epoch,
                    AeternaRecoveryRecord.recovery_generation
                    == account.current_recovery_generation,
                )
                .order_by(
                    AeternaRecoveryRecord.created_at.desc(), AeternaRecoveryGrant.id
                )
                .limit(1)
                .with_for_update()
            )
            if grant is None:
                raise AeternaProtocolException(
                    409, "recovery.record_unavailable", signed.request_id
                )
            await self.recovery.queue_grant_email(
                db,
                grant=grant,
                keys=keys,
                now=now,
                idempotency_key=f"recovery-notice-resend:{signed.request_id}:{grant.id}",
            )
            kind = "release"
        elif (
            contact.disclosure_mode == "PRIVATE_UNTIL_RELEASE"
            and contact.consent_status in {"NOT_REQUESTED", "INVITED"}
        ):
            source = await db.scalar(
                select(AccountPolicyOutboxEvent)
                .where(
                    AccountPolicyOutboxEvent.account_policy_id == policy.id,
                    AccountPolicyOutboxEvent.notification_type
                    == "owner-release-authorized",
                    AccountPolicyOutboxEvent.to_state == "RELEASED",
                )
                .order_by(
                    AccountPolicyOutboxEvent.created_at.desc(),
                    AccountPolicyOutboxEvent.id,
                )
                .limit(1)
            )
            if source is None:
                raise AeternaProtocolException(
                    503, "service.temporarily_unavailable", signed.request_id
                )
            invitation = await db.scalar(
                select(AeternaContactInvitation)
                .join(
                    AeternaEmailOutboxEvent,
                    AeternaEmailOutboxEvent.invitation_id
                    == AeternaContactInvitation.id,
                )
                .where(
                    AeternaContactInvitation.contact_id == contact.id,
                    AeternaContactInvitation.status == "pending",
                    AeternaContactInvitation.expires_at > now,
                    AeternaEmailOutboxEvent.account_id == account.id,
                    AeternaEmailOutboxEvent.contact_id == contact.id,
                    AeternaEmailOutboxEvent.source_policy_outbox_id == source.id,
                )
                .order_by(
                    AeternaContactInvitation.created_at.desc(),
                    AeternaContactInvitation.id,
                )
                .limit(1)
                .with_for_update(of=AeternaContactInvitation)
            )
            if invitation is not None and contact.consent_status == "INVITED":
                # Resend a still-valid neutral invitation without invalidating
                # the email the contact may already be reading.
                self.notifications._queue_email_event(
                    db,
                    account_id=account.id,
                    contact_id=contact.id,
                    invitation_id=invitation.id,
                    event_type="contact-invitation",
                    idempotency_key=f"recovery-notice-resend:{signed.request_id}:{invitation.id}",
                    now=now,
                    source_policy_outbox_id=source.id,
                )
            else:
                await self.notifications._queue_invitation(
                    db,
                    keys=keys,
                    contact=contact,
                    now=now,
                    key_suffix=f"release-resend:{signed.request_id}",
                    source_policy_outbox_id=source.id,
                )
            kind = "invitation"
        else:
            raise AeternaProtocolException(
                400, "contact.recipient_unavailable", signed.request_id
            )
        data = {
            "account_id": str(account.id),
            "device_id": str(device.id),
            "contact_id": str(contact.id),
            "observed_at": format_timestamp(now),
            "kind": kind,
            "status": "pending",
            "retry_after_seconds": RESEND_COOLDOWN_SECONDS,
        }
        # Both branches share the existing contact-invitation email budget.
        db.add(
            AeternaNotificationAbuseEvent(
                id=self.notifications.uuid_factory(),
                account_id=account.id,
                recipient_lookup=contact.email_lookup,
                event_type="contact_invite",
                created_at=now,
                updated_at=now,
            )
        )
        db.add(
            AeternaProtocolIdempotency(
                id=self.notifications.uuid_factory(),
                account_id=account.id,
                operation=signed.operation,
                request_id=uuid.UUID(signed.request_id),
                request_digest=digest,
                http_status=200,
                response_data=data,
                created_at=now,
                updated_at=now,
            )
        )
        await db.commit()
        return data

    async def _enforce_resend_limits(
        self,
        db: AsyncSession,
        account_id: uuid.UUID,
        device_id: uuid.UUID,
        contact_id: uuid.UUID,
        now: datetime,
        request_id: str,
    ) -> None:
        base = (
            AeternaProtocolIdempotency.account_id == account_id,
            AeternaProtocolIdempotency.operation == RESEND_OPERATION,
        )
        last_target = await db.scalar(
            select(AeternaProtocolIdempotency.created_at)
            .where(
                *base,
                AeternaProtocolIdempotency.response_data["contact_id"].as_string()
                == str(contact_id),
            )
            .order_by(AeternaProtocolIdempotency.created_at.desc())
            .limit(1)
        )
        if last_target is not None:
            remaining = RESEND_COOLDOWN_SECONDS - (now - last_target).total_seconds()
            if remaining > 0:
                raise AeternaProtocolException(
                    429,
                    "notification.rate_limited",
                    request_id,
                    retry_after_seconds=max(
                        1, min(RESEND_COOLDOWN_SECONDS, math.ceil(remaining))
                    ),
                )
        device_count = await db.scalar(
            select(func.count(AeternaProtocolIdempotency.id)).where(
                *base,
                AeternaProtocolIdempotency.response_data["device_id"].as_string()
                == str(device_id),
                AeternaProtocolIdempotency.created_at
                >= now - timedelta(seconds=RESEND_DAY_SECONDS),
            )
        )
        if (device_count or 0) >= MAX_DEVICE_RESENDS_PER_DAY:
            raise AeternaProtocolException(
                429,
                "notification.rate_limited",
                request_id,
                retry_after_seconds=RESEND_DAY_SECONDS,
            )

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise RuntimeError(
                "The recovery notice resend clock must be timezone-aware"
            )
        return value.astimezone(UTC)


def get_aeterna_recovery_notice_resend_service() -> AeternaRecoveryNoticeResendService:
    return AeternaRecoveryNoticeResendService(
        notice_service=get_aeterna_recovery_notice_service(),
        notification_service=get_aeterna_notification_service(),
        recovery_service=get_aeterna_recovery_service(),
    )
