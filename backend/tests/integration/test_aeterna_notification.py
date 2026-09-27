"""Real-PostgreSQL acceptance evidence for I12 contacts and email delivery."""

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import delete, select

from app.db.base import get_session_local
from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.models.account_policy import AccountPolicy, AccountPolicyOutboxEvent
from app.models.aeterna_identity import (
    AeternaAccount,
    AeternaDevice,
    AeternaProtocolIdempotency,
)
from app.models.aeterna_notification import (
    AeternaContact,
    AeternaContactInvitation,
    AeternaEmailDeliveryAttempt,
    AeternaEmailDeliveryCallback,
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
    NotificationTemplateRequest,
)
from app.services.client.aeterna_notification import AeternaNotificationService
from app.services.common.aeterna_email_adapter import (
    AeternaEmailEnvelope,
    EmailDeliveryFailure,
    ProviderAcceptance,
)
from app.services.common.aeterna_security import (
    AeternaIdentityKeys,
    canonicalize,
    decrypt_email,
    derive_invitation_token,
    encode_base64url,
    encrypt_email,
)
from app.services.internal.aeterna_email_delivery import (
    AeternaEmailDeliveryService,
    DeliveryCallbackType,
)

pytestmark = pytest.mark.asyncio(loop_scope="session")

INACTIVITY_SECONDS = 30 * 24 * 60 * 60
WARNING_SECONDS = 7 * 24 * 60 * 60
GRACE_SECONDS = 7 * 24 * 60 * 60


@dataclass
class MutableClock:
    current: datetime

    def __call__(self) -> datetime:
        return self.current


@dataclass
class FakeIdempotentAdapter:
    """Synthetic provider with explicit idempotency and failure control."""

    provider_name: str = "fake-provider"
    supports_idempotency: bool = True
    failures_remaining: int = 0
    envelopes: list[AeternaEmailEnvelope] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    accepted: dict[str, ProviderAcceptance] = field(default_factory=dict)

    async def send(
        self, envelope: AeternaEmailEnvelope, idempotency_key: str
    ) -> ProviderAcceptance:
        self.calls.append(idempotency_key)
        await asyncio.sleep(0)
        if self.failures_remaining:
            self.failures_remaining -= 1
            raise EmailDeliveryFailure("synthetic-transient", retryable=True)
        if idempotency_key not in self.accepted:
            self.envelopes.append(envelope)
            self.accepted[idempotency_key] = ProviderAcceptance(
                provider_name=self.provider_name,
                provider_message_id=f"message-{len(self.accepted) + 1}",
                accepted_at=datetime(2026, 9, 27, 12, tzinfo=UTC),
            )
        return self.accepted[idempotency_key]


@dataclass(frozen=True)
class AccountFixture:
    account_id: uuid.UUID
    device_id: uuid.UUID
    signing_key: Ed25519PrivateKey


@pytest_asyncio.fixture(autouse=True, loop_scope="session")
async def clean_i12_tables():
    session_factory = get_session_local()
    async with session_factory.begin() as db:
        for model in (
            AeternaEmailDeliveryCallback,
            AeternaEmailDeliveryAttempt,
            AeternaNotificationAudit,
            AeternaNotificationAbuseEvent,
            AeternaEmailOutboxEvent,
            AeternaContactInvitation,
            AeternaNotificationTemplate,
            AeternaContact,
            AeternaRecipientSuppression,
            AccountPolicyOutboxEvent,
            AccountPolicy,
            AeternaProtocolIdempotency,
            AeternaDevice,
            AeternaAccount,
        ):
            await db.execute(delete(model))


def synthetic_keys() -> AeternaIdentityKeys:
    return AeternaIdentityKeys(
        pii_key=bytes([0x11]) * 32,
        lookup_key=bytes([0x22]) * 32,
        otp_key=bytes([0x33]) * 32,
    )


async def create_account(now: datetime, owner_email: str = "owner@example.com"):
    keys = synthetic_keys()
    account_id = uuid.uuid4()
    device_id = uuid.uuid4()
    signing_key = Ed25519PrivateKey.generate()
    ciphertext, nonce, key_version = encrypt_email(
        keys,
        owner_email,
        "account",
        account_id,
        nonce_factory=lambda length: bytes([0x44]) * length,
    )
    public_key = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    session_factory = get_session_local()
    async with session_factory.begin() as db:
        db.add(
            AeternaAccount(
                id=account_id,
                email_lookup=bytes([0x55]) * 32,
                email_ciphertext=ciphertext,
                email_nonce=nonce,
                email_key_version=key_version,
                first_device_bound_at=now,
                is_active=True,
            )
        )
        db.add(
            AeternaDevice(
                id=device_id,
                account_id=account_id,
                public_key=public_key,
                status="active",
                bound_at=now,
                heartbeat_authorized_at=now,
                last_sequence=0,
            )
        )
    return AccountFixture(account_id, device_id, signing_key)


def signed_document(
    fixture: AccountFixture,
    *,
    domain: str,
    operation: str,
    members: dict,
) -> dict:
    signed = {
        "canonicalization": "jcs-rfc8785",
        "domain": domain,
        "operation": operation,
        "protocol_version": 1,
        "signature_version": 1,
        "request_id": str(uuid.uuid4()),
        "account_id": str(fixture.account_id),
        "authorizing_device_id": str(fixture.device_id),
        **members,
    }
    return {
        "protocol_version": 1,
        "signed": signed,
        "signature": encode_base64url(fixture.signing_key.sign(canonicalize(signed))),
    }


def create_document(fixture: AccountFixture, email: str, disclosure_mode: str) -> dict:
    return signed_document(
        fixture,
        domain="aeterna.contact.create.v1",
        operation="contact.create",
        members={"email": email, "disclosure_mode": disclosure_mode},
    )


def action_document(
    fixture: AccountFixture, contact_id: uuid.UUID, operation: str
) -> dict:
    domains = {
        "contact.invite": "aeterna.contact.invite.v1",
        "contact.delete": "aeterna.contact.delete.v1",
        "contact.status": "aeterna.contact.status.v1",
        "notification.test": "aeterna.notification.test.v1",
    }
    return signed_document(
        fixture,
        domain=domains[operation],
        operation=operation,
        members={"contact_id": str(contact_id)},
    )


def template_document(
    fixture: AccountFixture, owner_message: str, contact_message: str
) -> dict:
    return signed_document(
        fixture,
        domain="aeterna.notification-template.update.v1",
        operation="notification_template.update",
        members={
            "owner_message": owner_message,
            "contact_message": contact_message,
        },
    )


async def create_contact(
    service: AeternaNotificationService,
    fixture: AccountFixture,
    email: str,
    disclosure_mode: str,
):
    document = create_document(fixture, email, disclosure_mode)
    payload = ContactCreateRequest.model_validate(document)
    session_factory = get_session_local()
    async with session_factory() as db:
        return await service.create_contact(db, payload, document, "203.0.113.10")


async def latest_invitation(contact_id: uuid.UUID) -> AeternaContactInvitation:
    session_factory = get_session_local()
    async with session_factory() as db:
        invitation = await db.scalar(
            select(AeternaContactInvitation)
            .where(AeternaContactInvitation.contact_id == contact_id)
            .order_by(AeternaContactInvitation.created_at.desc())
            .limit(1)
        )
        assert invitation is not None
        db.expunge(invitation)
        return invitation


async def invitation_token(contact_id: uuid.UUID) -> str:
    invitation = await latest_invitation(contact_id)
    return derive_invitation_token(
        synthetic_keys(), invitation.id, invitation.token_key_version
    )


async def respond(
    service: AeternaNotificationService,
    contact_id: uuid.UUID,
    decision: str,
):
    payload = ContactInvitationResponseRequest(
        protocol_version=1,
        request_id=str(uuid.uuid4()),
        token=await invitation_token(contact_id),
        decision=decision,
    )
    session_factory = get_session_local()
    async with session_factory() as db:
        return await service.respond_to_invitation(db, payload, "198.51.100.15")


async def get_contact(contact_id: uuid.UUID) -> AeternaContact:
    session_factory = get_session_local()
    async with session_factory() as db:
        contact = await db.get(AeternaContact, contact_id)
        assert contact is not None
        db.expunge(contact)
        return contact


async def get_email_events(contact_id: uuid.UUID) -> list[AeternaEmailOutboxEvent]:
    session_factory = get_session_local()
    async with session_factory() as db:
        events = list(
            await db.scalars(
                select(AeternaEmailOutboxEvent)
                .where(AeternaEmailOutboxEvent.contact_id == contact_id)
                .order_by(AeternaEmailOutboxEvent.created_at)
            )
        )
        for event in events:
            db.expunge(event)
        return events


async def test_confirm_now_requires_acceptance_and_escapes_confirmed_content():
    now = datetime(2026, 9, 27, 12, tzinfo=UTC)
    clock = MutableClock(now)
    fixture = await create_account(now)
    service = AeternaNotificationService(
        key_provider=synthetic_keys,
        clock=clock,
        random_bytes=lambda length: bytes([0x66]) * length,
    )
    created = await create_contact(
        service, fixture, "contact@example.com", "CONFIRM_NOW"
    )
    contact_id = uuid.UUID(created["contact_id"])
    assert created["consent_status"] == "INVITED"
    assert created["is_recovery_contact"] is False
    events = await get_email_events(contact_id)
    assert [event.event_type for event in events] == ["contact-invitation"]

    test_document = action_document(fixture, contact_id, "notification.test")
    with pytest.raises(AeternaProtocolException) as exc_info:
        session_factory = get_session_local()
        async with session_factory() as db:
            await service.queue_test_email(
                db,
                ContactActionRequest.model_validate(test_document),
                test_document,
                "203.0.113.10",
            )
    assert exc_info.value.code == "contact.verification_required"

    custom = "Use <script>alert('unsafe')</script> only after verification."
    document = template_document(fixture, "Owner reminder", custom)
    async with get_session_local()() as db:
        await service.update_template(
            db, NotificationTemplateRequest.model_validate(document), document
        )

    adapter = FakeIdempotentAdapter()
    delivery = AeternaEmailDeliveryService(
        adapter=adapter, key_provider=synthetic_keys, clock=clock
    )
    async with get_session_local()() as db:
        result = await delivery.dispatch_event(db, events[0].id)
    assert result.status == "provider_accepted"
    assert len(adapter.envelopes) == 1
    invitation_body = adapter.envelopes[0].text_body
    assert "contact@example.com" not in invitation_body
    assert "Owner reminder" not in invitation_body
    assert "script" not in invitation_body
    assert "recovery material" in invitation_body.lower()
    assert "#token=" in invitation_body

    assert await respond(service, contact_id, "accept") == {"processed": True}
    contact = await get_contact(contact_id)
    assert contact.consent_status == "ACCEPTED"
    assert contact.verified_at == now

    test_document = action_document(fixture, contact_id, "notification.test")
    async with get_session_local()() as db:
        queued = await service.queue_test_email(
            db,
            ContactActionRequest.model_validate(test_document),
            test_document,
            "203.0.113.10",
        )
    assert queued["last_delivery_status"] == "queued"
    test_event = (await get_email_events(contact_id))[-1]
    async with get_session_local()() as db:
        await delivery.dispatch_event(db, test_event.id)
    assert custom in adapter.envelopes[-1].text_body
    assert "<script>" not in adapter.envelopes[-1].html_body
    assert "&lt;script&gt;" in adapter.envelopes[-1].html_body


async def test_private_target_sends_nothing_before_release_and_only_neutral_invite():
    now = datetime(2026, 9, 27, 12, tzinfo=UTC)
    clock = MutableClock(now)
    fixture = await create_account(now)
    service = AeternaNotificationService(key_provider=synthetic_keys, clock=clock)
    created = await create_contact(
        service, fixture, "private@example.com", "PRIVATE_UNTIL_RELEASE"
    )
    contact_id = uuid.UUID(created["contact_id"])
    assert created["consent_status"] == "NOT_REQUESTED"
    assert await get_email_events(contact_id) == []

    invite_document = action_document(fixture, contact_id, "contact.invite")
    with pytest.raises(AeternaProtocolException) as exc_info:
        async with get_session_local()() as db:
            await service.invite_contact(
                db,
                ContactActionRequest.model_validate(invite_document),
                invite_document,
                "203.0.113.10",
            )
    assert exc_info.value.code == "contact.disclosure_locked"

    template = template_document(
        fixture, "Owner-only text", "PRIVATE CUSTOM CONTENT MUST NOT LEAK"
    )
    async with get_session_local()() as db:
        await service.update_template(
            db, NotificationTemplateRequest.model_validate(template), template
        )

    policy_id = uuid.uuid4()
    source_id = uuid.uuid4()
    async with get_session_local().begin() as db:
        db.add(
            AccountPolicy(
                id=policy_id,
                account_id=fixture.account_id,
                state="RELEASED",
                version=1,
                inactivity_window_seconds=INACTIVITY_SECONDS,
                warning_window_seconds=WARNING_SECONDS,
                grace_window_seconds=GRACE_SECONDS,
                last_activity_at=now - timedelta(days=30),
                due_at=now - timedelta(days=1),
                state_changed_at=now,
                warning_started_at=now - timedelta(days=8),
                owner_warning_proven_at=now - timedelta(days=7),
                grace_started_at=now - timedelta(days=7),
                released_at=now,
            )
        )
        db.add(
            AccountPolicyOutboxEvent(
                id=source_id,
                account_policy_id=policy_id,
                event_type="account-policy-released",
                idempotency_key=f"release:{policy_id}",
                from_state="GRACE_PERIOD",
                to_state="RELEASED",
                policy_version=1,
                payload={"account_policy_id": str(policy_id)},
                scheduled_at=now,
                status="queued",
                notification_type="owner-release-authorized",
                delivery_idempotency_key=f"release-delivery:{policy_id}",
                attempt_count=1,
                queued_at=now,
            )
        )

    async with get_session_local()() as db:
        created_ids = await service.materialize_policy_event(db, source_id)
    assert len(created_ids) == 2
    async with get_session_local()() as db:
        assert await service.materialize_policy_event(db, source_id) == []
    contact_events = await get_email_events(contact_id)
    assert [event.event_type for event in contact_events] == ["contact-invitation"]
    assert (await get_contact(contact_id)).consent_status == "INVITED"

    adapter = FakeIdempotentAdapter()
    delivery = AeternaEmailDeliveryService(
        adapter=adapter, key_provider=synthetic_keys, clock=clock
    )
    async with get_session_local()() as db:
        await delivery.dispatch_event(db, contact_events[0].id)
    assert "PRIVATE CUSTOM CONTENT MUST NOT LEAK" not in adapter.envelopes[0].text_body
    assert "claim" not in adapter.envelopes[0].text_body.lower()
    assert "srs" not in adapter.envelopes[0].text_body.lower()

    assert await respond(service, contact_id, "accept") == {"processed": True}
    assert (await get_contact(contact_id)).consent_status == "ACCEPTED"


async def test_wrong_device_proof_cannot_create_or_elevate_contact():
    now = datetime(2026, 9, 27, 12, tzinfo=UTC)
    fixture = await create_account(now)
    service = AeternaNotificationService(key_provider=synthetic_keys, clock=lambda: now)
    document = create_document(fixture, "target@example.com", "CONFIRM_NOW")
    document["signature"] = encode_base64url(
        Ed25519PrivateKey.generate().sign(canonicalize(document["signed"]))
    )
    with pytest.raises(AeternaProtocolException) as exc_info:
        async with get_session_local()() as db:
            await service.create_contact(
                db,
                ContactCreateRequest.model_validate(document),
                document,
                "203.0.113.10",
            )
    assert exc_info.value.code == "device.proof_invalid"
    async with get_session_local()() as db:
        assert await db.scalar(select(AeternaContact.id)) is None


async def test_retry_concurrency_callbacks_and_bounce_visibility():
    now = datetime(2026, 9, 27, 12, tzinfo=UTC)
    clock = MutableClock(now)
    fixture = await create_account(now)
    notification = AeternaNotificationService(key_provider=synthetic_keys, clock=clock)
    created = await create_contact(
        notification, fixture, "retry@example.com", "CONFIRM_NOW"
    )
    contact_id = uuid.UUID(created["contact_id"])
    event = (await get_email_events(contact_id))[0]
    adapter = FakeIdempotentAdapter(failures_remaining=1)
    delivery = AeternaEmailDeliveryService(
        adapter=adapter, key_provider=synthetic_keys, clock=clock
    )

    async with get_session_local()() as db:
        failed = await delivery.dispatch_event(db, event.id)
    assert failed.status == "retry_pending"
    assert len(adapter.envelopes) == 0

    clock.current += timedelta(hours=2)

    async def dispatch_once():
        async with get_session_local()() as db:
            return await delivery.dispatch_event(db, event.id)

    first, second = await asyncio.gather(dispatch_once(), dispatch_once())
    assert "provider_accepted" in {first.status, second.status}
    assert {first.status, second.status} <= {"sending", "provider_accepted"}
    assert len(adapter.envelopes) == 1
    assert len(set(adapter.accepted)) == 1

    accepted = adapter.accepted[event.idempotency_key]

    async def record_delivery():
        async with get_session_local()() as db:
            return await delivery.record_callback(
                db,
                provider_name=accepted.provider_name,
                provider_message_id=accepted.provider_message_id,
                callback_id="callback-delivered",
                callback_type=DeliveryCallbackType.DELIVERED,
                occurred_at=clock.current,
            )

    delivered_results = await asyncio.gather(record_delivery(), record_delivery())
    assert {result.status for result in delivered_results} == {"delivered"}
    assert {result.duplicate for result in delivered_results} == {False, True}
    async with get_session_local()() as db:
        late_accepted = await delivery.record_callback(
            db,
            provider_name=accepted.provider_name,
            provider_message_id=accepted.provider_message_id,
            callback_id="callback-late-accepted",
            callback_type=DeliveryCallbackType.PROVIDER_ACCEPTED,
            occurred_at=clock.current - timedelta(minutes=1),
        )
    assert late_accepted.status == "delivered"
    async with get_session_local()() as db:
        bounced = await delivery.record_callback(
            db,
            provider_name=accepted.provider_name,
            provider_message_id=accepted.provider_message_id,
            callback_id="callback-bounced",
            callback_type=DeliveryCallbackType.BOUNCED,
            occurred_at=clock.current + timedelta(minutes=1),
            reason_code="hard-bounce",
        )
    assert bounced.status == "bounced"
    async with get_session_local()() as db:
        duplicate = await delivery.record_callback(
            db,
            provider_name=accepted.provider_name,
            provider_message_id=accepted.provider_message_id,
            callback_id="callback-bounced",
            callback_type=DeliveryCallbackType.BOUNCED,
            occurred_at=clock.current + timedelta(minutes=1),
            reason_code="hard-bounce",
        )
    assert duplicate.duplicate is True
    assert duplicate.status == "bounced"
    async with get_session_local()() as db:
        late_delivery = await delivery.record_callback(
            db,
            provider_name=accepted.provider_name,
            provider_message_id=accepted.provider_message_id,
            callback_id="callback-late-delivery",
            callback_type=DeliveryCallbackType.DELIVERED,
            occurred_at=clock.current + timedelta(minutes=2),
        )
    assert late_delivery.status == "bounced"
    with pytest.raises(RuntimeError, match="conflicts"):
        async with get_session_local()() as db:
            await delivery.record_callback(
                db,
                provider_name=accepted.provider_name,
                provider_message_id=accepted.provider_message_id,
                callback_id="callback-bounced",
                callback_type=DeliveryCallbackType.DELIVERED,
                occurred_at=clock.current + timedelta(minutes=3),
            )

    status_document = action_document(fixture, contact_id, "contact.status")
    async with get_session_local()() as db:
        status = await notification.contact_status(
            db,
            ContactActionRequest.model_validate(status_document),
            status_document,
        )
    assert status["last_delivery_status"] == "bounced"
    assert status["bounced_at"] is not None

    async with get_session_local()() as db:
        complained = await delivery.record_callback(
            db,
            provider_name=accepted.provider_name,
            provider_message_id=accepted.provider_message_id,
            callback_id="callback-complained",
            callback_type=DeliveryCallbackType.COMPLAINED,
            occurred_at=clock.current + timedelta(minutes=4),
            reason_code="provider-complaint",
        )
    assert complained.status == "complained"
    status_document = action_document(fixture, contact_id, "contact.status")
    contact = await get_contact(contact_id)
    async with get_session_local()() as db:
        status = await notification.contact_status(
            db,
            ContactActionRequest.model_validate(status_document),
            status_document,
        )
        suppression = await db.get(AeternaRecipientSuppression, contact.email_lookup)
    assert status["last_delivery_status"] == "complained"
    assert suppression is not None
    assert suppression.reason == "complaint"

    async with get_session_local()() as db:
        attempts = list(
            await db.scalars(
                select(AeternaEmailDeliveryAttempt).where(
                    AeternaEmailDeliveryAttempt.outbox_event_id == event.id
                )
            )
        )
        assert [attempt.status for attempt in attempts] == [
            "retryable_failure",
            "provider_accepted",
        ]


async def test_delete_revokes_token_cancels_delivery_and_redacts_ciphertext():
    now = datetime(2026, 9, 27, 12, tzinfo=UTC)
    fixture = await create_account(now)
    service = AeternaNotificationService(key_provider=synthetic_keys, clock=lambda: now)
    created = await create_contact(
        service, fixture, "delete@example.com", "CONFIRM_NOW"
    )
    contact_id = uuid.UUID(created["contact_id"])
    token = await invitation_token(contact_id)
    before = await get_contact(contact_id)

    document = action_document(fixture, contact_id, "contact.delete")
    async with get_session_local()() as db:
        deleted = await service.delete_contact(
            db, ContactActionRequest.model_validate(document), document
        )
    assert deleted["deleted"] is True
    after = await get_contact(contact_id)
    assert after.email_ciphertext != before.email_ciphertext
    assert after.verified_at is None
    with pytest.raises(Exception):
        decrypt_email(
            synthetic_keys(),
            after.email_ciphertext,
            after.email_nonce,
            "contact",
            after.id,
            after.email_key_version,
        )
    assert [event.status for event in await get_email_events(contact_id)] == [
        "cancelled"
    ]
    invitation = await latest_invitation(contact_id)
    assert invitation.status == "revoked"

    response = ContactInvitationResponseRequest(
        protocol_version=1,
        request_id=str(uuid.uuid4()),
        token=token,
        decision="accept",
    )
    async with get_session_local()() as db:
        assert await service.respond_to_invitation(db, response, "198.51.100.15") == {
            "processed": True
        }
    assert (await get_contact(contact_id)).consent_status == "DECLINED"

    async with get_session_local()() as db:
        audits = list(
            await db.scalars(
                select(AeternaNotificationAudit).where(
                    AeternaNotificationAudit.contact_id == contact_id
                )
            )
        )
        serialized = " ".join(
            f"{audit.event_type} {audit.status or ''} {audit.reason_code or ''}"
            for audit in audits
        )
    assert "delete@example.com" not in serialized


async def test_recipient_decline_deletes_and_suppresses_future_invites():
    now = datetime(2026, 9, 27, 12, tzinfo=UTC)
    fixture = await create_account(now)
    service = AeternaNotificationService(key_provider=synthetic_keys, clock=lambda: now)
    created = await create_contact(
        service, fixture, "decline@example.com", "CONFIRM_NOW"
    )
    contact_id = uuid.UUID(created["contact_id"])

    assert await respond(service, contact_id, "decline") == {"processed": True}
    declined = await get_contact(contact_id)
    assert declined.consent_status == "DECLINED"
    assert declined.deleted_at == now
    async with get_session_local()() as db:
        suppression = await db.get(AeternaRecipientSuppression, declined.email_lookup)
        assert suppression is not None
        assert suppression.reason == "declined"

    document = create_document(fixture, "decline@example.com", "CONFIRM_NOW")
    with pytest.raises(AeternaProtocolException) as exc_info:
        async with get_session_local()() as db:
            await service.create_contact(
                db,
                ContactCreateRequest.model_validate(document),
                document,
                "203.0.113.10",
            )
    assert exc_info.value.code == "contact.recipient_unavailable"


async def test_recipient_and_ip_abuse_limits_fail_without_queuing_more_mail():
    now = datetime(2026, 9, 27, 12, tzinfo=UTC)
    fixture = await create_account(now)
    service = AeternaNotificationService(key_provider=synthetic_keys, clock=lambda: now)
    created = await create_contact(
        service, fixture, "limited@example.com", "CONFIRM_NOW"
    )
    contact_id = uuid.UUID(created["contact_id"])
    contact = await get_contact(contact_id)
    async with get_session_local().begin() as db:
        for _ in range(4):
            db.add(
                AeternaNotificationAbuseEvent(
                    id=uuid.uuid4(),
                    account_id=fixture.account_id,
                    recipient_lookup=contact.email_lookup,
                    ip_lookup=bytes([0x77]) * 32,
                    event_type="contact_invite",
                    created_at=now,
                    updated_at=now,
                )
            )
    before_count = len(await get_email_events(contact_id))
    document = action_document(fixture, contact_id, "contact.invite")
    with pytest.raises(AeternaProtocolException) as exc_info:
        async with get_session_local()() as db:
            await service.invite_contact(
                db,
                ContactActionRequest.model_validate(document),
                document,
                "203.0.113.10",
            )
    assert exc_info.value.code == "notification.rate_limited"
    assert len(await get_email_events(contact_id)) == before_count


async def test_transport_delivery_cannot_manufacture_owner_warning_proof():
    now = datetime(2026, 9, 27, 12, tzinfo=UTC)
    fixture = await create_account(now)
    policy_id = uuid.uuid4()
    source_id = uuid.uuid4()
    async with get_session_local().begin() as db:
        db.add(
            AccountPolicy(
                id=policy_id,
                account_id=fixture.account_id,
                state="GRACE_PERIOD",
                version=1,
                inactivity_window_seconds=INACTIVITY_SECONDS,
                warning_window_seconds=WARNING_SECONDS,
                grace_window_seconds=GRACE_SECONDS,
                last_activity_at=now - timedelta(days=30),
                due_at=now,
                state_changed_at=now,
                warning_started_at=now,
                owner_warning_proven_at=None,
                grace_started_at=now,
            )
        )
        db.add(
            AccountPolicyOutboxEvent(
                id=source_id,
                account_policy_id=policy_id,
                event_type="account-policy-grace-started",
                idempotency_key=f"warning:{policy_id}",
                from_state="PRE_WARNING",
                to_state="GRACE_PERIOD",
                policy_version=1,
                payload={"account_policy_id": str(policy_id)},
                scheduled_at=now,
                status="queued",
                notification_type="owner-grace-period-started",
                delivery_idempotency_key=f"warning-delivery:{policy_id}",
                attempt_count=1,
                queued_at=now,
            )
        )
    notification = AeternaNotificationService(
        key_provider=synthetic_keys, clock=lambda: now
    )
    async with get_session_local()() as db:
        event_ids = await notification.materialize_policy_event(db, source_id)
    assert len(event_ids) == 1
    adapter = FakeIdempotentAdapter()
    delivery = AeternaEmailDeliveryService(
        adapter=adapter, key_provider=synthetic_keys, clock=lambda: now
    )
    async with get_session_local()() as db:
        sent = await delivery.dispatch_event(db, event_ids[0])
    acceptance = adapter.accepted[
        (await load_email_event(event_ids[0])).idempotency_key
    ]
    async with get_session_local()() as db:
        await delivery.record_callback(
            db,
            provider_name=acceptance.provider_name,
            provider_message_id=acceptance.provider_message_id,
            callback_id="owner-delivered",
            callback_type=DeliveryCallbackType.DELIVERED,
            occurred_at=now,
        )
    async with get_session_local()() as db:
        policy = await db.get(AccountPolicy, policy_id)
        assert policy is not None
        assert policy.owner_warning_proven_at is None
    assert sent.status == "provider_accepted"


async def load_email_event(event_id: uuid.UUID) -> AeternaEmailOutboxEvent:
    session_factory = get_session_local()
    async with session_factory() as db:
        event = await db.get(AeternaEmailOutboxEvent, event_id)
        assert event is not None
        db.expunge(event)
        return event
