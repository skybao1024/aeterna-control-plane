"""Synthetic PostgreSQL resend evidence: exact targets, retries and mail intents."""

import asyncio
import uuid
from datetime import timedelta

import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app.configs.docs_apps import create_client_app
from app.db.base import get_session_local
from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.models.aeterna_identity import AeternaDevice, AeternaProtocolIdempotency
from app.models.aeterna_notification import (
    AeternaContact,
    AeternaContactInvitation,
    AeternaEmailOutboxEvent,
    AeternaNotificationAbuseEvent,
    AeternaRecipientSuppression,
)
from app.models.aeterna_recovery import (
    AeternaRecoveryClaimLink,
    AeternaRecoveryGrant,
    AeternaRecoveryRecord,
)
from app.schemas.client.aeterna_recovery_notice import RecoveryNoticeResendRequest
from app.services.client.aeterna_notification import AeternaNotificationService
from app.services.client.aeterna_recovery import AeternaRecoveryService
from app.services.client.aeterna_recovery_notice_resend import (
    AeternaRecoveryNoticeResendService,
    get_aeterna_recovery_notice_resend_service,
)

from .test_aeterna_recovery_notice import (
    KEYS,
    NOW,
    create_contact,
    encode,
    invitation_event,
    notice_account,
    release_event,
    set_state,
)

pytestmark = pytest.mark.asyncio(loop_scope="session")


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        return self.now


def service(clock=None):
    clock = clock or Clock()
    return AeternaRecoveryNoticeResendService(
        clock=clock,
        notification_service=AeternaNotificationService(
            key_provider=lambda: KEYS, clock=clock
        ),
        recovery_service=AeternaRecoveryService(
            identity_key_provider=lambda: KEYS, clock=clock
        ),
    )


def document(fixture, contact_id, *, request_id=None, key=None):
    account_id, device_id, signer, _policy_id = fixture
    signed = {
        "canonicalization": "jcs-rfc8785",
        "domain": "aeterna.recovery-notice.resend.v1",
        "operation": "recovery_notice.resend",
        "protocol_version": 1,
        "signature_version": 1,
        "request_id": str(request_id or uuid.uuid4()),
        "account_id": str(account_id),
        "authorizing_device_id": str(device_id),
        "contact_id": str(contact_id),
    }
    return {
        "protocol_version": 1,
        "signed": signed,
        "signature": encode((key or signer).sign(rfc8785.dumps(signed))),
    }


async def resend(fixture, contact_id, *, instance=None, request=None):
    request = request or document(fixture, contact_id)
    async with get_session_local()() as db:
        return await (instance or service()).resend(
            db, RecoveryNoticeResendRequest.model_validate(request), request
        )


async def accept_contact(contact_id):
    async with get_session_local().begin() as db:
        contact = await db.get(AeternaContact, contact_id)
        contact.consent_status = "ACCEPTED"
        contact.accepted_at = NOW - timedelta(days=3)
        contact.verified_at = NOW - timedelta(days=3)


async def email_count(fixture, contact_id):
    async with get_session_local()() as db:
        return await db.scalar(
            select(func.count(AeternaEmailOutboxEvent.id)).where(
                AeternaEmailOutboxEvent.account_id == fixture[0],
                AeternaEmailOutboxEvent.contact_id == contact_id,
            )
        )


async def test_private_resend_preserves_live_invitation_and_queues_no_recovery_link(
    notice_account,
):
    contact = await create_contact(notice_account)
    await invitation_event(notice_account, contact)
    async with get_session_local().begin() as db:
        stored = await db.get(AeternaContact, contact)
        stored.consent_status = "INVITED"
    async with get_session_local()() as db:
        original = await db.scalar(
            select(AeternaContactInvitation).where(
                AeternaContactInvitation.contact_id == contact
            )
        )
        original_id, original_expiry = original.id, original.expires_at
    receipt = await resend(notice_account, contact)
    assert receipt == {
        "account_id": str(notice_account[0]),
        "device_id": str(notice_account[1]),
        "contact_id": str(contact),
        "observed_at": "2030-06-01T00:00:00Z",
        "kind": "invitation",
        "status": "pending",
        "retry_after_seconds": 60,
    }
    assert await email_count(notice_account, contact) == 2
    async with get_session_local()() as db:
        original = await db.get(AeternaContactInvitation, original_id)
        assert original.status == "pending"
        assert original.expires_at == original_expiry
        assert (
            await db.scalar(
                select(func.count(AeternaRecoveryClaimLink.id))
                .join(
                    AeternaRecoveryGrant,
                    AeternaRecoveryClaimLink.grant_id == AeternaRecoveryGrant.id,
                )
                .where(AeternaRecoveryGrant.contact_id == contact)
            )
            == 0
        )


async def test_expired_private_invitation_gets_current_neutral_invitation(
    notice_account,
):
    contact = await create_contact(notice_account)
    await invitation_event(notice_account, contact)
    async with get_session_local().begin() as db:
        invitation = await db.scalar(
            select(AeternaContactInvitation).where(
                AeternaContactInvitation.contact_id == contact
            )
        )
        invitation.expires_at = NOW - timedelta(seconds=1)
    receipt = await resend(notice_account, contact)
    assert receipt["kind"] == "invitation"
    async with get_session_local()() as db:
        invitations = list(
            (
                await db.scalars(
                    select(AeternaContactInvitation).where(
                        AeternaContactInvitation.contact_id == contact
                    )
                )
            ).all()
        )
        assert sorted(value.status for value in invitations) == ["pending", "revoked"]
        assert (
            await db.scalar(
                select(func.count(AeternaRecoveryGrant.id)).where(
                    AeternaRecoveryGrant.contact_id == contact
                )
            )
            == 0
        )


async def test_release_resend_uses_same_device_grant_without_changing_old_link(
    notice_account,
):
    contact = await create_contact(notice_account)
    await accept_contact(contact)
    await release_event(notice_account, contact)
    async with get_session_local()() as db:
        grant = await db.scalar(
            select(AeternaRecoveryGrant).where(
                AeternaRecoveryGrant.contact_id == contact
            )
        )
        old = await db.scalar(
            select(AeternaRecoveryClaimLink).where(
                AeternaRecoveryClaimLink.grant_id == grant.id
            )
        )
        grant_id, old_id, old_expiry, old_digest = (
            grant.id,
            old.id,
            old.expires_at,
            old.token_digest,
        )
    receipt = await resend(notice_account, contact)
    assert receipt["kind"] == "release"
    assert receipt["status"] == "pending"
    assert await email_count(notice_account, contact) == 2
    async with get_session_local()() as db:
        grant = await db.get(AeternaRecoveryGrant, grant_id)
        old = await db.get(AeternaRecoveryClaimLink, old_id)
        assert grant.state == "available"
        assert old.status == "active"
        assert old.expires_at == old_expiry
        assert old.token_digest == old_digest
        links = list(
            (
                await db.scalars(
                    select(AeternaRecoveryClaimLink).where(
                        AeternaRecoveryClaimLink.grant_id == grant_id
                    )
                )
            ).all()
        )
        assert len(links) == 2


async def test_exact_timeout_retry_and_concurrent_requests_queue_one_email(
    notice_account,
):
    contact = await create_contact(notice_account)
    await invitation_event(notice_account, contact)
    request = document(notice_account, contact)
    results = await asyncio.gather(
        resend(notice_account, contact, request=request),
        resend(notice_account, contact, request=request),
    )
    assert results[0] == results[1]
    assert await email_count(notice_account, contact) == 2
    async with get_session_local()() as db:
        receipts = await db.scalar(
            select(func.count(AeternaProtocolIdempotency.id)).where(
                AeternaProtocolIdempotency.account_id == notice_account[0],
                AeternaProtocolIdempotency.operation == "recovery_notice.resend",
            )
        )
        assert receipts == 1
    other = await create_contact(notice_account, "synthetic-other@example.com")
    changed = document(
        notice_account, other, request_id=request["signed"]["request_id"]
    )
    with pytest.raises(AeternaProtocolException) as failure:
        await resend(notice_account, other, request=changed)
    assert failure.value.code == "request.idempotency_conflict"


async def test_different_concurrent_resend_intents_share_target_cooldown(
    notice_account,
):
    contact = await create_contact(notice_account)
    await invitation_event(notice_account, contact)
    results = await asyncio.gather(
        resend(notice_account, contact),
        resend(notice_account, contact),
        return_exceptions=True,
    )
    assert sum(isinstance(value, dict) for value in results) == 1
    errors = [value for value in results if isinstance(value, AeternaProtocolException)]
    assert len(errors) == 1
    assert errors[0].code == "notification.rate_limited"
    assert await email_count(notice_account, contact) == 2


async def test_target_cooldown_and_shared_daily_recipient_budget_are_durable(
    notice_account,
):
    contact = await create_contact(notice_account)
    await invitation_event(notice_account, contact)
    clock = Clock()
    instance = service(clock)
    await resend(notice_account, contact, instance=instance)
    with pytest.raises(AeternaProtocolException) as failure:
        await resend(notice_account, contact, instance=instance)
    assert failure.value.code == "notification.rate_limited"
    for _ in range(4):
        clock.now += timedelta(seconds=60)
        await resend(notice_account, contact, instance=instance)
    clock.now += timedelta(seconds=60)
    with pytest.raises(AeternaProtocolException) as failure:
        await resend(notice_account, contact, instance=instance)
    assert failure.value.code == "notification.rate_limited"
    assert await email_count(notice_account, contact) == 6


async def test_device_daily_limit_spans_multiple_targets(notice_account):
    clock = Clock()
    instance = service(clock)
    contacts = [
        await create_contact(notice_account, f"synthetic-{index}@example.com")
        for index in range(6)
    ]
    for contact in contacts:
        await invitation_event(notice_account, contact)
    for index in range(10):
        clock.now += timedelta(seconds=60)
        await resend(notice_account, contacts[index % len(contacts)], instance=instance)
    clock.now += timedelta(seconds=60)
    with pytest.raises(AeternaProtocolException) as failure:
        await resend(notice_account, contacts[-1], instance=instance)
    assert failure.value.code == "notification.rate_limited"


async def test_existing_account_notification_budget_also_limits_resend(notice_account):
    contact = await create_contact(notice_account)
    await invitation_event(notice_account, contact)
    async with get_session_local().begin() as db:
        for _ in range(30):
            db.add(
                AeternaNotificationAbuseEvent(
                    id=uuid.uuid4(),
                    account_id=notice_account[0],
                    recipient_lookup=uuid.uuid4().bytes + uuid.uuid4().bytes,
                    event_type="contact_invite",
                    created_at=NOW,
                    updated_at=NOW,
                )
            )
    with pytest.raises(AeternaProtocolException) as failure:
        await resend(notice_account, contact)
    assert failure.value.code == "notification.rate_limited"
    assert await email_count(notice_account, contact) == 1


@pytest.mark.parametrize("device_state", ["active", "dormant"])
async def test_resend_never_changes_device_authority_and_requires_release(
    notice_account, device_state
):
    contact = await create_contact(notice_account)
    await invitation_event(notice_account, contact)
    await set_state(notice_account, device_state=device_state)
    await resend(notice_account, contact)
    async with get_session_local()() as db:
        device = await db.get(AeternaDevice, notice_account[1])
        assert device.status == device_state
        assert device.last_sequence == 3
        assert device.last_seen_at is None
    await set_state(notice_account, policy_state="ACTIVE")
    with pytest.raises(AeternaProtocolException) as failure:
        await resend(notice_account, contact)
    assert failure.value.code in {"policy.unavailable", "device.not_active"}


@pytest.mark.parametrize(
    "grant_state, record_state, epoch",
    [
        ("claimed", "sealed", 1),
        ("revoked", "revoked", 1),
        ("available", "sealed", 2),
    ],
)
async def test_resend_cannot_revive_claimed_revoked_or_historical_recovery(
    notice_account, grant_state, record_state, epoch
):
    contact = await create_contact(notice_account)
    await accept_contact(contact)
    await release_event(notice_account, contact, epoch=epoch)
    async with get_session_local().begin() as db:
        grant = await db.scalar(
            select(AeternaRecoveryGrant).where(
                AeternaRecoveryGrant.contact_id == contact
            )
        )
        grant.state = grant_state
        grant.claimed_at = NOW if grant_state == "claimed" else None
        record = await db.get(AeternaRecoveryRecord, grant.recovery_id)
        record.state = record_state
        record.abandoned_at = NOW if record_state == "revoked" else None
    with pytest.raises(AeternaProtocolException) as failure:
        await resend(notice_account, contact)
    assert failure.value.code == "recovery.record_unavailable"
    assert await email_count(notice_account, contact) == 1


async def test_suppressed_or_foreign_target_and_invalid_signature_cannot_queue_mail(
    notice_account,
):
    contact = await create_contact(notice_account)
    await invitation_event(notice_account, contact)
    invalid = document(notice_account, contact, key=Ed25519PrivateKey.generate())
    with pytest.raises(AeternaProtocolException) as failure:
        await resend(notice_account, contact, request=invalid)
    assert failure.value.code == "device.proof_invalid"
    with pytest.raises(AeternaProtocolException) as failure:
        await resend(notice_account, uuid.uuid4())
    assert failure.value.code == "contact.not_found"
    async with get_session_local().begin() as db:
        stored = await db.get(AeternaContact, contact)
        db.add(
            AeternaRecipientSuppression(
                recipient_lookup=stored.email_lookup, reason="declined"
            )
        )
    try:
        with pytest.raises(AeternaProtocolException) as failure:
            await resend(notice_account, contact)
        assert failure.value.code == "contact.recipient_unavailable"
        assert await email_count(notice_account, contact) == 1
    finally:
        async with get_session_local().begin() as db:
            stored = await db.get(AeternaContact, contact)
            suppression = await db.get(AeternaRecipientSuppression, stored.email_lookup)
            await db.delete(suppression)


async def test_resend_never_falls_back_to_another_device_grant(notice_account):
    contact = await create_contact(notice_account)
    await accept_contact(contact)
    await release_event(notice_account, contact)
    async with get_session_local().begin() as db:
        other_device = uuid.uuid4()
        key = Ed25519PrivateKey.generate()
        db.add(
            AeternaDevice(
                id=other_device,
                account_id=notice_account[0],
                public_key=key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                ),
                status="active",
                bound_at=NOW,
                heartbeat_authorized_at=NOW,
                last_sequence=0,
            )
        )
        await db.flush()
        grant = await db.scalar(
            select(AeternaRecoveryGrant).where(
                AeternaRecoveryGrant.contact_id == contact
            )
        )
        record = await db.get(AeternaRecoveryRecord, grant.recovery_id)
        record.device_id = other_device
    with pytest.raises(AeternaProtocolException) as failure:
        await resend(notice_account, contact)
    assert failure.value.code == "recovery.record_unavailable"
    assert await email_count(notice_account, contact) == 1


@pytest.mark.parametrize("device_state", ["lost", "revoked"])
async def test_terminal_device_cannot_resend_existing_contact_email(
    notice_account, device_state
):
    contact = await create_contact(notice_account)
    await invitation_event(notice_account, contact)
    await set_state(notice_account, device_state=device_state)
    with pytest.raises(AeternaProtocolException) as failure:
        await resend(notice_account, contact)
    assert failure.value.code == "device.not_active"
    assert await email_count(notice_account, contact) == 1


async def test_failed_commit_rolls_back_fresh_link_mail_and_receipt(
    notice_account, monkeypatch
):
    contact = await create_contact(notice_account)
    await accept_contact(contact)
    await release_event(notice_account, contact)
    request = document(notice_account, contact)
    async with get_session_local()() as db:

        async def fail_commit():
            raise SQLAlchemyError("synthetic commit interruption")

        monkeypatch.setattr(db, "commit", fail_commit)
        with pytest.raises(SQLAlchemyError):
            await service().resend(
                db, RecoveryNoticeResendRequest.model_validate(request), request
            )
        await db.rollback()
    assert await email_count(notice_account, contact) == 1
    receipt = await resend(notice_account, contact, request=request)
    assert receipt["status"] == "pending"
    assert await email_count(notice_account, contact) == 2


async def test_http_resend_is_no_store_and_rejects_caller_controlled_email(
    notice_account,
):
    contact = await create_contact(notice_account)
    await invitation_event(notice_account, contact)
    application = create_client_app()
    application.dependency_overrides[get_aeterna_recovery_notice_resend_service] = (
        service
    )
    request = document(notice_account, contact)
    async with AsyncClient(
        transport=ASGITransport(app=application), base_url="http://synthetic.test"
    ) as client:
        response = await client.post("/api/v1/recovery/notice/resend", json=request)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["data"]["status"] == "pending"
        request["signed"]["email"] = "arbitrary@example.com"
        response = await client.post("/api/v1/recovery/notice/resend", json=request)
        assert response.status_code == 400
