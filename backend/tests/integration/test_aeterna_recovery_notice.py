"""Real PostgreSQL evidence for exact release emails and read-only device proof."""

import base64
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

from app.configs.docs_apps import create_client_app
from app.db.base import get_session_local
from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.models.account_policy import AccountPolicy, AccountPolicyOutboxEvent
from app.models.aeterna_identity import AeternaAccount, AeternaDevice
from app.models.aeterna_notification import (
    AeternaContact,
    AeternaContactInvitation,
    AeternaEmailOutboxEvent,
)
from app.models.aeterna_recovery import (
    AeternaRecoveryClaimLink,
    AeternaRecoveryGrant,
    AeternaRecoveryRecord,
)
from app.schemas.client.aeterna_recovery_notice import RecoveryNoticeRequest
from app.services.client.aeterna_recovery_notice import (
    AeternaRecoveryNoticeService,
    get_aeterna_recovery_notice_service,
)
from app.services.common.aeterna_security import AeternaIdentityKeys, encrypt_email

pytestmark = pytest.mark.asyncio(loop_scope="session")
NOW = datetime(2030, 6, 1, tzinfo=UTC)
KEYS = AeternaIdentityKeys(
    pii_key=b"\x31" * 32, lookup_key=b"\x32" * 32, otp_key=b"\x33" * 32
)


def encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


@pytest_asyncio.fixture(loop_scope="session")
async def notice_account():
    account_id, device_id = uuid.uuid4(), uuid.uuid4()
    signing_key = Ed25519PrivateKey.generate()
    factory = get_session_local()
    policy_id = uuid.uuid4()
    async with factory.begin() as db:
        db.add(
            AeternaAccount(
                id=account_id,
                email_lookup=uuid.uuid4().bytes + uuid.uuid4().bytes,
                email_ciphertext=b"synthetic-account-mailbox",
                email_nonce=b"\x41" * 12,
                email_key_version=1,
                first_device_bound_at=NOW - timedelta(days=40),
                current_policy_epoch=1,
                current_recovery_generation=1,
                is_active=True,
            )
        )
        await db.flush()
        db.add(
            AeternaDevice(
                id=device_id,
                account_id=account_id,
                public_key=signing_key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                ),
                status="active",
                bound_at=NOW - timedelta(days=40),
                heartbeat_authorized_at=NOW - timedelta(days=40),
                last_sequence=3,
                policy_epoch=1,
            )
        )
        db.add(
            AccountPolicy(
                id=policy_id,
                account_id=account_id,
                epoch=1,
                state="RELEASED",
                version=3,
                inactivity_window_seconds=30 * 86_400,
                warning_window_seconds=7 * 86_400,
                grace_window_seconds=7 * 86_400,
                last_activity_at=NOW - timedelta(days=40),
                due_at=NOW - timedelta(days=10),
                state_changed_at=NOW - timedelta(days=3),
                released_at=NOW - timedelta(days=3),
            )
        )
    yield account_id, device_id, signing_key, policy_id
    async with factory.begin() as db:
        await db.execute(delete(AeternaAccount).where(AeternaAccount.id == account_id))


def request_document(fixture, contacts=(), *, key=None, **overrides):
    account_id, device_id, signing_key, _policy_id = fixture
    signed = {
        "canonicalization": "jcs-rfc8785",
        "domain": "aeterna.recovery-notice.read.v1",
        "operation": "recovery_notice.read",
        "protocol_version": 1,
        "signature_version": 1,
        "request_id": str(uuid.uuid4()),
        "account_id": str(account_id),
        "authorizing_device_id": str(device_id),
        "contact_ids": [str(value) for value in contacts],
        **overrides,
    }
    return {
        "protocol_version": 1,
        "signed": signed,
        "signature": encode((key or signing_key).sign(rfc8785.dumps(signed))),
    }


def service():
    return AeternaRecoveryNoticeService(key_provider=lambda: KEYS, clock=lambda: NOW)


async def read_notice(fixture, contacts=(), **kwargs):
    document = request_document(fixture, contacts, **kwargs)
    async with get_session_local()() as db:
        return await service().read(
            db, RecoveryNoticeRequest.model_validate(document), document
        )


async def create_contact(fixture, email="synthetic-contact@example.com"):
    account_id, *_ = fixture
    identifier = uuid.uuid4()
    ciphertext, nonce, version = encrypt_email(KEYS, email, "contact", identifier)
    async with get_session_local().begin() as db:
        db.add(
            AeternaContact(
                id=identifier,
                account_id=account_id,
                email_lookup=uuid.uuid4().bytes + uuid.uuid4().bytes,
                email_ciphertext=ciphertext,
                email_nonce=nonce,
                email_key_version=version,
                disclosure_mode="PRIVATE_UNTIL_RELEASE",
                notification_locale="en",
                consent_status="NOT_REQUESTED",
            )
        )
    return identifier


async def invitation_event(fixture, contact_id, *, released=True, status="queued"):
    account_id, _device_id, _key, policy_id = fixture
    source_id, invitation_id = uuid.uuid4(), uuid.uuid4()
    async with get_session_local().begin() as db:
        db.add(
            AccountPolicyOutboxEvent(
                id=source_id,
                account_policy_id=policy_id,
                event_type="synthetic.release" if released else "synthetic.warning",
                idempotency_key=str(source_id),
                from_state="GRACE_PERIOD" if released else "ACTIVE",
                to_state="RELEASED" if released else "PRE_WARNING",
                policy_version=3,
                payload={},
                scheduled_at=NOW - timedelta(days=3),
                status="acknowledged",
                notification_type=(
                    "owner-release-authorized" if released else "owner-pre-warning"
                ),
                delivery_idempotency_key=f"synthetic:{source_id}",
            )
        )
        db.add(
            AeternaContactInvitation(
                id=invitation_id,
                contact_id=contact_id,
                token_digest=uuid.uuid4().bytes + uuid.uuid4().bytes,
                token_key_version=1,
                status="pending",
                expires_at=NOW + timedelta(days=4),
            )
        )
        await db.flush()
        db.add(
            AeternaEmailOutboxEvent(
                id=uuid.uuid4(),
                account_id=account_id,
                contact_id=contact_id,
                invitation_id=invitation_id,
                source_policy_outbox_id=source_id,
                recipient_kind="contact",
                event_type="contact-invitation",
                idempotency_key=f"synthetic-invitation:{invitation_id}",
                status=status,
                next_attempt_at=NOW,
                attempt_count=0,
            )
        )


async def release_event(fixture, contact_id, *, epoch=1, status="delivered"):
    account_id, device_id, _key, _policy_id = fixture
    record_id, grant_id, link_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    async with get_session_local().begin() as db:
        db.add(
            AeternaRecoveryRecord(
                id=record_id,
                account_id=account_id,
                device_id=device_id,
                vault_id=uuid.uuid4(),
                policy_epoch=epoch,
                recovery_generation=1,
                state="sealed",
                encrypted_srs=b"synthetic-encrypted-recovery-material",
                kms_provider="synthetic",
                kms_key_arn="synthetic-test-key",
                kms_key_material_id="synthetic-test-version",
                kms_context_version=1,
                crypto_format_version=1,
                recovery_context_version=1,
                wrapper_digest=b"\x51" * 32,
                provision_request_id=uuid.uuid4(),
                provision_request_digest=b"\x52" * 32,
                expires_at=NOW + timedelta(days=1),
                confirmed_at=NOW - timedelta(days=35),
            )
        )
        await db.flush()
        db.add(
            AeternaRecoveryGrant(
                id=grant_id,
                account_id=account_id,
                recovery_id=record_id,
                contact_id=contact_id,
                state="available",
                released_at=NOW - timedelta(days=3),
            )
        )
        await db.flush()
        db.add(
            AeternaRecoveryClaimLink(
                id=link_id,
                grant_id=grant_id,
                token_digest=uuid.uuid4().bytes + uuid.uuid4().bytes,
                token_key_version=1,
                status="active",
                expires_at=NOW + timedelta(days=4),
            )
        )
        await db.flush()
        db.add(
            AeternaEmailOutboxEvent(
                id=uuid.uuid4(),
                account_id=account_id,
                contact_id=contact_id,
                recovery_link_id=link_id,
                recipient_kind="contact",
                event_type="recovery-claim-link",
                idempotency_key=f"synthetic-release:{grant_id}",
                status=status,
                next_attempt_at=NOW,
                attempt_count=0,
            )
        )


async def set_state(fixture, *, policy_state=None, device_state=None):
    account_id, device_id, _key, policy_id = fixture
    async with get_session_local().begin() as db:
        if policy_state is not None:
            policy = await db.get(AccountPolicy, policy_id)
            policy.state = policy_state
            policy.released_at = (
                None if policy_state != "RELEASED" else NOW - timedelta(days=3)
            )
        if device_state is not None:
            device = await db.get(AeternaDevice, device_id)
            device.status = device_state


async def test_notice_excludes_nonrelease_events_and_historical_epochs(notice_account):
    released = await create_contact(notice_account, "synthetic-released@example.com")
    private = await create_contact(notice_account, "synthetic-private@example.com")
    unrelated = await create_contact(notice_account, "synthetic-unrelated@example.com")
    await release_event(notice_account, released, status="provider_accepted")
    await invitation_event(notice_account, private)
    await invitation_event(
        notice_account, unrelated, released=False, status="delivered"
    )
    await release_event(notice_account, unrelated, epoch=2)
    data = await read_notice(notice_account, [released, private, unrelated])
    assert data["state"] == "RELEASED"
    assert data["recipients"] == [
        {
            "contact_id": str(released),
            "email": "synthetic-released@example.com",
            "kind": "release",
            "status": "submitted",
        },
        {
            "contact_id": str(private),
            "email": "synthetic-private@example.com",
            "kind": "invitation",
            "status": "pending",
        },
    ]
    assert data["last_activity_at"] == "2030-04-22T00:00:00Z"
    assert data["released_at"] == "2030-05-29T00:00:00Z"


async def test_notice_prefer_release_and_deduplicate_device_mail_evidence(
    notice_account,
):
    contact = await create_contact(notice_account)
    await invitation_event(notice_account, contact, status="delivered")
    await release_event(notice_account, contact, status="failed")
    await release_event(notice_account, contact, status="delivered")
    data = await read_notice(notice_account, [contact])
    assert len(data["recipients"]) == 1
    assert data["recipients"][0]["kind"] == "release"
    assert data["recipients"][0]["status"] == "delivered"


async def test_notice_suppresses_contact_details_when_policy_is_not_released(
    notice_account,
):
    contact = await create_contact(notice_account)
    await invitation_event(notice_account, contact, status="delivered")
    await set_state(notice_account, policy_state="ACTIVE")
    data = await read_notice(notice_account, [contact])
    assert data["state"] == "ACTIVE"
    assert data["recipients"] == []
    assert data["released_at"] is None


async def test_notice_rejects_unknown_contacts_and_wrong_signature(notice_account):
    with pytest.raises(AeternaProtocolException) as failure:
        await read_notice(notice_account, [uuid.uuid4()])
    assert failure.value.code == "contact.not_found"
    with pytest.raises(AeternaProtocolException) as failure:
        await read_notice(notice_account, key=Ed25519PrivateKey.generate())
    assert failure.value.code == "device.proof_invalid"


async def test_notice_rejects_existing_foreign_account_contact(notice_account):
    foreign_account_id = uuid.uuid4()
    foreign_contact = await create_contact(notice_account)
    factory = get_session_local()
    try:
        async with factory.begin() as db:
            db.add(
                AeternaAccount(
                    id=foreign_account_id,
                    email_lookup=uuid.uuid4().bytes + uuid.uuid4().bytes,
                    email_ciphertext=b"synthetic-foreign-account-mailbox",
                    email_nonce=b"\x61" * 12,
                    email_key_version=1,
                    first_device_bound_at=NOW,
                    is_active=True,
                )
            )
            await db.flush()
            contact = await db.get(AeternaContact, foreign_contact)
            contact.account_id = foreign_account_id
        with pytest.raises(AeternaProtocolException) as failure:
            await read_notice(notice_account, [foreign_contact])
        assert failure.value.code == "contact.not_found"
    finally:
        async with factory.begin() as db:
            await db.execute(
                delete(AeternaAccount).where(AeternaAccount.id == foreign_account_id)
            )


async def test_notice_omits_deleted_contact_without_reading_destroyed_mailbox(
    notice_account,
):
    contact_id = await create_contact(notice_account)
    await invitation_event(notice_account, contact_id, status="delivered")
    async with get_session_local().begin() as db:
        contact = await db.get(AeternaContact, contact_id)
        contact.deleted_at = NOW
        contact.email_ciphertext = b"synthetic-destroyed-mailbox"
    data = await read_notice(notice_account, [contact_id])
    assert data["recipients"] == []


async def test_dormant_device_can_only_discover_released_notice_without_reactivation(
    notice_account,
):
    await set_state(notice_account, device_state="dormant")
    data = await read_notice(notice_account)
    assert data["state"] == "RELEASED"
    account_id, device_id, _key, _policy_id = notice_account
    async with get_session_local()() as db:
        device = await db.get(AeternaDevice, device_id)
        assert device.status == "dormant"
        assert device.last_sequence == 3
        assert device.last_seen_at is None
        assert device.heartbeat_authorized_at == NOW - timedelta(days=40)
        account = await db.get(AeternaAccount, account_id)
        assert account.last_activity_at is None
    await set_state(notice_account, policy_state="ACTIVE")
    with pytest.raises(AeternaProtocolException) as failure:
        await read_notice(notice_account)
    assert failure.value.code == "device.not_active"


@pytest.mark.parametrize("state", ["lost", "revoked"])
async def test_terminal_device_cannot_read_contact_notice(notice_account, state):
    await set_state(notice_account, device_state=state)
    with pytest.raises(AeternaProtocolException) as failure:
        await read_notice(notice_account)
    assert failure.value.code == "device.not_active"


async def test_http_notice_uses_no_store_and_strict_request_schema(notice_account):
    application = create_client_app()
    application.dependency_overrides[get_aeterna_recovery_notice_service] = service
    document = request_document(notice_account)
    async with AsyncClient(
        transport=ASGITransport(app=application), base_url="http://synthetic.test"
    ) as client:
        response = await client.post("/api/v1/recovery/notice/read", json=document)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["data"]["state"] == "RELEASED"
        document["signed"]["claim_token"] = "synthetic-forbidden"
        response = await client.post("/api/v1/recovery/notice/read", json=document)
        assert response.status_code == 400
