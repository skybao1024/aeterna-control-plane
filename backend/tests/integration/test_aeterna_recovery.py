"""Real-PostgreSQL acceptance evidence for I13 delayed recovery claims."""

import asyncio
import base64
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import delete, func, select

from app.db.base import get_session_local
from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.models.account_policy import AccountPolicy
from app.models.aeterna_identity import AeternaAccount, AeternaDevice
from app.models.aeterna_notification import AeternaContact, AeternaEmailOutboxEvent
from app.models.aeterna_recipient_recovery import AeternaRecipientRecoveryRotation
from app.models.aeterna_recovery import (
    AeternaOwnerRecoveryRequest,
    AeternaRecoveryAudit,
    AeternaRecoveryClaimLink,
    AeternaRecoveryClaimToken,
    AeternaRecoveryGrant,
    AeternaRecoveryOtpChallenge,
    AeternaRecoveryRecord,
)
from app.schemas.client.aeterna_recipient_recovery import RecipientRecoverySecretRequest
from app.schemas.client.aeterna_recovery import (
    OwnerRecoveryActionRequest,
    OwnerRecoveryStartRequest,
    OwnerRecoveryVerifyRequest,
    RecoveryClaimStartRequest,
    RecoveryClaimVerifyRequest,
    RecoveryRecordActionRequest,
    RecoveryRecordProvisionRequest,
    RecoveryRotationConfirmRequest,
    RecoveryRotationProvisionRequest,
    RecoverySecretRequest,
)
from app.services.client.aeterna_recipient_recovery import (
    AeternaRecipientRecoveryService,
)
from app.services.client.aeterna_recovery import AeternaRecoveryService
from app.services.common.aeterna_email_adapter import (
    AeternaEmailEnvelope,
    ProviderAcceptance,
)
from app.services.common.aeterna_recovery_key import (
    InMemoryRecoveryKeyProvider,
    RecoveryKeyUnavailable,
)
from app.services.common.aeterna_security import (
    AeternaIdentityKeys,
    canonicalize,
    derive_recovery_link_token,
    derive_recovery_otp,
    encode_base64url,
    encrypt_email,
    make_token,
    otp_verifier,
)
from app.services.internal.aeterna_email_delivery import AeternaEmailDeliveryService

pytestmark = pytest.mark.asyncio(loop_scope="session")
CREATED_ACCOUNT_IDS: set[uuid.UUID] = set()


@dataclass
class MutableClock:
    current: datetime

    def __call__(self) -> datetime:
        return self.current


@dataclass(frozen=True)
class RecoveryFixture:
    account_id: uuid.UUID
    device_id: uuid.UUID
    contact_id: uuid.UUID
    vault_id: uuid.UUID
    recovery_id: uuid.UUID
    signing_key: Ed25519PrivateKey


class FailingDecryptProvider:
    def __init__(self, delegate):
        self.delegate = delegate

    def generate_srs(self, context):
        return self.delegate.generate_srs(context)

    def decrypt_srs(self, ciphertext, key_arn, context):
        raise RecoveryKeyUnavailable("synthetic unavailable key")


class CountingDecryptProvider:
    def __init__(self, delegate):
        self.delegate = delegate
        self.decrypt_calls = 0

    def generate_srs(self, context):
        return self.delegate.generate_srs(context)

    def decrypt_srs(self, ciphertext, key_arn, context):
        self.decrypt_calls += 1
        return self.delegate.decrypt_srs(ciphertext, key_arn, context)


class CapturingEmailAdapter:
    provider_name = "test-capture"
    supports_idempotency = True

    def __init__(self, now: datetime):
        self.now = now
        self.envelopes: list[AeternaEmailEnvelope] = []

    async def send(
        self, envelope: AeternaEmailEnvelope, idempotency_key: str
    ) -> ProviderAcceptance:
        self.envelopes.append(envelope)
        return ProviderAcceptance(
            provider_name=self.provider_name,
            provider_message_id=str(uuid.uuid5(uuid.NAMESPACE_URL, idempotency_key)),
            accepted_at=self.now,
        )


def synthetic_keys() -> AeternaIdentityKeys:
    return AeternaIdentityKeys(
        pii_key=bytes([0x11]) * 32,
        lookup_key=bytes([0x22]) * 32,
        otp_key=bytes([0x33]) * 32,
    )


def recovery_provider() -> InMemoryRecoveryKeyProvider:
    counter = 0

    def random_bytes(length: int) -> bytes:
        nonlocal counter
        counter += 1
        return bytes([counter]) * length

    return InMemoryRecoveryKeyProvider(bytes([0x44]) * 32, random_bytes)


@pytest_asyncio.fixture(autouse=True, scope="module", loop_scope="session")
async def remove_only_i13_test_accounts():
    yield
    if not CREATED_ACCOUNT_IDS:
        return
    session_factory = get_session_local()
    async with session_factory.begin() as db:
        await db.execute(
            delete(AeternaRecoveryAudit).where(
                AeternaRecoveryAudit.account_id.in_(CREATED_ACCOUNT_IDS)
            )
        )
        await db.execute(
            delete(AeternaAccount).where(AeternaAccount.id.in_(CREATED_ACCOUNT_IDS))
        )


async def create_fixture(
    now: datetime, *, accepted_contact: bool = True
) -> RecoveryFixture:
    keys = synthetic_keys()
    account_id = uuid.uuid4()
    CREATED_ACCOUNT_IDS.add(account_id)
    device_id = uuid.uuid4()
    contact_id = uuid.uuid4()
    signing_key = Ed25519PrivateKey.generate()
    public_key = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    owner_ciphertext, owner_nonce, owner_key_version = encrypt_email(
        keys,
        "owner@example.com",
        "account",
        account_id,
        nonce_factory=lambda length: bytes([0x51]) * length,
    )
    contact_ciphertext, contact_nonce, contact_key_version = encrypt_email(
        keys,
        "contact@example.com",
        "contact",
        contact_id,
        nonce_factory=lambda length: bytes([0x52]) * length,
    )
    session_factory = get_session_local()
    async with session_factory.begin() as db:
        account = AeternaAccount(
            id=account_id,
            email_lookup=uuid.uuid4().bytes + uuid.uuid4().bytes,
            email_ciphertext=owner_ciphertext,
            email_nonce=owner_nonce,
            email_key_version=owner_key_version,
            first_device_bound_at=now,
            is_active=True,
        )
        db.add(account)
        await db.flush()

        device = AeternaDevice(
            id=device_id,
            account_id=account_id,
            public_key=public_key,
            label="Owner Mac",
            status="active",
            bound_at=now,
            heartbeat_authorized_at=now,
            last_sequence=0,
        )
        db.add(device)
        await db.flush()

        db.add(
            AccountPolicy(
                id=uuid.uuid4(),
                account_id=account_id,
                state="ACTIVE",
                version=0,
                inactivity_window_seconds=30 * 24 * 60 * 60,
                warning_window_seconds=7 * 24 * 60 * 60,
                grace_window_seconds=7 * 24 * 60 * 60,
                last_activity_at=now,
                due_at=now + timedelta(days=30),
                state_changed_at=now,
            )
        )
        db.add(
            AeternaContact(
                id=contact_id,
                account_id=account_id,
                email_lookup=uuid.uuid4().bytes + uuid.uuid4().bytes,
                email_ciphertext=contact_ciphertext,
                email_nonce=contact_nonce,
                email_key_version=contact_key_version,
                disclosure_mode="PRIVATE_UNTIL_RELEASE",
                consent_status="ACCEPTED" if accepted_contact else "NOT_REQUESTED",
                accepted_at=now if accepted_contact else None,
                verified_at=now if accepted_contact else None,
            )
        )
    return RecoveryFixture(
        account_id=account_id,
        device_id=device_id,
        contact_id=contact_id,
        vault_id=uuid.uuid4(),
        recovery_id=uuid.uuid4(),
        signing_key=signing_key,
    )


def signed_document(
    fixture: RecoveryFixture,
    *,
    domain: str,
    operation: str,
    members: dict,
    include_recovery_binding: bool = True,
) -> dict:
    signed = {
        "account_id": str(fixture.account_id),
        "canonicalization": "jcs-rfc8785",
        "device_id": str(fixture.device_id),
        "domain": domain,
        "operation": operation,
        "protocol_version": 1,
        "request_id": str(uuid.uuid4()),
        "signature_version": 1,
    }
    if include_recovery_binding:
        signed.update(
            {
                "vault_id": str(fixture.vault_id),
                "recovery_id": str(fixture.recovery_id),
            }
        )
    signed.update(members)
    return {
        "protocol_version": 1,
        "signed": signed,
        "signature": encode_base64url(fixture.signing_key.sign(canonicalize(signed))),
    }


def decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


async def provision_and_confirm(
    service: AeternaRecoveryService, fixture: RecoveryFixture
) -> tuple[dict, bytes]:
    provision_document = signed_document(
        fixture,
        domain="aeterna.recovery-record.provision.v1",
        operation="recovery_record.provision",
        members={"crypto_format_version": 1, "recovery_context_version": 1},
    )
    provision = RecoveryRecordProvisionRequest.model_validate(provision_document)
    session_factory = get_session_local()
    async with session_factory() as db:
        data = await service.provision_record(db, provision, provision_document)
    confirm_document = signed_document(
        fixture,
        domain="aeterna.recovery-record.confirm.v1",
        operation="recovery_record.confirm",
        members={"wrapper_digest": encode_base64url(bytes([0x66]) * 32)},
    )
    confirm = RecoveryRecordActionRequest.model_validate(confirm_document)
    async with session_factory() as db:
        confirmed = await service.act_on_record(db, confirm, confirm_document)
    assert confirmed["state"] == "sealed"
    return provision_document, decode_base64url(data["srs"])


async def release_policy(account_id: uuid.UUID, now: datetime):
    session_factory = get_session_local()
    async with session_factory.begin() as db:
        policy = await db.scalar(
            select(AccountPolicy).where(AccountPolicy.account_id == account_id)
        )
        policy.state = "RELEASED"
        policy.released_at = now
        policy.state_changed_at = now


async def prepare_claim(
    service: AeternaRecoveryService, fixture: RecoveryFixture, now: datetime
) -> dict:
    await release_policy(fixture.account_id, now)
    session_factory = get_session_local()
    async with session_factory() as db:
        grants = await service.materialize_released_account(db, fixture.account_id)
    assert len(grants) == 1
    async with session_factory() as db:
        link = await db.scalar(
            select(AeternaRecoveryClaimLink)
            .join(AeternaRecoveryGrant)
            .where(AeternaRecoveryGrant.account_id == fixture.account_id)
        )
    claim_link_token = derive_recovery_link_token(
        synthetic_keys(), link.id, link.token_key_version
    )
    start = RecoveryClaimStartRequest(
        protocol_version=1,
        request_id=str(uuid.uuid4()),
        claim_link_token=claim_link_token,
    )
    async with session_factory() as db:
        challenge_data = await service.start_recipient_claim(db, start)
    code = derive_recovery_otp(
        synthetic_keys(), uuid.UUID(challenge_data["challenge_id"])
    )
    verify = RecoveryClaimVerifyRequest(
        protocol_version=1,
        request_id=str(uuid.uuid4()),
        challenge_id=challenge_data["challenge_id"],
        claim_link_token=claim_link_token,
        code=code,
    )
    async with session_factory() as db:
        return await service.verify_recipient_claim(db, verify)


def secret_request(claim_data: dict, **changes) -> RecoverySecretRequest:
    return RecoverySecretRequest(
        protocol_version=1,
        request_id=str(uuid.uuid4()),
        claim_token=claim_data["claim_token"],
        device_id=claim_data["device_id"],
        recovery_id=claim_data["recovery_id"],
        vault_id=changes.get("vault_id", claim_data["vault_id"]),
        wrapper_digest=claim_data["wrapper_digest"],
    )


def signed_secret_request(fixture, claim_data, **changes):
    document = signed_document(
        fixture,
        domain="aeterna.recipient-recovery.secret.v1",
        operation="recipient_recovery.secret",
        members={
            "wrapper_digest": claim_data["wrapper_digest"],
            "rotation_id": str(uuid.uuid4()),
            **changes,
        },
    )
    document["claim_token"] = claim_data["claim_token"]
    return document


async def release_signed_secret(recovery, document):
    recipient = AeternaRecipientRecoveryService(recovery_service=recovery)
    async with get_session_local()() as db:
        try:
            return await recipient.release_secret(
                db, RecipientRecoverySecretRequest.model_validate(document), document
            )
        except AeternaProtocolException:
            await db.rollback()
            raise


async def test_preexisting_legacy_proofs_cannot_release_or_be_promoted():
    now = datetime(2030, 1, 2, tzinfo=UTC)
    provider = CountingDecryptProvider(recovery_provider())
    service = AeternaRecoveryService(
        provision_provider=lambda: provider,
        claim_provider=lambda: provider,
        identity_key_provider=synthetic_keys,
        clock=MutableClock(now),
    )
    fixture = await create_fixture(now)
    _, expected_srs = await provision_and_confirm(service, fixture)
    await release_policy(fixture.account_id, now)
    sessions = get_session_local()
    async with sessions() as db:
        await service.materialize_released_account(db, fixture.account_id)
    legacy_challenge_id = uuid.uuid4()
    legacy_claim_id = uuid.uuid4()
    legacy_token, legacy_digest = make_token()
    legacy_code = derive_recovery_otp(synthetic_keys(), legacy_challenge_id)
    async with sessions.begin() as db:
        grant = await db.scalar(
            select(AeternaRecoveryGrant).where(
                AeternaRecoveryGrant.account_id == fixture.account_id
            )
        )
        link = await db.scalar(
            select(AeternaRecoveryClaimLink).where(
                AeternaRecoveryClaimLink.grant_id == grant.id
            )
        )
        record = await db.get(AeternaRecoveryRecord, fixture.recovery_id)
        grant_id, link_id = grant.id, link.id
        link_token = derive_recovery_link_token(
            synthetic_keys(), link.id, link.token_key_version
        )
        db.add(
            AeternaRecoveryOtpChallenge(
                id=legacy_challenge_id,
                link_id=link.id,
                otp_verifier=otp_verifier(
                    synthetic_keys(), legacy_challenge_id, "recovery-claim", legacy_code
                ),
                otp_key_version=1,
                scope="recovery.srs.read",
                status="active",
                expires_at=now + timedelta(minutes=10),
                resend_after=now + timedelta(seconds=60),
            )
        )
        db.add(
            AeternaRecoveryClaimToken(
                id=legacy_claim_id,
                grant_id=grant.id,
                account_id=fixture.account_id,
                contact_id=fixture.contact_id,
                recovery_id=fixture.recovery_id,
                device_id=fixture.device_id,
                vault_id=fixture.vault_id,
                wrapper_digest=record.wrapper_digest,
                token_digest=legacy_digest,
                scope="recovery.srs.read",
                status="active",
                expires_at=now + timedelta(minutes=5),
            )
        )

    async def authority_state():
        async with sessions() as db:
            grant = await db.get(AeternaRecoveryGrant, grant_id)
            link = await db.get(AeternaRecoveryClaimLink, link_id)
            otp = await db.get(AeternaRecoveryOtpChallenge, legacy_challenge_id)
            token = await db.get(AeternaRecoveryClaimToken, legacy_claim_id)
            counts = []
            for model in (
                AeternaEmailOutboxEvent,
                AeternaRecoveryAudit,
                AeternaRecoveryClaimToken,
                AeternaRecipientRecoveryRotation,
            ):
                counts.append(
                    await db.scalar(
                        select(func.count(model.id)).where(
                            model.account_id == fixture.account_id
                        )
                    )
                )
            return (
                grant.state,
                grant.claimed_at,
                link.status,
                link.consumed_at,
                otp.status,
                otp.attempt_count,
                otp.verified_at,
                token.status,
                token.consumed_at,
                tuple(counts),
            )

    start = RecoveryClaimStartRequest(
        protocol_version=1, request_id=str(uuid.uuid4()), claim_link_token=link_token
    )
    verify = RecoveryClaimVerifyRequest(
        protocol_version=1,
        request_id=str(uuid.uuid4()),
        challenge_id=str(legacy_challenge_id),
        claim_link_token=link_token,
        code=legacy_code,
    )
    authorization = {
        "claim_token": legacy_token,
        "device_id": str(fixture.device_id),
        "recovery_id": str(fixture.recovery_id),
        "vault_id": str(fixture.vault_id),
        "wrapper_digest": encode_base64url(bytes([0x66]) * 32),
    }
    before = await authority_state()
    for operation, payload in (
        ("start_claim", start),
        ("verify_claim", verify),
        ("release_secret", secret_request(authorization)),
    ):
        for _retry in range(2):
            async with sessions() as db:
                with pytest.raises(AeternaProtocolException) as denied:
                    await getattr(service, operation)(db, payload)
            assert denied.value.code == "recovery.claim_unavailable"
            assert await authority_state() == before
    async with sessions() as db:
        with pytest.raises(AeternaProtocolException) as wrong_scope:
            await service.verify_recipient_claim(db, verify)
    assert wrong_scope.value.code == "recovery.otp_invalid"
    with pytest.raises(AeternaProtocolException) as token_scope:
        await release_signed_secret(
            service, signed_secret_request(fixture, authorization)
        )
    assert token_scope.value.code == "recovery.claim_unavailable"
    assert provider.decrypt_calls == 0
    assert await authority_state() == before

    async with sessions() as db:
        challenge = await service.start_recipient_claim(db, start)
    async with sessions() as db:
        authorized = await service.verify_recipient_claim(
            db,
            RecoveryClaimVerifyRequest(
                protocol_version=1,
                request_id=str(uuid.uuid4()),
                challenge_id=challenge["challenge_id"],
                claim_link_token=link_token,
                code=derive_recovery_otp(
                    synthetic_keys(), uuid.UUID(challenge["challenge_id"])
                ),
            ),
        )
    released = await release_signed_secret(
        service, signed_secret_request(fixture, authorized)
    )
    assert decode_base64url(released["srs"]) == expected_srs
    assert provider.decrypt_calls == 1
    async with sessions() as db:
        assert (await db.get(AeternaRecoveryGrant, grant_id)).state == "available"
        assert (
            await db.get(AeternaRecoveryClaimToken, legacy_claim_id)
        ).status == "active"
        old_otp = await db.get(AeternaRecoveryOtpChallenge, legacy_challenge_id)
        assert old_otp.status == "active" and old_otp.attempt_count == 0


async def test_pre_release_paths_fail_and_full_claim_is_signed_and_reservation_bound():
    now = datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)
    provider = recovery_provider()
    service = AeternaRecoveryService(
        provision_provider=lambda: provider,
        claim_provider=lambda: provider,
        identity_key_provider=synthetic_keys,
        clock=MutableClock(now),
    )
    fixture = await create_fixture(now)
    provision_document, expected_srs = await provision_and_confirm(service, fixture)
    replay = RecoveryRecordProvisionRequest.model_validate(provision_document)
    session_factory = get_session_local()
    async with session_factory() as db:
        with pytest.raises(AeternaProtocolException) as raised:
            await service.provision_record(db, replay, provision_document)
    assert raised.value.code == "recovery.provision_retry_required"
    async with session_factory() as db:
        assert await service.materialize_released_account(db, fixture.account_id) == []

    claim_data = await prepare_claim(service, fixture, now)
    wrong_binding = signed_secret_request(
        fixture, claim_data, vault_id="00000000-0000-4000-8000-000000000099"
    )
    with pytest.raises(AeternaProtocolException) as raised:
        await release_signed_secret(service, wrong_binding)
    assert raised.value.code == "recovery.claim_unavailable"
    async with session_factory() as db:
        token = await db.scalar(
            select(AeternaRecoveryClaimToken).where(
                AeternaRecoveryClaimToken.account_id == fixture.account_id
            )
        )
        assert token.status == "active"

    request = signed_secret_request(fixture, claim_data)
    released = await release_signed_secret(service, request)
    assert decode_base64url(released["srs"]) == expected_srs
    assert await release_signed_secret(service, request) == released
    with pytest.raises(AeternaProtocolException) as raised:
        await release_signed_secret(service, signed_secret_request(fixture, claim_data))
    assert raised.value.code == "recovery.recipient_rotation_in_progress"
    async with session_factory() as db:
        record = await db.get(AeternaRecoveryRecord, fixture.recovery_id)
        grant = await db.scalar(
            select(AeternaRecoveryGrant).where(
                AeternaRecoveryGrant.account_id == fixture.account_id
            )
        )
        event_types = set(
            await db.scalars(
                select(AeternaEmailOutboxEvent.event_type).where(
                    AeternaEmailOutboxEvent.account_id == fixture.account_id
                )
            )
        )
        assert expected_srs not in record.encrypted_srs
        assert grant.state == "available"
        assert {
            "recovery-claim-link",
            "recovery-otp",
            "recovery-claimed-owner",
        } <= event_types


async def test_unverified_private_contact_never_receives_a_grant_after_release():
    now = datetime(2030, 2, 2, tzinfo=UTC)
    provider = recovery_provider()
    service = AeternaRecoveryService(
        provision_provider=lambda: provider,
        claim_provider=lambda: provider,
        identity_key_provider=synthetic_keys,
        clock=MutableClock(now),
    )
    fixture = await create_fixture(now, accepted_contact=False)
    await provision_and_confirm(service, fixture)
    await release_policy(fixture.account_id, now)
    session_factory = get_session_local()
    async with session_factory() as db:
        assert await service.materialize_released_account(db, fixture.account_id) == []
    async with session_factory() as db:
        assert (
            await db.scalar(
                select(AeternaRecoveryGrant.id).where(
                    AeternaRecoveryGrant.account_id == fixture.account_id
                )
            )
            is None
        )


async def test_expired_unconfirmed_record_is_removed_before_reprovisioning():
    now = datetime(2030, 2, 2, 12, tzinfo=UTC)
    provider = recovery_provider()
    service = AeternaRecoveryService(
        provision_provider=lambda: provider,
        claim_provider=lambda: provider,
        identity_key_provider=synthetic_keys,
        clock=MutableClock(now),
    )
    fixture = await create_fixture(now)
    first_document = signed_document(
        fixture,
        domain="aeterna.recovery-record.provision.v1",
        operation="recovery_record.provision",
        members={"crypto_format_version": 1, "recovery_context_version": 1},
    )
    session_factory = get_session_local()
    async with session_factory() as db:
        await service.provision_record(
            db,
            RecoveryRecordProvisionRequest.model_validate(first_document),
            first_document,
        )
    async with session_factory.begin() as db:
        first_record = await db.get(AeternaRecoveryRecord, fixture.recovery_id)
        first_record.expires_at = now - timedelta(seconds=1)

    replacement_fixture = replace(fixture, recovery_id=uuid.uuid4())
    replacement_document = signed_document(
        replacement_fixture,
        domain="aeterna.recovery-record.provision.v1",
        operation="recovery_record.provision",
        members={"crypto_format_version": 1, "recovery_context_version": 1},
    )
    async with session_factory() as db:
        await service.provision_record(
            db,
            RecoveryRecordProvisionRequest.model_validate(replacement_document),
            replacement_document,
        )
    async with session_factory() as db:
        assert await db.get(AeternaRecoveryRecord, fixture.recovery_id) is None
        assert (
            await db.get(AeternaRecoveryRecord, replacement_fixture.recovery_id)
        ).state == "pending_confirmation"


async def test_claim_link_and_otp_are_rendered_only_at_authorized_delivery():
    now = datetime(2030, 2, 3, tzinfo=UTC)
    provider = recovery_provider()
    service = AeternaRecoveryService(
        provision_provider=lambda: provider,
        claim_provider=lambda: provider,
        identity_key_provider=synthetic_keys,
        clock=MutableClock(now),
    )
    fixture = await create_fixture(now)
    await provision_and_confirm(service, fixture)
    await release_policy(fixture.account_id, now)
    session_factory = get_session_local()
    async with session_factory() as db:
        assert (
            len(await service.materialize_released_account(db, fixture.account_id)) == 1
        )
    async with session_factory() as db:
        link = await db.scalar(
            select(AeternaRecoveryClaimLink)
            .join(AeternaRecoveryGrant)
            .where(AeternaRecoveryGrant.account_id == fixture.account_id)
        )
        link_event = await db.scalar(
            select(AeternaEmailOutboxEvent).where(
                AeternaEmailOutboxEvent.account_id == fixture.account_id,
                AeternaEmailOutboxEvent.event_type == "recovery-claim-link",
            )
        )
    claim_link_token = derive_recovery_link_token(
        synthetic_keys(), link.id, link.token_key_version
    )
    adapter = CapturingEmailAdapter(now)
    delivery = AeternaEmailDeliveryService(
        adapter=adapter,
        key_provider=synthetic_keys,
        clock=MutableClock(now),
    )
    async with session_factory() as db:
        result = await delivery.dispatch_event(db, link_event.id)
    assert result.status == "provider_accepted"
    assert adapter.envelopes[0].recipient == "contact@example.com"
    assert f"#token={claim_link_token}" in adapter.envelopes[0].text_body

    start = RecoveryClaimStartRequest(
        protocol_version=1,
        request_id=str(uuid.uuid4()),
        claim_link_token=claim_link_token,
    )
    async with session_factory() as db:
        challenge_data = await service.start_recipient_claim(db, start)
    challenge_id = uuid.UUID(challenge_data["challenge_id"])
    async with session_factory() as db:
        otp_event = await db.scalar(
            select(AeternaEmailOutboxEvent).where(
                AeternaEmailOutboxEvent.recovery_challenge_id == challenge_id
            )
        )
    async with session_factory() as db:
        result = await delivery.dispatch_event(db, otp_event.id)
    assert result.status == "provider_accepted"
    expected_code = derive_recovery_otp(synthetic_keys(), challenge_id)
    assert expected_code in adapter.envelopes[1].text_body


async def test_recipient_resend_is_bounded_and_original_link_survives_delay():
    now = datetime(2030, 2, 4, tzinfo=UTC)
    clock = MutableClock(now)
    provider = recovery_provider()
    service = AeternaRecoveryService(
        provision_provider=lambda: provider,
        claim_provider=lambda: provider,
        identity_key_provider=synthetic_keys,
        clock=clock,
    )
    fixture = await create_fixture(now)
    await provision_and_confirm(service, fixture)
    await release_policy(fixture.account_id, now)
    session_factory = get_session_local()
    async with session_factory() as db:
        await service.materialize_released_account(db, fixture.account_id)
    async with session_factory() as db:
        original_link = await db.scalar(
            select(AeternaRecoveryClaimLink)
            .join(AeternaRecoveryGrant)
            .where(AeternaRecoveryGrant.account_id == fixture.account_id)
        )
    original_token = derive_recovery_link_token(
        synthetic_keys(), original_link.id, original_link.token_key_version
    )
    request = RecoveryClaimStartRequest(
        protocol_version=1,
        request_id=str(uuid.uuid4()),
        claim_link_token=original_token,
    )
    async with session_factory() as db:
        first = await service.start_recipient_claim(db, request)
    async with session_factory() as db:
        unchanged = await service.start_recipient_claim(db, request)
    assert unchanged["challenge_id"] == first["challenge_id"]

    clock.current = now + timedelta(seconds=61)
    async with session_factory() as db:
        resent = await service.start_recipient_claim(db, request)
    assert resent["challenge_id"] != first["challenge_id"]
    async with session_factory() as db:
        first_challenge = await db.get(
            AeternaRecoveryOtpChallenge, uuid.UUID(first["challenge_id"])
        )
    assert first_challenge.status == "expired"

    clock.current = now + timedelta(hours=24, seconds=1)
    for _attempt in range(3):
        async with session_factory() as db:
            neutral = await service.start_recipient_claim(db, request)
        assert neutral["challenge_id"] not in {
            first["challenge_id"],
            resent["challenge_id"],
        }
        async with session_factory() as db:
            link_count = await db.scalar(
                select(func.count(AeternaRecoveryClaimLink.id))
                .join(AeternaRecoveryGrant)
                .where(AeternaRecoveryGrant.account_id == fixture.account_id)
            )
        assert link_count == 1
        clock.current += timedelta(seconds=61)
    async with session_factory() as db:
        await service.start_recipient_claim(db, request)
    async with session_factory() as db:
        link_count = await db.scalar(
            select(func.count(AeternaRecoveryClaimLink.id))
            .join(AeternaRecoveryGrant)
            .where(AeternaRecoveryGrant.account_id == fixture.account_id)
        )
    assert link_count == 1


async def test_kms_failure_rolls_back_and_concurrent_release_has_one_winner():
    now = datetime(2030, 3, 2, tzinfo=UTC)
    provider = recovery_provider()
    service = AeternaRecoveryService(
        provision_provider=lambda: provider,
        claim_provider=lambda: provider,
        identity_key_provider=synthetic_keys,
        clock=MutableClock(now),
    )
    fixture = await create_fixture(now)
    await provision_and_confirm(service, fixture)
    claim_data = await prepare_claim(service, fixture, now)
    request = signed_secret_request(fixture, claim_data)
    failing = AeternaRecoveryService(
        provision_provider=lambda: provider,
        claim_provider=lambda: FailingDecryptProvider(provider),
        identity_key_provider=synthetic_keys,
        clock=MutableClock(now),
    )
    session_factory = get_session_local()
    with pytest.raises(AeternaProtocolException) as raised:
        await release_signed_secret(failing, request)
    assert raised.value.code == "recovery.material_unavailable"
    async with session_factory() as db:
        token = await db.scalar(
            select(AeternaRecoveryClaimToken).where(
                AeternaRecoveryClaimToken.account_id == fixture.account_id
            )
        )
        grant = await db.scalar(
            select(AeternaRecoveryGrant).where(
                AeternaRecoveryGrant.account_id == fixture.account_id
            )
        )
        assert token.status == "active"
        assert grant.state == "available"

    async def release_once():
        try:
            return await release_signed_secret(
                service, signed_secret_request(fixture, claim_data)
            )
        except AeternaProtocolException as exc:
            return exc.code

    outcomes = await asyncio.gather(release_once(), release_once())
    assert sum(isinstance(outcome, dict) for outcome in outcomes) == 1
    assert outcomes.count("recovery.recipient_rotation_in_progress") == 1


def owner_start_document(fixture: RecoveryFixture) -> dict:
    return signed_document(
        fixture,
        domain="aeterna.owner-recovery.start.v1",
        operation="owner_recovery.start",
        members={
            "policy_epoch": 1,
            "recovery_generation": 1,
            "wrapper_digest": encode_base64url(bytes([0x66]) * 32),
        },
    )


def owner_action_document(
    fixture: RecoveryFixture, owner_recovery_id: str, action: str
) -> dict:
    members = {
        "action": action,
        "owner_recovery_id": owner_recovery_id,
    }
    if action in {"release", "complete"}:
        members.update(
            {
                "wrapper_digest": encode_base64url(bytes([0x66]) * 32),
            }
        )
    return signed_document(
        fixture,
        domain="aeterna.owner-recovery.action.v1",
        operation="owner_recovery.action",
        members=members,
        include_recovery_binding=action in {"release", "complete"},
    )


async def begin_verified_owner_recovery(
    service: AeternaRecoveryService,
    fixture: RecoveryFixture,
    now: datetime,
) -> dict:
    session_factory = get_session_local()
    async with session_factory.begin() as db:
        device = await db.get(AeternaDevice, fixture.device_id)
        device.last_seen_at = now
    start_document = owner_start_document(fixture)
    async with session_factory() as db:
        started = await service.start_owner_recovery(
            db,
            OwnerRecoveryStartRequest.model_validate(start_document),
            start_document,
        )
    challenge_id = uuid.UUID(started["challenge_id"])
    verify = OwnerRecoveryVerifyRequest(
        protocol_version=1,
        request_id=str(uuid.uuid4()),
        owner_recovery_id=started["owner_recovery_id"],
        challenge_id=started["challenge_id"],
        code=derive_recovery_otp(synthetic_keys(), challenge_id),
    )
    async with session_factory() as db:
        return await service.verify_owner_recovery(db, verify)


async def test_owner_recovery_enforces_cooldown_redelivery_and_wrapper_completion():
    now = datetime(2030, 4, 2, tzinfo=UTC)
    clock = MutableClock(now)
    provider = recovery_provider()
    service = AeternaRecoveryService(
        provision_provider=lambda: provider,
        claim_provider=lambda: provider,
        identity_key_provider=synthetic_keys,
        clock=clock,
    )
    fixture = await create_fixture(now)
    _provision, expected_srs = await provision_and_confirm(service, fixture)
    verified = await begin_verified_owner_recovery(service, fixture, now)
    assert verified["state"] == "cooling_down"
    release_document = owner_action_document(
        fixture, verified["owner_recovery_id"], "release"
    )
    session_factory = get_session_local()
    async with session_factory() as db:
        with pytest.raises(AeternaProtocolException) as raised:
            await service.act_on_owner_recovery(
                db,
                OwnerRecoveryActionRequest.model_validate(release_document),
                release_document,
            )
    assert raised.value.code == "recovery.owner_not_ready"

    clock.current = now + timedelta(hours=24)
    async with session_factory.begin() as db:
        device = await db.get(AeternaDevice, fixture.device_id)
        device.last_seen_at = clock.current
    async with session_factory() as db:
        released = await service.act_on_owner_recovery(
            db,
            OwnerRecoveryActionRequest.model_validate(release_document),
            release_document,
        )
    assert decode_base64url(released["srs"]) == expected_srs
    assert released["rekey_required"] is False
    retry_document = owner_action_document(
        fixture, verified["owner_recovery_id"], "release"
    )
    async with session_factory() as db:
        retry = await service.act_on_owner_recovery(
            db,
            OwnerRecoveryActionRequest.model_validate(retry_document),
            retry_document,
        )
    assert decode_base64url(retry["srs"]) == expected_srs

    complete_document = owner_action_document(
        fixture, verified["owner_recovery_id"], "complete"
    )
    async with session_factory() as db:
        with pytest.raises(AeternaProtocolException) as raised:
            await service.act_on_owner_recovery(
                db,
                OwnerRecoveryActionRequest.model_validate(complete_document),
                complete_document,
            )
    assert raised.value.code == "recovery.rekey_required"

    target_recovery_id = uuid.uuid4()
    rotation_id = uuid.uuid4()
    rotation_document = signed_document(
        fixture,
        domain="aeterna.recovery-rotation.provision.v1",
        operation="recovery_rotation.provision",
        members={
            "kind": "erc_rotation",
            "recovery_id": str(target_recovery_id),
            "rotation_id": str(rotation_id),
            "source_generation": 1,
            "source_policy_epoch": 1,
            "target_generation": 2,
            "target_policy_epoch": 1,
        },
    )
    async with session_factory() as db:
        await service.provision_rotation(
            db,
            RecoveryRotationProvisionRequest.model_validate(rotation_document),
            rotation_document,
        )
    competing_document = signed_document(
        replace(fixture, recovery_id=uuid.uuid4()),
        domain="aeterna.recovery-rotation.provision.v1",
        operation="recovery_rotation.provision",
        members={
            "kind": "erc_rotation",
            "recovery_id": str(uuid.uuid4()),
            "rotation_id": str(uuid.uuid4()),
            "source_generation": 1,
            "source_policy_epoch": 1,
            "target_generation": 2,
            "target_policy_epoch": 1,
        },
    )
    async with session_factory() as db:
        with pytest.raises(AeternaProtocolException) as raised:
            await service.provision_rotation(
                db,
                RecoveryRotationProvisionRequest.model_validate(competing_document),
                competing_document,
            )
    assert raised.value.code == "recovery.rotation_unavailable"
    confirm_document = signed_document(
        replace(fixture, recovery_id=target_recovery_id),
        domain="aeterna.recovery-rotation.confirm.v1",
        operation="recovery_rotation.confirm",
        members={
            "rotation_id": str(rotation_id),
            "target_generation": 2,
            "target_policy_epoch": 1,
            "wrapper_digest": encode_base64url(bytes([0x83]) * 32),
        },
    )
    async with session_factory() as db:
        await service.confirm_rotation(
            db,
            RecoveryRotationConfirmRequest.model_validate(confirm_document),
            confirm_document,
        )
    complete_document = owner_action_document(
        fixture, verified["owner_recovery_id"], "complete"
    )
    async with session_factory() as db:
        completed = await service.act_on_owner_recovery(
            db,
            OwnerRecoveryActionRequest.model_validate(complete_document),
            complete_document,
        )
    assert completed["state"] == "completed"


async def test_owner_recovery_cancel_and_release_have_one_locked_winner():
    now = datetime(2030, 4, 5, tzinfo=UTC)
    clock = MutableClock(now)
    provider = recovery_provider()
    service = AeternaRecoveryService(
        provision_provider=lambda: provider,
        claim_provider=lambda: provider,
        identity_key_provider=synthetic_keys,
        clock=clock,
    )
    fixture = await create_fixture(now)
    cancelling_device_id = uuid.uuid4()
    cancelling_key = Ed25519PrivateKey.generate()
    session_factory = get_session_local()
    async with session_factory.begin() as db:
        db.add(
            AeternaDevice(
                id=cancelling_device_id,
                account_id=fixture.account_id,
                public_key=cancelling_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                ),
                label="Cancellation Device",
                status="active",
                bound_at=now,
                heartbeat_authorized_at=now,
                last_sequence=0,
            )
        )
    await provision_and_confirm(service, fixture)
    verified = await begin_verified_owner_recovery(service, fixture, now)
    clock.current = now + timedelta(hours=24)
    async with session_factory.begin() as db:
        device = await db.get(AeternaDevice, fixture.device_id)
        device.last_seen_at = clock.current
    release_document = owner_action_document(
        fixture, verified["owner_recovery_id"], "release"
    )
    cancel_document = owner_action_document(
        replace(
            fixture,
            device_id=cancelling_device_id,
            signing_key=cancelling_key,
        ),
        verified["owner_recovery_id"],
        "cancel",
    )

    async def act(document: dict):
        async with session_factory() as db:
            try:
                return await service.act_on_owner_recovery(
                    db,
                    OwnerRecoveryActionRequest.model_validate(document),
                    document,
                )
            except AeternaProtocolException as error:
                return error.code

    outcomes = await asyncio.gather(act(release_document), act(cancel_document))
    async with session_factory() as db:
        request = await db.get(
            AeternaOwnerRecoveryRequest, uuid.UUID(verified["owner_recovery_id"])
        )
        release_audits = await db.scalar(
            select(func.count(AeternaRecoveryAudit.id)).where(
                AeternaRecoveryAudit.account_id == fixture.account_id,
                AeternaRecoveryAudit.event_type == "owner.released",
            )
        )
    if request.state == "cancelled":
        assert "recovery.owner_not_ready" in outcomes
        assert release_audits == 0
    else:
        assert request.state == "material_released"
        assert any(
            isinstance(outcome, dict) and "srs" in outcome for outcome in outcomes
        )
        assert release_audits == 1


async def test_policy_release_during_owner_cooldown_forces_successor_authorization():
    now = datetime(2030, 4, 3, tzinfo=UTC)
    clock = MutableClock(now)
    provider = recovery_provider()
    service = AeternaRecoveryService(
        provision_provider=lambda: provider,
        claim_provider=lambda: provider,
        identity_key_provider=synthetic_keys,
        clock=clock,
    )
    fixture = await create_fixture(now)
    await provision_and_confirm(service, fixture)
    authorization = await begin_verified_owner_recovery(service, fixture, now)
    await release_policy(fixture.account_id, now)
    clock.current = now + timedelta(hours=24)
    release_document = owner_action_document(
        fixture, authorization["owner_recovery_id"], "release"
    )
    session_factory = get_session_local()
    async with session_factory() as db:
        with pytest.raises(AeternaProtocolException) as raised:
            await service.act_on_owner_recovery(
                db,
                OwnerRecoveryActionRequest.model_validate(release_document),
                release_document,
            )
    assert raised.value.code == "recovery.rekey_required"
    async with session_factory() as db:
        request = await db.get(
            AeternaOwnerRecoveryRequest,
            uuid.UUID(authorization["owner_recovery_id"]),
        )
    assert request.state == "cancelled"
    successor = await begin_verified_owner_recovery(service, fixture, clock.current)
    assert successor["state"] == "ready"
    assert successor["rekey_required"] is True


@pytest.mark.parametrize("managed_erc", [False, True])
async def test_post_compromise_confirmation_preserves_released_epoch_and_grants(
    managed_erc,
):
    now = datetime(2030, 5, 2, tzinfo=UTC)
    clock = MutableClock(now)
    provider = recovery_provider()
    service = AeternaRecoveryService(
        provision_provider=lambda: provider,
        claim_provider=lambda: provider,
        identity_key_provider=synthetic_keys,
        clock=clock,
    )
    fixture = await create_fixture(now)
    second_device_id = uuid.uuid4()
    second_key = Ed25519PrivateKey.generate()
    session_factory = get_session_local()
    async with session_factory.begin() as db:
        db.add(
            AeternaDevice(
                id=second_device_id,
                account_id=fixture.account_id,
                public_key=second_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                ),
                label="Travel Mac",
                status="active",
                bound_at=now,
                heartbeat_authorized_at=now,
                last_seen_at=now,
                last_sequence=0,
            )
        )
    await provision_and_confirm(service, fixture)
    source_commitment = bytes([0x44]) * 32
    target_commitment = bytes([0x45]) * 32
    if managed_erc:
        async with session_factory.begin() as db:
            account = await db.get(AeternaAccount, fixture.account_id)
            record = await db.get(AeternaRecoveryRecord, fixture.recovery_id)
            account.erc_commitment = source_commitment
            account.erc_commitment_epoch = 1
            account.erc_commitment_generation = 1
            record.erc_commitment = source_commitment
    await release_policy(fixture.account_id, now)
    async with session_factory() as db:
        assert (
            len(await service.materialize_released_account(db, fixture.account_id)) == 1
        )
    authorization = await begin_verified_owner_recovery(service, fixture, now)
    assert authorization["state"] == "ready"
    assert authorization["rekey_required"] is True

    target_recovery_id = uuid.uuid4()
    rotation_id = uuid.uuid4()
    rotation_document = signed_document(
        fixture,
        domain="aeterna.recovery-rotation.provision.v1",
        operation="recovery_rotation.provision",
        members={
            "kind": "post_compromise",
            "owner_recovery_id": authorization["owner_recovery_id"],
            "recovery_id": str(target_recovery_id),
            "rotation_id": str(rotation_id),
            "source_generation": 1,
            "source_policy_epoch": 1,
            "target_generation": 2,
            "target_policy_epoch": 2,
        },
    )
    async with session_factory() as db:
        provisioned = await service.provision_rotation(
            db,
            RecoveryRotationProvisionRequest.model_validate(rotation_document),
            rotation_document,
        )
    first_srs = decode_base64url(provisioned["srs"])
    confirm_document = signed_document(
        replace(fixture, recovery_id=target_recovery_id),
        domain="aeterna.recovery-rotation.confirm.v1",
        operation="recovery_rotation.confirm",
        members={
            "rotation_id": str(rotation_id),
            "target_generation": 2,
            "target_policy_epoch": 2,
            **(
                {"erc_commitment": encode_base64url(target_commitment)}
                if managed_erc
                else {}
            ),
            "wrapper_digest": encode_base64url(bytes([0x77]) * 32),
        },
    )
    if managed_erc:
        missing_document = signed_document(
            replace(fixture, recovery_id=target_recovery_id),
            domain="aeterna.recovery-rotation.confirm.v1",
            operation="recovery_rotation.confirm",
            members={
                key: value
                for key, value in confirm_document["signed"].items()
                if key
                not in {
                    "erc_commitment",
                    "request_id",
                    "domain",
                    "operation",
                    "account_id",
                    "device_id",
                    "vault_id",
                    "recovery_id",
                    "canonicalization",
                    "signature_version",
                    "protocol_version",
                }
            },
        )
        async with session_factory() as db:
            with pytest.raises(AeternaProtocolException) as rejected:
                await service.confirm_rotation(
                    db,
                    RecoveryRotationConfirmRequest.model_validate(missing_document),
                    missing_document,
                )
        assert rejected.value.code == "recovery.erc_mismatch"
    async with session_factory() as db:
        result = await service.confirm_rotation(
            db,
            RecoveryRotationConfirmRequest.model_validate(confirm_document),
            confirm_document,
        )
    assert result["complete"] is False
    assert {row["state"] for row in result["devices"]} == {"complete", "pending"}
    assert {row["device_label"] for row in result["devices"]} == {
        "Owner Mac",
        "Travel Mac",
    }
    second_recovery_id = uuid.uuid4()
    second_vault_id = uuid.uuid4()
    second_fixture = replace(
        fixture,
        device_id=second_device_id,
        recovery_id=second_recovery_id,
        vault_id=second_vault_id,
        signing_key=second_key,
    )
    second_provision_document = signed_document(
        second_fixture,
        domain="aeterna.recovery-rotation.provision.v1",
        operation="recovery_rotation.provision",
        members={
            "kind": "post_compromise",
            "owner_recovery_id": authorization["owner_recovery_id"],
            "recovery_id": str(second_recovery_id),
            "rotation_id": str(rotation_id),
            "source_generation": 1,
            "source_policy_epoch": 1,
            "target_generation": 2,
            "target_policy_epoch": 2,
        },
    )
    async with session_factory() as db:
        second_provisioned = await service.provision_rotation(
            db,
            RecoveryRotationProvisionRequest.model_validate(second_provision_document),
            second_provision_document,
        )
    assert decode_base64url(second_provisioned["srs"]) != first_srs
    second_confirm_document = signed_document(
        second_fixture,
        domain="aeterna.recovery-rotation.confirm.v1",
        operation="recovery_rotation.confirm",
        members={
            "rotation_id": str(rotation_id),
            "target_generation": 2,
            "target_policy_epoch": 2,
            **(
                {"erc_commitment": encode_base64url(target_commitment)}
                if managed_erc
                else {}
            ),
            "wrapper_digest": encode_base64url(bytes([0x78]) * 32),
        },
    )
    if managed_erc:
        wrong_document = signed_document(
            second_fixture,
            domain="aeterna.recovery-rotation.confirm.v1",
            operation="recovery_rotation.confirm",
            members={
                "rotation_id": str(rotation_id),
                "target_generation": 2,
                "target_policy_epoch": 2,
                "wrapper_digest": encode_base64url(bytes([0x78]) * 32),
                "erc_commitment": encode_base64url(bytes([0x46]) * 32),
            },
        )
        async with session_factory() as db:
            with pytest.raises(AeternaProtocolException) as rejected:
                await service.confirm_rotation(
                    db,
                    RecoveryRotationConfirmRequest.model_validate(wrong_document),
                    wrong_document,
                )
        assert rejected.value.code == "recovery.erc_mismatch"
    async with session_factory() as db:
        result = await service.confirm_rotation(
            db,
            RecoveryRotationConfirmRequest.model_validate(second_confirm_document),
            second_confirm_document,
        )
    assert result["complete"] is True
    clock.current = now + timedelta(days=2)
    async with session_factory() as db:
        replayed = await service.confirm_rotation(
            db,
            RecoveryRotationConfirmRequest.model_validate(confirm_document),
            confirm_document,
        )
    assert replayed["complete"] is True
    if managed_erc:
        conflicting_commitment = signed_document(
            replace(fixture, recovery_id=target_recovery_id),
            domain="aeterna.recovery-rotation.confirm.v1",
            operation="recovery_rotation.confirm",
            members={
                "rotation_id": str(rotation_id),
                "target_generation": 2,
                "target_policy_epoch": 2,
                "erc_commitment": encode_base64url(bytes([0x46]) * 32),
                "wrapper_digest": encode_base64url(bytes([0x77]) * 32),
            },
        )
        async with session_factory() as db:
            with pytest.raises(AeternaProtocolException) as rejected:
                await service.confirm_rotation(
                    db,
                    RecoveryRotationConfirmRequest.model_validate(
                        conflicting_commitment
                    ),
                    conflicting_commitment,
                )
        assert rejected.value.code == "recovery.erc_mismatch"
    wrong_vault = signed_document(
        replace(fixture, recovery_id=target_recovery_id, vault_id=uuid.uuid4()),
        domain="aeterna.recovery-rotation.confirm.v1",
        operation="recovery_rotation.confirm",
        members={
            "rotation_id": str(rotation_id),
            "target_generation": 2,
            "target_policy_epoch": 2,
            **(
                {"erc_commitment": encode_base64url(target_commitment)}
                if managed_erc
                else {}
            ),
            "wrapper_digest": encode_base64url(bytes([0x77]) * 32),
        },
    )
    async with session_factory() as db:
        with pytest.raises(AeternaProtocolException) as rejected:
            await service.confirm_rotation(
                db,
                RecoveryRotationConfirmRequest.model_validate(wrong_vault),
                wrong_vault,
            )
    assert rejected.value.code == "recovery.rotation_unavailable"
    conflicting_confirm = signed_document(
        replace(fixture, recovery_id=target_recovery_id),
        domain="aeterna.recovery-rotation.confirm.v1",
        operation="recovery_rotation.confirm",
        members={
            "rotation_id": str(rotation_id),
            "target_generation": 2,
            "target_policy_epoch": 2,
            **(
                {"erc_commitment": encode_base64url(target_commitment)}
                if managed_erc
                else {}
            ),
            "wrapper_digest": encode_base64url(bytes([0x7A]) * 32),
        },
    )
    async with session_factory() as db:
        with pytest.raises(AeternaProtocolException) as raised:
            await service.confirm_rotation(
                db,
                RecoveryRotationConfirmRequest.model_validate(conflicting_confirm),
                conflicting_confirm,
            )
    assert raised.value.code == "recovery.rotation_unavailable"
    async with session_factory() as db:
        account = await db.get(AeternaAccount, fixture.account_id)
        policies = list(
            (
                await db.scalars(
                    select(AccountPolicy)
                    .where(AccountPolicy.account_id == fixture.account_id)
                    .order_by(AccountPolicy.epoch)
                )
            ).all()
        )
        old_record = await db.get(AeternaRecoveryRecord, fixture.recovery_id)
        grant = await db.scalar(
            select(AeternaRecoveryGrant).where(
                AeternaRecoveryGrant.account_id == fixture.account_id
            )
        )
        owner_request = await db.get(
            AeternaOwnerRecoveryRequest, uuid.UUID(authorization["owner_recovery_id"])
        )
        second_record = await db.get(AeternaRecoveryRecord, second_recovery_id)
    assert account.erc_commitment == (target_commitment if managed_erc else None)
    assert account.erc_commitment_epoch == (2 if managed_erc else None)
    assert account.erc_commitment_generation == (2 if managed_erc else None)
    assert second_record.erc_commitment == (target_commitment if managed_erc else None)
    assert account.current_policy_epoch == 2
    assert account.current_recovery_generation == 2
    assert [(policy.epoch, policy.state) for policy in policies] == [
        (1, "RELEASED"),
        (2, "ACTIVE"),
    ]
    assert policies[0].retired_at == now
    assert policies[1].retired_at is None
    assert old_record.state == "sealed"
    assert grant.state == "available"
    assert owner_request.state == "completed"
    assert second_record.device_id == second_device_id
    assert second_record.vault_id == second_vault_id
    assert second_record.state == "sealed"
    # Later revocation must not turn an exact historical confirmation into a mutation.
    async with session_factory.begin() as db:
        retired = await db.get(AeternaRecoveryRecord, target_recovery_id)
        retired.state = "revoked"
        retired.abandoned_at = clock.current
    async with session_factory() as db:
        replayed = await service.confirm_rotation(
            db,
            RecoveryRotationConfirmRequest.model_validate(confirm_document),
            confirm_document,
        )
    assert replayed["complete"] is True
    async with session_factory() as db:
        retired = await db.get(AeternaRecoveryRecord, target_recovery_id)
        account = await db.get(AeternaAccount, fixture.account_id)
    assert retired.state == "revoked"
    assert account.current_policy_epoch == 2


async def test_pre_release_erc_rotation_revokes_old_generation_on_activation():
    now = datetime(2030, 6, 2, tzinfo=UTC)
    provider = recovery_provider()
    service = AeternaRecoveryService(
        provision_provider=lambda: provider,
        claim_provider=lambda: provider,
        identity_key_provider=synthetic_keys,
        clock=MutableClock(now),
    )
    fixture = await create_fixture(now)
    await provision_and_confirm(service, fixture)
    target_recovery_id = uuid.uuid4()
    rotation_id = uuid.uuid4()
    rotation_document = signed_document(
        fixture,
        domain="aeterna.recovery-rotation.provision.v1",
        operation="recovery_rotation.provision",
        members={
            "kind": "erc_rotation",
            "recovery_id": str(target_recovery_id),
            "rotation_id": str(rotation_id),
            "source_generation": 1,
            "source_policy_epoch": 1,
            "target_generation": 2,
            "target_policy_epoch": 1,
        },
    )
    session_factory = get_session_local()
    async with session_factory() as db:
        await service.provision_rotation(
            db,
            RecoveryRotationProvisionRequest.model_validate(rotation_document),
            rotation_document,
        )
    confirm_document = signed_document(
        replace(fixture, recovery_id=target_recovery_id),
        domain="aeterna.recovery-rotation.confirm.v1",
        operation="recovery_rotation.confirm",
        members={
            "rotation_id": str(rotation_id),
            "target_generation": 2,
            "target_policy_epoch": 1,
            "wrapper_digest": encode_base64url(bytes([0x79]) * 32),
        },
    )
    async with session_factory() as db:
        result = await service.confirm_rotation(
            db,
            RecoveryRotationConfirmRequest.model_validate(confirm_document),
            confirm_document,
        )
    assert result["complete"] is True
    async with session_factory() as db:
        account = await db.get(AeternaAccount, fixture.account_id)
        old_record = await db.get(AeternaRecoveryRecord, fixture.recovery_id)
        new_record = await db.get(AeternaRecoveryRecord, target_recovery_id)
    assert account.current_policy_epoch == 1
    assert account.current_recovery_generation == 2
    assert old_record.state == "revoked"
    assert old_record.abandoned_at == now
    assert new_record.state == "sealed"
