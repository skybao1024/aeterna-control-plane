"""Real PostgreSQL evidence for signed policy setup and durable enrollment status."""

import base64
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from app.configs.docs_apps import create_client_app
from app.db.base import get_session_local
from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.models.account_policy import AccountPolicy, AccountPolicyOutboxEvent
from app.models.aeterna_identity import AeternaAccount, AeternaDevice
from app.models.aeterna_recovery import AeternaRecoveryRecord
from app.schemas.client.aeterna_recovery import (
    RecoveryRecordActionRequest,
    RecoveryRecordEnrollRequest,
    RecoveryRecordProvisionRequest,
)
from app.schemas.client.aeterna_setup import PolicyConfigureRequest, SetupStatusRequest
from app.services.client.aeterna_recovery import (
    AeternaRecoveryService,
    get_aeterna_recovery_service,
)
from app.services.client.aeterna_setup import AeternaSetupService
from app.services.common.aeterna_recovery_key import (
    InMemoryRecoveryKeyProvider,
    RecoveryKeyUnavailable,
)

pytestmark = pytest.mark.asyncio(loop_scope="session")


class UnavailableRecoveryProvider:
    def generate_srs(self, _context):
        raise RecoveryKeyUnavailable("synthetic provider failure")


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


@pytest_asyncio.fixture(loop_scope="session")
async def bound_account():
    account_id, device_id, second_device_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    first_key, second_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    now = datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)
    factory = get_session_local()
    async with factory.begin() as db:
        db.add(
            AeternaAccount(
                id=account_id,
                email_lookup=uuid.uuid4().bytes + uuid.uuid4().bytes,
                email_ciphertext=b"synthetic-email-ciphertext",
                email_nonce=b"\x51" * 12,
                email_key_version=1,
                first_device_bound_at=now,
                is_active=True,
            )
        )
        for identifier, key, label in (
            (device_id, first_key, "Owner Mac"),
            (second_device_id, second_key, "Travel Mac"),
        ):
            db.add(
                AeternaDevice(
                    id=identifier,
                    account_id=account_id,
                    public_key=key.public_key().public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    ),
                    label=label,
                    status="active",
                    bound_at=now,
                    heartbeat_authorized_at=now,
                    last_sequence=0,
                )
            )
    yield account_id, device_id, second_device_id, first_key, second_key, now
    async with factory.begin() as db:
        await db.execute(delete(AeternaAccount).where(AeternaAccount.id == account_id))


def envelope(signed: dict, key: Ed25519PrivateKey) -> dict:
    return {
        "protocol_version": 1,
        "signed": signed,
        "signature": encode(key.sign(rfc8785.dumps(signed))),
    }


def policy_request(account_id, device_id, key, **overrides):
    signed = {
        "account_id": str(account_id),
        "canonicalization": "jcs-rfc8785",
        "device_id": str(device_id),
        "domain": "aeterna.policy.configure.v1",
        "grace_days": 7,
        "inactivity_days": 30,
        "operation": "policy.configure",
        "protocol_version": 1,
        "request_id": str(uuid.uuid4()),
        "signature_version": 1,
        "warning_days": 7,
    }
    signed.update(overrides)
    return envelope(signed, key)


def status_request(account_id, device_id, key, vault_id=None):
    signed = {
        "account_id": str(account_id),
        "canonicalization": "jcs-rfc8785",
        "device_id": str(device_id),
        "domain": "aeterna.setup.status.v1",
        "operation": "setup.status",
        "protocol_version": 1,
        "request_id": str(uuid.uuid4()),
        "signature_version": 1,
    }
    if vault_id is not None:
        signed["vault_id"] = str(vault_id)
    return envelope(signed, key)


def enroll_request(account_id, device_id, key, vault_id, commitment):
    return envelope(
        {
            "account_id": str(account_id),
            "canonicalization": "jcs-rfc8785",
            "crypto_format_version": 1,
            "device_id": str(device_id),
            "domain": "aeterna.recovery-record.enroll.v1",
            "erc_commitment": encode(commitment),
            "operation": "recovery_record.enroll",
            "protocol_version": 1,
            "recovery_context_version": 1,
            "recovery_id": str(uuid.uuid4()),
            "request_id": str(uuid.uuid4()),
            "signature_version": 1,
            "vault_id": str(vault_id),
        },
        key,
    )


async def call(service, method, document):
    model = (
        PolicyConfigureRequest if method == "configure_policy" else SetupStatusRequest
    )
    payload = model.model_validate(document)
    factory = get_session_local()
    async with factory() as db:
        return await getattr(service, method)(db, payload, document)


async def test_setup_policy_replay_signature_and_durable_multi_device_status(
    bound_account,
):
    account_id, device_id, second_device_id, key, _second_key, now = bound_account
    service = AeternaSetupService(clock=lambda: now)
    before = await call(service, "status", status_request(account_id, device_id, key))
    assert "policy" not in before
    assert {device["state"] for device in before["devices"]} == {"not_enrolled"}

    request = policy_request(account_id, device_id, key)
    result = await call(service, "configure_policy", request)
    assert result["policy"]["due_at"] == "2030-02-01T03:04:05Z"
    assert result["policy"]["version"] == 0
    assert await call(service, "configure_policy", request) == result

    conflict = {**request, "signed": {**request["signed"], "warning_days": 8}}
    conflict = envelope(conflict["signed"], key)
    with pytest.raises(AeternaProtocolException) as error:
        await call(service, "configure_policy", conflict)
    assert error.value.code == "request.idempotency_conflict"

    wrong_key = policy_request(account_id, device_id, Ed25519PrivateKey.generate())
    with pytest.raises(AeternaProtocolException) as error:
        await call(service, "configure_policy", wrong_key)
    assert error.value.code == "device.proof_invalid"

    with pytest.raises(ValueError):
        PolicyConfigureRequest.model_validate(
            policy_request(account_id, device_id, key, inactivity_days=13)
        )

    factory = get_session_local()
    async with factory() as db:
        policy = await db.scalar(
            select(AccountPolicy).where(AccountPolicy.account_id == account_id)
        )
        events = list(
            (
                await db.scalars(
                    select(AccountPolicyOutboxEvent).where(
                        AccountPolicyOutboxEvent.account_policy_id == policy.id
                    )
                )
            ).all()
        )
        assert len(events) == 1
        assert events[0].event_type == "account-policy-configured"
    vault_id, recovery_id = uuid.uuid4(), uuid.uuid4()
    request_id = uuid.uuid4()
    async with factory.begin() as db:
        db.add(
            AeternaRecoveryRecord(
                id=recovery_id,
                account_id=account_id,
                device_id=device_id,
                vault_id=vault_id,
                policy_epoch=1,
                recovery_generation=1,
                state="sealed",
                encrypted_srs=b"synthetic-ciphertext",
                kms_provider="local-test",
                kms_key_arn="local-test",
                kms_key_material_id="synthetic",
                kms_context_version=1,
                crypto_format_version=1,
                recovery_context_version=1,
                wrapper_digest=b"\x33" * 32,
                provision_request_id=request_id,
                provision_request_digest=b"\x44" * 32,
                expires_at=now + timedelta(days=1),
                confirmed_at=now,
            )
        )
    restarted_service = AeternaSetupService(clock=lambda: now + timedelta(minutes=1))
    after = await call(
        restarted_service,
        "status",
        status_request(account_id, device_id, key, vault_id),
    )
    assert after["local_record"]["recovery_id"] == str(recovery_id)
    assert after["local_record"]["wrapper_digest"] == encode(b"\x33" * 32)
    assert not after["erc_committed"]
    assert {device["state"] for device in after["devices"]} == {"not_enrolled"}
    assert any(
        device["device_id"] == str(second_device_id)
        and device["state"] == "not_enrolled"
        for device in after["devices"]
    )

    changed = await call(
        AeternaSetupService(clock=lambda: now + timedelta(days=1)),
        "configure_policy",
        policy_request(account_id, device_id, key, inactivity_days=60),
    )
    assert changed["policy"]["version"] == 1
    assert changed["policy"]["due_at"] == "2030-03-04T03:04:05Z"
    async with factory.begin() as db:
        policy = await db.scalar(
            select(AccountPolicy).where(AccountPolicy.account_id == account_id)
        )
        policy.state = "PRE_WARNING"
    with pytest.raises(AeternaProtocolException) as error:
        await call(
            service,
            "configure_policy",
            policy_request(account_id, device_id, key),
        )
    assert error.value.code == "policy.unavailable"


async def test_new_policy_allows_synthetic_srs_provision_and_exact_confirm(
    bound_account,
):
    account_id, device_id, _second_device_id, key, _second_key, now = bound_account
    vault_id, recovery_id = uuid.uuid4(), uuid.uuid4()
    provision_document = envelope(
        {
            "account_id": str(account_id),
            "canonicalization": "jcs-rfc8785",
            "crypto_format_version": 1,
            "device_id": str(device_id),
            "domain": "aeterna.recovery-record.provision.v1",
            "operation": "recovery_record.provision",
            "protocol_version": 1,
            "recovery_context_version": 1,
            "recovery_id": str(recovery_id),
            "request_id": str(uuid.uuid4()),
            "signature_version": 1,
            "vault_id": str(vault_id),
        },
        key,
    )
    provider = InMemoryRecoveryKeyProvider(
        b"\x44" * 32, lambda length: b"\x55" * length
    )
    recovery = AeternaRecoveryService(
        provision_provider=lambda: provider,
        claim_provider=lambda: provider,
        clock=lambda: now,
    )
    factory = get_session_local()
    payload = RecoveryRecordProvisionRequest.model_validate(provision_document)
    async with factory() as db:
        with pytest.raises(AeternaProtocolException) as error:
            await recovery.provision_record(db, payload, provision_document)
        assert error.value.code == "device.proof_invalid"
        await db.rollback()

    await call(
        AeternaSetupService(clock=lambda: now),
        "configure_policy",
        policy_request(account_id, device_id, key),
    )
    unavailable = AeternaRecoveryService(
        provision_provider=lambda: UnavailableRecoveryProvider(),
        claim_provider=lambda: provider,
        clock=lambda: now,
    )
    async with factory() as db:
        with pytest.raises(AeternaProtocolException) as error:
            await unavailable.provision_record(db, payload, provision_document)
        assert error.value.code == "recovery.material_unavailable"
        await db.rollback()
    async with factory() as db:
        provisioned = await recovery.provision_record(db, payload, provision_document)
    assert provisioned["state"] == "pending_confirmation"
    assert len(base64.urlsafe_b64decode(provisioned["srs"] + "=")) == 32

    pending = await call(
        AeternaSetupService(clock=lambda: now),
        "status",
        status_request(account_id, device_id, key, vault_id),
    )
    assert pending["local_record"]["state"] == "pending_confirmation"
    digest = encode(b"\x66" * 32)
    confirmed_document = envelope(
        {
            "account_id": str(account_id),
            "canonicalization": "jcs-rfc8785",
            "device_id": str(device_id),
            "domain": "aeterna.recovery-record.confirm.v1",
            "operation": "recovery_record.confirm",
            "protocol_version": 1,
            "recovery_id": str(recovery_id),
            "request_id": str(uuid.uuid4()),
            "signature_version": 1,
            "vault_id": str(vault_id),
            "wrapper_digest": digest,
        },
        key,
    )
    confirm_payload = RecoveryRecordActionRequest.model_validate(confirmed_document)
    async with factory() as db:
        result = await recovery.act_on_record(db, confirm_payload, confirmed_document)
    assert result["state"] == "sealed"
    after = await call(
        AeternaSetupService(clock=lambda: now + timedelta(seconds=1)),
        "status",
        status_request(account_id, device_id, key, vault_id),
    )
    assert after["local_record"]["wrapper_digest"] == digest
    assert not after["erc_committed"]
    assert {device["state"] for device in after["devices"]} == {"not_enrolled"}


async def test_shared_erc_commitment_rejects_mismatch_and_tracks_both_devices(
    bound_account,
):
    account_id, device_id, second_device_id, key, second_key, now = bound_account
    await call(
        AeternaSetupService(clock=lambda: now),
        "configure_policy",
        policy_request(account_id, device_id, key),
    )
    provider = InMemoryRecoveryKeyProvider(
        b"\x44" * 32, lambda length: b"\x55" * length
    )
    recovery = AeternaRecoveryService(
        provision_provider=lambda: provider,
        claim_provider=lambda: provider,
        clock=lambda: now,
    )
    factory = get_session_local()
    first_vault, second_vault = uuid.uuid4(), uuid.uuid4()
    first = enroll_request(account_id, device_id, key, first_vault, b"\x11" * 32)
    first_payload = RecoveryRecordEnrollRequest.model_validate(first)
    unavailable = AeternaRecoveryService(
        provision_provider=lambda: UnavailableRecoveryProvider(),
        claim_provider=lambda: provider,
        clock=lambda: now,
    )
    async with factory() as db:
        with pytest.raises(AeternaProtocolException) as error:
            await unavailable.provision_record(db, first_payload, first)
        assert error.value.code == "recovery.material_unavailable"
        await db.rollback()
    before = await call(
        AeternaSetupService(clock=lambda: now),
        "status",
        status_request(account_id, device_id, key, first_vault),
    )
    assert not before["erc_committed"]

    async with factory() as db:
        enrolled = await recovery.provision_record(db, first_payload, first)
    assert enrolled["state"] == "pending_confirmation"
    pending = await call(
        AeternaSetupService(clock=lambda: now),
        "status",
        status_request(account_id, device_id, key, first_vault),
    )
    assert pending["erc_committed"]
    assert {item["state"] for item in pending["devices"]} == {"pending", "not_enrolled"}

    abandoned = envelope(
        {
            "account_id": str(account_id),
            "canonicalization": "jcs-rfc8785",
            "device_id": str(device_id),
            "domain": "aeterna.recovery-record.abandon.v1",
            "operation": "recovery_record.abandon",
            "protocol_version": 1,
            "recovery_id": first["signed"]["recovery_id"],
            "request_id": str(uuid.uuid4()),
            "signature_version": 1,
            "vault_id": str(first_vault),
        },
        key,
    )
    async with factory() as db:
        await recovery.act_on_record(
            db, RecoveryRecordActionRequest.model_validate(abandoned), abandoned
        )
    reset = await call(
        AeternaSetupService(clock=lambda: now),
        "status",
        status_request(account_id, device_id, key, first_vault),
    )
    assert not reset["erc_committed"]
    first = enroll_request(account_id, device_id, key, first_vault, b"\x11" * 32)
    async with factory() as db:
        await recovery.provision_record(
            db, RecoveryRecordEnrollRequest.model_validate(first), first
        )

    mismatch = enroll_request(
        account_id, second_device_id, second_key, second_vault, b"\x22" * 32
    )
    async with factory() as db:
        with pytest.raises(AeternaProtocolException) as error:
            await recovery.provision_record(
                db, RecoveryRecordEnrollRequest.model_validate(mismatch), mismatch
            )
        assert error.value.code == "recovery.erc_mismatch"
        await db.rollback()

    matching = enroll_request(
        account_id, second_device_id, second_key, second_vault, b"\x11" * 32
    )
    async with factory() as db:
        await recovery.provision_record(
            db, RecoveryRecordEnrollRequest.model_validate(matching), matching
        )
    for enrolled_document, signing_key in ((first, key), (matching, second_key)):
        signed = enrolled_document["signed"]
        confirmation = envelope(
            {
                "account_id": str(account_id),
                "canonicalization": "jcs-rfc8785",
                "device_id": signed["device_id"],
                "domain": "aeterna.recovery-record.confirm.v1",
                "operation": "recovery_record.confirm",
                "protocol_version": 1,
                "recovery_id": signed["recovery_id"],
                "request_id": str(uuid.uuid4()),
                "signature_version": 1,
                "vault_id": signed["vault_id"],
                "wrapper_digest": encode(b"\x66" * 32),
            },
            signing_key,
        )
        async with factory() as db:
            await recovery.act_on_record(
                db,
                RecoveryRecordActionRequest.model_validate(confirmation),
                confirmation,
            )
    after = await call(
        AeternaSetupService(clock=lambda: now + timedelta(minutes=1)),
        "status",
        status_request(account_id, device_id, key, first_vault),
    )
    assert after["erc_committed"]
    assert {item["state"] for item in after["devices"]} == {"complete"}
    async with factory() as db:
        account = await db.get(AeternaAccount, account_id)
        assert account.erc_commitment == b"\x11" * 32
        assert account.erc_commitment_epoch == 1
        assert account.erc_commitment_generation == 1
        records = list(
            (
                await db.scalars(
                    select(AeternaRecoveryRecord).where(
                        AeternaRecoveryRecord.account_id == account_id
                    )
                )
            ).all()
        )
        assert {record.erc_commitment for record in records} == {b"\x11" * 32}


async def test_setup_http_routes_return_closed_non_cached_responses(bound_account):
    account_id, device_id, second_device_id, key, second_key, _now = bound_account
    app = create_client_app()
    provider = InMemoryRecoveryKeyProvider(b"\x44" * 32)
    app.dependency_overrides[get_aeterna_recovery_service] = (
        lambda: AeternaRecoveryService(
            provision_provider=lambda: provider,
            claim_provider=lambda: provider,
        )
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test.local"
    ) as client:
        status = await client.post(
            "/api/v1/setup/status",
            json=status_request(account_id, device_id, key),
        )
        assert status.status_code == 200
        assert status.headers["cache-control"] == "no-store"
        assert "policy" not in status.json()["data"]

        configured = await client.put(
            "/api/v1/policy", json=policy_request(account_id, device_id, key)
        )
        assert configured.status_code == 200
        assert configured.headers["cache-control"] == "no-store"
        assert configured.json()["data"]["policy"]["state"] == "ACTIVE"

        refreshed = await client.post(
            "/api/v1/setup/status",
            json=status_request(account_id, device_id, key),
        )
        assert refreshed.status_code == 200
        assert refreshed.json()["data"]["policy"]["inactivity_days"] == 30

        first_vault, second_vault = uuid.uuid4(), uuid.uuid4()
        first_enrollment = enroll_request(
            account_id, device_id, key, first_vault, b"\x11" * 32
        )
        first_response = await client.post(
            "/api/v1/recovery/records/enroll", json=first_enrollment
        )
        assert first_response.status_code == 200
        assert first_response.headers["cache-control"] == "no-store"

        mismatch = await client.post(
            "/api/v1/recovery/records/enroll",
            json=enroll_request(
                account_id, second_device_id, second_key, second_vault, b"\x22" * 32
            ),
        )
        assert mismatch.status_code == 409
        assert mismatch.json()["error"]["code"] == "recovery.erc_mismatch"

        second_enrollment = enroll_request(
            account_id, second_device_id, second_key, second_vault, b"\x11" * 32
        )
        second_response = await client.post(
            "/api/v1/recovery/records/enroll", json=second_enrollment
        )
        assert second_response.status_code == 200
        for enrollment, signing_key in (
            (first_enrollment, key),
            (second_enrollment, second_key),
        ):
            signed = enrollment["signed"]
            confirmation = envelope(
                {
                    "account_id": signed["account_id"],
                    "canonicalization": "jcs-rfc8785",
                    "device_id": signed["device_id"],
                    "domain": "aeterna.recovery-record.confirm.v1",
                    "operation": "recovery_record.confirm",
                    "protocol_version": 1,
                    "recovery_id": signed["recovery_id"],
                    "request_id": str(uuid.uuid4()),
                    "signature_version": 1,
                    "vault_id": signed["vault_id"],
                    "wrapper_digest": encode(b"\x66" * 32),
                },
                signing_key,
            )
            confirmed = await client.post(
                f"/api/v1/recovery/records/{signed['recovery_id']}/confirm",
                json=confirmation,
            )
            assert confirmed.status_code == 200
        complete = await client.post(
            "/api/v1/setup/status",
            json=status_request(account_id, device_id, key, first_vault),
        )
        assert complete.status_code == 200
        assert complete.json()["data"]["erc_committed"]
        assert {item["state"] for item in complete.json()["data"]["devices"]} == {
            "complete"
        }

        rejected = await client.put(
            "/api/v1/policy",
            json=policy_request(account_id, device_id, Ed25519PrivateKey.generate()),
        )
        assert rejected.status_code == 401
        assert rejected.json()["error"]["code"] == "device.proof_invalid"
