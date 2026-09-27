"""Real-PostgreSQL I10 heartbeat, replay, and aggregation evidence."""

import asyncio
import base64
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import delete

from app.db.base import get_session_local
from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.models.aeterna_identity import (
    AeternaAccount,
    AeternaAccountChallenge,
    AeternaBindingGrant,
    AeternaDevice,
    AeternaDeviceBinding,
    AeternaProtocolIdempotency,
    AeternaSecurityAudit,
)
from app.schemas.client.aeterna_protocol import (
    DeviceStatusChangeRequest,
    HeartbeatRequest,
)
from app.services.client.aeterna_heartbeat import AeternaHeartbeatService

pytestmark = pytest.mark.asyncio(loop_scope="session")


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def signing_key(seed_byte: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)


def raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def signed_envelope(signed: dict, private_key: Ed25519PrivateKey) -> dict:
    return {
        "protocol_version": 1,
        "signed": signed,
        "signature": encode(private_key.sign(rfc8785.dumps(signed))),
    }


def heartbeat_document(
    account_id: uuid.UUID,
    device_id: uuid.UUID,
    private_key: Ed25519PrivateKey,
    sequence: int,
    request_id: uuid.UUID | None = None,
) -> tuple[HeartbeatRequest, dict]:
    signed = {
        "account_id": str(account_id),
        "canonicalization": "jcs-rfc8785",
        "device_id": str(device_id),
        "domain": "aeterna.heartbeat.submit.v1",
        "operation": "heartbeat.submit",
        "protocol_version": 1,
        "request_id": str(request_id or uuid.uuid4()),
        "sequence": sequence,
        "signature_version": 1,
    }
    document = signed_envelope(signed, private_key)
    return HeartbeatRequest.model_validate(document), document


def status_document(
    account_id: uuid.UUID,
    authorizing_id: uuid.UUID,
    target_id: uuid.UUID,
    private_key: Ed25519PrivateKey,
    action: str,
    request_id: uuid.UUID | None = None,
) -> tuple[DeviceStatusChangeRequest, dict]:
    signed = {
        "account_id": str(account_id),
        "action": action,
        "authorizing_device_id": str(authorizing_id),
        "canonicalization": "jcs-rfc8785",
        "domain": "aeterna.device-status.change.v1",
        "operation": "device_status.change",
        "protocol_version": 1,
        "request_id": str(request_id or uuid.uuid4()),
        "signature_version": 1,
        "target_device_id": str(target_id),
    }
    document = signed_envelope(signed, private_key)
    return DeviceStatusChangeRequest.model_validate(document), document


@dataclass
class MutableClock:
    current: datetime

    def now(self) -> datetime:
        return self.current

    def advance(self, delta: timedelta) -> None:
        self.current += delta


async def clear_identity_tables() -> None:
    session_factory = get_session_local()
    async with session_factory.begin() as db:
        for model in [
            AeternaBindingGrant,
            AeternaAccountChallenge,
            AeternaProtocolIdempotency,
            AeternaSecurityAudit,
            AeternaDeviceBinding,
            AeternaDevice,
            AeternaAccount,
        ]:
            await db.execute(delete(model))


@pytest_asyncio.fixture(autouse=True, loop_scope="session")
async def clean_identity_tables():
    await clear_identity_tables()
    yield
    await clear_identity_tables()


async def seed_account(device_count: int = 2):
    now = datetime(2030, 1, 1, tzinfo=UTC)
    account_id = uuid.uuid4()
    keys = [signing_key(index + 1) for index in range(device_count)]
    device_ids = [uuid.uuid4() for _ in range(device_count)]
    session_factory = get_session_local()
    async with session_factory.begin() as db:
        db.add(
            AeternaAccount(
                id=account_id,
                email_lookup=bytes([0x31]) * 32,
                email_ciphertext=b"synthetic-ciphertext",
                email_nonce=bytes([0x32]) * 12,
                email_key_version=1,
                first_device_bound_at=now,
                is_active=True,
            )
        )
        for device_id, key in zip(device_ids, keys, strict=True):
            db.add(
                AeternaDevice(
                    id=device_id,
                    account_id=account_id,
                    public_key=raw_public_key(key),
                    label="Synthetic device",
                    status="active",
                    bound_at=now,
                    heartbeat_authorized_at=now,
                    last_sequence=0,
                )
            )
    return now, account_id, device_ids, keys


async def test_exact_retry_sequence_cooldown_and_server_receipt_time():
    now, account_id, device_ids, keys = await seed_account(1)
    clock = MutableClock(now)
    service = AeternaHeartbeatService(clock=clock.now)
    payload, document = heartbeat_document(
        account_id, device_ids[0], keys[0], sequence=1
    )
    session_factory = get_session_local()
    async with session_factory() as db:
        first = await service.submit_heartbeat(db, payload, document)
    assert first["accepted_at"] == "2030-01-01T00:00:00Z"

    clock.advance(timedelta(minutes=5))
    async with session_factory() as db:
        replay = await service.submit_heartbeat(db, payload, document)
    assert replay == first

    duplicate, duplicate_document = heartbeat_document(
        account_id, device_ids[0], keys[0], sequence=1
    )
    async with session_factory() as db:
        with pytest.raises(AeternaProtocolException) as raised:
            await service.submit_heartbeat(db, duplicate, duplicate_document)
    assert raised.value.code == "heartbeat.sequence_not_increasing"

    early, early_document = heartbeat_document(
        account_id, device_ids[0], keys[0], sequence=2
    )
    async with session_factory() as db:
        with pytest.raises(AeternaProtocolException) as raised:
            await service.submit_heartbeat(db, early, early_document)
    assert raised.value.code == "heartbeat.cooldown"
    assert raised.value.retry_after_seconds == 1500

    clock.advance(timedelta(minutes=25))
    async with session_factory() as db:
        second = await service.submit_heartbeat(db, early, early_document)
        account = await db.get(AeternaAccount, account_id)
        device = await db.get(AeternaDevice, device_ids[0])
    assert second["accepted_at"] == "2030-01-01T00:30:00Z"
    assert account.last_activity_at == clock.current
    assert device.last_sequence == 2
    assert device.last_seen_at == clock.current


async def test_modified_wrong_key_and_request_id_conflict_fail_closed():
    now, account_id, device_ids, keys = await seed_account(1)
    service = AeternaHeartbeatService(clock=lambda: now)
    request_id = uuid.uuid4()
    payload, document = heartbeat_document(
        account_id, device_ids[0], keys[0], 1, request_id
    )
    session_factory = get_session_local()
    async with session_factory() as db:
        await service.submit_heartbeat(db, payload, document)

    changed_payload, changed_document = heartbeat_document(
        account_id, device_ids[0], keys[0], 2, request_id
    )
    async with session_factory() as db:
        with pytest.raises(AeternaProtocolException) as raised:
            await service.submit_heartbeat(db, changed_payload, changed_document)
    assert raised.value.code == "request.idempotency_conflict"

    wrong_payload, wrong_document = heartbeat_document(
        account_id, device_ids[0], signing_key(0x77), 2
    )
    async with session_factory() as db:
        with pytest.raises(AeternaProtocolException) as raised:
            await service.submit_heartbeat(db, wrong_payload, wrong_document)
    assert raised.value.code == "device.proof_invalid"

    modified_document = {**document, "signed": {**document["signed"], "sequence": 9}}
    modified_payload = HeartbeatRequest.model_validate(modified_document)
    async with session_factory() as db:
        with pytest.raises(AeternaProtocolException) as raised:
            await service.submit_heartbeat(db, modified_payload, modified_document)
    assert raised.value.code == "device.proof_invalid"


async def test_concurrent_devices_aggregate_max_and_same_request_mutates_once():
    now, account_id, device_ids, keys = await seed_account(2)
    first_clock = MutableClock(now + timedelta(seconds=1))
    second_clock = MutableClock(now + timedelta(seconds=2))
    first_service = AeternaHeartbeatService(clock=first_clock.now)
    second_service = AeternaHeartbeatService(clock=second_clock.now)
    first_payload, first_document = heartbeat_document(
        account_id, device_ids[0], keys[0], 1
    )
    second_payload, second_document = heartbeat_document(
        account_id, device_ids[1], keys[1], 1
    )
    session_factory = get_session_local()

    async def submit(service, payload, document):
        async with session_factory() as db:
            return await service.submit_heartbeat(db, payload, document)

    await asyncio.gather(
        submit(first_service, first_payload, first_document),
        submit(second_service, second_payload, second_document),
    )
    async with session_factory() as db:
        account = await db.get(AeternaAccount, account_id)
    assert account.last_activity_at == second_clock.current

    second_clock.advance(timedelta(minutes=30))
    duplicate_payload, duplicate_document = heartbeat_document(
        account_id, device_ids[1], keys[1], 2
    )
    results = await asyncio.gather(
        submit(second_service, duplicate_payload, duplicate_document),
        submit(second_service, duplicate_payload, duplicate_document),
    )
    assert results[0] == results[1]
    async with session_factory() as db:
        device = await db.get(AeternaDevice, device_ids[1])
    assert device.last_sequence == 2
    assert device.last_seen_at == second_clock.current


async def test_lost_revoked_and_dormant_devices_cannot_extend_activity():
    now, account_id, device_ids, keys = await seed_account(2)
    clock = MutableClock(now)
    service = AeternaHeartbeatService(clock=clock.now)
    session_factory = get_session_local()
    for index in range(2):
        payload, document = heartbeat_document(
            account_id, device_ids[index], keys[index], 1
        )
        async with session_factory() as db:
            await service.submit_heartbeat(db, payload, document)

    clock.advance(timedelta(minutes=30))
    lost_payload, lost_document = status_document(
        account_id, device_ids[0], device_ids[1], keys[0], "mark_lost"
    )
    async with session_factory() as db:
        lost = await service.change_device_status(db, lost_payload, lost_document)
    assert lost["status"] == "lost"
    async with session_factory() as db:
        assert (
            await service.change_device_status(db, lost_payload, lost_document) == lost
        )

    lost_heartbeat, lost_heartbeat_document = heartbeat_document(
        account_id, device_ids[1], keys[1], 2
    )
    async with session_factory() as db:
        with pytest.raises(AeternaProtocolException) as raised:
            await service.submit_heartbeat(db, lost_heartbeat, lost_heartbeat_document)
    assert raised.value.code == "device.not_active"

    revoke_payload, revoke_document = status_document(
        account_id, device_ids[0], device_ids[0], keys[0], "revoke"
    )
    async with session_factory() as db:
        revoked = await service.change_device_status(
            db, revoke_payload, revoke_document
        )
    assert revoked["status"] == "revoked"
    async with session_factory() as db:
        assert (
            await service.change_device_status(db, revoke_payload, revoke_document)
            == revoked
        )
        account = await db.get(AeternaAccount, account_id)
    assert account.last_activity_at is None

    await clear_identity_tables()
    now, account_id, device_ids, keys = await seed_account(1)
    clock = MutableClock(now + timedelta(days=90))
    service = AeternaHeartbeatService(clock=clock.now)
    dormant_payload, dormant_document = heartbeat_document(
        account_id, device_ids[0], keys[0], 1
    )
    async with session_factory() as db:
        with pytest.raises(AeternaProtocolException) as raised:
            await service.submit_heartbeat(db, dormant_payload, dormant_document)
    assert raised.value.code == "device.reverification_required"
    async with session_factory() as db:
        device = await db.get(AeternaDevice, device_ids[0])
        account = await db.get(AeternaAccount, account_id)
    assert device.status == "dormant"
    assert device.last_sequence == 0
    assert account.last_activity_at is None
