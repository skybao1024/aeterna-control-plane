"""Real-PostgreSQL evidence for I09 account and device binding."""

import base64
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
import rfc8785
from botocore.exceptions import PartialCredentialsError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Request
from sqlalchemy import delete, func, select

from app.api.client.v1.aeterna_identity import initiate_account_challenge
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
    AccountChallengeRequest,
    AccountChallengeVerificationRequest,
    DeviceBindingApprovalRequest,
    DeviceBindingCancellationRequest,
    DeviceBindingDelayedConfirmationRequest,
    DeviceBindingRequest,
    DeviceBindingStatusRequest,
)
from app.services.client.aeterna_identity import AeternaIdentityService
from app.services.common.aeterna_notifier import get_aeterna_account_notifier
from app.services.common.aeterna_security import AeternaIdentityKeys

pytestmark = pytest.mark.asyncio(loop_scope="session")
SYNTHETIC_EMAIL = "owner-i09@example.com"
SYNTHETIC_OTP = "12345678"


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def new_request_id() -> str:
    return str(uuid.uuid4())


@dataclass
class MutableClock:
    current: datetime

    def now(self) -> datetime:
        return self.current

    def advance(self, delta: timedelta) -> None:
        self.current += delta


class CommitObservingNotifier:
    """Record synthetic delivery and prove it occurs after the DB commit."""

    def __init__(self):
        self.codes: list[str] = []
        self.challenge_was_committed: list[bool] = []
        self.security_events: list[str] = []

    async def send_challenge(
        self, email: str, code: str, expires_in_minutes: int
    ) -> bool:
        assert email.endswith("@example.com")
        assert expires_in_minutes == 10
        session_factory = get_session_local()
        async with session_factory() as db:
            count = await db.scalar(select(func.count(AeternaAccountChallenge.id)))
        self.challenge_was_committed.append(bool(count))
        self.codes.append(code)
        return True

    async def send_security_notice(self, email: str, event: str) -> bool:
        assert email == SYNTHETIC_EMAIL
        self.security_events.append(event)
        return True


def signing_key(seed_byte: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)


def public_key(private_key: Ed25519PrivateKey) -> str:
    return encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def signed_envelope(signed: dict, private_key: Ed25519PrivateKey) -> dict:
    return {
        "protocol_version": 1,
        "signed": signed,
        "signature": encode(private_key.sign(rfc8785.dumps(signed))),
    }


async def clear_identity_tables() -> None:
    session_factory = get_session_local()
    async with session_factory.begin() as db:
        for model in [
            AeternaBindingGrant,
            AeternaAccountChallenge,
            AeternaProtocolIdempotency,
            AeternaSecurityAudit,
            AeternaDevice,
            AeternaDeviceBinding,
            AeternaAccount,
        ]:
            await db.execute(delete(model))


@pytest_asyncio.fixture(autouse=True, loop_scope="session")
async def clean_identity_tables():
    await clear_identity_tables()
    yield
    await clear_identity_tables()


@pytest_asyncio.fixture(loop_scope="session")
async def identity_context():
    clock = MutableClock(datetime(2026, 9, 27, 0, tzinfo=UTC))
    keys = AeternaIdentityKeys(
        pii_key=bytes([0x41]) * 32,
        lookup_key=bytes([0x42]) * 32,
        otp_key=bytes([0x43]) * 32,
    )
    service = AeternaIdentityService(
        key_provider=lambda: keys,
        clock=clock.now,
        otp_factory=lambda: SYNTHETIC_OTP,
    )
    notifier = CommitObservingNotifier()
    return service, clock, notifier


async def issue_grant(
    db,
    service: AeternaIdentityService,
    notifier: CommitObservingNotifier,
    purpose: str,
    client_address: str,
    binding_id: str | None = None,
) -> dict:
    challenge_document = {
        "protocol_version": 1,
        "request_id": new_request_id(),
        "email": SYNTHETIC_EMAIL,
        "purpose": purpose,
        **({"binding_id": binding_id} if binding_id else {}),
    }
    challenge = AccountChallengeRequest.model_validate(challenge_document)
    challenge_data = await service.initiate_challenge(
        db, challenge, challenge_document, client_address, notifier
    )
    verification_document = {
        "protocol_version": 1,
        "request_id": new_request_id(),
        "challenge_id": challenge_data["challenge_id"],
        "code": notifier.codes[-1],
    }
    verification = AccountChallengeVerificationRequest.model_validate(
        verification_document
    )
    return await service.verify_challenge(db, verification)


async def request_binding(
    db,
    service: AeternaIdentityService,
    grant: dict,
    private_key: Ed25519PrivateKey,
    device_id: str,
    label: str,
) -> tuple[dict, dict]:
    signed = {
        "binding_grant_id": grant["binding_grant_id"],
        "canonicalization": "jcs-rfc8785",
        "device_id": device_id,
        "device_label": label,
        "domain": "aeterna.device-binding.request.v1",
        "operation": "device_binding.request",
        "protocol_version": 1,
        "public_key": public_key(private_key),
        "request_id": new_request_id(),
        "signature_version": 1,
    }
    document = signed_envelope(signed, private_key)
    payload = DeviceBindingRequest.model_validate(document)
    status_code, data = await service.request_binding(
        db, payload, document, grant["binding_grant_token"]
    )
    assert status_code == 201
    return document, data


async def read_binding_status(
    db,
    service: AeternaIdentityService,
    account_id: str,
    device_id: str,
    private_key: Ed25519PrivateKey,
    signing_private_key: Ed25519PrivateKey | None = None,
) -> dict:
    signed = {
        "account_id": account_id,
        "canonicalization": "jcs-rfc8785",
        "device_id": device_id,
        "domain": "aeterna.device-binding.status.v1",
        "operation": "device_binding.status",
        "protocol_version": 1,
        "public_key": public_key(private_key),
        "request_id": new_request_id(),
        "signature_version": 1,
    }
    document = signed_envelope(signed, signing_private_key or private_key)
    payload = DeviceBindingStatusRequest.model_validate(document)
    return await service.read_binding_status(db, payload, document)


async def test_binding_status_survives_service_restart_and_rejects_wrong_key(
    identity_context,
):
    service, clock, notifier = identity_context
    first_key = signing_key(0x71)
    second_key = signing_key(0x72)
    wrong_key = signing_key(0x73)
    first_id = str(uuid.uuid4())
    second_id = str(uuid.uuid4())
    session_factory = get_session_local()

    async with session_factory() as db:
        grant = await issue_grant(
            db, service, notifier, "account_onboarding", "192.0.2.71"
        )
        _, first = await request_binding(
            db, service, grant, first_key, first_id, "First synthetic device"
        )
        assert first["state"] == "active"

        invalid_signed = {
            "binding_grant_id": grant["binding_grant_id"],
            "canonicalization": "jcs-rfc8785",
            "device_id": str(uuid.uuid4()),
            "domain": "aeterna.device-binding.request.v1",
            "operation": "device_binding.request",
            "protocol_version": 1,
            "public_key": public_key(wrong_key),
            "request_id": new_request_id(),
            "signature_version": 1,
        }
        invalid_document = signed_envelope(invalid_signed, wrong_key)
        invalid_payload = DeviceBindingRequest.model_validate(invalid_document)
        with pytest.raises(AeternaProtocolException) as invalid_grant:
            await service.request_binding(
                db, invalid_payload, invalid_document, encode(bytes([0x91]) * 32)
            )
        assert invalid_grant.value.code == "auth.binding_grant_invalid"
        await db.rollback()

        clock.advance(timedelta(seconds=61))
        second_grant = await issue_grant(
            db, service, notifier, "device_binding", "192.0.2.72"
        )
        _, pending = await request_binding(
            db, service, second_grant, second_key, second_id, "Second synthetic device"
        )
        restarted_service = AeternaIdentityService(
            key_provider=service.key_provider,
            clock=clock.now,
            otp_factory=lambda: SYNTHETIC_OTP,
        )
        observed_pending = await read_binding_status(
            db, restarted_service, grant["account_id"], second_id, second_key
        )
        assert observed_pending["state"] == "pending"
        assert observed_pending["challenge"] == pending["challenge"]
        assert "active_device_count" not in observed_pending

        with pytest.raises(AeternaProtocolException) as invalid_proof:
            await read_binding_status(
                db,
                restarted_service,
                grant["account_id"],
                second_id,
                second_key,
                signing_private_key=wrong_key,
            )
        assert invalid_proof.value.code == "device.binding_not_found"
        await db.rollback()

        approval_signed = {
            "account_id": grant["account_id"],
            "approving_device_id": first_id,
            "binding_id": pending["binding_id"],
            "canonicalization": "jcs-rfc8785",
            "challenge": encode(bytes([0x00]) * 32),
            "device_id": second_id,
            "domain": "aeterna.device-binding.approval.v1",
            "operation": "device_binding.approval",
            "protocol_version": 1,
            "public_key": public_key(second_key),
            "request_id": new_request_id(),
            "signature_version": 1,
        }
        rejected_document = signed_envelope(approval_signed, first_key)
        rejected_payload = DeviceBindingApprovalRequest.model_validate(
            rejected_document
        )
        with pytest.raises(AeternaProtocolException) as rejected:
            await service.approve_binding(
                db, rejected_payload, rejected_document, notifier
            )
        assert rejected.value.code == "device.proof_invalid"
        await db.rollback()

        approved = await approve_pending_binding(
            db,
            restarted_service,
            notifier,
            grant["account_id"],
            pending,
            first_id,
            first_key,
            second_key,
        )
        assert approved["state"] == "active"
        observed_active = await read_binding_status(
            db, service, grant["account_id"], second_id, second_key
        )
        assert observed_active["active_device_count"] == 2
        assert "challenge" not in observed_active


async def approve_pending_binding(
    db,
    service: AeternaIdentityService,
    notifier: CommitObservingNotifier,
    account_id: str,
    pending: dict,
    approving_device_id: str,
    approving_key: Ed25519PrivateKey,
    proposed_key: Ed25519PrivateKey,
) -> dict:
    signed = {
        "account_id": account_id,
        "approving_device_id": approving_device_id,
        "binding_id": pending["binding_id"],
        "canonicalization": "jcs-rfc8785",
        "challenge": pending["challenge"],
        "device_id": pending["device_id"],
        "domain": "aeterna.device-binding.approval.v1",
        "operation": "device_binding.approval",
        "protocol_version": 1,
        "public_key": public_key(proposed_key),
        "request_id": new_request_id(),
        "signature_version": 1,
    }
    document = signed_envelope(signed, approving_key)
    payload = DeviceBindingApprovalRequest.model_validate(document)
    status_code, data = await service.approve_binding(db, payload, document, notifier)
    assert status_code == 200
    return data


async def test_invalid_approval_cannot_mutate_a_stale_approver(identity_context):
    service, clock, notifier = identity_context
    approver_key = signing_key(0x61)
    wrong_key = signing_key(0x62)
    proposed_key = signing_key(0x63)
    approver_id = str(uuid.uuid4())
    proposed_id = str(uuid.uuid4())
    session_factory = get_session_local()

    async with session_factory() as db:
        first_grant = await issue_grant(
            db, service, notifier, "account_onboarding", "203.0.113.20"
        )
        await request_binding(
            db,
            service,
            first_grant,
            approver_key,
            approver_id,
            "Stale synthetic approver",
        )
        clock.advance(timedelta(seconds=61))
        proposed_grant = await issue_grant(
            db, service, notifier, "device_binding", "203.0.113.21"
        )
        _, pending = await request_binding(
            db,
            service,
            proposed_grant,
            proposed_key,
            proposed_id,
            "Pending synthetic device",
        )
        clock.advance(timedelta(days=90))

        signed = {
            "account_id": first_grant["account_id"],
            "approving_device_id": approver_id,
            "binding_id": pending["binding_id"],
            "canonicalization": "jcs-rfc8785",
            "challenge": pending["challenge"],
            "device_id": proposed_id,
            "domain": "aeterna.device-binding.approval.v1",
            "operation": "device_binding.approval",
            "protocol_version": 1,
            "public_key": public_key(proposed_key),
            "request_id": new_request_id(),
            "signature_version": 1,
        }
        document = signed_envelope(signed, wrong_key)
        payload = DeviceBindingApprovalRequest.model_validate(document)
        with pytest.raises(AeternaProtocolException) as invalid:
            await service.approve_binding(db, payload, document, notifier)
        assert invalid.value.code == "device.proof_invalid"

        approver = await db.get(AeternaDevice, uuid.UUID(approver_id))
        assert approver is not None
        assert approver.status == "active"


async def test_complete_first_approval_cancellation_and_delayed_binding_paths(
    identity_context,
):
    service, clock, notifier = identity_context
    first_key = signing_key(0x11)
    second_key = signing_key(0x22)
    cancelled_key = signing_key(0x33)
    delayed_key = signing_key(0x44)
    first_device_id = str(uuid.uuid4())
    second_device_id = str(uuid.uuid4())
    cancelled_device_id = str(uuid.uuid4())
    delayed_device_id = str(uuid.uuid4())
    session_factory = get_session_local()

    async with session_factory() as db:
        first_grant = await issue_grant(
            db, service, notifier, "account_onboarding", "192.0.2.10"
        )
        _first_document, first_binding = await request_binding(
            db,
            service,
            first_grant,
            first_key,
            first_device_id,
            "First synthetic device",
        )
        assert first_binding["state"] == "active"

        clock.advance(timedelta(seconds=61))
        second_grant = await issue_grant(
            db, service, notifier, "device_binding", "192.0.2.11"
        )
        _second_document, pending = await request_binding(
            db,
            service,
            second_grant,
            second_key,
            second_device_id,
            "Second synthetic device",
        )
        assert pending["state"] == "pending"
        approval_signed = {
            "account_id": first_grant["account_id"],
            "approving_device_id": first_device_id,
            "binding_id": pending["binding_id"],
            "canonicalization": "jcs-rfc8785",
            "challenge": pending["challenge"],
            "device_id": second_device_id,
            "domain": "aeterna.device-binding.approval.v1",
            "operation": "device_binding.approval",
            "protocol_version": 1,
            "public_key": public_key(second_key),
            "request_id": new_request_id(),
            "signature_version": 1,
        }
        approval_document = signed_envelope(approval_signed, first_key)
        approval = DeviceBindingApprovalRequest.model_validate(approval_document)
        status_code, approved = await service.approve_binding(
            db, approval, approval_document, notifier
        )
        assert status_code == 200
        assert approved["state"] == "active"
        replay_status, replay = await service.approve_binding(
            db, approval, approval_document, notifier
        )
        assert replay_status == 200
        assert replay == approved

        conflicting_signed = {**approval_signed, "challenge": encode(bytes(32))}
        conflicting_document = signed_envelope(conflicting_signed, first_key)
        conflicting = DeviceBindingApprovalRequest.model_validate(conflicting_document)
        with pytest.raises(AeternaProtocolException) as conflict:
            await service.approve_binding(
                db, conflicting, conflicting_document, notifier
            )
        assert conflict.value.code == "request.idempotency_conflict"
        await db.rollback()

        clock.advance(timedelta(seconds=61))
        cancellation_request_grant = await issue_grant(
            db, service, notifier, "device_binding", "192.0.2.12"
        )
        _cancel_request_document, cancellation_pending = await request_binding(
            db,
            service,
            cancellation_request_grant,
            cancelled_key,
            cancelled_device_id,
            "Cancelled synthetic device",
        )
        clock.advance(timedelta(seconds=61))
        cancellation_grant = await issue_grant(
            db,
            service,
            notifier,
            "device_binding_cancellation",
            "192.0.2.13",
            cancellation_pending["binding_id"],
        )
        cancellation_signed = {
            "account_id": cancellation_grant["account_id"],
            "binding_grant_id": cancellation_grant["binding_grant_id"],
            "binding_id": cancellation_pending["binding_id"],
            "canonicalization": "jcs-rfc8785",
            "challenge": cancellation_pending["challenge"],
            "device_id": cancelled_device_id,
            "domain": "aeterna.device-binding.request.v1",
            "operation": "device_binding.cancellation",
            "protocol_version": 1,
            "public_key": public_key(cancelled_key),
            "request_id": new_request_id(),
            "signature_version": 1,
        }
        cancellation_document = signed_envelope(cancellation_signed, cancelled_key)
        cancellation = DeviceBindingCancellationRequest.model_validate(
            cancellation_document
        )
        _, cancelled = await service.cancel_binding(
            db,
            cancellation,
            cancellation_document,
            cancellation_grant["binding_grant_token"],
            notifier,
        )
        assert cancelled["state"] == "cancelled"

        clock.advance(timedelta(seconds=61))
        delayed_request_grant = await issue_grant(
            db, service, notifier, "device_binding", "192.0.2.14"
        )
        _delayed_request_document, delayed_pending = await request_binding(
            db,
            service,
            delayed_request_grant,
            delayed_key,
            delayed_device_id,
            "Delayed synthetic device",
        )
        clock.advance(timedelta(hours=23, minutes=55))
        delayed_grant = await issue_grant(
            db,
            service,
            notifier,
            "device_binding_delayed_confirmation",
            "192.0.2.15",
            delayed_pending["binding_id"],
        )
        delayed_signed = {
            "account_id": delayed_grant["account_id"],
            "binding_grant_id": delayed_grant["binding_grant_id"],
            "binding_id": delayed_pending["binding_id"],
            "canonicalization": "jcs-rfc8785",
            "challenge": delayed_pending["challenge"],
            "device_id": delayed_device_id,
            "domain": "aeterna.device-binding.request.v1",
            "operation": "device_binding.delayed_confirmation",
            "protocol_version": 1,
            "public_key": public_key(delayed_key),
            "request_id": new_request_id(),
            "signature_version": 1,
        }
        delayed_document = signed_envelope(delayed_signed, delayed_key)
        delayed_confirmation = DeviceBindingDelayedConfirmationRequest.model_validate(
            delayed_document
        )
        with pytest.raises(AeternaProtocolException) as not_ready:
            await service.confirm_delayed_binding(
                db,
                delayed_confirmation,
                delayed_document,
                delayed_grant["binding_grant_token"],
                notifier,
            )
        assert not_ready.value.code == "device.binding_not_ready"
        await db.rollback()
        clock.advance(timedelta(minutes=5, seconds=1))
        _, delayed_active = await service.confirm_delayed_binding(
            db,
            delayed_confirmation,
            delayed_document,
            delayed_grant["binding_grant_token"],
            notifier,
        )
        assert delayed_active["state"] == "active"

    assert notifier.challenge_was_committed
    assert all(notifier.challenge_was_committed)
    assert notifier.security_events == [
        "device bound",
        "binding cancelled",
        "device bound",
    ]
    async with session_factory() as db:
        account = await db.scalar(select(AeternaAccount))
        assert account is not None
        assert account.first_device_bound_at is not None
        assert SYNTHETIC_EMAIL.encode() not in account.email_ciphertext
        challenge_ciphertexts = list(
            (await db.scalars(select(AeternaAccountChallenge.email_ciphertext))).all()
        )
        assert all(
            SYNTHETIC_EMAIL.encode() not in ciphertext
            for ciphertext in challenge_ciphertexts
        )
        active_devices = await db.scalar(
            select(func.count(AeternaDevice.id)).where(AeternaDevice.status == "active")
        )
        assert active_devices == 3
        states = list(
            (
                await db.scalars(
                    select(AeternaDeviceBinding.state).order_by(
                        AeternaDeviceBinding.created_at
                    )
                )
            ).all()
        )
        assert states == ["active", "active", "cancelled", "active"]


async def test_ses_initialization_failure_preserves_challenge_202_and_no_resend(
    identity_context, monkeypatch, caplog
):
    service, clock, _notifier = identity_context
    settings = {
        "ENV": "production",
        "AETERNA_EMAIL_PROVIDER": "aws-ses",
        "AETERNA_EMAIL_PRODUCTION_ENABLED": True,
        "AWS_SES_REGION": "ap-southeast-1",
        "AWS_SES_FROM_ADDRESS": "noreply@example.com",
        "AWS_SES_CONFIGURATION_SET": "aeterna-events",
        "AWS_SES_SNS_TOPIC_ARN": (
            "arn:aws:sns:ap-southeast-1:123456789012:aeterna-events"
        ),
    }
    for name, value in settings.items():
        monkeypatch.setattr(
            f"app.services.common.aeterna_email_adapter.settings.{name}", value
        )
    client_calls = []

    def create_client(*args, **kwargs):
        client_calls.append((args, kwargs))
        raise PartialCredentialsError(
            provider="synthetic-sensitive-detail", cred_var="synthetic-missing-variable"
        )

    monkeypatch.setattr(
        "app.services.common.aeterna_email_adapter.boto3.client", create_client
    )
    notifier = get_aeterna_account_notifier()
    adapter_send = notifier.email_service.adapter.send
    send_calls = []

    async def record_send(envelope, idempotency_key):
        send_calls.append(idempotency_key)
        return await adapter_send(envelope, idempotency_key)

    monkeypatch.setattr(notifier.email_service.adapter, "send", record_send)
    document = {
        "protocol_version": 1,
        "request_id": new_request_id(),
        "email": SYNTHETIC_EMAIL,
        "purpose": "account_onboarding",
    }
    body = json.dumps(document).encode()

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    session_factory = get_session_local()
    async with session_factory() as db:
        responses = []
        for _ in range(2):
            request = Request(
                {
                    "type": "http",
                    "method": "POST",
                    "path": "/account-challenges",
                    "headers": [(b"content-type", b"application/json")],
                    "client": ("198.51.100.88", 80),
                },
                receive,
            )
            response = await initiate_account_challenge(
                request, db=db, service=service, notifier=notifier
            )
            assert response.status_code == 202
            responses.append(json.loads(response.body))
        assert responses[0] == responses[1]
        data = responses[0]["data"]
        assert set(data) == {
            "challenge_id",
            "expires_in_seconds",
            "resend_after_seconds",
        }
        assert data["expires_in_seconds"] == 600
        assert data["resend_after_seconds"] == 60
        stored = await db.get(AeternaAccountChallenge, uuid.UUID(data["challenge_id"]))
        assert stored is not None
        assert stored.status == "pending"
        assert stored.delivery_status == "failed"
        assert stored.expires_at == clock.now() + timedelta(minutes=10)
        assert stored.resend_after == clock.now() + timedelta(seconds=60)

    assert len(client_calls) == 1
    assert len(send_calls) == 1
    assert "synthetic-sensitive-detail" not in caplog.text


async def test_challenge_exhausts_after_five_constant_shape_failures(identity_context):
    service, _clock, notifier = identity_context
    session_factory = get_session_local()
    async with session_factory() as db:
        challenge_document = {
            "protocol_version": 1,
            "request_id": new_request_id(),
            "email": "attempt-limit@example.com",
            "purpose": "account_onboarding",
        }
        challenge = AccountChallengeRequest.model_validate(challenge_document)
        data = await service.initiate_challenge(
            db, challenge, challenge_document, "198.51.100.1", notifier
        )
        for attempt in range(1, 6):
            verification = AccountChallengeVerificationRequest.model_validate(
                {
                    "protocol_version": 1,
                    "request_id": new_request_id(),
                    "challenge_id": data["challenge_id"],
                    "code": "00000000",
                }
            )
            with pytest.raises(AeternaProtocolException) as failure:
                await service.verify_challenge(db, verification)
            expected = (
                "auth.attempts_exhausted" if attempt == 5 else "auth.challenge_invalid"
            )
            assert failure.value.code == expected

        stored = await db.get(AeternaAccountChallenge, uuid.UUID(data["challenge_id"]))
        assert stored is not None
        assert stored.attempt_count == 5
        assert stored.status == "exhausted"


async def test_dormant_device_reverification_preserves_sequence_for_both_paths(
    identity_context,
):
    service, clock, notifier = identity_context
    first_key = signing_key(0x51)
    second_key = signing_key(0x52)
    first_device_id = str(uuid.uuid4())
    second_device_id = str(uuid.uuid4())
    session_factory = get_session_local()

    async with session_factory() as db:
        first_grant = await issue_grant(
            db, service, notifier, "account_onboarding", "203.0.113.10"
        )
        _, first_binding = await request_binding(
            db,
            service,
            first_grant,
            first_key,
            first_device_id,
            "First reverify device",
        )
        clock.advance(timedelta(seconds=61))
        second_grant = await issue_grant(
            db, service, notifier, "device_binding", "203.0.113.11"
        )
        _, second_pending = await request_binding(
            db,
            service,
            second_grant,
            second_key,
            second_device_id,
            "Second reverify device",
        )
        await approve_pending_binding(
            db,
            service,
            notifier,
            first_grant["account_id"],
            second_pending,
            first_device_id,
            first_key,
            second_key,
        )

        first_device = await db.get(AeternaDevice, uuid.UUID(first_device_id))
        first_device.status = "dormant"
        first_device.last_sequence = 7
        first_device.last_seen_at = clock.current - timedelta(days=91)
        await db.commit()

        clock.advance(timedelta(seconds=61))
        reverify_grant = await issue_grant(
            db, service, notifier, "device_binding", "203.0.113.12"
        )
        _, reverify_pending = await request_binding(
            db,
            service,
            reverify_grant,
            first_key,
            first_device_id,
            "First reverified device",
        )
        assert reverify_pending["state"] == "pending"
        await approve_pending_binding(
            db,
            service,
            notifier,
            first_grant["account_id"],
            reverify_pending,
            second_device_id,
            second_key,
            first_key,
        )
        await db.refresh(first_device)
        assert first_device.status == "active"
        assert first_device.last_sequence == 7
        assert first_device.last_seen_at is None
        assert first_device.heartbeat_authorized_at == clock.current

        second_device = await db.get(AeternaDevice, uuid.UUID(second_device_id))
        second_device.status = "dormant"
        second_device.last_sequence = 9
        second_device.last_seen_at = clock.current - timedelta(days=91)
        await db.commit()

        clock.advance(timedelta(seconds=61))
        delayed_start_grant = await issue_grant(
            db, service, notifier, "device_binding", "203.0.113.13"
        )
        _, delayed_pending = await request_binding(
            db,
            service,
            delayed_start_grant,
            second_key,
            second_device_id,
            "Second reverified device",
        )
        clock.advance(timedelta(hours=24, seconds=1))
        delayed_grant = await issue_grant(
            db,
            service,
            notifier,
            "device_binding_delayed_confirmation",
            "203.0.113.14",
            delayed_pending["binding_id"],
        )
        delayed_signed = {
            "account_id": delayed_grant["account_id"],
            "binding_grant_id": delayed_grant["binding_grant_id"],
            "binding_id": delayed_pending["binding_id"],
            "canonicalization": "jcs-rfc8785",
            "challenge": delayed_pending["challenge"],
            "device_id": second_device_id,
            "domain": "aeterna.device-binding.request.v1",
            "operation": "device_binding.delayed_confirmation",
            "protocol_version": 1,
            "public_key": public_key(second_key),
            "request_id": new_request_id(),
            "signature_version": 1,
        }
        delayed_document = signed_envelope(delayed_signed, second_key)
        delayed_payload = DeviceBindingDelayedConfirmationRequest.model_validate(
            delayed_document
        )
        status_code, delayed_active = await service.confirm_delayed_binding(
            db,
            delayed_payload,
            delayed_document,
            delayed_grant["binding_grant_token"],
            notifier,
        )
        assert status_code == 200
        assert delayed_active["state"] == "active"
        await db.refresh(second_device)
        assert second_device.status == "active"
        assert second_device.last_sequence == 9
        assert second_device.last_seen_at is None
        assert second_device.heartbeat_authorized_at == clock.current

        bindings = list(
            (
                await db.scalars(
                    select(AeternaDeviceBinding).where(
                        AeternaDeviceBinding.proposed_device_id.in_(
                            [uuid.UUID(first_device_id), uuid.UUID(second_device_id)]
                        )
                    )
                )
            ).all()
        )
        assert len(bindings) == 4
        reverified_events = await db.scalar(
            select(func.count(AeternaSecurityAudit.id)).where(
                AeternaSecurityAudit.event_type == "device.reverified"
            )
        )
        assert reverified_events == 2
