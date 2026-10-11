"""Synthetic real-PostgreSQL tests for isolated timing, proofs and dispatch races."""

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import delete, select

from app.db.base import get_engine, get_session_local
from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.models.account_policy import AccountPolicy
from app.models.aeterna_identity import AeternaAccount, AeternaDevice
from app.models.aeterna_notification import AeternaContact, AeternaEmailOutboxEvent
from app.models.aeterna_trigger_test import (
    AeternaTriggerTest,
    AeternaTriggerTestChallenge,
    AeternaTriggerTestMail,
)
from app.schemas.client.aeterna_trigger_test import TriggerTestRequest, TriggerTestView
from app.services.client.aeterna_trigger_test import AeternaTriggerTestService
from app.services.common.aeterna_email_adapter import (
    EmailDeliveryFailure,
    ProviderAcceptance,
)
from app.services.common.aeterna_security import (
    AeternaIdentityKeys,
    canonicalize,
    decrypt_private_text,
    email_lookup,
    encode_base64url,
    encrypt_email,
)

pytestmark = pytest.mark.asyncio(loop_scope="session")
BASE = datetime(2026, 10, 11, 12, tzinfo=UTC)


@dataclass
class Clock:
    current: datetime = BASE

    def __call__(self):
        return self.current


@dataclass
class Adapter:
    provider_name: str = "synthetic-provider"
    supports_idempotency: bool = False
    failure: str | None = None
    messages: list = field(default_factory=list, repr=False)
    entered: asyncio.Event | None = None
    release: asyncio.Event | None = None

    async def send(self, envelope, key):
        self.messages.append((envelope, key))
        if self.entered is not None:
            self.entered.set()
            await self.release.wait()
        if self.failure:
            raise EmailDeliveryFailure(
                "synthetic-provider-failure",
                retryable=False,
                ambiguous=self.failure == "unknown",
            )
        return ProviderAcceptance(
            self.provider_name, f"synthetic-{len(self.messages)}", BASE
        )


class Harness:
    def __init__(self):
        self.account_id, self.device_id = uuid.uuid4(), uuid.uuid4()
        self.signer = Ed25519PrivateKey.generate()
        self.clock, self.adapter = Clock(), Adapter()
        self.keys = AeternaIdentityKeys(
            pii_key=b"\x11" * 32, lookup_key=b"\x22" * 32, otp_key=b"\x33" * 32
        )
        self.service = AeternaTriggerTestService(
            clock=self.clock,
            keys=lambda: self.keys,
            adapter=self.adapter,
            notice_origin="http://127.0.0.1:61835",
        )
        self.sessions = get_session_local()

    def document(self, operation, **fields):
        signed = {
            "canonicalization": "jcs-rfc8785",
            "domain": f"aeterna.trigger-test.{operation}.v1",
            "operation": f"trigger_test.{operation.replace('-', '_')}",
            "protocol_version": 1,
            "signature_version": 1,
            "request_id": str(uuid.uuid4()),
            "account_id": str(self.account_id),
            "device_id": str(self.device_id),
            **fields,
        }
        return {
            "protocol_version": 1,
            "signed": signed,
            "signature": encode_base64url(self.signer.sign(canonicalize(signed))),
        }

    async def call_document(self, document):
        async with self.sessions() as db:
            result = await self.service.operate(
                db, TriggerTestRequest.model_validate(document), document
            )
            TriggerTestView.model_validate(result["view"])
            return result

    async def call(self, operation, **fields):
        return await self.call_document(self.document(operation, **fields))

    async def create(self, recovery=False, **changes):
        self.vault_id = str(uuid.uuid4()) if recovery else None
        result = await self.call(
            "create",
            recipient_contact_id=None,
            include_recovery=recovery,
            sample_vault_id=self.vault_id,
            locale="en",
            effects_acknowledged=True,
            **changes,
        )
        self.test_id = result["view"]["session"]["id"]
        return result

    async def activate(self, recovery=False):
        if recovery:
            source = await self.call("provision", session_id=self.test_id)
            self.source_id = source["source_recovery_id"]
            return await self.call(
                "activate",
                session_id=self.test_id,
                sample_vault_id=self.vault_id,
                source_recovery_id=self.source_id,
                wrapper_digest=encode_base64url(b"\x44" * 32),
            )
        return await self.call(
            "activate",
            session_id=self.test_id,
            sample_vault_id=None,
            source_recovery_id=None,
            wrapper_digest=None,
        )

    async def scan(self, elapsed):
        self.clock.current = BASE + timedelta(seconds=elapsed)
        async with self.sessions() as db:
            await self.service.scan(db, uuid.UUID(self.test_id))

    async def dispatch_all(self):
        async with self.sessions() as db:
            ids = list(
                await db.scalars(
                    select(AeternaTriggerTestMail.id).where(
                        AeternaTriggerTestMail.test_id == uuid.UUID(self.test_id),
                        AeternaTriggerTestMail.status == "queued",
                    )
                )
            )
        for mail_id in ids:
            async with self.sessions() as db:
                await self.service.dispatch(db, mail_id)

    async def challenge_code(self, challenge_id):
        async with self.sessions() as db:
            challenge = await db.get(
                AeternaTriggerTestChallenge, uuid.UUID(challenge_id)
            )
            return decrypt_private_text(
                self.keys,
                challenge.code_ciphertext,
                challenge.code_nonce,
                "trigger-test-code",
                challenge.id,
                challenge.key_version,
            )

    async def warning_proof(self):
        response = await self.call("warning-challenge", session_id=self.test_id)
        challenge_id = response["challenge"]["id"]
        return await self.call(
            "warning-verify",
            session_id=self.test_id,
            challenge_id=challenge_id,
            code=await self.challenge_code(challenge_id),
        )

    async def released(self, recovery=False):
        await self.create(recovery)
        await self.activate(recovery)
        await self.scan(60)
        await self.dispatch_all()
        await self.warning_proof()
        await self.scan(120)
        await self.scan(180)
        await self.dispatch_all()

    async def recipient_proof(self):
        async with self.sessions() as db:
            test = await db.get(AeternaTriggerTest, uuid.UUID(self.test_id))
            token = decrypt_private_text(
                self.keys,
                test.notice_ciphertext,
                test.notice_nonce,
                "trigger-test-notice",
                test.id,
                test.email_key_version,
            )
        response = await self.call(
            "recipient-challenge", session_id=self.test_id, notice_token=token
        )
        challenge_id = response["challenge"]["id"]
        await self.dispatch_all()
        return await self.call(
            "recipient-verify",
            session_id=self.test_id,
            challenge_id=challenge_id,
            code=await self.challenge_code(challenge_id),
        )

    async def read(self):
        return await self.call("read", session_id=self.test_id)


@pytest_asyncio.fixture(loop_scope="session")
async def harness():
    get_engine().echo = False
    harness = Harness()
    cipher, nonce, version = encrypt_email(
        harness.keys, "synthetic-owner@example.test", "account", harness.account_id
    )
    async with harness.sessions.begin() as db:
        db.add(
            AeternaAccount(
                id=harness.account_id,
                email_lookup=email_lookup(harness.keys, "synthetic-owner@example.test"),
                email_ciphertext=cipher,
                email_nonce=nonce,
                email_key_version=version,
                first_device_bound_at=BASE,
                last_activity_at=BASE,
                is_active=True,
            )
        )
        await db.flush()
        db.add(
            AeternaDevice(
                id=harness.device_id,
                account_id=harness.account_id,
                public_key=harness.signer.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                ),
                status="active",
                bound_at=BASE,
                heartbeat_authorized_at=BASE,
                last_sequence=0,
            )
        )
        db.add(
            AccountPolicy(
                account_id=harness.account_id,
                inactivity_window_seconds=30 * 86400,
                warning_window_seconds=7 * 86400,
                grace_window_seconds=7 * 86400,
                last_activity_at=BASE,
                due_at=BASE + timedelta(days=30),
                state_changed_at=BASE,
            )
        )
    yield harness
    async with harness.sessions.begin() as db:
        await db.execute(
            delete(AeternaAccount).where(AeternaAccount.id == harness.account_id)
        )


async def test_real_timing_mailbox_proofs_and_completion_leave_normal_policy_untouched(
    harness,
):
    await harness.released()
    response = await harness.recipient_proof()
    session = response["view"]["session"]
    assert session["stage"] == "complete"
    assert session["notificationTransport"] == "accepted"
    assert session["recipientVerified"] and session["warningConfirmed"]
    assert session["evidence"][4]["outcome"] == "not_selected"
    assert len(harness.adapter.messages) == 3
    assert all(
        message.track_in_outbox is False for message, _ in harness.adapter.messages
    )
    notice = harness.adapter.messages[1][0].text_body
    assert "/trigger-tests/notice#session=" in notice
    assert "not a real inactivity event" in notice
    async with harness.sessions() as db:
        account = await db.get(AeternaAccount, harness.account_id)
        policy = await db.scalar(
            select(AccountPolicy).where(AccountPolicy.account_id == harness.account_id)
        )
        assert account.last_activity_at == BASE and account.current_policy_epoch == 1
        assert policy.state == "ACTIVE" and policy.version == 0
        assert (
            list(
                await db.scalars(
                    select(AeternaEmailOutboxEvent.id).where(
                        AeternaEmailOutboxEvent.account_id == harness.account_id
                    )
                )
            )
            == []
        )


async def test_late_confirmation_requires_an_entire_fresh_grace_interval(harness):
    await harness.create()
    await harness.activate()
    await harness.scan(300)
    assert (await harness.read())["view"]["session"]["stage"] == "warning"
    await harness.scan(310)
    await harness.scan(400)
    assert (await harness.read())["view"]["session"]["stage"] == "grace"
    harness.clock.current = BASE + timedelta(seconds=400)
    await harness.warning_proof()
    await harness.scan(459)
    assert (await harness.read())["view"]["session"]["stage"] == "grace"
    await harness.scan(460)
    assert (await harness.read())["view"]["session"]["stage"] == "released"


async def test_creation_and_factors_replay_exactly_and_wrong_binding_is_rejected(
    harness,
):
    document = harness.document(
        "create",
        recipient_contact_id=None,
        include_recovery=True,
        sample_vault_id=str(uuid.uuid4()),
        locale="en",
        effects_acknowledged=True,
    )
    first = await harness.call_document(document)
    second = await harness.call_document(document)
    assert first["view"]["session"]["id"] == second["view"]["session"]["id"]
    harness.test_id = first["view"]["session"]["id"]
    source = await harness.call("provision", session_id=harness.test_id)
    replay = await harness.call("provision", session_id=harness.test_id)
    assert source["source_recovery_id"] == replay["source_recovery_id"]
    assert source["source_srs"] == replay["source_srs"]
    with pytest.raises(AeternaProtocolException, match="trigger_test.binding_mismatch"):
        await harness.call(
            "activate",
            session_id=harness.test_id,
            sample_vault_id=str(uuid.uuid4()),
            source_recovery_id=source["source_recovery_id"],
            wrapper_digest=encode_base64url(b"\x44" * 32),
        )


async def test_recovery_target_is_durable_and_cross_role_ciphertext_swap_fails(harness):
    await harness.released(True)
    proof = await harness.recipient_proof()
    fields = {
        "session_id": harness.test_id,
        "sample_vault_id": harness.vault_id,
        "source_recovery_id": harness.source_id,
        "claim_token": proof["claim_token"],
    }
    first = await harness.call("release-secret", **fields)
    second = await harness.call("release-secret", **fields)
    assert first["target_recovery_id"] == second["target_recovery_id"]
    assert first["target_srs"] == second["target_srs"]
    assert first["source_srs"] != first["target_srs"]
    await harness.call(
        "rotation-confirm",
        session_id=harness.test_id,
        sample_vault_id=harness.vault_id,
        target_recovery_id=first["target_recovery_id"],
        wrapper_digest=encode_base64url(b"\x55" * 32),
        generation=2,
        claim_token=proof["claim_token"],
    )
    assert (await harness.call("release-secret", **fields))["target_srs"] == first[
        "target_srs"
    ]
    async with harness.sessions.begin() as db:
        test = await db.get(AeternaTriggerTest, uuid.UUID(harness.test_id))
        test.source_ciphertext, test.source_nonce = (
            test.target_ciphertext,
            test.target_nonce,
        )
    with pytest.raises(RuntimeError, match="factor binding is invalid"):
        await harness.call("release-secret", **fields)


async def test_activity_stops_and_cancels_queued_work(harness):
    await harness.create()
    await harness.activate()
    await harness.scan(60)
    result = await harness.call("activity", session_id=harness.test_id)
    assert result["view"]["session"]["stage"] == "stopped"
    assert result["view"]["session"]["activityStopped"]
    await harness.dispatch_all()
    assert harness.adapter.messages == []
    await harness.scan(180)
    assert (await harness.read())["view"]["session"]["stage"] == "stopped"


async def test_dispatch_transaction_winning_stop_preserves_actual_transport(harness):
    await harness.released()
    proof = await harness.recipient_proof()
    # Create a fresh independent warning-code send to exercise committed dispatch.
    await harness.call("stop", session_id=harness.test_id)
    harness.clock.current = BASE
    await harness.create()
    await harness.activate()
    await harness.scan(60)
    harness.adapter.entered, harness.adapter.release = asyncio.Event(), asyncio.Event()
    async with harness.sessions() as db:
        mail_id = await db.scalar(
            select(AeternaTriggerTestMail.id).where(
                AeternaTriggerTestMail.test_id == uuid.UUID(harness.test_id)
            )
        )

    async def dispatch():
        async with harness.sessions() as db:
            await harness.service.dispatch(db, mail_id)

    task = asyncio.create_task(dispatch())
    await asyncio.wait_for(harness.adapter.entered.wait(), 2)
    stopped = await harness.call("stop", session_id=harness.test_id)
    assert stopped["view"]["session"]["stage"] == "stopped"
    harness.adapter.release.set()
    await task
    view = (await harness.read())["view"]["session"]
    assert view["stage"] == "stopped" and view["warningTransport"] == "accepted"


@pytest.mark.parametrize("failure", ["failed", "unknown"])
async def test_retry_only_repeats_known_failure_and_never_ambiguity(harness, failure):
    await harness.create()
    await harness.activate()
    await harness.scan(60)
    harness.adapter.failure = failure
    await harness.dispatch_all()
    view = (await harness.read())["view"]["session"]
    assert view["warningTransport"] == failure
    if failure == "unknown":
        with pytest.raises(AeternaProtocolException, match="not_ready"):
            await harness.call("retry", session_id=harness.test_id)
    else:
        retry = harness.document("retry", session_id=harness.test_id)
        await harness.call_document(retry)
        await harness.call_document(retry)
        harness.adapter.failure = None
        await harness.dispatch_all()
        assert (await harness.read())["view"]["session"][
            "warningTransport"
        ] == "accepted"
        assert len(harness.adapter.messages) == 2


async def test_wrong_codes_lock_after_five_attempts_without_proving_warning(harness):
    await harness.create()
    await harness.activate()
    await harness.scan(60)
    response = await harness.call("warning-challenge", session_id=harness.test_id)
    challenge_id = response["challenge"]["id"]
    actual = await harness.challenge_code(challenge_id)
    wrong = "00000000" if actual != "00000000" else "11111111"
    for _ in range(5):
        with pytest.raises(AeternaProtocolException, match="challenge_invalid"):
            await harness.call(
                "warning-verify",
                session_id=harness.test_id,
                challenge_id=challenge_id,
                code=wrong,
            )
    with pytest.raises(AeternaProtocolException, match="attempts_exhausted"):
        await harness.call(
            "warning-verify",
            session_id=harness.test_id,
            challenge_id=challenge_id,
            code=actual,
        )
    assert not (await harness.read())["view"]["session"]["warningConfirmed"]


@pytest.mark.parametrize("entry_point", ["scheduler", "read", "mutation"])
async def test_expiry_clears_all_factor_and_link_capabilities(harness, entry_point):
    await harness.released(True)
    await harness.recipient_proof()
    if entry_point == "scheduler":
        await harness.scan(1800)
    else:
        harness.clock.current = BASE + timedelta(seconds=1800)
        if entry_point == "read":
            await harness.read()
        else:
            with pytest.raises(AeternaProtocolException, match="expired"):
                await harness.call("provision", session_id=harness.test_id)
    async with harness.sessions() as db:
        test = await db.get(AeternaTriggerTest, uuid.UUID(harness.test_id))
        assert test.state == "EXPIRED"
    assert (await harness.read())["view"]["session"]["stage"] == "expired"
    async with harness.sessions() as db:
        test = await db.get(AeternaTriggerTest, uuid.UUID(harness.test_id))
        assert test.source_ciphertext is None and test.target_ciphertext is None
        assert test.notice_verifier is None and test.claim_verifier is None
    with pytest.raises(AeternaProtocolException, match="expired"):
        await harness.call("provision", session_id=harness.test_id)


@pytest.mark.parametrize(
    "mode,consent", [("CONFIRM_NOW", "INVITED"), ("PRIVATE_UNTIL_RELEASE", "ACCEPTED")]
)
async def test_private_or_unconfirmed_targets_cannot_receive_test_mail(
    harness, mode, consent
):
    contact_id = uuid.uuid4()
    cipher, nonce, version = encrypt_email(
        harness.keys, "synthetic-contact@example.test", "contact", contact_id
    )
    async with harness.sessions.begin() as db:
        db.add(
            AeternaContact(
                id=contact_id,
                account_id=harness.account_id,
                email_lookup=email_lookup(
                    harness.keys, "synthetic-contact@example.test"
                ),
                email_ciphertext=cipher,
                email_nonce=nonce,
                email_key_version=version,
                disclosure_mode=mode,
                consent_status=consent,
                accepted_at=BASE if consent == "ACCEPTED" else None,
                verified_at=BASE if consent == "ACCEPTED" else None,
            )
        )
    with pytest.raises(AeternaProtocolException, match="recipient_unavailable"):
        await harness.call(
            "create",
            recipient_contact_id=str(contact_id),
            include_recovery=False,
            sample_vault_id=None,
            locale="en",
            effects_acknowledged=True,
        )
    assert harness.adapter.messages == []


async def test_notice_token_and_separate_recipient_code_are_required(harness):
    await harness.released()
    with pytest.raises(AeternaProtocolException, match="claim_invalid"):
        await harness.call(
            "recipient-challenge",
            session_id=harness.test_id,
            notice_token=encode_base64url(b"\x88" * 32),
        )
    proof = await harness.recipient_proof()
    assert proof["view"]["session"]["recipientVerified"]


async def test_invalid_device_signature_cannot_read_or_mutate_session(harness):
    await harness.create()
    document = harness.document("stop", session_id=harness.test_id)
    document["signature"] = encode_base64url(b"\x77" * 64)
    with pytest.raises(AeternaProtocolException, match="device.proof_invalid"):
        await harness.call_document(document)
    assert (await harness.read())["view"]["session"]["stage"] == "preparing"


async def test_completed_sample_reverifies_mailbox_and_reopens_same_committed_target(
    harness,
):
    await harness.released(True)
    proof = await harness.recipient_proof()
    fields = {
        "session_id": harness.test_id,
        "sample_vault_id": harness.vault_id,
        "source_recovery_id": harness.source_id,
        "claim_token": proof["claim_token"],
    }
    secret = await harness.call("release-secret", **fields)
    await harness.call(
        "rotation-confirm",
        session_id=harness.test_id,
        sample_vault_id=harness.vault_id,
        target_recovery_id=secret["target_recovery_id"],
        wrapper_digest=encode_base64url(b"\x55" * 32),
        generation=2,
        claim_token=proof["claim_token"],
    )
    assert (await harness.read())["view"]["session"]["stage"] == "complete"
    harness.clock.current = BASE + timedelta(seconds=500)
    with pytest.raises(AeternaProtocolException, match="claim_invalid"):
        await harness.call("release-secret", **fields)
    renewed = await harness.recipient_proof()
    reopened = await harness.call(
        "release-secret", **{**fields, "claim_token": renewed["claim_token"]}
    )
    assert reopened["target_recovery_id"] == secret["target_recovery_id"]
    assert reopened["target_srs"] == secret["target_srs"]
    assert reopened["view"]["session"]["stage"] == "complete"


async def test_revoked_device_cannot_authorize_queued_test_mail(harness):
    await harness.create()
    await harness.activate()
    await harness.scan(60)
    async with harness.sessions.begin() as db:
        device = await db.get(AeternaDevice, harness.device_id)
        device.status = "revoked"
    await harness.dispatch_all()
    assert harness.adapter.messages == []
    await harness.scan(180)
    async with harness.sessions() as db:
        test = await db.get(AeternaTriggerTest, uuid.UUID(harness.test_id))
        assert test.state == "STOPPED"


async def test_another_session_cannot_decrypt_copied_factor_ciphertext(harness):
    await harness.create(True)
    first_id = harness.test_id
    await harness.call("provision", session_id=first_id)
    async with harness.sessions() as db:
        first = await db.get(AeternaTriggerTest, uuid.UUID(first_id))
        cipher, nonce, recovery_id = (
            first.source_ciphertext,
            first.source_nonce,
            first.source_recovery_id,
        )
    await harness.call("stop", session_id=first_id)
    await harness.create(True)
    await harness.call("provision", session_id=harness.test_id)
    async with harness.sessions.begin() as db:
        second = await db.get(AeternaTriggerTest, uuid.UUID(harness.test_id))
        second.source_ciphertext, second.source_nonce, second.source_recovery_id = (
            cipher,
            nonce,
            recovery_id,
        )
    from cryptography.exceptions import InvalidTag

    with pytest.raises(InvalidTag):
        await harness.call("provision", session_id=harness.test_id)


async def test_concurrent_workers_create_and_dispatch_one_warning(harness):
    await harness.create()
    await harness.activate()
    harness.clock.current = BASE + timedelta(seconds=60)

    async def scan():
        async with harness.sessions() as db:
            await harness.service.scan(db, uuid.UUID(harness.test_id))

    await asyncio.gather(scan(), scan())
    async with harness.sessions() as db:
        ids = list(
            await db.scalars(
                select(AeternaTriggerTestMail.id).where(
                    AeternaTriggerTestMail.test_id == uuid.UUID(harness.test_id)
                )
            )
        )
    assert len(ids) == 1

    async def dispatch():
        async with harness.sessions() as db:
            await harness.service.dispatch(db, ids[0])

    await asyncio.gather(dispatch(), dispatch())
    assert len(harness.adapter.messages) == 1


async def test_real_signed_http_to_local_mailpit_requires_separate_mailbox_proofs(
    harness,
):
    import re

    from httpx import ASGITransport, AsyncClient

    from app.core.config import settings
    from app.route import create_app
    from app.services.client.aeterna_trigger_test import (
        get_aeterna_trigger_test_service,
    )
    from app.services.common.aeterna_email_adapter import SmtpDevelopmentEmailAdapter

    assert settings.MAIL_HOST == "mailpit" and settings.ENV == "development"
    harness.service.adapter = SmtpDevelopmentEmailAdapter()
    app = create_app()
    app.dependency_overrides[get_aeterna_trigger_test_service] = lambda: harness.service
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://synthetic.invalid"
    ) as api, AsyncClient(base_url="http://mailpit:8025", trust_env=False) as mail:

        async def call(operation, **fields):
            document = harness.document(operation, **fields)
            response = await api.post(
                f"/api/v1/trigger-tests/{operation}", json=document
            )
            assert response.status_code == 200
            assert response.headers["cache-control"] == "no-store"
            body = response.json()
            assert body["request_id"] == document["signed"]["request_id"]
            return body["data"]

        response = await call(
            "create",
            recipient_contact_id=None,
            include_recovery=False,
            sample_vault_id=None,
            locale="en",
            effects_acknowledged=True,
        )
        harness.test_id = response["view"]["session"]["id"]
        await call(
            "activate",
            session_id=harness.test_id,
            sample_vault_id=None,
            source_recovery_id=None,
            wrapper_digest=None,
        )
        await harness.scan(60)
        await harness.dispatch_all()
        messages = (await mail.get("/api/v1/messages")).json()["messages"]
        warning = await mail.get(f'/api/v1/message/{messages[0]["ID"]}')
        text = warning.json()["Text"]
        code = re.search(r"verification code: ([0-9]{8})", text).group(1)
        challenge = await call("warning-challenge", session_id=harness.test_id)
        await call(
            "warning-verify",
            session_id=harness.test_id,
            challenge_id=challenge["challenge"]["id"],
            code=code,
        )
        await harness.scan(120)
        await harness.scan(180)
        await harness.dispatch_all()
        messages = (await mail.get("/api/v1/messages")).json()["messages"]
        notice = (await mail.get(f'/api/v1/message/{messages[0]["ID"]}')).json()["Text"]
        token = re.search(r"&token=([A-Za-z0-9_-]{43})", notice).group(1)
        assert not (await harness.read())["view"]["session"]["recipientVerified"]
        challenge = await call(
            "recipient-challenge", session_id=harness.test_id, notice_token=token
        )
        await harness.dispatch_all()
        messages = (await mail.get("/api/v1/messages")).json()["messages"]
        text = (await mail.get(f'/api/v1/message/{messages[0]["ID"]}')).json()["Text"]
        code = re.search(r"verification code: ([0-9]{8})", text).group(1)
        verified = await call(
            "recipient-verify",
            session_id=harness.test_id,
            challenge_id=challenge["challenge"]["id"],
            code=code,
        )
        assert verified["view"]["session"]["stage"] == "complete"
        assert verified["view"]["session"]["recipientVerified"]
        # Retain no mailbox codes, capabilities, addresses or rendered content in output.


async def test_missing_notice_origin_reports_unavailable_without_allocating_session(
    harness,
):
    harness.service.notice_origin = ""
    harness.service.available = False
    response = await harness.call("read", session_id=None)
    assert not response["view"]["available"]
    with pytest.raises(AeternaProtocolException, match="trigger_test.unavailable"):
        await harness.create()
    async with harness.sessions() as db:
        assert (
            await db.scalar(
                select(AeternaTriggerTest.id).where(
                    AeternaTriggerTest.account_id == harness.account_id
                )
            )
            is None
        )


async def test_existing_session_remains_manageable_after_delivery_capability_disappears(
    harness,
):
    await harness.create()
    await harness.activate()
    harness.service.notice_origin = ""
    harness.service.available = False
    view = (await harness.read())["view"]
    assert view["available"] is True
    assert view["sampleRecoveryAvailable"] is False
    assert view["session"]["stage"] == "waiting"
    stopped = await harness.call("stop", session_id=harness.test_id)
    assert stopped["view"]["session"]["stage"] == "stopped"
    with pytest.raises(AeternaProtocolException, match="unavailable"):
        await harness.create()
