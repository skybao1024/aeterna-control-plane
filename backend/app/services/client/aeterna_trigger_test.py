"""Real, bounded inactivity tests isolated from normal policies and recovery grants."""

from __future__ import annotations

import html
import json
import secrets
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.models.aeterna_identity import AeternaAccount, AeternaDevice
from app.models.aeterna_notification import AeternaContact, AeternaRecipientSuppression
from app.models.aeterna_recovery import AeternaRecoveryRecord
from app.models.aeterna_trigger_test import (
    AeternaTriggerTest,
    AeternaTriggerTestChallenge,
    AeternaTriggerTestMail,
)
from app.schemas.client.aeterna_trigger_test import TriggerTestRequest
from app.services.common.aeterna_email_adapter import (
    AeternaEmailAdapter,
    AeternaEmailEnvelope,
    EmailDeliveryFailure,
    UnavailableProductionEmailAdapter,
    get_aeterna_email_adapter,
)
from app.services.common.aeterna_management import (
    AeternaManagementAuthorityService,
    get_aeterna_management_authority_service,
)
from app.services.common.aeterna_security import (
    AeternaIdentityKeys,
    decode_base64url,
    decrypt_email,
    decrypt_private_text,
    encode_base64url,
    encrypt_private_text,
    get_identity_keys,
    make_otp,
    make_token,
    otp_verifier,
    private_request_digest,
    token_digest,
    verify_otp,
    verify_signature,
)
from app.services.internal.inactivity_timing import due_inactivity_transition

WARNING_SECONDS = 60
INACTIVITY_SECONDS = 120
GRACE_SECONDS = 60
SESSION_LIFETIME = timedelta(minutes=30)
CHALLENGE_LIFETIME = timedelta(minutes=10)
CLAIM_LIFETIME = timedelta(minutes=5)
DEVICE_DORMANCY = timedelta(days=30)
TERMINAL_STATES = {"STOPPED", "EXPIRED"}
STAGE = {
    "PREPARING": "preparing",
    "ACTIVE": "waiting",
    "PRE_WARNING": "warning",
    "GRACE_PERIOD": "grace",
    "RELEASED": "released",
    "COMPLETE": "complete",
    "STOPPED": "stopped",
    "EXPIRED": "expired",
}


def timestamp(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z") if value else None


class AeternaTriggerTestService:
    """Lock account then test then mail/challenge; only test-owned rows mutate."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        keys: Callable[[], AeternaIdentityKeys] = get_identity_keys,
        adapter: AeternaEmailAdapter | None = None,
        management: AeternaManagementAuthorityService | None = None,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
        uuid_factory: Callable[[], uuid.UUID] = uuid.uuid4,
        notice_origin: str = "",
    ):
        self.clock = clock
        self.keys = keys
        self.adapter = adapter
        self.management = management or AeternaManagementAuthorityService()
        self.random_bytes = random_bytes
        self.uuid_factory = uuid_factory
        self.notice_origin = notice_origin.rstrip("/")
        self.available = (
            bool(self.notice_origin)
            and adapter is not None
            and not isinstance(adapter, UnavailableProductionEmailAdapter)
        )

    def _now(self):
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise RuntimeError("Trigger-test server time must be aware UTC")
        return now

    def _error(self, signed, code, status=None):
        status = status or {
            "trigger_test.not_found": 404,
            "trigger_test.conflict": 409,
            "trigger_test.expired": 410,
            "trigger_test.not_ready": 409,
            "trigger_test.recipient_unavailable": 409,
            "trigger_test.rate_limited": 429,
            "trigger_test.claim_invalid": 401,
            "trigger_test.binding_mismatch": 409,
            "trigger_test.attempts_exhausted": 429,
        }.get(code, 400)
        return AeternaProtocolException(status, code, signed.request_id)

    async def operate(
        self, db: AsyncSession, payload: TriggerTestRequest, document: dict
    ) -> dict:
        signed = payload.signed
        operation = signed.operation.removeprefix("trigger_test.")
        error = None
        result = {}
        async with db.begin():
            account, device = await self._authorize(db, payload, document)
            now = self._now()
            keys = self.keys()
            if operation == "create":
                test = await self._create(
                    db, account, device, signed, document, keys, now
                )
            else:
                test = await self._test(db, account.id, device.id, signed.session_id)
                if test is not None and test.expires_at <= now:
                    await self._expire(db, test, now)
                if operation != "read":
                    if test is None:
                        raise self._error(signed, "trigger_test.not_found", 404)
                    if test.state in TERMINAL_STATES and operation != "stop":
                        # Commit expiry invalidation before returning the protocol error.
                        error = self._error(signed, "trigger_test.expired")
                    else:
                        duplicate = self._receipt(test, document, keys, signed)
                        result = (
                            {}
                            if duplicate and operation == "retry"
                            else await self._act(db, test, signed, operation, keys, now)
                        )
                        if isinstance(result, AeternaProtocolException):
                            error, result = result, {}
            view = await self._view(db, account, test, keys, now)
            result = {"view": view, **result}
        if error is not None:
            raise error
        return result

    async def _authorize(self, db, payload, document):
        signed = payload.signed
        account = await db.scalar(
            select(AeternaAccount)
            .where(
                AeternaAccount.id == uuid.UUID(signed.account_id),
                AeternaAccount.is_active.is_(True),
            )
            .with_for_update()
        )
        device = await db.scalar(
            select(AeternaDevice)
            .where(
                AeternaDevice.id == uuid.UUID(signed.device_id),
                AeternaDevice.account_id == uuid.UUID(signed.account_id),
            )
            .with_for_update()
        )
        if (
            account is None
            or device is None
            or not verify_signature(
                device.public_key, document["signed"], payload.signature
            )
        ):
            raise self._error(signed, "device.proof_invalid", 401)
        reference = device.last_seen_at or device.heartbeat_authorized_at
        if device.status != "active" or reference + DEVICE_DORMANCY <= self._now():
            raise self._error(signed, "device.not_active", 403)
        return account, device

    async def _test(self, db, account_id, device_id, session_id):
        query = select(AeternaTriggerTest).where(
            AeternaTriggerTest.account_id == account_id,
            AeternaTriggerTest.device_id == device_id,
        )
        if session_id is not None:
            query = query.where(AeternaTriggerTest.id == uuid.UUID(session_id))
        else:
            query = query.order_by(
                AeternaTriggerTest.created_at.desc(), AeternaTriggerTest.id.desc()
            ).limit(1)
        return await db.scalar(query.with_for_update())

    async def _create(self, db, account, device, signed, document, keys, now):
        if not self.available:
            raise self._error(signed, "trigger_test.unavailable", 503)
        digest = private_request_digest(keys, document)
        replay = await db.scalar(
            select(AeternaTriggerTest).where(
                AeternaTriggerTest.create_request_id == uuid.UUID(signed.request_id)
            )
        )
        if replay is not None:
            if (
                replay.account_id != account.id
                or replay.device_id != device.id
                or not secrets.compare_digest(replay.create_request_digest, digest)
            ):
                raise self._error(signed, "request.idempotency_conflict", 409)
            return replay
        active = list(
            await db.scalars(
                select(AeternaTriggerTest)
                .where(
                    AeternaTriggerTest.account_id == account.id,
                    AeternaTriggerTest.device_id == device.id,
                    AeternaTriggerTest.state.not_in({"COMPLETE", "STOPPED", "EXPIRED"}),
                )
                .with_for_update()
            )
        )
        for previous in active:
            if previous.expires_at <= now:
                await self._expire(db, previous, now)
            else:
                raise self._error(signed, "trigger_test.conflict", 409)
        count = await db.scalar(
            select(func.count(AeternaTriggerTest.id)).where(
                AeternaTriggerTest.account_id == account.id,
                AeternaTriggerTest.created_at >= now - timedelta(days=1),
            )
        )
        if count >= 3:
            raise self._error(signed, "trigger_test.rate_limited", 429)
        owner = await self.management.mailbox(db, keys, account)
        recipient = owner
        contact_id = (
            uuid.UUID(signed.recipient_contact_id)
            if signed.recipient_contact_id
            else None
        )
        if contact_id is not None:
            contact = await db.scalar(
                select(AeternaContact)
                .where(
                    AeternaContact.id == contact_id,
                    AeternaContact.account_id == account.id,
                )
                .with_for_update()
            )
            if not self._eligible_contact(contact):
                raise self._error(signed, "trigger_test.recipient_unavailable")
            if (
                await db.get(AeternaRecipientSuppression, contact.email_lookup)
                is not None
            ):
                raise self._error(signed, "trigger_test.recipient_unavailable")
            recipient = decrypt_email(
                keys,
                contact.email_ciphertext,
                contact.email_nonce,
                "contact",
                contact.id,
                contact.email_key_version,
            )
        if signed.sample_vault_id is not None:
            production = await db.scalar(
                select(AeternaRecoveryRecord.id)
                .where(
                    AeternaRecoveryRecord.vault_id == uuid.UUID(signed.sample_vault_id)
                )
                .limit(1)
            )
            if production is not None:
                raise self._error(signed, "trigger_test.binding_mismatch")
        test_id = self.uuid_factory()
        owner_cipher, owner_nonce, version = encrypt_private_text(
            keys, owner, "trigger-test-owner", test_id, self.random_bytes
        )
        recipient_cipher, recipient_nonce, _ = encrypt_private_text(
            keys, recipient, "trigger-test-recipient", test_id, self.random_bytes
        )
        test = AeternaTriggerTest(
            id=test_id,
            account_id=account.id,
            device_id=device.id,
            contact_id=contact_id,
            locale=signed.locale,
            include_recovery=signed.include_recovery,
            state="PREPARING",
            version=1,
            create_request_id=uuid.UUID(signed.request_id),
            create_request_digest=digest,
            operation_receipts={},
            expires_at=now + SESSION_LIFETIME,
            sample_vault_id=(
                uuid.UUID(signed.sample_vault_id) if signed.sample_vault_id else None
            ),
            owner_ciphertext=owner_cipher,
            owner_nonce=owner_nonce,
            recipient_ciphertext=recipient_cipher,
            recipient_nonce=recipient_nonce,
            email_key_version=version,
            created_at=now,
            updated_at=now,
        )
        db.add(test)
        await db.flush()
        return test

    def _eligible_contact(self, contact):
        return (
            contact is not None
            and contact.deleted_at is None
            and contact.verified_at is not None
            and contact.consent_status == "ACCEPTED"
            and contact.disclosure_mode == "CONFIRM_NOW"
        )

    def _receipt(self, test, document, keys, signed):
        receipts = dict(test.operation_receipts)
        digest = encode_base64url(private_request_digest(keys, document))
        previous = receipts.get(signed.request_id)
        if previous is not None and previous != digest:
            raise self._error(signed, "request.idempotency_conflict", 409)
        if previous is None:
            if len(receipts) >= 128:
                raise self._error(signed, "trigger_test.rate_limited", 429)
            receipts[signed.request_id] = digest
            test.operation_receipts = receipts
        return previous is not None

    def _changed(self, test, now):
        test.version += 1
        test.updated_at = now

    async def _act(self, db, test, signed, operation, keys, now):
        if operation == "provision":
            if test.state != "PREPARING" or not test.include_recovery:
                raise self._error(signed, "trigger_test.binding_mismatch")
            if test.source_recovery_id is None:
                test.source_recovery_id = self.uuid_factory()
                test.source_ciphertext, test.source_nonce, test.factor_key_version = (
                    self._encrypt_factor(keys, test, "source", test.source_recovery_id)
                )
                self._changed(test, now)
            return {
                "source_recovery_id": str(test.source_recovery_id),
                "source_srs": self._factor(keys, test, "source"),
            }
        if operation == "activate":
            if test.state != "PREPARING":
                if test.started_at is not None and self._activation_matches(
                    test, signed
                ):
                    return {}
                raise self._error(signed, "trigger_test.binding_mismatch")
            if test.include_recovery:
                if (
                    test.source_recovery_id is None
                    or signed.sample_vault_id != str(test.sample_vault_id)
                    or signed.source_recovery_id != str(test.source_recovery_id)
                ):
                    raise self._error(signed, "trigger_test.binding_mismatch")
                test.source_wrapper_digest = decode_base64url(signed.wrapper_digest, 32)
            elif signed.sample_vault_id is not None:
                raise self._error(signed, "trigger_test.binding_mismatch")
            test.state, test.started_at = "ACTIVE", now
            test.due_at = now + timedelta(seconds=INACTIVITY_SECONDS)
            self._changed(test, now)
            return {}
        if operation in {"stop", "activity"}:
            if operation == "activity" and test.released_at is not None:
                raise self._error(signed, "trigger_test.conflict")
            if test.state not in TERMINAL_STATES:
                test.state, test.stopped_at = "STOPPED", now
                test.stop_reason = "activity" if operation == "activity" else "user"
                if operation == "activity":
                    test.activity_resumed_at = now
                await self._invalidate(db, test, now)
                self._changed(test, now)
            return {}
        if operation == "retry":
            kind = (
                "warning" if test.state in {"PRE_WARNING", "GRACE_PERIOD"} else "notice"
            )
            if test.state not in {
                "PRE_WARNING",
                "GRACE_PERIOD",
                "RELEASED",
                "COMPLETE",
            }:
                raise self._error(signed, "trigger_test.not_ready")
            event = await db.scalar(
                select(AeternaTriggerTestMail)
                .where(
                    AeternaTriggerTestMail.test_id == test.id,
                    AeternaTriggerTestMail.kind.in_(
                        {"warning", "warning-code"} if kind == "warning" else {"notice"}
                    ),
                )
                .order_by(AeternaTriggerTestMail.created_at.desc())
                .limit(1)
                .with_for_update()
            )
            if event is None or event.status != "failed" or event.attempt_count >= 3:
                raise self._error(signed, "trigger_test.not_ready")
            event.status, event.last_error_code = "queued", None
            self._changed(test, now)
            return {}
        if operation in {"warning_challenge", "recipient_challenge"}:
            purpose = "warning" if operation == "warning_challenge" else "recipient"
            if purpose == "warning":
                if (
                    test.state not in {"PRE_WARNING", "GRACE_PERIOD"}
                    or test.owner_warning_proven_at is not None
                ):
                    raise self._error(signed, "trigger_test.not_ready")
            else:
                if (
                    test.state not in {"RELEASED", "COMPLETE"}
                    or test.notice_verifier is None
                    or not secrets.compare_digest(
                        token_digest(signed.notice_token), test.notice_verifier
                    )
                ):
                    raise self._error(signed, "trigger_test.claim_invalid")
            challenge = await self._challenge(db, test, keys, purpose, now)
            return {
                "challenge": {
                    "id": str(challenge.id),
                    "expiresAt": timestamp(challenge.expires_at),
                    "resendAfterSeconds": max(
                        0,
                        int(
                            (
                                challenge.created_at + timedelta(seconds=60) - now
                            ).total_seconds()
                        ),
                    ),
                }
            }
        if operation in {"warning_verify", "recipient_verify"}:
            purpose = "warning" if operation == "warning_verify" else "recipient"
            return await self._verify(db, test, signed, keys, purpose, now)
        if operation in {"release_secret", "rotation_confirm"}:
            self._require_claim(test, signed, now)
            if (
                signed.sample_vault_id != str(test.sample_vault_id)
                or not test.include_recovery
            ):
                raise self._error(signed, "trigger_test.binding_mismatch")
            if operation == "release_secret":
                if signed.source_recovery_id != str(test.source_recovery_id):
                    raise self._error(signed, "trigger_test.binding_mismatch")
                if test.target_recovery_id is None:
                    test.target_recovery_id = self.uuid_factory()
                    (
                        test.target_ciphertext,
                        test.target_nonce,
                        test.factor_key_version,
                    ) = self._encrypt_factor(
                        keys, test, "target", test.target_recovery_id
                    )
                    self._changed(test, now)
                return {
                    "source_srs": self._factor(keys, test, "source"),
                    "target_recovery_id": str(test.target_recovery_id),
                    "target_srs": self._factor(keys, test, "target"),
                }
            if signed.target_recovery_id != str(test.target_recovery_id):
                raise self._error(signed, "trigger_test.binding_mismatch")
            digest = decode_base64url(signed.wrapper_digest, 32)
            if test.target_wrapper_digest is not None and not secrets.compare_digest(
                test.target_wrapper_digest, digest
            ):
                raise self._error(signed, "trigger_test.binding_mismatch")
            if test.sample_rotated_at is None:
                test.target_wrapper_digest, test.sample_rotated_at = digest, now
                test.state, test.completed_at = "COMPLETE", now
                self._changed(test, now)
            return {}
        raise self._error(signed, "protocol.invalid_request")

    def _activation_matches(self, test, signed):
        if not test.include_recovery:
            return signed.sample_vault_id is None
        return (
            signed.sample_vault_id == str(test.sample_vault_id)
            and signed.source_recovery_id == str(test.source_recovery_id)
            and secrets.compare_digest(
                decode_base64url(signed.wrapper_digest, 32), test.source_wrapper_digest
            )
        )

    def _encrypt_factor(self, keys, test, role, recovery_id):
        factor = bytearray(self.random_bytes(32))
        try:
            content = json.dumps(
                {
                    "role": role,
                    "recovery_id": str(recovery_id),
                    "srs": encode_base64url(factor),
                },
                separators=(",", ":"),
            )
            return encrypt_private_text(
                keys, content, "trigger-test-srs", test.id, self.random_bytes
            )
        finally:
            factor[:] = b"\x00" * len(factor)

    def _factor(self, keys, test, role):
        ciphertext, nonce, recovery_id = (
            (test.source_ciphertext, test.source_nonce, test.source_recovery_id)
            if role == "source"
            else (test.target_ciphertext, test.target_nonce, test.target_recovery_id)
        )
        value = json.loads(
            decrypt_private_text(
                keys,
                ciphertext,
                nonce,
                "trigger-test-srs",
                test.id,
                test.factor_key_version,
            )
        )
        if (
            set(value) != {"role", "recovery_id", "srs"}
            or value["role"] != role
            or value["recovery_id"] != str(recovery_id)
        ):
            raise RuntimeError("Isolated test factor binding is invalid")
        decode_base64url(value["srs"], 32)
        return value["srs"]

    def _require_claim(self, test, signed, now):
        if (
            test.state not in {"RELEASED", "COMPLETE"}
            or test.claim_verifier is None
            or test.claim_expires_at <= now
            or not secrets.compare_digest(
                token_digest(signed.claim_token), test.claim_verifier
            )
        ):
            raise self._error(signed, "trigger_test.claim_invalid")

    async def _challenge(self, db, test, keys, purpose, now, initial=False):
        previous = await db.scalar(
            select(AeternaTriggerTestChallenge)
            .where(
                AeternaTriggerTestChallenge.test_id == test.id,
                AeternaTriggerTestChallenge.purpose == purpose,
            )
            .order_by(AeternaTriggerTestChallenge.created_at.desc())
            .limit(1)
            .with_for_update()
        )
        if (
            previous is not None
            and previous.status == "pending"
            and previous.expires_at > now
            and previous.created_at + timedelta(seconds=60) > now
        ):
            return previous
        count = await db.scalar(
            select(func.count(AeternaTriggerTestChallenge.id)).where(
                AeternaTriggerTestChallenge.test_id == test.id,
                AeternaTriggerTestChallenge.purpose == purpose,
            )
        )
        if count >= 5:
            raise AeternaProtocolException(429, "trigger_test.rate_limited")
        if previous is not None and previous.status == "pending":
            previous.status = "expired"
        challenge_id = self.uuid_factory()
        code = make_otp()
        cipher, nonce, version = encrypt_private_text(
            keys, code, "trigger-test-code", challenge_id, self.random_bytes
        )
        challenge = AeternaTriggerTestChallenge(
            id=challenge_id,
            test_id=test.id,
            purpose=purpose,
            status="pending",
            verifier=otp_verifier(keys, challenge_id, f"trigger-test-{purpose}", code),
            code_ciphertext=cipher,
            code_nonce=nonce,
            key_version=version,
            attempt_count=0,
            expires_at=min(now + CHALLENGE_LIFETIME, test.expires_at),
            created_at=now,
            updated_at=now,
        )
        db.add(challenge)
        await db.flush()
        self._mail(
            db, test, "warning" if initial else f"{purpose}-code", now, challenge.id
        )
        self._changed(test, now)
        return challenge

    async def _verify(self, db, test, signed, keys, purpose, now):
        states = (
            {"PRE_WARNING", "GRACE_PERIOD"}
            if purpose == "warning"
            else {"RELEASED", "COMPLETE"}
        )
        challenge = await db.scalar(
            select(AeternaTriggerTestChallenge)
            .where(
                AeternaTriggerTestChallenge.id == uuid.UUID(signed.challenge_id),
                AeternaTriggerTestChallenge.test_id == test.id,
                AeternaTriggerTestChallenge.purpose == purpose,
            )
            .with_for_update()
        )
        if challenge is not None and challenge.status == "locked":
            return self._error(signed, "trigger_test.attempts_exhausted")
        if challenge is not None and challenge.expires_at <= now:
            return self._error(signed, "trigger_test.challenge_expired")
        if (
            test.state not in states
            or challenge is None
            or challenge.status != "pending"
        ):
            return self._error(signed, "trigger_test.challenge_invalid")
        challenge.attempt_count += 1
        challenge.updated_at = now
        if not verify_otp(
            keys,
            challenge.id,
            f"trigger-test-{purpose}",
            signed.code,
            challenge.verifier,
        ):
            if challenge.attempt_count >= 5:
                challenge.status = "locked"
            self._changed(test, now)
            return self._error(signed, "trigger_test.challenge_invalid")
        challenge.status, challenge.verified_at = "verified", now
        self._changed(test, now)
        if purpose == "warning":
            test.owner_warning_proven_at = now
            if test.state == "GRACE_PERIOD":
                test.grace_started_at = now
            return {}
        test.recipient_verified_at = now
        token, verifier = make_token()
        test.claim_verifier, test.claim_expires_at = verifier, min(
            now + CLAIM_LIFETIME, test.expires_at
        )
        if not test.include_recovery:
            test.state, test.completed_at = "COMPLETE", now
        return {
            "claim_token": token,
            "claim_expires_at": timestamp(test.claim_expires_at),
        }

    def _mail(self, db, test, kind, now, challenge_id=None):
        event_id = self.uuid_factory()
        db.add(
            AeternaTriggerTestMail(
                id=event_id,
                test_id=test.id,
                challenge_id=challenge_id,
                kind=kind,
                status="queued",
                idempotency_key=f"trigger-test:{test.id}:{kind}:{challenge_id or 'once'}",
                attempt_count=0,
                created_at=now,
                updated_at=now,
            )
        )

    async def _invalidate(self, db, test, now):
        test.claim_verifier = None
        test.claim_expires_at = None
        test.notice_verifier = None
        test.notice_ciphertext = None
        test.notice_nonce = None
        test.source_ciphertext = test.source_nonce = None
        test.target_ciphertext = test.target_nonce = None
        await db.execute(
            update(AeternaTriggerTestChallenge)
            .where(
                AeternaTriggerTestChallenge.test_id == test.id,
                AeternaTriggerTestChallenge.status == "pending",
            )
            .values(status="expired", updated_at=now)
        )
        await db.execute(
            update(AeternaTriggerTestMail)
            .where(
                AeternaTriggerTestMail.test_id == test.id,
                AeternaTriggerTestMail.status == "queued",
            )
            .values(status="cancelled", updated_at=now)
        )

    async def _expire(self, db, test, now):
        if test.state not in TERMINAL_STATES:
            test.state = "EXPIRED"
            await self._invalidate(db, test, now)
            self._changed(test, now)

    async def _device_eligible(self, db, test, now):
        device = await db.scalar(
            select(AeternaDevice)
            .where(
                AeternaDevice.id == test.device_id,
                AeternaDevice.account_id == test.account_id,
            )
            .with_for_update()
        )
        return (
            device is not None
            and device.status == "active"
            and (device.last_seen_at or device.heartbeat_authorized_at)
            + DEVICE_DORMANCY
            > now
        )

    async def scan(self, db, test_id):
        async with db.begin():
            account_id = await db.scalar(
                select(AeternaTriggerTest.account_id).where(
                    AeternaTriggerTest.id == test_id
                )
            )
            account = await db.scalar(
                select(AeternaAccount)
                .where(AeternaAccount.id == account_id)
                .with_for_update()
            )
            test = await db.scalar(
                select(AeternaTriggerTest)
                .where(AeternaTriggerTest.id == test_id)
                .with_for_update()
            )
            if account is None or test is None:
                return
            now = self._now()
            if test.expires_at <= now:
                await self._expire(db, test, now)
                return
            if not account.is_active or not await self._device_eligible(db, test, now):
                test.state = "STOPPED"
                await self._invalidate(db, test, now)
                self._changed(test, now)
                return
            if test.state not in {"ACTIVE", "PRE_WARNING", "GRACE_PERIOD"}:
                return
            due = due_inactivity_transition(
                state=test.state,
                now=now,
                due_at=test.due_at,
                warning_window_seconds=WARNING_SECONDS,
                grace_window_seconds=GRACE_SECONDS,
                grace_started_at=test.grace_started_at,
                owner_warning_proven_at=test.owner_warning_proven_at,
            )
            if due is None:
                return
            test.state = due.target_state
            setattr(test, due.timestamp_field, now)
            self._changed(test, now)
            if test.state == "PRE_WARNING":
                await self._challenge(
                    db, test, self.keys(), "warning", now, initial=True
                )
            elif test.state == "RELEASED":
                token, verifier = make_token()
                cipher, nonce, _ = encrypt_private_text(
                    self.keys(),
                    token,
                    "trigger-test-notice",
                    test.id,
                    self.random_bytes,
                )
                test.notice_verifier, test.notice_ciphertext, test.notice_nonce = (
                    verifier,
                    cipher,
                    nonce,
                )
                self._mail(db, test, "notice", now)

    async def dispatch(self, db, mail_id):
        envelope = None
        async with db.begin():
            test_id = await db.scalar(
                select(AeternaTriggerTestMail.test_id).where(
                    AeternaTriggerTestMail.id == mail_id
                )
            )
            account_id = await db.scalar(
                select(AeternaTriggerTest.account_id).where(
                    AeternaTriggerTest.id == test_id
                )
            )
            account = await db.scalar(
                select(AeternaAccount)
                .where(AeternaAccount.id == account_id)
                .with_for_update()
            )
            test = await db.scalar(
                select(AeternaTriggerTest)
                .where(AeternaTriggerTest.id == test_id)
                .with_for_update()
            )
            event = await db.scalar(
                select(AeternaTriggerTestMail)
                .where(AeternaTriggerTestMail.id == mail_id)
                .with_for_update()
            )
            if event is None or test is None or account is None:
                return
            now = self._now()
            if event.status == "sending":
                if event.sending_at + timedelta(minutes=2) <= now:
                    event.status, event.last_error_code = (
                        "ambiguous",
                        "dispatch-interrupted",
                    )
                    self._changed(test, now)
                return
            if event.status != "queued":
                return
            if test.expires_at <= now:
                await self._expire(db, test, now)
            allowed = (
                test.state not in TERMINAL_STATES
                and account.is_active
                and await self._device_eligible(db, test, now)
            )
            if event.kind in {"notice", "recipient-code"}:
                allowed = allowed and test.state in {"RELEASED", "COMPLETE"}
            if event.kind in {"warning", "warning-code"}:
                allowed = allowed and test.state in {"PRE_WARNING", "GRACE_PERIOD"}
            keys = self.keys()
            if test.contact_id is not None and event.kind in {
                "notice",
                "recipient-code",
            }:
                contact = await db.scalar(
                    select(AeternaContact)
                    .where(AeternaContact.id == test.contact_id)
                    .with_for_update()
                )
                allowed = allowed and self._eligible_contact(contact)
                if allowed:
                    allowed = (
                        await db.get(AeternaRecipientSuppression, contact.email_lookup)
                        is None
                    )
                    current_email = decrypt_email(
                        keys,
                        contact.email_ciphertext,
                        contact.email_nonce,
                        "contact",
                        contact.id,
                        contact.email_key_version,
                    )
                    allowed = allowed and current_email == self._email(
                        keys, test, "recipient"
                    )
            if event.challenge_id is not None:
                challenge = await db.get(
                    AeternaTriggerTestChallenge, event.challenge_id
                )
                allowed = (
                    allowed
                    and challenge is not None
                    and challenge.status == "pending"
                    and challenge.expires_at > now
                )
            if not allowed:
                event.status = "cancelled"
                self._changed(test, now)
                return
            envelope = await self._render(db, event, test, keys)
            event.status, event.sending_at = "sending", now
            event.attempt_count += 1
            self._changed(test, now)
            key = event.idempotency_key
        try:
            if self.adapter is None:
                raise EmailDeliveryFailure(
                    "test-email-provider-unavailable", retryable=False
                )
            acceptance = await self.adapter.send(envelope, key)
            if (
                acceptance.provider_name != self.adapter.provider_name
                or len(acceptance.provider_message_id) > 256
            ):
                raise EmailDeliveryFailure(
                    "test-email-provider-invalid", retryable=False, ambiguous=True
                )
            status, error = "provider_accepted", None
        except EmailDeliveryFailure as exc:
            status, error = ("ambiguous" if exc.ambiguous else "failed"), (
                "test-email-ambiguous" if exc.ambiguous else "test-email-failed"
            )
            acceptance = None
        except Exception:
            status, error, acceptance = "ambiguous", "test-email-ambiguous", None
        async with db.begin():
            await db.scalar(
                select(AeternaAccount)
                .where(AeternaAccount.id == account_id)
                .with_for_update()
            )
            test = await db.scalar(
                select(AeternaTriggerTest)
                .where(AeternaTriggerTest.id == test_id)
                .with_for_update()
            )
            event = await db.scalar(
                select(AeternaTriggerTestMail)
                .where(AeternaTriggerTestMail.id == mail_id)
                .with_for_update()
            )
            if event is None or test is None or event.status != "sending":
                return
            event.status, event.last_error_code = status, error
            if acceptance is not None:
                event.accepted_at, event.provider_name, event.provider_message_id = (
                    acceptance.accepted_at,
                    acceptance.provider_name,
                    acceptance.provider_message_id,
                )
            self._changed(test, self._now())

    def _email(self, keys, test, kind):
        cipher, nonce = (
            (test.owner_ciphertext, test.owner_nonce)
            if kind == "owner"
            else (test.recipient_ciphertext, test.recipient_nonce)
        )
        return decrypt_private_text(
            keys, cipher, nonce, f"trigger-test-{kind}", test.id, test.email_key_version
        )

    async def _render(self, db, event, test, keys):
        from app.services.common.aeterna_trigger_test_copy import trigger_test_copy

        copy = trigger_test_copy(test.locale)
        recipient = self._email(
            keys,
            test,
            "recipient" if event.kind in {"notice", "recipient-code"} else "owner",
        )
        if event.challenge_id is not None:
            challenge = await db.get(AeternaTriggerTestChallenge, event.challenge_id)
            code = decrypt_private_text(
                keys,
                challenge.code_ciphertext,
                challenge.code_nonce,
                "trigger-test-code",
                challenge.id,
                challenge.key_version,
            )
            label = (
                copy["warningCode"]
                if event.kind in {"warning", "warning-code"}
                else copy["recipientCode"]
            )
            body = f'{copy["intro"]}\n\n{label}: {code}\n{copy["codeExpiry"]}'
        else:
            token = decrypt_private_text(
                keys,
                test.notice_ciphertext,
                test.notice_nonce,
                "trigger-test-notice",
                test.id,
                test.email_key_version,
            )
            if not self.notice_origin:
                raise RuntimeError("The test notice origin is unavailable")
            link = f"{self.notice_origin}/trigger-tests/notice#session={test.id}&token={token}"
            body = f'{copy["intro"]}\n\n{copy["notice"]}\n{link}'
        return AeternaEmailEnvelope(
            recipient,
            copy["subject"],
            body,
            f"<p>{html.escape(body).replace(chr(10), '<br>')}</p>",
            track_in_outbox=False,
        )

    async def _view(self, db, account, test, keys, now):
        owner = await self.management.mailbox(db, keys, account)
        recipients = [{"id": "owner", "kind": "owner", "email": owner}]
        contacts = list(
            await db.scalars(
                select(AeternaContact)
                .where(
                    AeternaContact.account_id == account.id,
                    AeternaContact.deleted_at.is_(None),
                    AeternaContact.verified_at.is_not(None),
                    AeternaContact.consent_status == "ACCEPTED",
                    AeternaContact.disclosure_mode == "CONFIRM_NOW",
                )
                .order_by(AeternaContact.created_at)
                .limit(10)
            )
        )
        for contact in contacts:
            if await db.get(AeternaRecipientSuppression, contact.email_lookup) is None:
                recipients.append(
                    {
                        "id": str(contact.id),
                        "kind": "contact",
                        "email": decrypt_email(
                            keys,
                            contact.email_ciphertext,
                            contact.email_nonce,
                            "contact",
                            contact.id,
                            contact.email_key_version,
                        ),
                    }
                )
        session = None
        if test is not None:
            mail = list(
                await db.scalars(
                    select(AeternaTriggerTestMail).where(
                        AeternaTriggerTestMail.test_id == test.id
                    )
                )
            )
            transports = {
                kind: self._transport(
                    [
                        item
                        for item in mail
                        if item.kind
                        in (
                            {"warning", "warning-code"}
                            if kind == "warning"
                            else {"notice"}
                        )
                    ]
                )
                for kind in ("warning", "notice")
            }
            warning_at = (
                test.started_at + timedelta(seconds=WARNING_SECONDS)
                if test.started_at
                else None
            )
            release_at = (
                max(test.grace_started_at, test.owner_warning_proven_at)
                + timedelta(seconds=GRACE_SECONDS)
                if test.grace_started_at and test.owner_warning_proven_at
                else None
            )
            if test.released_at is not None:
                release_at = test.released_at
            next_at = {
                "ACTIVE": warning_at,
                "PRE_WARNING": test.due_at,
                "GRACE_PERIOD": release_at,
            }.get(test.state)
            observed = timestamp(now)
            evidence = []
            for key, verified, at in (
                ("trigger", test.released_at is not None, test.released_at),
                (
                    "warning",
                    test.owner_warning_proven_at is not None,
                    test.owner_warning_proven_at,
                ),
                (
                    "notification",
                    transports["notice"] == "accepted",
                    max(
                        (
                            item.accepted_at
                            for item in mail
                            if item.kind == "notice" and item.accepted_at is not None
                        ),
                        default=None,
                    ),
                ),
                (
                    "recipient",
                    test.recipient_verified_at is not None,
                    test.recipient_verified_at,
                ),
                (
                    "recovery",
                    test.sample_rotated_at is not None,
                    test.sample_rotated_at,
                ),
                (
                    "activity",
                    test.activity_resumed_at is not None,
                    test.activity_resumed_at,
                ),
            ):
                outcome = "verified" if verified else "not_verified"
                if not verified and key == "recovery" and not test.include_recovery:
                    outcome = "not_selected"
                elif not verified and (
                    key == "activity"
                    or test.state in {"PREPARING", "ACTIVE"}
                    or (
                        test.activity_resumed_at is not None
                        and key in {"trigger", "notification", "recipient", "recovery"}
                    )
                ):
                    outcome = "not_tested"
                evidence.append(
                    {"key": key, "outcome": outcome, "observedAt": timestamp(at)}
                )
            session = {
                "id": str(test.id),
                "version": test.version,
                "stage": STAGE[test.state],
                "includeRecovery": test.include_recovery,
                "recipientId": str(test.contact_id) if test.contact_id else "owner",
                "recipientEmail": self._email(keys, test, "recipient"),
                "warningAt": timestamp(warning_at),
                "dueAt": timestamp(test.due_at),
                "releaseAt": timestamp(release_at),
                "nextAt": timestamp(next_at),
                "expiresAt": timestamp(test.expires_at),
                "observedAt": observed,
                "warningTransport": transports["warning"],
                "notificationTransport": transports["notice"],
                "warningConfirmed": test.owner_warning_proven_at is not None,
                "recipientVerified": test.recipient_verified_at is not None,
                "sampleState": (
                    "protected"
                    if test.sample_rotated_at
                    else "prepared" if test.source_wrapper_digest else "absent"
                ),
                "activityStopped": test.activity_resumed_at is not None,
                "evidence": evidence,
            }
        return {
            "available": self.available or test is not None,
            "sampleRecoveryAvailable": self.available,
            "ownerEmail": owner,
            "recipients": recipients,
            "session": session,
        }

    def _transport(self, mail):
        if not mail:
            return "not_started"
        latest = max(mail, key=lambda item: item.created_at)
        return {
            "queued": "pending",
            "sending": "unknown",
            "provider_accepted": "accepted",
            "failed": "failed",
            "ambiguous": "unknown",
            "cancelled": "not_started",
        }[latest.status]

    async def cleanup(self, db):
        now = self._now()
        async with db.begin():
            # Expired results retain minimal evidence for one day; factors are already cleared.
            await db.execute(
                delete(AeternaTriggerTest).where(
                    AeternaTriggerTest.expires_at < now - timedelta(days=1)
                )
            )


def get_aeterna_trigger_test_service() -> AeternaTriggerTestService:
    from app.core.config import settings
    from app.services.common.aeterna_trigger_test_origin import (
        validated_test_notice_origin,
    )

    return AeternaTriggerTestService(
        adapter=get_aeterna_email_adapter(),
        management=get_aeterna_management_authority_service(),
        notice_origin=validated_test_notice_origin(
            settings.AETERNA_TRIGGER_TEST_NOTICE_ORIGIN, settings.ENV
        ),
    )
