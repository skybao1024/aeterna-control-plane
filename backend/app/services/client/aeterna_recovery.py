"""Transactional delayed-recovery provisioning and one-time claim service."""

from __future__ import annotations

import base64
import secrets
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.models.account_policy import AccountPolicy, AccountPolicyState
from app.models.aeterna_identity import AeternaAccount, AeternaDevice
from app.models.aeterna_notification import AeternaContact, AeternaEmailOutboxEvent
from app.models.aeterna_recovery import (
    AeternaRecoveryAudit,
    AeternaRecoveryClaimLink,
    AeternaRecoveryClaimToken,
    AeternaRecoveryGrant,
    AeternaRecoveryOtpChallenge,
    AeternaRecoveryRecord,
)
from app.schemas.client.aeterna_recovery import (
    RecoveryClaimStartRequest,
    RecoveryClaimVerifyRequest,
    RecoveryRecordActionRequest,
    RecoveryRecordProvisionRequest,
    RecoverySecretRequest,
)
from app.services.common.aeterna_recovery_key import (
    KMS_CONTEXT_VERSION,
    RecoveryKeyProvider,
    RecoveryKeyUnavailable,
    get_recovery_key_provider,
    recovery_encryption_context,
)
from app.services.common.aeterna_security import (
    AeternaIdentityKeys,
    IdentityKeyUnavailable,
    decode_base64url,
    derive_recovery_link_token,
    derive_recovery_otp,
    encode_base64url,
    get_identity_keys,
    make_token,
    otp_verifier,
    request_digest,
    token_digest,
    verify_otp,
    verify_signature,
)

PROVISION_LIFETIME = timedelta(hours=24)
CLAIM_LINK_LIFETIME = timedelta(hours=24)
OTP_LIFETIME = timedelta(minutes=10)
OTP_RESEND = timedelta(seconds=60)
CLAIM_TOKEN_LIFETIME = timedelta(minutes=5)
MAX_OTP_ATTEMPTS = 5


def utc_now() -> datetime:
    return datetime.now(UTC)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class AeternaRecoveryService:
    """Own SRS envelopes, release authorization, and contact-scoped claims."""

    def __init__(
        self,
        *,
        provision_provider: Callable[
            [], RecoveryKeyProvider
        ] = get_recovery_key_provider,
        claim_provider: Callable[[], RecoveryKeyProvider] = get_recovery_key_provider,
        identity_key_provider: Callable[[], AeternaIdentityKeys] = get_identity_keys,
        clock: Callable[[], datetime] = utc_now,
        uuid_factory: Callable[[], uuid.UUID] = uuid.uuid4,
    ):
        self.provision_provider = provision_provider
        self.claim_provider = claim_provider
        self.identity_key_provider = identity_key_provider
        self.clock = clock
        self.uuid_factory = uuid_factory

    async def provision_record(
        self,
        db: AsyncSession,
        payload: RecoveryRecordProvisionRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        signed = payload.signed
        request_id = signed.request_id
        account_id = uuid.UUID(signed.account_id)
        device_id = uuid.UUID(signed.device_id)
        recovery_id = uuid.UUID(signed.recovery_id)
        vault_id = uuid.UUID(signed.vault_id)
        account, policy, device = await self._authorize_device(
            db, account_id, device_id, request_id, document["signed"], payload.signature
        )
        digest = request_digest(document)
        replay = await db.scalar(
            select(AeternaRecoveryRecord).where(
                AeternaRecoveryRecord.provision_request_id == uuid.UUID(request_id)
            )
        )
        if replay is not None:
            if replay.account_id != account.id or not secrets.compare_digest(
                replay.provision_request_digest, digest
            ):
                raise AeternaProtocolException(
                    409, "request.idempotency_conflict", request_id
                )
            raise AeternaProtocolException(
                409, "recovery.provision_retry_required", request_id
            )
        if policy.state in {
            AccountPolicyState.RELEASED.value,
            AccountPolicyState.DISABLED.value,
            AccountPolicyState.DELETED.value,
        }:
            raise AeternaProtocolException(
                409, "recovery.record_unavailable", request_id
            )
        now = self._now()
        existing = await db.scalar(
            select(AeternaRecoveryRecord)
            .where(
                AeternaRecoveryRecord.account_id == account.id,
                AeternaRecoveryRecord.device_id == device.id,
                AeternaRecoveryRecord.vault_id == vault_id,
                AeternaRecoveryRecord.state.in_({"pending_confirmation", "sealed"}),
            )
            .with_for_update()
        )
        if existing is not None and (
            existing.state != "pending_confirmation" or existing.expires_at > now
        ):
            raise AeternaProtocolException(
                409, "recovery.record_unavailable", request_id
            )
        if existing is not None:
            await db.delete(existing)
            await db.flush()

        context = recovery_encryption_context(
            environment=settings.ENV,
            protocol_version=1,
            account_id=account.id,
            device_id=device.id,
            vault_id=vault_id,
            recovery_id=recovery_id,
        )
        try:
            envelope = self.provision_provider().generate_srs(context)
        except RecoveryKeyUnavailable:
            raise AeternaProtocolException(
                503, "recovery.material_unavailable", request_id
            ) from None
        try:
            record = AeternaRecoveryRecord(
                id=recovery_id,
                account_id=account.id,
                device_id=device.id,
                vault_id=vault_id,
                state="pending_confirmation",
                encrypted_srs=envelope.ciphertext,
                kms_provider=(
                    "aws-kms" if envelope.key_arn.startswith("arn:") else "local-test"
                ),
                kms_key_arn=envelope.key_arn,
                kms_key_material_id=envelope.key_material_id,
                kms_context_version=KMS_CONTEXT_VERSION,
                crypto_format_version=signed.crypto_format_version,
                recovery_context_version=signed.recovery_context_version,
                provision_request_id=uuid.UUID(request_id),
                provision_request_digest=digest,
                expires_at=now + PROVISION_LIFETIME,
            )
            db.add(record)
            self._audit(
                db,
                account.id,
                recovery_id,
                None,
                None,
                uuid.UUID(request_id),
                "record.provisioned",
            )
            await db.commit()
            return {
                "account_id": str(account.id),
                "device_id": str(device.id),
                "expires_at": format_timestamp(record.expires_at),
                "kms_context_version": KMS_CONTEXT_VERSION,
                "recovery_id": str(record.id),
                "srs": encode_base64url(bytes(envelope.plaintext)),
                "state": record.state,
                "vault_id": str(record.vault_id),
            }
        finally:
            envelope.plaintext[:] = b"\x00" * len(envelope.plaintext)

    async def act_on_record(
        self,
        db: AsyncSession,
        payload: RecoveryRecordActionRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        signed = payload.signed
        account_id = uuid.UUID(signed.account_id)
        device_id = uuid.UUID(signed.device_id)
        _account, policy, _device = await self._authorize_device(
            db,
            account_id,
            device_id,
            signed.request_id,
            document["signed"],
            payload.signature,
        )
        record = await db.scalar(
            select(AeternaRecoveryRecord)
            .where(
                AeternaRecoveryRecord.id == uuid.UUID(signed.recovery_id),
                AeternaRecoveryRecord.account_id == account_id,
                AeternaRecoveryRecord.device_id == device_id,
                AeternaRecoveryRecord.vault_id == uuid.UUID(signed.vault_id),
            )
            .with_for_update()
        )
        if record is None or policy.state in {
            AccountPolicyState.RELEASED.value,
            AccountPolicyState.DISABLED.value,
            AccountPolicyState.DELETED.value,
        }:
            raise AeternaProtocolException(
                409, "recovery.record_unavailable", signed.request_id
            )
        now = self._now()
        if signed.operation == "recovery_record.confirm":
            wrapper_digest = decode_base64url(signed.wrapper_digest, 32)
            if record.state == "sealed" and secrets.compare_digest(
                record.wrapper_digest, wrapper_digest
            ):
                await db.rollback()
                return self._record_data(record, now)
            if record.state != "pending_confirmation" or record.expires_at <= now:
                raise AeternaProtocolException(
                    409, "recovery.record_unavailable", signed.request_id
                )
            record.state = "sealed"
            record.wrapper_digest = wrapper_digest
            record.confirmed_at = now
            event_type = "record.confirmed"
        else:
            if record.state == "abandoned":
                await db.rollback()
                return self._record_data(record, now)
            if record.state != "pending_confirmation":
                raise AeternaProtocolException(
                    409, "recovery.record_unavailable", signed.request_id
                )
            record.state = "abandoned"
            record.abandoned_at = now
            event_type = "record.abandoned"
        record.updated_at = now
        self._audit(
            db,
            account_id,
            record.id,
            None,
            None,
            uuid.UUID(signed.request_id),
            event_type,
        )
        await db.commit()
        return self._record_data(record, now)

    async def materialize_released_account(
        self, db: AsyncSession, account_id: uuid.UUID
    ) -> list[uuid.UUID]:
        account = await db.scalar(
            select(AeternaAccount)
            .where(AeternaAccount.id == account_id, AeternaAccount.is_active.is_(True))
            .with_for_update()
        )
        policy = await db.scalar(
            select(AccountPolicy)
            .where(AccountPolicy.account_id == account_id)
            .with_for_update()
        )
        if (
            account is None
            or policy is None
            or policy.state != AccountPolicyState.RELEASED.value
        ):
            await db.rollback()
            return []
        records = list(
            (
                await db.scalars(
                    select(AeternaRecoveryRecord)
                    .where(
                        AeternaRecoveryRecord.account_id == account_id,
                        AeternaRecoveryRecord.state == "sealed",
                    )
                    .with_for_update()
                )
            ).all()
        )
        contacts = list(
            (
                await db.scalars(
                    select(AeternaContact)
                    .where(
                        AeternaContact.account_id == account_id,
                        AeternaContact.consent_status == "ACCEPTED",
                        AeternaContact.verified_at.is_not(None),
                        AeternaContact.deleted_at.is_(None),
                    )
                    .with_for_update()
                )
            ).all()
        )
        keys = self._identity_keys()
        now = self._now()
        created: list[uuid.UUID] = []
        for record in records:
            for contact in contacts:
                grant = await db.scalar(
                    select(AeternaRecoveryGrant).where(
                        AeternaRecoveryGrant.recovery_id == record.id,
                        AeternaRecoveryGrant.contact_id == contact.id,
                    )
                )
                if grant is not None:
                    continue
                grant = AeternaRecoveryGrant(
                    id=self.uuid_factory(),
                    account_id=account_id,
                    recovery_id=record.id,
                    contact_id=contact.id,
                    state="available",
                    released_at=now,
                )
                db.add(grant)
                await db.flush()
                link_id = self.uuid_factory()
                link_token = derive_recovery_link_token(keys, link_id)
                link = AeternaRecoveryClaimLink(
                    id=link_id,
                    grant_id=grant.id,
                    token_digest=token_digest(link_token),
                    token_key_version=keys.version,
                    status="active",
                    expires_at=now + CLAIM_LINK_LIFETIME,
                    created_at=now,
                    updated_at=now,
                )
                db.add(link)
                await db.flush()
                event = self._email_event(
                    account_id=account_id,
                    contact_id=contact.id,
                    event_type="recovery-claim-link",
                    idempotency_key=f"recovery-claim-link:{grant.id}",
                    now=now,
                    recovery_link_id=link.id,
                )
                db.add(event)
                created.append(grant.id)
                self._audit(
                    db,
                    account_id,
                    record.id,
                    contact.id,
                    grant.id,
                    None,
                    "grant.created",
                )
        await db.commit()
        return created

    async def start_claim(
        self, db: AsyncSession, payload: RecoveryClaimStartRequest
    ) -> dict[str, Any]:
        try:
            digest = token_digest(payload.claim_link_token)
        except ValueError:
            return await self._dummy_challenge(db)
        relation = (
            await db.execute(
                select(
                    AeternaRecoveryClaimLink.id,
                    AeternaRecoveryGrant.account_id,
                    AeternaRecoveryGrant.id.label("grant_id"),
                )
                .join(
                    AeternaRecoveryGrant,
                    AeternaRecoveryGrant.id == AeternaRecoveryClaimLink.grant_id,
                )
                .where(AeternaRecoveryClaimLink.token_digest == digest)
            )
        ).one_or_none()
        if relation is None:
            return await self._dummy_challenge(db)
        account = await db.scalar(
            select(AeternaAccount)
            .where(AeternaAccount.id == relation.account_id)
            .with_for_update()
        )
        policy = await db.scalar(
            select(AccountPolicy)
            .where(AccountPolicy.account_id == relation.account_id)
            .with_for_update()
        )
        grant = await db.scalar(
            select(AeternaRecoveryGrant)
            .where(AeternaRecoveryGrant.id == relation.grant_id)
            .with_for_update()
        )
        contact = (
            await db.scalar(
                select(AeternaContact)
                .where(AeternaContact.id == grant.contact_id)
                .with_for_update()
            )
            if grant is not None
            else None
        )
        record = (
            await db.scalar(
                select(AeternaRecoveryRecord)
                .where(AeternaRecoveryRecord.id == grant.recovery_id)
                .with_for_update()
            )
            if grant is not None
            else None
        )
        link = await db.scalar(
            select(AeternaRecoveryClaimLink)
            .where(AeternaRecoveryClaimLink.id == relation.id)
            .with_for_update()
        )
        now = self._now()
        authority_available = (
            account is not None
            and policy is not None
            and grant is not None
            and contact is not None
            and record is not None
            and link is not None
            and policy.state == AccountPolicyState.RELEASED.value
            and grant.state == "available"
            and record.state == "sealed"
            and contact.consent_status == "ACCEPTED"
            and contact.verified_at is not None
            and contact.deleted_at is None
        )
        if (
            authority_available
            and link is not None
            and link.status in {"active", "expired"}
            and link.expires_at <= now
        ):
            if link.status == "active":
                link.status = "expired"
                link.consumed_at = now
                link.updated_at = now
            await self._issue_replacement_link(db, grant, now)
            await db.commit()
            return self._neutral_challenge()
        if (
            not authority_available
            or link is None
            or link.status != "active"
            or link.expires_at <= now
        ):
            return await self._dummy_challenge(db)
        challenge = await db.scalar(
            select(AeternaRecoveryOtpChallenge)
            .where(
                AeternaRecoveryOtpChallenge.link_id == link.id,
                AeternaRecoveryOtpChallenge.status == "active",
            )
            .order_by(AeternaRecoveryOtpChallenge.created_at.desc())
            .limit(1)
            .with_for_update()
        )
        if challenge is not None and (
            challenge.expires_at <= now or challenge.resend_after <= now
        ):
            challenge.status = "expired"
            challenge.updated_at = now
            challenge = None
        if challenge is None:
            keys = self._identity_keys(payload.request_id)
            challenge_id = self.uuid_factory()
            code = derive_recovery_otp(keys, challenge_id)
            challenge = AeternaRecoveryOtpChallenge(
                id=challenge_id,
                link_id=link.id,
                otp_verifier=otp_verifier(keys, challenge_id, "recovery-claim", code),
                otp_key_version=keys.version,
                attempt_count=0,
                status="active",
                expires_at=now + OTP_LIFETIME,
                resend_after=now + OTP_RESEND,
                created_at=now,
                updated_at=now,
            )
            db.add(challenge)
            await db.flush()
            db.add(
                self._email_event(
                    account_id=grant.account_id,
                    contact_id=grant.contact_id,
                    event_type="recovery-otp",
                    idempotency_key=f"recovery-otp:{challenge.id}",
                    now=now,
                    recovery_challenge_id=challenge.id,
                )
            )
            self._audit(
                db,
                grant.account_id,
                grant.recovery_id,
                grant.contact_id,
                grant.id,
                uuid.UUID(payload.request_id),
                "claim.started",
            )
        await db.commit()
        return {
            "challenge_id": str(challenge.id),
            "expires_in_seconds": 600,
            "resend_after_seconds": 60,
        }

    async def verify_claim(
        self, db: AsyncSession, payload: RecoveryClaimVerifyRequest
    ) -> dict[str, Any]:
        relation = (
            await db.execute(
                select(
                    AeternaRecoveryOtpChallenge.id.label("challenge_id"),
                    AeternaRecoveryClaimLink.id.label("link_id"),
                    AeternaRecoveryGrant.id.label("grant_id"),
                    AeternaRecoveryGrant.account_id,
                    AeternaRecoveryGrant.contact_id,
                    AeternaRecoveryGrant.recovery_id,
                )
                .join(
                    AeternaRecoveryClaimLink,
                    AeternaRecoveryClaimLink.id == AeternaRecoveryOtpChallenge.link_id,
                )
                .join(
                    AeternaRecoveryGrant,
                    AeternaRecoveryGrant.id == AeternaRecoveryClaimLink.grant_id,
                )
                .where(
                    AeternaRecoveryOtpChallenge.id == uuid.UUID(payload.challenge_id)
                )
            )
        ).one_or_none()
        if relation is None:
            raise AeternaProtocolException(
                400, "recovery.otp_invalid", payload.request_id
            )
        account = await db.scalar(
            select(AeternaAccount)
            .where(AeternaAccount.id == relation.account_id)
            .with_for_update()
        )
        policy = await db.scalar(
            select(AccountPolicy)
            .where(AccountPolicy.account_id == relation.account_id)
            .with_for_update()
        )
        contact = await db.scalar(
            select(AeternaContact)
            .where(AeternaContact.id == relation.contact_id)
            .with_for_update()
        )
        record = await db.scalar(
            select(AeternaRecoveryRecord)
            .where(AeternaRecoveryRecord.id == relation.recovery_id)
            .with_for_update()
        )
        grant = await db.scalar(
            select(AeternaRecoveryGrant)
            .where(AeternaRecoveryGrant.id == relation.grant_id)
            .with_for_update()
        )
        link = await db.scalar(
            select(AeternaRecoveryClaimLink)
            .where(AeternaRecoveryClaimLink.id == relation.link_id)
            .with_for_update()
        )
        challenge = await db.scalar(
            select(AeternaRecoveryOtpChallenge)
            .where(AeternaRecoveryOtpChallenge.id == relation.challenge_id)
            .with_for_update()
        )
        if challenge is None:
            raise AeternaProtocolException(
                400, "recovery.otp_invalid", payload.request_id
            )
        now = self._now()
        keys = self._identity_keys(payload.request_id)
        valid_link = False
        if link is not None:
            try:
                valid_link = secrets.compare_digest(
                    link.token_digest, token_digest(payload.claim_link_token)
                )
            except ValueError:
                valid_link = False
        valid = (
            valid_link
            and account is not None
            and grant is not None
            and record is not None
            and policy is not None
            and contact is not None
            and challenge is not None
            and link is not None
            and policy.state == AccountPolicyState.RELEASED.value
            and grant.state == "available"
            and record.state == "sealed"
            and record.wrapper_digest is not None
            and contact.consent_status == "ACCEPTED"
            and contact.verified_at is not None
            and contact.deleted_at is None
            and link.status == "active"
            and link.expires_at > now
            and challenge.status == "active"
            and challenge.expires_at > now
            and challenge.attempt_count < MAX_OTP_ATTEMPTS
            and verify_otp(
                keys,
                challenge.id,
                "recovery-claim",
                payload.code,
                challenge.otp_verifier,
            )
        )
        if not valid:
            challenge.attempt_count = min(MAX_OTP_ATTEMPTS, challenge.attempt_count + 1)
            if challenge.attempt_count >= MAX_OTP_ATTEMPTS:
                challenge.status = "locked"
            challenge.updated_at = now
            await db.commit()
            code = (
                "recovery.otp_attempts_exhausted"
                if challenge.status == "locked"
                else "recovery.otp_invalid"
            )
            raise AeternaProtocolException(
                429 if challenge.status == "locked" else 400,
                code,
                payload.request_id,
            )
        claim_token, claim_digest = make_token()
        challenge.status = "verified"
        challenge.verified_at = now
        challenge.updated_at = now
        link.status = "consumed"
        link.consumed_at = now
        link.updated_at = now
        claim = AeternaRecoveryClaimToken(
            id=self.uuid_factory(),
            grant_id=grant.id,
            account_id=grant.account_id,
            contact_id=grant.contact_id,
            recovery_id=record.id,
            device_id=record.device_id,
            vault_id=record.vault_id,
            wrapper_digest=record.wrapper_digest,
            token_digest=claim_digest,
            scope="recovery.srs.read",
            status="active",
            expires_at=now + CLAIM_TOKEN_LIFETIME,
        )
        db.add(claim)
        self._audit(
            db,
            grant.account_id,
            record.id,
            grant.contact_id,
            grant.id,
            uuid.UUID(payload.request_id),
            "claim.verified",
        )
        await db.commit()
        return {
            "account_id": str(grant.account_id),
            "claim_token": claim_token,
            "device_id": str(record.device_id),
            "expires_at": format_timestamp(claim.expires_at),
            "recovery_id": str(record.id),
            "scope": claim.scope,
            "vault_id": str(record.vault_id),
            "wrapper_digest": encode_base64url(record.wrapper_digest),
        }

    async def release_secret(
        self, db: AsyncSession, payload: RecoverySecretRequest
    ) -> dict[str, Any]:
        try:
            digest = token_digest(payload.claim_token)
        except ValueError:
            raise AeternaProtocolException(
                400, "recovery.claim_unavailable", payload.request_id
            ) from None
        relation = (
            await db.execute(
                select(
                    AeternaRecoveryClaimToken.id,
                    AeternaRecoveryClaimToken.account_id,
                    AeternaRecoveryClaimToken.contact_id,
                    AeternaRecoveryClaimToken.recovery_id,
                    AeternaRecoveryClaimToken.grant_id,
                ).where(AeternaRecoveryClaimToken.token_digest == digest)
            )
        ).one_or_none()
        if relation is None:
            raise AeternaProtocolException(
                400, "recovery.claim_unavailable", payload.request_id
            )
        account = await db.scalar(
            select(AeternaAccount)
            .where(AeternaAccount.id == relation.account_id)
            .with_for_update()
        )
        policy = await db.scalar(
            select(AccountPolicy)
            .where(AccountPolicy.account_id == relation.account_id)
            .with_for_update()
        )
        record = await db.scalar(
            select(AeternaRecoveryRecord)
            .where(AeternaRecoveryRecord.id == relation.recovery_id)
            .with_for_update()
        )
        grant = await db.scalar(
            select(AeternaRecoveryGrant)
            .where(AeternaRecoveryGrant.id == relation.grant_id)
            .with_for_update()
        )
        contact = await db.scalar(
            select(AeternaContact)
            .where(AeternaContact.id == relation.contact_id)
            .with_for_update()
        )
        claim = await db.scalar(
            select(AeternaRecoveryClaimToken)
            .where(AeternaRecoveryClaimToken.id == relation.id)
            .with_for_update()
        )
        now = self._now()
        try:
            wrapper_digest = decode_base64url(payload.wrapper_digest, 32)
        except ValueError:
            wrapper_digest = b""
        if (
            account is None
            or policy is None
            or record is None
            or grant is None
            or contact is None
            or claim is None
            or policy.state != AccountPolicyState.RELEASED.value
            or record.state != "sealed"
            or record.wrapper_digest is None
            or grant.state != "available"
            or contact.consent_status != "ACCEPTED"
            or contact.verified_at is None
            or contact.deleted_at is not None
            or claim.status != "active"
            or claim.expires_at <= now
            or claim.scope != "recovery.srs.read"
            or str(record.id) != payload.recovery_id
            or str(record.device_id) != payload.device_id
            or str(record.vault_id) != payload.vault_id
            or not secrets.compare_digest(record.wrapper_digest, wrapper_digest)
            or not secrets.compare_digest(claim.wrapper_digest, wrapper_digest)
        ):
            raise AeternaProtocolException(
                400, "recovery.claim_unavailable", payload.request_id
            )
        context = recovery_encryption_context(
            environment=settings.ENV,
            protocol_version=1,
            account_id=record.account_id,
            device_id=record.device_id,
            vault_id=record.vault_id,
            recovery_id=record.id,
        )
        try:
            plaintext = self.claim_provider().decrypt_srs(
                record.encrypted_srs, record.kms_key_arn, context
            )
        except RecoveryKeyUnavailable:
            raise AeternaProtocolException(
                503, "recovery.material_unavailable", payload.request_id
            ) from None
        try:
            claim.status = "consumed"
            claim.consumed_at = now
            claim.updated_at = now
            grant.state = "claimed"
            grant.claimed_at = now
            grant.updated_at = now
            self._audit(
                db,
                record.account_id,
                record.id,
                grant.contact_id,
                grant.id,
                uuid.UUID(payload.request_id),
                "secret.released",
            )
            db.add(
                self._email_event(
                    account_id=record.account_id,
                    contact_id=None,
                    event_type="recovery-claimed-owner",
                    idempotency_key=f"recovery-claimed-owner:{grant.id}",
                    now=now,
                )
            )
            other_contacts = list(
                (
                    await db.scalars(
                        select(AeternaContact).where(
                            AeternaContact.account_id == record.account_id,
                            AeternaContact.id != grant.contact_id,
                            AeternaContact.consent_status == "ACCEPTED",
                            AeternaContact.verified_at.is_not(None),
                            AeternaContact.deleted_at.is_(None),
                        )
                    )
                ).all()
            )
            for contact in other_contacts:
                db.add(
                    self._email_event(
                        account_id=record.account_id,
                        contact_id=contact.id,
                        event_type="recovery-claimed-contact",
                        idempotency_key=f"recovery-claimed-contact:{grant.id}:{contact.id}",
                        now=now,
                    )
                )
            await db.commit()
            return {
                "account_id": str(record.account_id),
                "device_id": str(record.device_id),
                "recovery_id": str(record.id),
                "srs": base64.urlsafe_b64encode(bytes(plaintext))
                .rstrip(b"=")
                .decode("ascii"),
                "vault_id": str(record.vault_id),
                "wrapper_digest": encode_base64url(record.wrapper_digest),
            }
        finally:
            plaintext[:] = b"\x00" * len(plaintext)

    async def _authorize_device(
        self,
        db: AsyncSession,
        account_id: uuid.UUID,
        device_id: uuid.UUID,
        request_id: str,
        signed_document: dict[str, Any],
        signature: str,
    ) -> tuple[AeternaAccount, AccountPolicy, AeternaDevice]:
        account = await db.scalar(
            select(AeternaAccount)
            .where(AeternaAccount.id == account_id, AeternaAccount.is_active.is_(True))
            .with_for_update()
        )
        policy = await db.scalar(
            select(AccountPolicy)
            .where(AccountPolicy.account_id == account_id)
            .with_for_update()
        )
        device = await db.scalar(
            select(AeternaDevice)
            .where(
                AeternaDevice.id == device_id,
                AeternaDevice.account_id == account_id,
            )
            .with_for_update()
        )
        if (
            account is None
            or policy is None
            or device is None
            or device.status != "active"
            or not verify_signature(device.public_key, signed_document, signature)
        ):
            raise AeternaProtocolException(401, "device.proof_invalid", request_id)
        return account, policy, device

    async def _dummy_challenge(self, db: AsyncSession) -> dict[str, Any]:
        await db.rollback()
        return self._neutral_challenge()

    def _neutral_challenge(self) -> dict[str, Any]:
        return {
            "challenge_id": str(self.uuid_factory()),
            "expires_in_seconds": 600,
            "resend_after_seconds": 60,
        }

    async def _issue_replacement_link(
        self,
        db: AsyncSession,
        grant: AeternaRecoveryGrant,
        now: datetime,
    ) -> bool:
        rolling_start = now - CLAIM_LINK_LIFETIME
        issued_count = await db.scalar(
            select(func.count(AeternaRecoveryClaimLink.id)).where(
                AeternaRecoveryClaimLink.grant_id == grant.id,
                AeternaRecoveryClaimLink.created_at >= rolling_start,
            )
        )
        latest_issued_at = await db.scalar(
            select(AeternaRecoveryClaimLink.created_at)
            .where(AeternaRecoveryClaimLink.grant_id == grant.id)
            .order_by(AeternaRecoveryClaimLink.created_at.desc())
            .limit(1)
        )
        if (issued_count or 0) >= 3 or (
            latest_issued_at is not None and latest_issued_at > now - OTP_RESEND
        ):
            return False

        keys = self._identity_keys()
        link_id = self.uuid_factory()
        link_token = derive_recovery_link_token(keys, link_id)
        link = AeternaRecoveryClaimLink(
            id=link_id,
            grant_id=grant.id,
            token_digest=token_digest(link_token),
            token_key_version=keys.version,
            status="active",
            expires_at=now + CLAIM_LINK_LIFETIME,
            created_at=now,
            updated_at=now,
        )
        db.add(link)
        await db.flush()
        db.add(
            self._email_event(
                account_id=grant.account_id,
                contact_id=grant.contact_id,
                event_type="recovery-claim-link",
                idempotency_key=f"recovery-claim-link:{grant.id}:{link.id}",
                now=now,
                recovery_link_id=link.id,
            )
        )
        return True

    def _record_data(
        self, record: AeternaRecoveryRecord, updated_at: datetime
    ) -> dict[str, Any]:
        return {
            "account_id": str(record.account_id),
            "device_id": str(record.device_id),
            "recovery_id": str(record.id),
            "state": record.state,
            "updated_at": format_timestamp(updated_at),
            "vault_id": str(record.vault_id),
        }

    def _email_event(
        self,
        *,
        account_id: uuid.UUID,
        contact_id: uuid.UUID | None,
        event_type: str,
        idempotency_key: str,
        now: datetime,
        recovery_link_id: uuid.UUID | None = None,
        recovery_challenge_id: uuid.UUID | None = None,
    ) -> AeternaEmailOutboxEvent:
        return AeternaEmailOutboxEvent(
            id=self.uuid_factory(),
            account_id=account_id,
            contact_id=contact_id,
            recovery_link_id=recovery_link_id,
            recovery_challenge_id=recovery_challenge_id,
            recipient_kind="contact" if contact_id is not None else "owner",
            event_type=event_type,
            idempotency_key=idempotency_key,
            status="queued",
            next_attempt_at=now,
            attempt_count=0,
        )

    def _audit(
        self,
        db: AsyncSession,
        account_id: uuid.UUID,
        recovery_id: uuid.UUID | None,
        contact_id: uuid.UUID | None,
        grant_id: uuid.UUID | None,
        request_id: uuid.UUID | None,
        event_type: str,
    ) -> None:
        db.add(
            AeternaRecoveryAudit(
                id=self.uuid_factory(),
                account_id=account_id,
                recovery_id=recovery_id,
                contact_id=contact_id,
                grant_id=grant_id,
                request_id=request_id,
                event_type=event_type,
                status="succeeded",
            )
        )

    def _identity_keys(self, request_id: str | None = None) -> AeternaIdentityKeys:
        try:
            return self.identity_key_provider()
        except IdentityKeyUnavailable:
            raise AeternaProtocolException(
                503, "service.temporarily_unavailable", request_id
            ) from None

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise RuntimeError("The recovery clock must be timezone-aware")
        return value.astimezone(UTC)


def get_aeterna_recovery_service() -> AeternaRecoveryService:
    return AeternaRecoveryService()
