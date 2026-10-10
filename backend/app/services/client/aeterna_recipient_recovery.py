"""Device-signed recipient rotation of one released historical Vault."""

from __future__ import annotations

import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from cryptography.exceptions import InvalidTag
from sqlalchemy import delete, func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.models.account_policy import AccountPolicy, AccountPolicyState
from app.models.aeterna_identity import AeternaAccount, AeternaDevice
from app.models.aeterna_management import (
    AeternaCustodyChallenge,
    AeternaManagementAlias,
)
from app.models.aeterna_notification import AeternaContact
from app.models.aeterna_recipient_recovery import AeternaRecipientRecoveryRotation
from app.models.aeterna_recovery import (
    AeternaRecoveryClaimLink,
    AeternaRecoveryClaimToken,
    AeternaRecoveryGrant,
    AeternaRecoveryRecord,
)
from app.schemas.client.aeterna_recipient_recovery import (
    RecipientRecoveryAbandonRequest,
    RecipientRecoveryConfirmRequest,
    RecipientRecoveryPrepareRequest,
    RecipientRecoveryProvisionRequest,
    RecipientRecoveryProvisionSigned,
    RecipientRecoverySecretRequest,
    RecoveryCustodyChallengeRequest,
    RecoveryCustodyVerifyRequest,
)
from app.services.client.aeterna_recovery import (
    AeternaRecoveryService,
    format_timestamp,
    get_aeterna_recovery_service,
)
from app.services.common.aeterna_custody_limiter import (
    AeternaCustodyLimiter,
    get_aeterna_custody_limiter,
)
from app.services.common.aeterna_management import (
    AeternaManagementAuthorityService,
    get_aeterna_management_authority_service,
)
from app.services.common.aeterna_recovery_key import (
    RecoveryKeyUnavailable,
    recovery_encryption_context,
)
from app.services.common.aeterna_security import (
    IdentityKeyUnavailable,
    decode_base64url,
    decrypt_email,
    encode_base64url,
    request_digest,
    token_digest,
    verify_signature,
)

RECIPIENT_SCOPE = "recovery.recipient.rotate"
MAX_ABANDONED_ROTATIONS_PER_DAY = 16
CUSTODY_CHALLENGE_LIFETIME = timedelta(minutes=5)
CUSTODY_CLEANUP_BATCH_SIZE = 256

RecipientRequest = (
    RecipientRecoverySecretRequest
    | RecipientRecoveryProvisionRequest
    | RecipientRecoveryPrepareRequest
    | RecipientRecoveryConfirmRequest
    | RecipientRecoveryAbandonRequest
)


@dataclass(repr=False)
class RecipientAuthority:
    record: AeternaRecoveryRecord
    grant: AeternaRecoveryGrant
    claim: AeternaRecoveryClaimToken
    rotation: AeternaRecipientRecoveryRotation | None


class AeternaRecipientRecoveryService:
    """Keep successor material durable and confirm explicit account handoff."""

    def __init__(
        self,
        *,
        recovery_service: AeternaRecoveryService | None = None,
        custody_limiter: AeternaCustodyLimiter | None = None,
        management_service: AeternaManagementAuthorityService | None = None,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
        recovery_service_provider: Callable[
            [], AeternaRecoveryService
        ] = get_aeterna_recovery_service,
    ):
        self.recovery = recovery_service or recovery_service_provider()
        self.random_bytes = random_bytes
        self.custody_limiter = custody_limiter or get_aeterna_custody_limiter()
        self.management = (
            management_service or get_aeterna_management_authority_service()
        )

    async def _authorize(
        self,
        db: AsyncSession,
        payload: RecipientRequest,
        document: dict[str, Any],
        *,
        allow_complete: bool = False,
    ) -> RecipientAuthority:
        signed = payload.signed
        request_id = signed.request_id
        claim = await db.scalar(
            select(AeternaRecoveryClaimToken).where(
                AeternaRecoveryClaimToken.token_digest
                == token_digest(payload.claim_token)
            )
        )
        if claim is None:
            raise AeternaProtocolException(
                400, "recovery.claim_unavailable", request_id
            )
        # All recovery writers serialize on the account before locking children.
        account = await db.scalar(
            select(AeternaAccount)
            .where(AeternaAccount.id == claim.account_id)
            .with_for_update()
        )
        record = await db.scalar(
            select(AeternaRecoveryRecord)
            .where(AeternaRecoveryRecord.id == claim.recovery_id)
            .with_for_update()
        )
        policy = (
            await db.scalar(
                select(AccountPolicy)
                .where(
                    AccountPolicy.account_id == claim.account_id,
                    AccountPolicy.epoch == record.policy_epoch,
                )
                .with_for_update()
            )
            if record is not None
            else None
        )
        grant = await db.scalar(
            select(AeternaRecoveryGrant)
            .where(AeternaRecoveryGrant.id == claim.grant_id)
            .with_for_update()
        )
        contact = await db.scalar(
            select(AeternaContact)
            .where(AeternaContact.id == claim.contact_id)
            .with_for_update()
        )
        claim = await db.scalar(
            select(AeternaRecoveryClaimToken)
            .where(AeternaRecoveryClaimToken.id == claim.id)
            .execution_options(populate_existing=True)
            .with_for_update()
        )
        if claim is None:
            raise AeternaProtocolException(
                400, "recovery.claim_unavailable", request_id
            )
        device = await db.scalar(
            select(AeternaDevice)
            .where(AeternaDevice.id == uuid.UUID(signed.device_id))
            .with_for_update()
        )
        rotation = await db.scalar(
            select(AeternaRecipientRecoveryRotation)
            .where(AeternaRecipientRecoveryRotation.id == uuid.UUID(signed.rotation_id))
            .with_for_update()
        )
        now = self.recovery._now()
        wrapper = decode_base64url(signed.wrapper_digest, 32)
        completed = (
            allow_complete
            and rotation is not None
            and rotation.state == "complete"
            and rotation.contact_id == claim.contact_id
            and rotation.grant_id == claim.grant_id
            and rotation.source_recovery_id == claim.recovery_id
        )
        if (
            account is None
            or not account.is_active
            or record is None
            or policy is None
            or grant is None
            or contact is None
            or claim is None
            or policy.state != AccountPolicyState.RELEASED.value
            or (
                record.state != "sealed"
                and not (completed and record.state == "revoked")
            )
            or (
                grant.state != "available"
                and not (completed and grant.state == "revoked")
            )
            or record.wrapper_digest is None
            or grant.recovery_id != record.id
            or grant.account_id != account.id
            or grant.contact_id != contact.id
            or contact.account_id != account.id
            or contact.consent_status != "ACCEPTED"
            or contact.verified_at is None
            or contact.deleted_at is not None
            or (
                claim.status != "active"
                and not (completed and claim.status == "expired")
            )
            or claim.expires_at <= now
            or claim.scope != RECIPIENT_SCOPE
            or str(account.id) != signed.account_id
            or str(record.id) != signed.recovery_id
            or str(record.device_id) != signed.device_id
            or str(record.vault_id) != signed.vault_id
            or claim.device_id != record.device_id
            or claim.vault_id != record.vault_id
            or not secrets.compare_digest(record.wrapper_digest, wrapper)
            or not secrets.compare_digest(claim.wrapper_digest, wrapper)
        ):
            raise AeternaProtocolException(
                400, "recovery.claim_unavailable", request_id
            )
        if (
            device is None
            or device.account_id != account.id
            or device.status != "active"
            or not verify_signature(
                device.public_key, document["signed"], payload.signature
            )
        ):
            raise AeternaProtocolException(401, "device.proof_invalid", request_id)
        if rotation is not None and (
            rotation.account_id != account.id
            or rotation.contact_id != contact.id
            or rotation.grant_id != grant.id
            or rotation.device_id != record.device_id
            or rotation.source_recovery_id != record.id
            or rotation.vault_id != record.vault_id
            or not secrets.compare_digest(rotation.source_wrapper_digest, wrapper)
        ):
            raise AeternaProtocolException(
                409, "recovery.recipient_rotation_unavailable", request_id
            )
        return RecipientAuthority(record, grant, claim, rotation)

    def _context(
        self, record: AeternaRecoveryRecord, recovery_id: uuid.UUID
    ) -> dict[str, str]:
        return recovery_encryption_context(
            environment=settings.ENV,
            protocol_version=1,
            account_id=record.account_id,
            device_id=record.device_id,
            vault_id=record.vault_id,
            recovery_id=recovery_id,
        )

    def _audit(
        self,
        db: AsyncSession,
        authority: RecipientAuthority,
        request_id: str,
        event: str,
    ) -> None:
        self.recovery._audit(
            db,
            authority.record.account_id,
            authority.record.id,
            authority.grant.contact_id,
            authority.grant.id,
            uuid.UUID(request_id),
            event,
        )

    async def release_secret(
        self,
        db: AsyncSession,
        payload: RecipientRecoverySecretRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        authority = await self._authorize(db, payload, document)
        record = authority.record
        request_id = payload.signed.request_id
        rotation = authority.rotation
        new_reservation = rotation is None
        signed_digest = request_digest(document["signed"])
        replay = await db.scalar(
            select(AeternaRecipientRecoveryRotation).where(
                AeternaRecipientRecoveryRotation.secret_request_id
                == uuid.UUID(request_id)
            )
        )
        if replay is not None and (
            replay.id != uuid.UUID(payload.signed.rotation_id)
            or not secrets.compare_digest(replay.secret_request_digest, signed_digest)
        ):
            raise AeternaProtocolException(
                409, "request.idempotency_conflict", request_id
            )
        if rotation is None:
            live = await db.scalar(
                select(AeternaRecipientRecoveryRotation.id).where(
                    AeternaRecipientRecoveryRotation.source_recovery_id == record.id,
                    AeternaRecipientRecoveryRotation.state != "abandoned",
                )
            )
            if live is not None:
                raise AeternaProtocolException(
                    409, "recovery.recipient_rotation_in_progress", request_id
                )
            now = self.recovery._now()
            abandoned_count = await db.scalar(
                select(func.count(AeternaRecipientRecoveryRotation.id)).where(
                    AeternaRecipientRecoveryRotation.source_recovery_id == record.id,
                    AeternaRecipientRecoveryRotation.state == "abandoned",
                    AeternaRecipientRecoveryRotation.created_at
                    > now - timedelta(days=1),
                )
            )
            if abandoned_count >= MAX_ABANDONED_ROTATIONS_PER_DAY:
                raise AeternaProtocolException(
                    429, "recovery.recipient_rotation_limit", request_id
                )
            rotation = AeternaRecipientRecoveryRotation(
                id=uuid.UUID(payload.signed.rotation_id),
                account_id=record.account_id,
                contact_id=authority.grant.contact_id,
                grant_id=authority.grant.id,
                device_id=record.device_id,
                source_recovery_id=record.id,
                vault_id=record.vault_id,
                source_policy_epoch=record.policy_epoch,
                source_generation=record.recovery_generation,
                source_wrapper_digest=record.wrapper_digest,
                target_generation=1,
                state="reserved",
                secret_request_id=uuid.UUID(request_id),
                secret_request_digest=signed_digest,
                created_at=now,
                updated_at=now,
            )
            db.add(rotation)
            self._audit(db, authority, request_id, "recipient.reserved")
        elif rotation.state != "reserved":
            raise AeternaProtocolException(
                409, "recovery.recipient_rotation_unavailable", request_id
            )
        try:
            plaintext = self.recovery.claim_provider().decrypt_srs(
                record.encrypted_srs,
                record.kms_key_arn,
                self._context(record, record.id),
            )
        except RecoveryKeyUnavailable:
            raise AeternaProtocolException(
                503, "recovery.material_unavailable", request_id
            ) from None
        try:
            if new_reservation:
                now = self.recovery._now()
                db.add(
                    self.recovery._email_event(
                        account_id=record.account_id,
                        contact_id=None,
                        event_type="recovery-claimed-owner",
                        idempotency_key=f"recipient-released-owner:{rotation.id}",
                        now=now,
                    )
                )
                other_contacts = list(
                    (
                        await db.scalars(
                            select(AeternaContact).where(
                                AeternaContact.account_id == record.account_id,
                                AeternaContact.id != authority.grant.contact_id,
                                AeternaContact.consent_status == "ACCEPTED",
                                AeternaContact.verified_at.is_not(None),
                                AeternaContact.deleted_at.is_(None),
                            )
                        )
                    ).all()
                )
                for contact in other_contacts:
                    db.add(
                        self.recovery._email_event(
                            account_id=record.account_id,
                            contact_id=contact.id,
                            event_type="recovery-claimed-contact",
                            idempotency_key=f"recipient-released-contact:{rotation.id}:{contact.id}",
                            now=now,
                        )
                    )
            await db.commit()
            return {
                "account_id": str(record.account_id),
                "device_id": str(record.device_id),
                "vault_id": str(record.vault_id),
                "recovery_id": str(record.id),
                "wrapper_digest": encode_base64url(record.wrapper_digest),
                "policy_epoch": record.policy_epoch,
                "recovery_generation": record.recovery_generation,
                "rekey_required": True,
                "srs": encode_base64url(plaintext),
                "rotation_id": str(rotation.id),
                "state": "reserved",
            }
        finally:
            plaintext[:] = b"\x00" * len(plaintext)

    def _require_rotation(
        self, authority: RecipientAuthority, request_id: str
    ) -> AeternaRecipientRecoveryRotation:
        rotation = authority.rotation
        if rotation is None or rotation.state == "abandoned":
            raise AeternaProtocolException(
                409, "recovery.recipient_rotation_unavailable", request_id
            )
        return rotation

    def _target_matches(
        self,
        rotation: AeternaRecipientRecoveryRotation,
        signed: RecipientRecoveryProvisionSigned,
    ) -> bool:
        return (
            str(rotation.target_recovery_id) == signed.target_recovery_id
            and rotation.erc_commitment is not None
            and secrets.compare_digest(
                rotation.erc_commitment, decode_base64url(signed.erc_commitment, 32)
            )
        )

    def _target_data(
        self, rotation: AeternaRecipientRecoveryRotation
    ) -> dict[str, Any]:
        return {
            "account_id": str(rotation.account_id),
            "device_id": str(rotation.device_id),
            "vault_id": str(rotation.vault_id),
            "rotation_id": str(rotation.id),
            "source_recovery_id": str(rotation.source_recovery_id),
            "source_wrapper_digest": encode_base64url(rotation.source_wrapper_digest),
            "source_policy_epoch": rotation.source_policy_epoch,
            "source_generation": rotation.source_generation,
            "target_recovery_id": str(rotation.target_recovery_id),
            "target_policy_epoch": rotation.source_policy_epoch,
            "target_generation": 1,
            "erc_commitment": encode_base64url(rotation.erc_commitment),
            "binding_kind": "recipient_successor",
        }

    def _result(
        self,
        rotation: AeternaRecipientRecoveryRotation,
        management_email: str | None = None,
    ) -> dict[str, Any]:
        return {
            **self._target_data(rotation),
            "target_wrapper_digest": encode_base64url(rotation.target_wrapper_digest),
            "state": rotation.state,
            "protection_active": False,
            "account_management_transferred": rotation.state == "complete"
            and rotation.management_alias_id is not None,
            "management_email": management_email,
            "updated_at": format_timestamp(rotation.updated_at),
        }

    async def provision(
        self,
        db: AsyncSession,
        payload: RecipientRecoveryProvisionRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        authority = await self._authorize(db, payload, document)
        request_id = payload.signed.request_id
        rotation = self._require_rotation(authority, request_id)
        target_id = uuid.UUID(payload.signed.target_recovery_id)
        if rotation.state != "reserved" and not self._target_matches(
            rotation, payload.signed
        ):
            raise AeternaProtocolException(
                409, "recovery.recipient_rotation_conflict", request_id
            )
        if rotation.state == "reserved":
            existing_record = await db.get(AeternaRecoveryRecord, target_id)
            existing_rotation = await db.scalar(
                select(AeternaRecipientRecoveryRotation.id).where(
                    AeternaRecipientRecoveryRotation.target_recovery_id == target_id
                )
            )
            if existing_record is not None or existing_rotation is not None:
                raise AeternaProtocolException(
                    409, "recovery.recipient_rotation_conflict", request_id
                )
            try:
                envelope = self.recovery.provision_provider().generate_srs(
                    self._context(authority.record, target_id)
                )
            except RecoveryKeyUnavailable:
                raise AeternaProtocolException(
                    503, "recovery.material_unavailable", request_id
                ) from None
            plaintext = envelope.plaintext
            rotation.target_recovery_id = target_id
            rotation.erc_commitment = decode_base64url(
                payload.signed.erc_commitment, 32
            )
            rotation.encrypted_srs = envelope.ciphertext
            rotation.kms_provider = (
                "aws-kms" if envelope.key_arn.startswith("arn:") else "local-test"
            )
            rotation.kms_key_arn = envelope.key_arn
            rotation.kms_key_material_id = envelope.key_material_id
            rotation.state = "provisioned"
            rotation.updated_at = self.recovery._now()
            self._audit(db, authority, request_id, "recipient.provisioned")
        else:
            try:
                plaintext = self.recovery.claim_provider().decrypt_srs(
                    rotation.encrypted_srs,
                    rotation.kms_key_arn,
                    self._context(authority.record, target_id),
                )
            except RecoveryKeyUnavailable:
                raise AeternaProtocolException(
                    503, "recovery.material_unavailable", request_id
                ) from None
        try:
            # Store the encrypted successor before the client can commit its Vault.
            await db.commit()
            return {
                **self._target_data(rotation),
                "state": "provisioned",
                "srs": encode_base64url(plaintext),
            }
        finally:
            plaintext[:] = b"\x00" * len(plaintext)

    async def prepare(
        self,
        db: AsyncSession,
        payload: RecipientRecoveryPrepareRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        authority = await self._authorize(db, payload, document)
        request_id = payload.signed.request_id
        rotation = self._require_rotation(authority, request_id)
        digest = decode_base64url(payload.signed.target_wrapper_digest, 32)
        if rotation.state not in {
            "provisioned",
            "prepared",
        } or not self._target_matches(rotation, payload.signed):
            raise AeternaProtocolException(
                409, "recovery.recipient_rotation_conflict", request_id
            )
        if rotation.state == "prepared":
            if not secrets.compare_digest(rotation.target_wrapper_digest, digest):
                raise AeternaProtocolException(
                    409, "recovery.recipient_rotation_conflict", request_id
                )
        else:
            now = self.recovery._now()
            rotation.target_wrapper_digest = digest
            rotation.state = "prepared"
            rotation.prepared_at = now
            rotation.updated_at = now
            self._audit(db, authority, request_id, "recipient.prepared")
        await db.flush()
        await db.refresh(rotation, ["updated_at"])
        result = self._result(rotation)
        await db.commit()
        return result

    async def confirm(
        self,
        db: AsyncSession,
        payload: RecipientRecoveryConfirmRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        authority = await self._authorize(db, payload, document, allow_complete=True)
        request_id = payload.signed.request_id
        rotation = self._require_rotation(authority, request_id)
        digest = decode_base64url(payload.signed.target_wrapper_digest, 32)
        if (
            rotation.state not in {"prepared", "complete"}
            or not self._target_matches(rotation, payload.signed)
            or not secrets.compare_digest(rotation.target_wrapper_digest, digest)
        ):
            raise AeternaProtocolException(
                409, "recovery.recipient_rotation_conflict", request_id
            )
        now = self.recovery._now()
        try:
            keys = self.recovery._identity_keys(request_id)
            if rotation.management_alias_id is None:
                account = await db.get(AeternaAccount, rotation.account_id)
                contact = await db.get(AeternaContact, rotation.contact_id)
                management_email = await self.management.transfer(
                    db, keys, account, contact, rotation, now
                )
            else:
                alias = await db.get(
                    AeternaManagementAlias, rotation.management_alias_id
                )
                management_email = decrypt_email(
                    keys,
                    alias.email_ciphertext,
                    alias.email_nonce,
                    "account",
                    rotation.account_id,
                    alias.email_key_version,
                )
        except (IdentityKeyUnavailable, InvalidTag, UnicodeError, ValueError):
            raise AeternaProtocolException(
                503, "service.temporarily_unavailable", request_id
            ) from None
        if rotation.state == "complete":
            await db.flush()
            await db.refresh(rotation, ["updated_at"])
            result = self._result(rotation, management_email)
            await db.commit()
            return result
        rotation.state = "complete"
        rotation.completed_at = now
        rotation.updated_at = now
        authority.record.state = "revoked"
        authority.record.abandoned_at = now
        authority.record.updated_at = now
        grants = list(
            (
                await db.scalars(
                    select(AeternaRecoveryGrant)
                    .where(AeternaRecoveryGrant.recovery_id == authority.record.id)
                    .with_for_update()
                )
            ).all()
        )
        grant_ids = [grant.id for grant in grants]
        for grant in grants:
            grant.state = "revoked"
            grant.claimed_at = None
            grant.updated_at = now
        links = list(
            (
                await db.scalars(
                    select(AeternaRecoveryClaimLink)
                    .where(AeternaRecoveryClaimLink.grant_id.in_(grant_ids))
                    .with_for_update()
                )
            ).all()
        )
        for link in links:
            link.status = "revoked"
            link.consumed_at = now
            link.updated_at = now
        claims = list(
            (
                await db.scalars(
                    select(AeternaRecoveryClaimToken)
                    .where(
                        AeternaRecoveryClaimToken.recovery_id == authority.record.id,
                        AeternaRecoveryClaimToken.status == "active",
                    )
                    .with_for_update()
                )
            ).all()
        )
        for claim in claims:
            claim.status = "expired"
            claim.consumed_at = now
            claim.updated_at = now
        self._audit(db, authority, request_id, "recipient.completed")
        await db.flush()
        await db.refresh(rotation, ["updated_at"])
        result = self._result(rotation, management_email)
        await db.commit()
        return result

    async def abandon(
        self,
        db: AsyncSession,
        payload: RecipientRecoveryAbandonRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        authority = await self._authorize(db, payload, document)
        rotation = authority.rotation
        request_id = payload.signed.request_id
        if rotation is None or rotation.state == "complete":
            raise AeternaProtocolException(
                409, "recovery.recipient_rotation_unavailable", request_id
            )
        if rotation.state != "abandoned":
            now = self.recovery._now()
            rotation.state = "abandoned"
            rotation.abandoned_at = now
            rotation.updated_at = now
            # Retain encrypted material: the server cannot prove no local commit occurred.
            self._audit(db, authority, request_id, "recipient.abandoned")
        await db.flush()
        await db.refresh(rotation, ["updated_at"])
        result = {
            "rotation_id": str(rotation.id),
            "state": "abandoned",
            "updated_at": format_timestamp(rotation.updated_at),
        }
        await db.commit()
        return result

    async def _custody_binding(self, db, payload, document):
        signed = payload.signed
        request_id = signed.request_id
        # Read-only validation must not serialize unrelated account writers.
        device = await db.scalar(
            select(AeternaDevice).where(
                AeternaDevice.id == uuid.UUID(signed.device_id),
                AeternaDevice.account_id == uuid.UUID(signed.account_id),
            )
        )
        if (
            device is None
            or device.status != "active"
            or not verify_signature(
                device.public_key, document["signed"], payload.signature
            )
        ):
            raise AeternaProtocolException(401, "device.proof_invalid", request_id)
        await self.custody_limiter.check(
            "device", f"{signed.account_id}:{signed.device_id}", request_id
        )
        account = await db.scalar(
            select(AeternaAccount).where(
                AeternaAccount.id == device.account_id,
                AeternaAccount.is_active.is_(True),
            )
        )
        if account is None:
            raise AeternaProtocolException(401, "device.proof_invalid", request_id)
        wrapper = decode_base64url(signed.wrapper_digest, 32)
        record = await db.scalar(
            select(AeternaRecoveryRecord).where(
                AeternaRecoveryRecord.id == uuid.UUID(signed.recovery_id)
            )
        )
        if record is not None:
            policy = await db.scalar(
                select(AccountPolicy).where(
                    AccountPolicy.account_id == account.id,
                    AccountPolicy.retired_at.is_(None),
                )
            )
            if (
                policy is None
                or policy.state != AccountPolicyState.ACTIVE.value
                or record.state != "sealed"
                or record.account_id != account.id
                or record.device_id != device.id
                or str(record.vault_id) != signed.vault_id
                or record.policy_epoch != account.current_policy_epoch
                or record.recovery_generation != account.current_recovery_generation
                or record.wrapper_digest is None
                or not secrets.compare_digest(record.wrapper_digest, wrapper)
                or record.erc_commitment is None
                or account.erc_commitment is None
                or account.erc_commitment_epoch != record.policy_epoch
                or account.erc_commitment_generation != record.recovery_generation
                or not secrets.compare_digest(
                    record.erc_commitment, account.erc_commitment
                )
            ):
                raise AeternaProtocolException(
                    409, "recovery.record_unavailable", request_id
                )
            return record.erc_commitment
        successor = await db.scalar(
            select(AeternaRecipientRecoveryRotation).where(
                AeternaRecipientRecoveryRotation.target_recovery_id
                == uuid.UUID(signed.recovery_id),
                AeternaRecipientRecoveryRotation.account_id == account.id,
                AeternaRecipientRecoveryRotation.device_id == device.id,
                AeternaRecipientRecoveryRotation.vault_id == uuid.UUID(signed.vault_id),
                AeternaRecipientRecoveryRotation.state == "complete",
                AeternaRecipientRecoveryRotation.management_alias_id.is_not(None),
            )
        )
        if (
            successor is None
            or successor.target_wrapper_digest is None
            or not secrets.compare_digest(successor.target_wrapper_digest, wrapper)
            or successor.erc_commitment is None
        ):
            raise AeternaProtocolException(
                409, "recovery.record_unavailable", request_id
            )
        newer_owner = await db.scalar(
            select(AeternaRecoveryRecord.id)
            .where(
                AeternaRecoveryRecord.account_id == account.id,
                AeternaRecoveryRecord.device_id == device.id,
                AeternaRecoveryRecord.vault_id == successor.vault_id,
                AeternaRecoveryRecord.state == "sealed",
                AeternaRecoveryRecord.confirmed_at >= successor.completed_at,
            )
            .limit(1)
        )
        newer_successor = await db.scalar(
            select(AeternaRecipientRecoveryRotation.id)
            .where(
                AeternaRecipientRecoveryRotation.account_id == account.id,
                AeternaRecipientRecoveryRotation.device_id == device.id,
                AeternaRecipientRecoveryRotation.vault_id == successor.vault_id,
                AeternaRecipientRecoveryRotation.id != successor.id,
                AeternaRecipientRecoveryRotation.state == "complete",
                or_(
                    AeternaRecipientRecoveryRotation.completed_at
                    > successor.completed_at,
                    AeternaRecipientRecoveryRotation.source_policy_epoch
                    > successor.source_policy_epoch,
                ),
            )
            .limit(1)
        )
        if newer_owner is not None or newer_successor is not None:
            raise AeternaProtocolException(
                409, "recovery.record_unavailable", request_id
            )
        return successor.erc_commitment

    def _challenge_result(self, challenge):
        return {
            "challenge_id": str(challenge.id),
            "challenge": encode_base64url(challenge.challenge),
            "expires_at": format_timestamp(challenge.expires_at),
        }

    async def challenge_custody(
        self,
        db: AsyncSession,
        payload: RecoveryCustodyChallengeRequest,
        document: dict[str, Any],
    ):
        await self._custody_binding(db, payload, document)
        signed = payload.signed
        now = self.recovery._now()
        expired = (
            select(AeternaCustodyChallenge.id)
            .where(AeternaCustodyChallenge.expires_at <= now)
            .order_by(AeternaCustodyChallenge.expires_at)
            .limit(CUSTODY_CLEANUP_BATCH_SIZE)
            .with_for_update(skip_locked=True)
        )
        await db.execute(
            delete(AeternaCustodyChallenge).where(
                AeternaCustodyChallenge.id.in_(expired)
            )
        )
        digest = request_digest(document["signed"])
        await db.execute(
            insert(AeternaCustodyChallenge)
            .values(
                id=self.recovery.uuid_factory(),
                account_id=uuid.UUID(signed.account_id),
                device_id=uuid.UUID(signed.device_id),
                vault_id=uuid.UUID(signed.vault_id),
                recovery_id=uuid.UUID(signed.recovery_id),
                wrapper_digest=decode_base64url(signed.wrapper_digest, 32),
                challenge=self.random_bytes(32),
                request_id=uuid.UUID(signed.request_id),
                request_digest=digest,
                expires_at=now + CUSTODY_CHALLENGE_LIFETIME,
                created_at=now,
                updated_at=now,
            )
            .on_conflict_do_nothing(index_elements=["request_id"])
        )
        challenge = await db.scalar(
            select(AeternaCustodyChallenge).where(
                AeternaCustodyChallenge.request_id == uuid.UUID(signed.request_id)
            )
        )
        if not secrets.compare_digest(challenge.request_digest, digest):
            raise AeternaProtocolException(
                409, "request.idempotency_conflict", signed.request_id
            )
        if challenge.expires_at <= now or challenge.consumed_at is not None:
            raise AeternaProtocolException(
                409, "recovery.custody_challenge_unavailable", signed.request_id
            )
        result = self._challenge_result(challenge)
        await db.commit()
        return result

    async def verify_custody(
        self,
        db: AsyncSession,
        payload: RecoveryCustodyVerifyRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        expected = await self._custody_binding(db, payload, document)
        signed = payload.signed
        request_id = signed.request_id
        now = self.recovery._now()
        challenge = await db.scalar(
            select(AeternaCustodyChallenge)
            .where(AeternaCustodyChallenge.id == uuid.UUID(signed.challenge_id))
            .with_for_update()
        )
        if (
            challenge is None
            or challenge.account_id != uuid.UUID(signed.account_id)
            or challenge.device_id != uuid.UUID(signed.device_id)
            or challenge.vault_id != uuid.UUID(signed.vault_id)
            or challenge.recovery_id != uuid.UUID(signed.recovery_id)
            or challenge.expires_at <= now
            or not secrets.compare_digest(
                challenge.wrapper_digest, decode_base64url(signed.wrapper_digest, 32)
            )
            or not secrets.compare_digest(
                challenge.challenge, decode_base64url(signed.challenge, 32)
            )
        ):
            raise AeternaProtocolException(
                409, "recovery.custody_challenge_unavailable", request_id
            )
        digest = request_digest(document["signed"])
        if challenge.consumed_at is not None:
            if challenge.verified_request_id != uuid.UUID(
                request_id
            ) or not secrets.compare_digest(challenge.verified_digest, digest):
                raise AeternaProtocolException(
                    409, "request.idempotency_conflict", request_id
                )
            verified = challenge.verified
        else:
            verified = secrets.compare_digest(
                expected, decode_base64url(signed.erc_commitment, 32)
            )
            challenge.consumed_at = now
            challenge.verified_request_id = uuid.UUID(request_id)
            challenge.verified_digest = digest
            challenge.verified = verified
            challenge.updated_at = now
        await db.commit()
        if not verified:
            raise AeternaProtocolException(409, "recovery.erc_mismatch", request_id)
        return {"verified": True}


def get_aeterna_recipient_recovery_service() -> AeternaRecipientRecoveryService:
    return AeternaRecipientRecoveryService(
        recovery_service=get_aeterna_recovery_service(),
        custody_limiter=get_aeterna_custody_limiter(),
        management_service=get_aeterna_management_authority_service(),
    )
