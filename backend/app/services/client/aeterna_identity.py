"""Transactional account and device-binding service for public protocol v1."""

import secrets
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

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
from app.services.client.aeterna_heartbeat import DEVICE_DORMANCY
from app.services.common.aeterna_management import (
    AeternaManagementAuthorityService,
    get_aeterna_management_authority_service,
)
from app.services.common.aeterna_notifier import AeternaAccountNotifier
from app.services.common.aeterna_security import (
    AeternaIdentityKeys,
    IdentityKeyUnavailable,
    InvalidEmail,
    decode_base64url,
    decrypt_email,
    email_lookup,
    encode_base64url,
    encrypt_email,
    get_identity_keys,
    ip_lookup,
    make_otp,
    make_token,
    normalize_email,
    otp_verifier,
    private_request_digest,
    request_digest,
    token_digest,
    validate_device_label,
    verify_otp,
    verify_signature,
)

CHALLENGE_LIFETIME = timedelta(minutes=10)
CHALLENGE_RESEND_DELAY = timedelta(seconds=60)
GRANT_LIFETIME = timedelta(minutes=10)
BINDING_DELAY = timedelta(hours=24)
BINDING_LIFETIME = timedelta(days=7)
MAX_ATTEMPTS = 5
MAX_PENDING_DEVICES = 3
MAX_ACTIVE_DEVICES = 10


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class AeternaIdentityService:
    """Own the authoritative I09 account and device transition rules."""

    def __init__(
        self,
        key_provider: Callable[[], AeternaIdentityKeys] = get_identity_keys,
        clock: Callable[[], datetime] = utc_now,
        uuid_factory: Callable[[], uuid.UUID] = uuid.uuid4,
        otp_factory: Callable[[], str] = make_otp,
        token_factory: Callable[[], tuple[str, bytes]] = make_token,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
        management_service: AeternaManagementAuthorityService | None = None,
    ):
        self.key_provider = key_provider
        self.clock = clock
        self.uuid_factory = uuid_factory
        self.otp_factory = otp_factory
        self.token_factory = token_factory
        self.random_bytes = random_bytes
        self.management = (
            management_service or get_aeterna_management_authority_service()
        )

    def _keys(self, request_id: str | None = None) -> AeternaIdentityKeys:
        try:
            return self.key_provider()
        except IdentityKeyUnavailable:
            raise AeternaProtocolException(
                503, "service.temporarily_unavailable", request_id
            ) from None

    async def initiate_challenge(
        self,
        db: AsyncSession,
        payload: AccountChallengeRequest,
        document: dict[str, Any],
        client_address: str,
        notifier: AeternaAccountNotifier,
    ) -> dict[str, Any]:
        keys = self._keys(payload.request_id)
        try:
            normalized_email = normalize_email(payload.email)
        except InvalidEmail:
            raise AeternaProtocolException(
                400, "protocol.invalid_request", payload.request_id
            ) from None

        request_uuid = uuid.UUID(payload.request_id)
        digest = private_request_digest(keys, document)
        existing = await db.scalar(
            select(AeternaAccountChallenge).where(
                AeternaAccountChallenge.request_id == request_uuid
            )
        )
        if existing is not None:
            if not secrets.compare_digest(existing.request_digest, digest):
                raise AeternaProtocolException(
                    409, "request.idempotency_conflict", payload.request_id
                )
            return self._challenge_data(existing)

        lookup = email_lookup(keys, normalized_email)
        remote_lookup = ip_lookup(keys, client_address)
        now = self.clock()
        latest = await db.scalar(
            select(AeternaAccountChallenge)
            .where(
                or_(
                    AeternaAccountChallenge.email_lookup == lookup,
                    AeternaAccountChallenge.ip_lookup == remote_lookup,
                ),
                AeternaAccountChallenge.resend_after > now,
            )
            .order_by(AeternaAccountChallenge.resend_after.desc())
            .limit(1)
        )
        if latest is not None:
            retry = max(1, int((latest.resend_after - now).total_seconds()) + 1)
            raise AeternaProtocolException(
                429, "auth.rate_limited", payload.request_id, retry_after_seconds=retry
            )

        binding_id = uuid.UUID(payload.binding_id) if payload.binding_id else None
        if payload.account_id is not None:
            account = await db.get(AeternaAccount, uuid.UUID(payload.account_id))
        elif binding_id is not None:
            binding = await db.get(AeternaDeviceBinding, binding_id)
            account = (
                await db.get(AeternaAccount, binding.account_id)
                if binding is not None
                else None
            )
        else:
            account = await db.scalar(
                select(AeternaAccount).where(AeternaAccount.email_lookup == lookup)
            )
        verified_binding_id: Optional[uuid.UUID] = None
        if account is not None and not await self.management.accepts_mailbox(
            db, account, lookup
        ):
            raise AeternaProtocolException(
                400, "auth.challenge_invalid", payload.request_id
            )
        if payload.account_id is not None and account is None:
            raise AeternaProtocolException(
                400, "auth.challenge_invalid", payload.request_id
            )
        if binding_id is not None and account is not None:
            visible_binding = await db.scalar(
                select(AeternaDeviceBinding.id).where(
                    AeternaDeviceBinding.id == binding_id,
                    AeternaDeviceBinding.account_id == account.id,
                )
            )
            if visible_binding is not None:
                verified_binding_id = visible_binding

        challenge_id = self.uuid_factory()
        ciphertext, nonce, key_version = encrypt_email(
            keys,
            normalized_email,
            "challenge",
            challenge_id,
            nonce_factory=self.random_bytes,
        )
        code = self.otp_factory()
        challenge = AeternaAccountChallenge(
            id=challenge_id,
            request_id=request_uuid,
            request_digest=digest,
            purpose=payload.purpose,
            account_id=account.id if account is not None else None,
            binding_id=verified_binding_id,
            email_lookup=lookup,
            email_ciphertext=ciphertext,
            email_nonce=nonce,
            email_key_version=key_version,
            otp_verifier=otp_verifier(keys, challenge_id, payload.purpose, code),
            ip_lookup=remote_lookup,
            attempt_count=0,
            status="pending",
            expires_at=now + CHALLENGE_LIFETIME,
            resend_after=now + CHALLENGE_RESEND_DELAY,
            delivery_status="pending",
        )
        db.add(challenge)
        await db.commit()

        delivery_status = "failed"
        try:
            if await notifier.send_challenge(
                normalized_email, code, int(CHALLENGE_LIFETIME.total_seconds() // 60)
            ):
                delivery_status = "sent"
        except Exception:
            delivery_status = "failed"
        challenge.delivery_status = delivery_status
        await db.commit()
        return self._challenge_data(challenge)

    async def verify_challenge(
        self,
        db: AsyncSession,
        payload: AccountChallengeVerificationRequest,
    ) -> dict[str, Any]:
        keys = self._keys(payload.request_id)
        challenge_uuid = uuid.UUID(payload.challenge_id)
        visible = await db.get(AeternaAccountChallenge, challenge_uuid)
        if visible is not None and visible.account_id is not None:
            await db.scalar(
                select(AeternaAccount)
                .where(AeternaAccount.id == visible.account_id)
                .with_for_update()
            )
        challenge = await db.scalar(
            select(AeternaAccountChallenge)
            .where(AeternaAccountChallenge.id == challenge_uuid)
            .execution_options(populate_existing=True)
            .with_for_update()
        )
        if challenge is None or challenge.status == "consumed":
            raise AeternaProtocolException(
                400, "auth.challenge_invalid", payload.request_id
            )
        now = self.clock()
        if challenge.status == "exhausted":
            raise AeternaProtocolException(
                429, "auth.attempts_exhausted", payload.request_id
            )
        if challenge.status == "expired" or challenge.expires_at <= now:
            challenge.status = "expired"
            await db.commit()
            raise AeternaProtocolException(
                400, "auth.challenge_expired", payload.request_id
            )

        challenge.attempt_count += 1
        if not verify_otp(
            keys,
            challenge.id,
            challenge.purpose,
            payload.code,
            challenge.otp_verifier,
        ):
            if challenge.attempt_count >= MAX_ATTEMPTS:
                challenge.status = "exhausted"
                await db.commit()
                raise AeternaProtocolException(
                    429, "auth.attempts_exhausted", payload.request_id
                )
            await db.commit()
            raise AeternaProtocolException(
                400, "auth.challenge_invalid", payload.request_id
            )

        binding_scoped = challenge.purpose in {
            "device_binding_cancellation",
            "device_binding_delayed_confirmation",
        }
        if binding_scoped and (
            challenge.account_id is None or challenge.binding_id is None
        ):
            challenge.status = "consumed"
            await db.commit()
            raise AeternaProtocolException(
                400, "auth.challenge_invalid", payload.request_id
            )

        account = await self._resolve_or_create_account(
            db, keys, challenge, payload.request_id
        )
        challenge.account_id = account.id
        challenge.status = "consumed"
        token, digest = self.token_factory()
        grant = AeternaBindingGrant(
            id=self.uuid_factory(),
            challenge_id=challenge.id,
            account_id=account.id,
            purpose=challenge.purpose,
            binding_id=challenge.binding_id,
            token_digest=digest,
            expires_at=now + GRANT_LIFETIME,
        )
        db.add(grant)
        await db.flush()
        await db.commit()
        return {
            "account_id": str(account.id),
            "binding_grant_id": str(grant.id),
            "binding_grant_token": token,
            "expires_at": format_timestamp(grant.expires_at),
            "purpose": grant.purpose,
            **({"binding_id": str(grant.binding_id)} if grant.binding_id else {}),
        }

    async def request_binding(
        self,
        db: AsyncSession,
        payload: DeviceBindingRequest,
        document: dict[str, Any],
        bearer_token: str,
    ) -> tuple[int, dict[str, Any]]:
        request_id = payload.signed.request_id
        public_key = self._public_key(payload.signed.public_key, request_id)
        if not verify_signature(public_key, document["signed"], payload.signature):
            raise AeternaProtocolException(401, "device.proof_invalid", request_id)
        try:
            label = validate_device_label(payload.signed.device_label)
        except ValueError:
            raise AeternaProtocolException(
                400, "protocol.invalid_request", request_id
            ) from None

        grant = await self._grant(
            db,
            payload.signed.binding_grant_id,
            bearer_token,
            request_id,
            allowed_purposes={"account_onboarding", "device_binding"},
            allow_consumed=True,
        )
        digest = request_digest(document)
        replay = await self._idempotent_replay(
            db, grant.account_id, payload.signed.operation, request_id, digest
        )
        if replay is not None:
            return replay
        if grant.consumed_at is not None:
            raise AeternaProtocolException(
                401, "auth.binding_grant_invalid", request_id
            )

        account = await db.scalar(
            select(AeternaAccount)
            .where(
                AeternaAccount.id == grant.account_id,
                AeternaAccount.is_active.is_(True),
            )
            .with_for_update()
        )
        if account is None:
            raise AeternaProtocolException(
                401, "auth.binding_grant_invalid", request_id
            )
        active_count = await self._device_count(db, account.id, "active")
        pending_count = await self._binding_count(db, account.id, "pending")
        proposed_device_id = uuid.UUID(payload.signed.device_id)
        existing_device = await db.scalar(
            select(AeternaDevice)
            .where(
                AeternaDevice.id == proposed_device_id,
                AeternaDevice.account_id == account.id,
            )
            .with_for_update()
        )
        reverify_dormant = existing_device is not None
        if existing_device is not None:
            if existing_device.status != "dormant":
                raise AeternaProtocolException(
                    409, "device.status_terminal", request_id
                )
            if not secrets.compare_digest(existing_device.public_key, public_key):
                raise AeternaProtocolException(401, "device.proof_invalid", request_id)

        if (active_count >= MAX_ACTIVE_DEVICES and not reverify_dormant) or (
            account.first_device_bound_at is not None
            and pending_count >= MAX_PENDING_DEVICES
        ):
            raise AeternaProtocolException(409, "device.limit_reached", request_id)

        now = self.clock()
        immediate = (
            account.first_device_bound_at is None
            and active_count == 0
            and not reverify_dormant
        )
        binding = AeternaDeviceBinding(
            id=self.uuid_factory(),
            account_id=account.id,
            proposed_device_id=proposed_device_id,
            public_key=public_key,
            label=label,
            state="active" if immediate else "pending",
            challenge=None if immediate else self.random_bytes(32),
            not_before=None if immediate else now + BINDING_DELAY,
            expires_at=now + BINDING_LIFETIME,
            activated_at=now if immediate else None,
            request_id=uuid.UUID(request_id),
            request_digest=digest,
        )
        db.add(binding)
        await db.flush()
        if immediate:
            account.first_device_bound_at = now
            db.add(
                AeternaDevice(
                    id=binding.proposed_device_id,
                    account_id=account.id,
                    public_key=public_key,
                    label=label,
                    status="active",
                    bound_at=now,
                    heartbeat_authorized_at=now,
                    last_sequence=0,
                )
            )
            event_type = "device.bound"
        else:
            event_type = "device.binding_requested"
        grant.consumed_at = now
        data = self._binding_data(binding)
        self._record_result(
            db, account.id, payload.signed.operation, request_id, digest, 201, data
        )
        self._audit(db, account.id, event_type, request_id, binding)
        await db.commit()
        return 201, data

    async def approve_binding(
        self,
        db: AsyncSession,
        payload: DeviceBindingApprovalRequest,
        document: dict[str, Any],
        notifier: AeternaAccountNotifier,
    ) -> tuple[int, dict[str, Any]]:
        signed = payload.signed
        request_id = signed.request_id
        account_id = uuid.UUID(signed.account_id)
        account = await db.scalar(
            select(AeternaAccount)
            .where(
                AeternaAccount.id == account_id,
                AeternaAccount.is_active.is_(True),
            )
            .with_for_update()
        )
        if account is None:
            raise AeternaProtocolException(
                403, "device.approver_not_active", request_id
            )
        approver = await db.scalar(
            select(AeternaDevice)
            .where(
                AeternaDevice.id == uuid.UUID(signed.approving_device_id),
                AeternaDevice.account_id == account_id,
                AeternaDevice.status == "active",
            )
            .with_for_update()
        )
        if approver is None:
            raise AeternaProtocolException(
                403, "device.approver_not_active", request_id
            )
        if not verify_signature(
            approver.public_key, document["signed"], payload.signature
        ):
            raise AeternaProtocolException(401, "device.proof_invalid", request_id)

        digest = request_digest(document)
        replay = await self._idempotent_replay(
            db, account_id, signed.operation, request_id, digest
        )
        if replay is not None:
            return replay

        now = self.clock()
        reference = approver.last_seen_at or approver.heartbeat_authorized_at
        if reference + DEVICE_DORMANCY <= now:
            approver.status = "dormant"
            account.last_activity_at = await db.scalar(
                select(func.max(AeternaDevice.last_seen_at)).where(
                    AeternaDevice.account_id == account_id,
                    AeternaDevice.status == "active",
                )
            )
            db.add(
                AeternaSecurityAudit(
                    id=self.uuid_factory(),
                    account_id=account_id,
                    event_type="device.dormant",
                    request_id=uuid.UUID(request_id),
                    device_id=approver.id,
                )
            )
            await db.commit()
            raise AeternaProtocolException(
                403, "device.approver_not_active", request_id
            )
        binding = await self._pending_binding(
            db, account_id, signed.binding_id, request_id
        )
        self._match_binding(
            binding,
            signed.device_id,
            signed.public_key,
            signed.challenge,
            request_id,
        )
        return await self._activate_binding(
            db, binding, signed.operation, request_id, digest, notifier
        )

    async def read_binding_status(
        self,
        db: AsyncSession,
        payload: DeviceBindingStatusRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        """Read one binding only after proof from its exact stored device key."""
        signed = payload.signed
        request_id = signed.request_id
        binding = await db.scalar(
            select(AeternaDeviceBinding)
            .where(
                AeternaDeviceBinding.account_id == uuid.UUID(signed.account_id),
                AeternaDeviceBinding.proposed_device_id == uuid.UUID(signed.device_id),
            )
            .order_by(
                AeternaDeviceBinding.created_at.desc(),
                AeternaDeviceBinding.id.desc(),
            )
            .limit(1)
        )
        if binding is None:
            raise AeternaProtocolException(404, "device.binding_not_found", request_id)
        public_key = self._public_key(signed.public_key, request_id)
        if not secrets.compare_digest(
            binding.public_key, public_key
        ) or not verify_signature(
            binding.public_key, document["signed"], payload.signature
        ):
            raise AeternaProtocolException(404, "device.binding_not_found", request_id)

        state = binding.state
        if state == "pending" and binding.expires_at <= self.clock():
            state = "expired"
        device = await db.scalar(
            select(AeternaDevice).where(
                AeternaDevice.account_id == binding.account_id,
                AeternaDevice.id == binding.proposed_device_id,
            )
        )
        if state == "active":
            if device is None:
                raise AeternaProtocolException(
                    503, "service.temporarily_unavailable", request_id
                )
            state = device.status
        data: dict[str, Any] = {
            "account_id": signed.account_id,
            "binding_id": str(binding.id),
            "device_id": signed.device_id,
            "state": state,
            "observed_at": format_timestamp(self.clock()),
        }
        if state == "pending" and binding.challenge is not None:
            data["challenge"] = encode_base64url(binding.challenge)
            data["not_before"] = format_timestamp(binding.not_before)
            data["expires_at"] = format_timestamp(binding.expires_at)
        if state == "active":
            data["active_device_count"] = await self._device_count(
                db, binding.account_id, "active"
            )
        return data

    async def confirm_delayed_binding(
        self,
        db: AsyncSession,
        payload: DeviceBindingDelayedConfirmationRequest,
        document: dict[str, Any],
        bearer_token: str,
        notifier: AeternaAccountNotifier,
    ) -> tuple[int, dict[str, Any]]:
        signed = payload.signed
        request_id = signed.request_id
        public_key = self._public_key(signed.public_key, request_id)
        if not verify_signature(public_key, document["signed"], payload.signature):
            raise AeternaProtocolException(401, "device.proof_invalid", request_id)
        grant = await self._grant(
            db,
            signed.binding_grant_id,
            bearer_token,
            request_id,
            allowed_purposes={"device_binding_delayed_confirmation"},
            binding_id=uuid.UUID(signed.binding_id),
            allow_consumed=True,
        )
        account_id = uuid.UUID(signed.account_id)
        if grant.account_id != account_id:
            raise AeternaProtocolException(
                401, "auth.binding_grant_invalid", request_id
            )
        digest = request_digest(document)
        replay = await self._idempotent_replay(
            db, account_id, signed.operation, request_id, digest
        )
        if replay is not None:
            return replay
        if grant.consumed_at is not None:
            raise AeternaProtocolException(
                401, "auth.binding_grant_invalid", request_id
            )
        binding = await self._pending_binding(
            db, account_id, signed.binding_id, request_id
        )
        now = self.clock()
        if binding.not_before is None or binding.not_before > now:
            retry = 86_400
            if binding.not_before is not None:
                retry = max(1, int((binding.not_before - now).total_seconds()) + 1)
            raise AeternaProtocolException(
                409,
                "device.binding_not_ready",
                request_id,
                retry_after_seconds=min(retry, 86_400),
            )
        self._match_binding(
            binding, signed.device_id, signed.public_key, signed.challenge, request_id
        )
        grant.consumed_at = now
        return await self._activate_binding(
            db, binding, signed.operation, request_id, digest, notifier
        )

    async def cancel_binding(
        self,
        db: AsyncSession,
        payload: DeviceBindingCancellationRequest,
        document: dict[str, Any],
        bearer_token: str,
        notifier: AeternaAccountNotifier,
    ) -> tuple[int, dict[str, Any]]:
        signed = payload.signed
        request_id = signed.request_id
        public_key = self._public_key(signed.public_key, request_id)
        if not verify_signature(public_key, document["signed"], payload.signature):
            raise AeternaProtocolException(401, "device.proof_invalid", request_id)
        grant = await self._grant(
            db,
            signed.binding_grant_id,
            bearer_token,
            request_id,
            allowed_purposes={"device_binding_cancellation"},
            binding_id=uuid.UUID(signed.binding_id),
            allow_consumed=True,
        )
        account_id = uuid.UUID(signed.account_id)
        if grant.account_id != account_id:
            raise AeternaProtocolException(
                401, "auth.binding_grant_invalid", request_id
            )
        digest = request_digest(document)
        replay = await self._idempotent_replay(
            db, account_id, signed.operation, request_id, digest
        )
        if replay is not None:
            return replay
        if grant.consumed_at is not None:
            raise AeternaProtocolException(
                401, "auth.binding_grant_invalid", request_id
            )
        binding = await self._pending_binding(
            db, account_id, signed.binding_id, request_id
        )
        self._match_binding(
            binding, signed.device_id, signed.public_key, signed.challenge, request_id
        )
        now = self.clock()
        binding.state = "cancelled"
        binding.cancelled_at = now
        binding.challenge_consumed_at = now
        binding.challenge = None
        grant.consumed_at = now
        data = self._binding_data(binding)
        self._record_result(
            db, account_id, signed.operation, request_id, digest, 200, data
        )
        self._audit(db, account_id, "device.binding_cancelled", request_id, binding)
        notification_email = await self._account_email(db, account_id, request_id)
        await db.commit()
        await self._send_notice(notifier, notification_email, "binding cancelled")
        return 200, data

    async def _resolve_or_create_account(
        self,
        db: AsyncSession,
        keys: AeternaIdentityKeys,
        challenge: AeternaAccountChallenge,
        request_id: str,
    ) -> AeternaAccount:
        advisory_key = int.from_bytes(challenge.email_lookup[:8], "big", signed=True)
        await db.execute(
            text("SELECT pg_advisory_xact_lock(:key)"), {"key": advisory_key}
        )
        account = await db.scalar(
            select(AeternaAccount)
            .where(
                AeternaAccount.id == challenge.account_id
                if challenge.account_id is not None
                else AeternaAccount.email_lookup == challenge.email_lookup
            )
            .with_for_update()
        )
        if account is not None:
            if not account.is_active or not await self.management.accepts_mailbox(
                db, account, challenge.email_lookup
            ):
                raise AeternaProtocolException(
                    400, "auth.challenge_invalid", request_id
                )
            return account
        if challenge.account_id is not None:
            raise AeternaProtocolException(400, "auth.challenge_invalid", request_id)
        if challenge.purpose in {
            "device_binding_cancellation",
            "device_binding_delayed_confirmation",
        }:
            raise AeternaProtocolException(400, "auth.challenge_invalid", request_id)
        normalized_email = decrypt_email(
            keys,
            challenge.email_ciphertext,
            challenge.email_nonce,
            "challenge",
            challenge.id,
            challenge.email_key_version,
        )
        account_id = self.uuid_factory()
        ciphertext, nonce, version = encrypt_email(
            keys,
            normalized_email,
            "account",
            account_id,
            nonce_factory=self.random_bytes,
        )
        account = AeternaAccount(
            id=account_id,
            email_lookup=challenge.email_lookup,
            email_ciphertext=ciphertext,
            email_nonce=nonce,
            email_key_version=version,
            is_active=True,
        )
        db.add(account)
        db.add(
            AeternaSecurityAudit(
                id=self.uuid_factory(),
                account_id=account_id,
                event_type="account.created",
                request_id=uuid.UUID(request_id),
            )
        )
        await db.flush()
        return account

    async def _grant(
        self,
        db: AsyncSession,
        grant_id: str,
        bearer_token: str,
        request_id: str,
        allowed_purposes: set[str],
        binding_id: uuid.UUID | None = None,
        allow_consumed: bool = False,
    ) -> AeternaBindingGrant:
        try:
            digest = token_digest(bearer_token)
        except ValueError:
            raise AeternaProtocolException(
                401, "auth.binding_grant_invalid", request_id
            ) from None
        visible = await db.scalar(
            select(AeternaBindingGrant).where(
                AeternaBindingGrant.id == uuid.UUID(grant_id),
                AeternaBindingGrant.token_digest == digest,
            )
        )
        if visible is None:
            raise AeternaProtocolException(
                401, "auth.binding_grant_invalid", request_id
            )
        await db.scalar(
            select(AeternaAccount)
            .where(AeternaAccount.id == visible.account_id)
            .with_for_update()
        )
        grant = await db.scalar(
            select(AeternaBindingGrant)
            .where(
                AeternaBindingGrant.id == uuid.UUID(grant_id),
                AeternaBindingGrant.token_digest == digest,
            )
            .execution_options(populate_existing=True)
            .with_for_update()
        )
        if (
            grant is None
            or grant.purpose not in allowed_purposes
            or grant.expires_at <= self.clock()
            or (grant.consumed_at is not None and not allow_consumed)
            or (binding_id is not None and grant.binding_id != binding_id)
        ):
            raise AeternaProtocolException(
                401, "auth.binding_grant_invalid", request_id
            )
        challenge = await db.get(AeternaAccountChallenge, grant.challenge_id)
        account = await db.get(AeternaAccount, grant.account_id)
        if (
            challenge is None
            or account is None
            or not await self.management.accepts_mailbox(
                db, account, challenge.email_lookup
            )
        ):
            raise AeternaProtocolException(
                401, "auth.binding_grant_invalid", request_id
            )
        return grant

    async def _pending_binding(
        self,
        db: AsyncSession,
        account_id: uuid.UUID,
        binding_id: str,
        request_id: str,
    ) -> AeternaDeviceBinding:
        binding = await db.scalar(
            select(AeternaDeviceBinding)
            .where(
                AeternaDeviceBinding.id == uuid.UUID(binding_id),
                AeternaDeviceBinding.account_id == account_id,
            )
            .with_for_update()
        )
        if binding is None or binding.state == "active":
            raise AeternaProtocolException(404, "device.binding_not_found", request_id)
        if binding.state == "cancelled":
            raise AeternaProtocolException(409, "device.binding_cancelled", request_id)
        if binding.state == "expired" or binding.expires_at <= self.clock():
            binding.state = "expired"
            await db.commit()
            raise AeternaProtocolException(409, "device.binding_expired", request_id)
        return binding

    def _match_binding(
        self,
        binding: AeternaDeviceBinding,
        device_id: str,
        public_key: str,
        challenge: str,
        request_id: str,
    ) -> None:
        try:
            public_key_bytes = decode_base64url(public_key, 32)
            challenge_bytes = decode_base64url(challenge, 32)
        except ValueError:
            raise AeternaProtocolException(401, "device.proof_invalid", request_id)
        if (
            binding.proposed_device_id != uuid.UUID(device_id)
            or not secrets.compare_digest(binding.public_key, public_key_bytes)
            or binding.challenge is None
            or not secrets.compare_digest(binding.challenge, challenge_bytes)
        ):
            raise AeternaProtocolException(401, "device.proof_invalid", request_id)

    async def _activate_binding(
        self,
        db: AsyncSession,
        binding: AeternaDeviceBinding,
        operation: str,
        request_id: str,
        digest: bytes,
        notifier: AeternaAccountNotifier,
    ) -> tuple[int, dict[str, Any]]:
        account = await db.scalar(
            select(AeternaAccount)
            .where(AeternaAccount.id == binding.account_id)
            .with_for_update()
        )
        if account is None:
            raise AeternaProtocolException(404, "device.binding_not_found", request_id)
        if (
            await self._device_count(db, binding.account_id, "active")
            >= MAX_ACTIVE_DEVICES
        ):
            raise AeternaProtocolException(409, "device.limit_reached", request_id)
        now = self.clock()
        binding.state = "active"
        binding.activated_at = now
        binding.challenge_consumed_at = now
        binding.challenge = None
        existing_device = await db.scalar(
            select(AeternaDevice)
            .where(
                AeternaDevice.id == binding.proposed_device_id,
                AeternaDevice.account_id == binding.account_id,
            )
            .with_for_update()
        )
        if existing_device is None:
            db.add(
                AeternaDevice(
                    id=binding.proposed_device_id,
                    account_id=binding.account_id,
                    public_key=binding.public_key,
                    label=binding.label,
                    status="active",
                    bound_at=now,
                    heartbeat_authorized_at=now,
                    last_sequence=0,
                )
            )
            audit_event = "device.bound"
        else:
            if existing_device.status != "dormant" or not secrets.compare_digest(
                existing_device.public_key, binding.public_key
            ):
                raise AeternaProtocolException(
                    409, "device.status_terminal", request_id
                )
            existing_device.status = "active"
            existing_device.label = binding.label
            existing_device.heartbeat_authorized_at = now
            existing_device.last_seen_at = None
            existing_device.last_heartbeat_request_id = None
            existing_device.last_heartbeat_request_digest = None
            audit_event = "device.reverified"
        if account.first_device_bound_at is None:
            account.first_device_bound_at = now
        data = self._binding_data(binding)
        self._record_result(
            db, binding.account_id, operation, request_id, digest, 200, data
        )
        self._audit(db, binding.account_id, audit_event, request_id, binding)
        notification_email = await self._account_email(
            db, binding.account_id, request_id
        )
        await db.commit()
        await self._send_notice(notifier, notification_email, "device bound")
        return 200, data

    async def _idempotent_replay(
        self,
        db: AsyncSession,
        account_id: uuid.UUID,
        operation: str,
        request_id: str,
        digest: bytes,
    ) -> tuple[int, dict[str, Any]] | None:
        record = await db.scalar(
            select(AeternaProtocolIdempotency).where(
                AeternaProtocolIdempotency.operation == operation,
                AeternaProtocolIdempotency.request_id == uuid.UUID(request_id),
            )
        )
        if record is None:
            return None
        if record.account_id != account_id or not secrets.compare_digest(
            record.request_digest, digest
        ):
            raise AeternaProtocolException(
                409, "request.idempotency_conflict", request_id
            )
        return record.http_status, record.response_data

    def _record_result(
        self,
        db: AsyncSession,
        account_id: uuid.UUID,
        operation: str,
        request_id: str,
        digest: bytes,
        http_status: int,
        data: dict[str, Any],
    ) -> None:
        db.add(
            AeternaProtocolIdempotency(
                id=self.uuid_factory(),
                account_id=account_id,
                operation=operation,
                request_id=uuid.UUID(request_id),
                request_digest=digest,
                http_status=http_status,
                response_data=data,
            )
        )

    def _audit(
        self,
        db: AsyncSession,
        account_id: uuid.UUID,
        event_type: str,
        request_id: str,
        binding: AeternaDeviceBinding,
    ) -> None:
        db.add(
            AeternaSecurityAudit(
                id=self.uuid_factory(),
                account_id=account_id,
                event_type=event_type,
                request_id=uuid.UUID(request_id),
                binding_id=binding.id,
                device_id=binding.proposed_device_id,
            )
        )

    async def _device_count(
        self, db: AsyncSession, account_id: uuid.UUID, status: str
    ) -> int:
        count = await db.scalar(
            select(func.count(AeternaDevice.id)).where(
                AeternaDevice.account_id == account_id,
                AeternaDevice.status == status,
            )
        )
        return int(count or 0)

    async def _binding_count(
        self, db: AsyncSession, account_id: uuid.UUID, state: str
    ) -> int:
        count = await db.scalar(
            select(func.count(AeternaDeviceBinding.id)).where(
                AeternaDeviceBinding.account_id == account_id,
                AeternaDeviceBinding.state == state,
            )
        )
        return int(count or 0)

    async def _account_email(
        self, db: AsyncSession, account_id: uuid.UUID, request_id: str
    ) -> str:
        account = await db.get(AeternaAccount, account_id)
        if account is None:
            raise AeternaProtocolException(404, "device.binding_not_found", request_id)
        keys = self._keys(request_id)
        try:
            return await self.management.mailbox(db, keys, account)
        except (IdentityKeyUnavailable, UnicodeDecodeError, ValueError):
            raise AeternaProtocolException(
                503, "service.temporarily_unavailable", request_id
            ) from None

    async def _send_notice(
        self, notifier: AeternaAccountNotifier, email: str, event: str
    ) -> None:
        try:
            await notifier.send_security_notice(email, event)
        except Exception:
            return

    def _public_key(self, encoded: str, request_id: str) -> bytes:
        try:
            return decode_base64url(encoded, 32)
        except ValueError:
            raise AeternaProtocolException(401, "device.proof_invalid", request_id)

    def _challenge_data(self, challenge: AeternaAccountChallenge) -> dict[str, Any]:
        return {
            "challenge_id": str(challenge.id),
            "expires_in_seconds": 600,
            "resend_after_seconds": 60,
        }

    def _binding_data(self, binding: AeternaDeviceBinding) -> dict[str, Any]:
        data: dict[str, Any] = {
            "account_id": str(binding.account_id),
            "binding_id": str(binding.id),
            "device_id": str(binding.proposed_device_id),
            "state": binding.state,
        }
        if binding.challenge is not None:
            data["challenge"] = encode_base64url(binding.challenge)
        if binding.not_before is not None:
            data["not_before"] = format_timestamp(binding.not_before)
        if binding.expires_at is not None:
            data["expires_at"] = format_timestamp(binding.expires_at)
        return data


def get_aeterna_identity_service() -> AeternaIdentityService:
    return AeternaIdentityService(
        key_provider=get_identity_keys,
        management_service=get_aeterna_management_authority_service(),
    )
