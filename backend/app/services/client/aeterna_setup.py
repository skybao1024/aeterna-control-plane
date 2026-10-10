"""Transactional Owner policy setup and durable recovery enrollment visibility."""

import secrets
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.models.account_policy import (
    AccountPolicy,
    AccountPolicyOutboxEvent,
    AccountPolicyState,
)
from app.models.aeterna_identity import (
    AeternaAccount,
    AeternaDevice,
    AeternaProtocolIdempotency,
)
from app.models.aeterna_recovery import AeternaRecoveryRecord
from app.schemas.client.aeterna_setup import PolicyConfigureRequest, SetupStatusRequest
from app.services.common.aeterna_management import (
    AeternaManagementAuthorityService,
    get_aeterna_management_authority_service,
)
from app.services.common.aeterna_security import (
    encode_base64url,
    request_digest,
    verify_signature,
)

SECONDS_PER_DAY = 86_400
MAX_SETUP_RECORDS = 256
MAX_SETUP_DEVICES = 32


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class AeternaSetupService:
    """Own signed setup reads and policy mutation under the account row lock."""

    def __init__(
        self,
        clock: Callable[[], datetime] = utc_now,
        uuid_factory: Callable[[], uuid.UUID] = uuid.uuid4,
        management_service: AeternaManagementAuthorityService | None = None,
    ):
        self.clock = clock
        self.uuid_factory = uuid_factory
        self.management = (
            management_service or get_aeterna_management_authority_service()
        )

    async def configure_policy(
        self,
        db: AsyncSession,
        payload: PolicyConfigureRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        signed = payload.signed
        account, device = await self._authorize_device(
            db,
            signed.account_id,
            signed.device_id,
            document["signed"],
            payload.signature,
            signed.request_id,
        )
        transferred = await self.management.primary_alias(db, account.id) is not None
        if device.policy_epoch != account.current_policy_epoch and not transferred:
            raise AeternaProtocolException(403, "device.not_active", signed.request_id)

        digest = request_digest(document)
        replay = await db.scalar(
            select(AeternaProtocolIdempotency).where(
                AeternaProtocolIdempotency.operation == signed.operation,
                AeternaProtocolIdempotency.request_id == uuid.UUID(signed.request_id),
            )
        )
        if replay is not None:
            if replay.account_id != account.id or not secrets.compare_digest(
                replay.request_digest, digest
            ):
                raise AeternaProtocolException(
                    409, "request.idempotency_conflict", signed.request_id
                )
            response_data = replay.response_data
            await db.rollback()
            return response_data

        policy = await db.scalar(
            select(AccountPolicy)
            .where(
                AccountPolicy.account_id == account.id,
                AccountPolicy.retired_at.is_(None),
            )
            .with_for_update()
        )
        recipient_reactivation = (
            transferred
            and policy is not None
            and policy.state == AccountPolicyState.RELEASED.value
            and policy.epoch == account.current_policy_epoch
        )
        if policy is not None and (
            (
                policy.state != AccountPolicyState.ACTIVE.value
                and not recipient_reactivation
            )
            or policy.epoch != account.current_policy_epoch
        ):
            raise AeternaProtocolException(409, "policy.unavailable", signed.request_id)

        now = self._now()
        inactivity_seconds = signed.inactivity_days * SECONDS_PER_DAY
        warning_seconds = signed.warning_days * SECONDS_PER_DAY
        grace_seconds = signed.grace_days * SECONDS_PER_DAY
        if recipient_reactivation:
            policy.retired_at = now
            policy.updated_at = now
            account.current_policy_epoch += 1
            account.current_recovery_generation = 1
            account.erc_commitment = None
            account.erc_commitment_epoch = None
            account.erc_commitment_generation = None
            await db.flush()
            policy = None
        if transferred:
            device.policy_epoch = account.current_policy_epoch
            device.heartbeat_authorized_at = now
        if policy is None:
            policy = AccountPolicy(
                id=self.uuid_factory(),
                account_id=account.id,
                epoch=account.current_policy_epoch,
                state=AccountPolicyState.ACTIVE.value,
                version=0,
                inactivity_window_seconds=inactivity_seconds,
                warning_window_seconds=warning_seconds,
                grace_window_seconds=grace_seconds,
                last_activity_at=now,
                due_at=now + timedelta(seconds=inactivity_seconds),
                state_changed_at=now,
            )
            db.add(policy)
            from_state = "UNCONFIGURED"
        else:
            from_state = policy.state
            policy.version += 1
            policy.inactivity_window_seconds = inactivity_seconds
            policy.warning_window_seconds = warning_seconds
            policy.grace_window_seconds = grace_seconds
            policy.last_activity_at = now
            policy.due_at = now + timedelta(seconds=inactivity_seconds)
            policy.updated_at = now
        account.last_activity_at = now
        await db.flush()

        db.add(
            AccountPolicyOutboxEvent(
                id=self.uuid_factory(),
                account_policy_id=policy.id,
                event_type="account-policy-configured",
                idempotency_key=f"account-policy-configure:{signed.request_id}",
                from_state=from_state,
                to_state=AccountPolicyState.ACTIVE.value,
                policy_version=policy.version,
                payload={
                    "account_policy_id": str(policy.id),
                    "from_state": from_state,
                    "to_state": AccountPolicyState.ACTIVE.value,
                    "policy_version": policy.version,
                    "occurred_at": now.isoformat(),
                },
                scheduled_at=now,
                status="pending",
                attempt_count=0,
            )
        )
        data = {
            "account_id": str(account.id),
            "observed_at": format_timestamp(now),
            "policy": self._policy_snapshot(account, policy),
        }
        db.add(
            AeternaProtocolIdempotency(
                id=self.uuid_factory(),
                account_id=account.id,
                operation=signed.operation,
                request_id=uuid.UUID(signed.request_id),
                request_digest=digest,
                http_status=200,
                response_data=data,
            )
        )
        await db.commit()
        return data

    async def status(
        self,
        db: AsyncSession,
        payload: SetupStatusRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        signed = payload.signed
        account, _device = await self._authorize_device(
            db,
            signed.account_id,
            signed.device_id,
            document["signed"],
            payload.signature,
            signed.request_id,
        )
        now = self._now()
        policy = await db.scalar(
            select(AccountPolicy).where(
                AccountPolicy.account_id == account.id,
                AccountPolicy.retired_at.is_(None),
            )
        )
        devices = list(
            (
                await db.scalars(
                    select(AeternaDevice)
                    .where(
                        AeternaDevice.account_id == account.id,
                        AeternaDevice.status == "active",
                    )
                    .order_by(AeternaDevice.id)
                    .limit(MAX_SETUP_DEVICES + 1)
                )
            ).all()
        )
        if len(devices) > MAX_SETUP_DEVICES:
            raise AeternaProtocolException(
                503, "service.temporarily_unavailable", signed.request_id
            )
        records: list[AeternaRecoveryRecord] = []
        current_commitment = (
            account.erc_commitment
            if account.erc_commitment_epoch == account.current_policy_epoch
            and account.erc_commitment_generation == account.current_recovery_generation
            else None
        )
        if policy is not None:
            records = list(
                (
                    await db.scalars(
                        select(AeternaRecoveryRecord)
                        .where(
                            AeternaRecoveryRecord.account_id == account.id,
                            AeternaRecoveryRecord.policy_epoch
                            == account.current_policy_epoch,
                            AeternaRecoveryRecord.recovery_generation
                            == account.current_recovery_generation,
                            AeternaRecoveryRecord.state.in_(
                                {"pending_confirmation", "sealed"}
                            ),
                        )
                        .limit(MAX_SETUP_RECORDS + 1)
                    )
                ).all()
            )
            if len(records) > MAX_SETUP_RECORDS:
                raise AeternaProtocolException(
                    503, "service.temporarily_unavailable", signed.request_id
                )
        device_data = []
        for device in devices:
            own = [record for record in records if record.device_id == device.id]
            state = "not_enrolled"
            if current_commitment is not None and any(
                record.state == "sealed"
                and record.erc_commitment is not None
                and secrets.compare_digest(record.erc_commitment, current_commitment)
                for record in own
            ):
                state = "complete"
            elif any(
                record.state == "pending_confirmation" and record.expires_at > now
                for record in own
            ):
                state = "pending"
            entry: dict[str, Any] = {"device_id": str(device.id), "state": state}
            if device.label is not None:
                entry["label"] = device.label
            device_data.append(entry)

        data: dict[str, Any] = {
            "account_id": str(account.id),
            "device_id": str(signed.device_id),
            "observed_at": format_timestamp(now),
            "devices": device_data,
            "erc_committed": current_commitment is not None,
        }
        if policy is not None:
            data["policy"] = self._policy_snapshot(account, policy)
        if signed.vault_id is not None:
            local = next(
                (
                    record
                    for record in records
                    if str(record.device_id) == signed.device_id
                    and str(record.vault_id) == signed.vault_id
                ),
                None,
            )
            if local is not None:
                local_state = (
                    "expired"
                    if local.state == "pending_confirmation" and local.expires_at <= now
                    else local.state
                )
                local_data: dict[str, Any] = {
                    "recovery_id": str(local.id),
                    "vault_id": str(local.vault_id),
                    "state": local_state,
                    "expires_at": format_timestamp(local.expires_at),
                }
                if local.state == "sealed":
                    local_data["wrapper_digest"] = encode_base64url(
                        local.wrapper_digest
                    )
                data["local_record"] = local_data
        await db.rollback()
        return data

    async def _authorize_device(
        self,
        db: AsyncSession,
        account_id: str,
        device_id: str,
        signed_document: dict[str, Any],
        signature: str,
        request_id: str,
    ) -> tuple[AeternaAccount, AeternaDevice]:
        account = await db.scalar(
            select(AeternaAccount)
            .where(
                AeternaAccount.id == uuid.UUID(account_id),
                AeternaAccount.is_active.is_(True),
            )
            .with_for_update()
        )
        device = await db.scalar(
            select(AeternaDevice)
            .where(
                AeternaDevice.id == uuid.UUID(device_id),
                AeternaDevice.account_id == uuid.UUID(account_id),
            )
            .with_for_update()
        )
        if (
            account is None
            or device is None
            or device.status != "active"
            or not verify_signature(device.public_key, signed_document, signature)
        ):
            raise AeternaProtocolException(401, "device.proof_invalid", request_id)
        return account, device

    def _policy_snapshot(
        self, account: AeternaAccount, policy: AccountPolicy
    ) -> dict[str, Any]:
        windows = (
            policy.inactivity_window_seconds,
            policy.warning_window_seconds,
            policy.grace_window_seconds,
        )
        if any(value % SECONDS_PER_DAY for value in windows):
            raise AeternaProtocolException(503, "service.temporarily_unavailable")
        return {
            "epoch": policy.epoch,
            "generation": account.current_recovery_generation,
            "state": policy.state,
            "inactivity_days": windows[0] // SECONDS_PER_DAY,
            "warning_days": windows[1] // SECONDS_PER_DAY,
            "grace_days": windows[2] // SECONDS_PER_DAY,
            "due_at": format_timestamp(policy.due_at),
            "version": policy.version,
        }

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise RuntimeError("The setup clock must be timezone-aware")
        return value.astimezone(timezone.utc)


def get_aeterna_setup_service() -> AeternaSetupService:
    return AeternaSetupService(
        management_service=get_aeterna_management_authority_service()
    )
