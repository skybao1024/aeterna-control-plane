"""Transactional I10 signed heartbeat and device-status service."""

import math
import secrets
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.models.aeterna_identity import (
    AeternaAccount,
    AeternaDevice,
    AeternaProtocolIdempotency,
    AeternaSecurityAudit,
)
from app.schemas.client.aeterna_protocol import (
    DeviceStatusChangeRequest,
    HeartbeatRequest,
)
from app.services.common.aeterna_security import request_digest, verify_signature

HEARTBEAT_COOLDOWN = timedelta(minutes=30)
DEVICE_DORMANCY = timedelta(days=90)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class AeternaHeartbeatService:
    """Own server-time heartbeat replay, eligibility, and aggregation rules."""

    def __init__(
        self,
        clock: Callable[[], datetime] = utc_now,
        uuid_factory: Callable[[], uuid.UUID] = uuid.uuid4,
    ):
        self.clock = clock
        self.uuid_factory = uuid_factory

    async def submit_heartbeat(
        self,
        db: AsyncSession,
        payload: HeartbeatRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        signed = payload.signed
        request_id = signed.request_id
        account_id = uuid.UUID(signed.account_id)
        device_id = uuid.UUID(signed.device_id)
        account = await self._locked_account(db, account_id, request_id)
        device = await db.scalar(
            select(AeternaDevice)
            .where(
                AeternaDevice.id == device_id,
                AeternaDevice.account_id == account_id,
            )
            .with_for_update()
        )
        if device is None or not verify_signature(
            device.public_key, document["signed"], payload.signature
        ):
            raise AeternaProtocolException(401, "device.proof_invalid", request_id)

        digest = request_digest(document)
        request_uuid = uuid.UUID(request_id)
        if device.last_heartbeat_request_id == request_uuid:
            if (
                device.last_heartbeat_request_digest is None
                or not secrets.compare_digest(
                    device.last_heartbeat_request_digest, digest
                )
            ):
                raise AeternaProtocolException(
                    409, "request.idempotency_conflict", request_id
                )
            if device.last_seen_at is None:
                raise AeternaProtocolException(
                    503, "service.temporarily_unavailable", request_id
                )
            return self._heartbeat_data(device, device.last_seen_at)

        now = self.clock()
        if device.status in {"lost", "revoked"}:
            raise AeternaProtocolException(403, "device.not_active", request_id)
        if device.status == "dormant":
            raise AeternaProtocolException(
                403, "device.reverification_required", request_id
            )
        if self._is_dormant(device, now):
            device.status = "dormant"
            await self._recompute_account_activity(db, account)
            self._audit(db, account_id, device_id, request_id, "device.dormant")
            await db.commit()
            raise AeternaProtocolException(
                403, "device.reverification_required", request_id
            )
        if signed.sequence <= device.last_sequence:
            raise AeternaProtocolException(
                409, "heartbeat.sequence_not_increasing", request_id
            )
        if device.last_seen_at is not None:
            next_allowed = device.last_seen_at + HEARTBEAT_COOLDOWN
            if now < next_allowed:
                retry = max(1, math.ceil((next_allowed - now).total_seconds()))
                raise AeternaProtocolException(
                    429,
                    "heartbeat.cooldown",
                    request_id,
                    retry_after_seconds=min(retry, 86_400),
                )

        device.last_sequence = signed.sequence
        device.last_seen_at = now
        device.last_heartbeat_request_id = request_uuid
        device.last_heartbeat_request_digest = digest
        await db.flush()
        await self._recompute_account_activity(db, account)
        await db.commit()
        return self._heartbeat_data(device, now)

    async def change_device_status(
        self,
        db: AsyncSession,
        payload: DeviceStatusChangeRequest,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        signed = payload.signed
        request_id = signed.request_id
        account_id = uuid.UUID(signed.account_id)
        authorizing_id = uuid.UUID(signed.authorizing_device_id)
        target_id = uuid.UUID(signed.target_device_id)
        account = await self._locked_account(db, account_id, request_id)
        authorizing = await db.scalar(
            select(AeternaDevice)
            .where(
                AeternaDevice.id == authorizing_id,
                AeternaDevice.account_id == account_id,
            )
            .with_for_update()
        )
        if authorizing is None or not verify_signature(
            authorizing.public_key, document["signed"], payload.signature
        ):
            raise AeternaProtocolException(401, "device.proof_invalid", request_id)

        digest = request_digest(document)
        replay = await self._idempotent_replay(
            db, account_id, signed.operation, request_id, digest
        )
        if replay is not None:
            return replay

        now = self.clock()
        if authorizing.status != "active":
            raise AeternaProtocolException(403, "device.not_active", request_id)
        if self._is_dormant(authorizing, now):
            authorizing.status = "dormant"
            await self._recompute_account_activity(db, account)
            self._audit(db, account_id, authorizing_id, request_id, "device.dormant")
            await db.commit()
            raise AeternaProtocolException(
                403, "device.reverification_required", request_id
            )

        if target_id == authorizing_id:
            target = authorizing
        else:
            target = await db.scalar(
                select(AeternaDevice)
                .where(
                    AeternaDevice.id == target_id,
                    AeternaDevice.account_id == account_id,
                )
                .with_for_update()
            )
        if target is None:
            raise AeternaProtocolException(404, "device.target_not_found", request_id)
        if target.status in {"lost", "revoked"}:
            raise AeternaProtocolException(409, "device.status_terminal", request_id)

        target_status = "lost" if signed.action == "mark_lost" else "revoked"
        target.status = target_status
        if target_status == "revoked":
            target.revoked_at = now
        await db.flush()
        await self._recompute_account_activity(db, account)
        data = {
            "account_id": str(account_id),
            "changed_at": format_timestamp(now),
            "device_id": str(target_id),
            "status": target_status,
        }
        db.add(
            AeternaProtocolIdempotency(
                id=self.uuid_factory(),
                account_id=account_id,
                operation=signed.operation,
                request_id=uuid.UUID(request_id),
                request_digest=digest,
                http_status=200,
                response_data=data,
            )
        )
        self._audit(
            db,
            account_id,
            target_id,
            request_id,
            f"device.{target_status}",
        )
        await db.commit()
        return data

    async def _locked_account(
        self, db: AsyncSession, account_id: uuid.UUID, request_id: str
    ) -> AeternaAccount:
        account = await db.scalar(
            select(AeternaAccount)
            .where(
                AeternaAccount.id == account_id,
                AeternaAccount.is_active.is_(True),
            )
            .with_for_update()
        )
        if account is None:
            raise AeternaProtocolException(401, "device.proof_invalid", request_id)
        return account

    async def _recompute_account_activity(
        self, db: AsyncSession, account: AeternaAccount
    ) -> None:
        account.last_activity_at = await db.scalar(
            select(func.max(AeternaDevice.last_seen_at)).where(
                AeternaDevice.account_id == account.id,
                AeternaDevice.status == "active",
            )
        )

    def _is_dormant(self, device: AeternaDevice, now: datetime) -> bool:
        reference = device.last_seen_at or device.heartbeat_authorized_at
        return reference + DEVICE_DORMANCY <= now

    def _heartbeat_data(
        self, device: AeternaDevice, accepted_at: datetime
    ) -> dict[str, Any]:
        return {
            "accepted_at": format_timestamp(accepted_at),
            "accepted_sequence": device.last_sequence,
            "account_id": str(device.account_id),
            "device_id": str(device.id),
            "next_heartbeat_not_before": format_timestamp(
                accepted_at + HEARTBEAT_COOLDOWN
            ),
        }

    async def _idempotent_replay(
        self,
        db: AsyncSession,
        account_id: uuid.UUID,
        operation: str,
        request_id: str,
        digest: bytes,
    ) -> dict[str, Any] | None:
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
        return record.response_data

    def _audit(
        self,
        db: AsyncSession,
        account_id: uuid.UUID,
        device_id: uuid.UUID,
        request_id: str,
        event_type: str,
    ) -> None:
        db.add(
            AeternaSecurityAudit(
                id=self.uuid_factory(),
                account_id=account_id,
                event_type=event_type,
                request_id=uuid.UUID(request_id),
                device_id=device_id,
            )
        )


def get_aeterna_heartbeat_service() -> AeternaHeartbeatService:
    return AeternaHeartbeatService()
