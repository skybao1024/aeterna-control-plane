"""Idempotent I11 preparation and callback handling for notification intents."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import transaction
from app.models.account_policy import (
    AccountPolicyOutboxAttempt,
    AccountPolicyOutboxCallback,
    AccountPolicyOutboxEvent,
)
from app.services.internal.account_policy_transition import (
    InvalidAccountPolicyTransitionError,
    InvalidServerTimeError,
    SystemUtcClock,
    UtcClock,
)


class OutboxPreparationOutcome(str, Enum):
    """Observable queue-preparation result."""

    PREPARED = "prepared"
    DUPLICATE = "duplicate"
    CANCELLED = "cancelled"


class OutboxCallbackOutcome(str, Enum):
    """Allowed internal dispatch callback outcomes."""

    DISPATCH_ACCEPTED = "dispatch-accepted"
    DISPATCH_FAILED = "dispatch-failed"


@dataclass(frozen=True)
class OutboxPreparationResult:
    """A provider-neutral delivery envelope reference."""

    outcome: OutboxPreparationOutcome
    outbox_event_id: uuid.UUID
    attempt_number: int
    delivery_idempotency_key: str


@dataclass(frozen=True)
class OutboxCallbackResult:
    """The durable result of an internal dispatch callback."""

    duplicate: bool
    outbox_event_id: uuid.UUID
    outcome: OutboxCallbackOutcome
    outbox_status: str


class AccountPolicyOutboxService:
    """Prepare notification intents without claiming external delivery."""

    def __init__(self, clock: UtcClock | None = None):
        self.clock = clock or SystemUtcClock()

    async def prepare_delivery(
        self,
        db: AsyncSession,
        event_id: uuid.UUID,
        task_id: str,
    ) -> OutboxPreparationResult:
        """Prepare one retry while preserving one stable delivery key."""

        task_key = self._idempotency_key(event_id, "queue-task", task_id)
        async with transaction(db):
            event = await self._lock_event(db, event_id)
            self._require_notification_intent(event)
            duplicate = await db.scalar(
                select(AccountPolicyOutboxAttempt).where(
                    AccountPolicyOutboxAttempt.task_idempotency_key == task_key
                )
            )
            if duplicate is not None:
                return OutboxPreparationResult(
                    outcome=OutboxPreparationOutcome.DUPLICATE,
                    outbox_event_id=event.id,
                    attempt_number=duplicate.attempt_number,
                    delivery_idempotency_key=duplicate.delivery_idempotency_key,
                )

            delivery_key = event.delivery_idempotency_key
            if delivery_key is None:
                raise InvalidAccountPolicyTransitionError(
                    "Notification intent is missing its delivery idempotency key"
                )
            if event.status == "cancelled":
                return OutboxPreparationResult(
                    outcome=OutboxPreparationOutcome.CANCELLED,
                    outbox_event_id=event.id,
                    attempt_number=event.attempt_count,
                    delivery_idempotency_key=delivery_key,
                )

            now = self._now()
            attempt_number = event.attempt_count + 1
            attempt = AccountPolicyOutboxAttempt(
                outbox_event_id=event.id,
                task_idempotency_key=task_key,
                delivery_idempotency_key=delivery_key,
                attempt_number=attempt_number,
                status="prepared",
                prepared_at=now,
            )
            db.add(attempt)
            event.attempt_count = attempt_number
            event.status = "queued"
            event.queued_at = now
            event.acknowledged_at = None
            event.updated_at = now
            await db.flush()
            return OutboxPreparationResult(
                outcome=OutboxPreparationOutcome.PREPARED,
                outbox_event_id=event.id,
                attempt_number=attempt_number,
                delivery_idempotency_key=delivery_key,
            )

    async def record_callback(
        self,
        db: AsyncSession,
        event_id: uuid.UUID,
        callback_id: str,
        outcome: OutboxCallbackOutcome,
    ) -> OutboxCallbackResult:
        """Record an internal dispatch callback without creating warning proof."""

        callback_key = self._idempotency_key(event_id, "callback", callback_id)
        async with transaction(db):
            event = await self._lock_event(db, event_id)
            self._require_notification_intent(event)
            duplicate = await db.scalar(
                select(AccountPolicyOutboxCallback).where(
                    AccountPolicyOutboxCallback.idempotency_key == callback_key
                )
            )
            if duplicate is not None:
                if (
                    duplicate.outbox_event_id != event.id
                    or duplicate.outcome != outcome.value
                ):
                    raise InvalidAccountPolicyTransitionError(
                        "Callback idempotency key conflicts with persisted outcome"
                    )
                return OutboxCallbackResult(
                    duplicate=True,
                    outbox_event_id=event.id,
                    outcome=outcome,
                    outbox_status=event.status,
                )

            now = self._now()
            db.add(
                AccountPolicyOutboxCallback(
                    outbox_event_id=event.id,
                    idempotency_key=callback_key,
                    outcome=outcome.value,
                    received_at=now,
                )
            )
            if event.status != "cancelled":
                if outcome is OutboxCallbackOutcome.DISPATCH_ACCEPTED:
                    event.status = "acknowledged"
                    event.acknowledged_at = now
                else:
                    event.status = "pending"
                    event.acknowledged_at = None
                event.updated_at = now
            await db.flush()
            return OutboxCallbackResult(
                duplicate=False,
                outbox_event_id=event.id,
                outcome=outcome,
                outbox_status=event.status,
            )

    async def _lock_event(
        self, db: AsyncSession, event_id: uuid.UUID
    ) -> AccountPolicyOutboxEvent:
        event = await db.scalar(
            select(AccountPolicyOutboxEvent)
            .where(AccountPolicyOutboxEvent.id == event_id)
            .with_for_update()
        )
        if event is None:
            raise InvalidAccountPolicyTransitionError(
                f"Account-policy Outbox event {event_id} was not found"
            )
        return event

    def _require_notification_intent(self, event: AccountPolicyOutboxEvent) -> None:
        if event.notification_type is None:
            raise InvalidAccountPolicyTransitionError(
                "Structural Outbox events cannot be prepared for notification"
            )

    def _now(self) -> datetime:
        value = self.clock.now()
        if value.tzinfo is None or value.utcoffset() is None:
            raise InvalidServerTimeError(
                "The injected server clock must return timezone-aware UTC time"
            )
        return value.astimezone(UTC)

    def _idempotency_key(
        self, event_id: uuid.UUID, namespace: str, operation_id: str
    ) -> str:
        if not operation_id or not operation_id.strip():
            raise InvalidAccountPolicyTransitionError(
                "An idempotent operation identifier is required"
            )
        digest = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()
        return f"account-policy-outbox:{event_id}:{namespace}:{digest}"


def get_account_policy_outbox_service() -> AccountPolicyOutboxService:
    """Assemble the internal Outbox service dependency chain."""

    return AccountPolicyOutboxService(clock=SystemUtcClock())
