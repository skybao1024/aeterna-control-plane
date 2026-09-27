"""Transactional I11 account-policy state transitions."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Protocol

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import transaction
from app.models.account_policy import (
    AccountPolicy,
    AccountPolicyOutboxEvent,
    AccountPolicyState,
)
from app.models.aeterna_identity import AeternaAccount

MIN_INACTIVITY_SECONDS = 14 * 24 * 60 * 60
MAX_INACTIVITY_SECONDS = 365 * 24 * 60 * 60
DEFAULT_INACTIVITY_SECONDS = 30 * 24 * 60 * 60
MIN_WARNING_SECONDS = 3 * 24 * 60 * 60
MAX_WARNING_SECONDS = 30 * 24 * 60 * 60
DEFAULT_WARNING_SECONDS = 7 * 24 * 60 * 60
MIN_GRACE_SECONDS = 3 * 24 * 60 * 60
DEFAULT_GRACE_SECONDS = 7 * 24 * 60 * 60

OWNER_PRE_WARNING = "owner-pre-warning"
OWNER_GRACE_STARTED = "owner-grace-period-started"
OWNER_WARNING_REQUIRED = "owner-warning-required"
OWNER_RELEASE_AUTHORIZED = "owner-release-authorized"


class AccountPolicyTransitionError(RuntimeError):
    """Base error for rejected internal policy mutations."""


class AccountPolicyNotFoundError(AccountPolicyTransitionError):
    """Raised when a requested policy does not exist."""


class InvalidAccountPolicyTransitionError(AccountPolicyTransitionError):
    """Raised when a command is incompatible with persisted policy state."""


class ConcurrentAccountPolicyTransitionError(AccountPolicyTransitionError):
    """Raised when the explicit compare-and-set condition loses a race."""


class InvalidServerTimeError(AccountPolicyTransitionError):
    """Raised when the injected server clock does not return aware UTC time."""


class TransitionOutcome(str, Enum):
    """Observable result of an internal transition attempt."""

    APPLIED = "applied"
    DUPLICATE = "duplicate"
    NOOP = "noop"
    RELEASED_REJECTED = "released-rejected"
    TERMINAL_REJECTED = "terminal-rejected"


@dataclass(frozen=True)
class TransitionResult:
    """State returned after a transition attempt commits."""

    outcome: TransitionOutcome
    state: AccountPolicyState
    version: int
    outbox_event_id: uuid.UUID | None = None


class UtcClock(Protocol):
    """Clock boundary for authoritative and deterministic server time."""

    def now(self) -> datetime:
        """Return the current timezone-aware server instant."""


class SystemUtcClock:
    """Production UTC clock implementation."""

    def now(self) -> datetime:
        return datetime.now(UTC)


class AccountPolicyTransitionHooks:
    """No-op coordination hooks overridden by deterministic integration tests."""

    async def before_policy_lock(self, operation: str, policy_id: uuid.UUID) -> None:
        """Run immediately before requesting the account and policy locks."""

    async def after_policy_lock(self, operation: str, policy: AccountPolicy) -> None:
        """Run while the account and policy locks are held."""

    async def after_state_write(self, operation: str, policy: AccountPolicy) -> None:
        """Run after compare-and-set and before the Outbox insert."""

    async def after_outbox_write(
        self, operation: str, event: AccountPolicyOutboxEvent
    ) -> None:
        """Run after Outbox flush but before transaction commit."""


class AccountPolicyTransitionService:
    """Serialize account policy changes and atomically persist their intents."""

    _NORMAL_TRANSITIONS = {
        AccountPolicyState.ACTIVE: {
            AccountPolicyState.PRE_WARNING,
            AccountPolicyState.DISABLED,
            AccountPolicyState.DELETED,
        },
        AccountPolicyState.PRE_WARNING: {
            AccountPolicyState.ACTIVE,
            AccountPolicyState.GRACE_PERIOD,
            AccountPolicyState.DISABLED,
            AccountPolicyState.DELETED,
        },
        AccountPolicyState.GRACE_PERIOD: {
            AccountPolicyState.ACTIVE,
            AccountPolicyState.RELEASED,
            AccountPolicyState.DISABLED,
            AccountPolicyState.DELETED,
        },
        AccountPolicyState.RELEASED: set(),
        AccountPolicyState.DISABLED: {AccountPolicyState.DELETED},
        AccountPolicyState.DELETED: set(),
    }

    def __init__(
        self,
        clock: UtcClock | None = None,
        hooks: AccountPolicyTransitionHooks | None = None,
    ):
        self.clock = clock or SystemUtcClock()
        self.hooks = hooks or AccountPolicyTransitionHooks()

    async def record_heartbeat(
        self,
        db: AsyncSession,
        policy_id: uuid.UUID,
        heartbeat_id: str,
    ) -> TransitionResult:
        """Apply one valid heartbeat using server receipt time."""

        async with transaction(db):
            policy = await self._lock_policy(db, policy_id, "heartbeat")
            return await self.record_locked_account_heartbeat(
                db=db,
                account_id=policy.account_id,
                policy=policy,
                heartbeat_id=heartbeat_id,
                received_at=self._now(),
            )

    async def lock_policy_for_account(
        self,
        db: AsyncSession,
        account_id: uuid.UUID,
        operation: str,
    ) -> AccountPolicy | None:
        """Lock the policy after the caller has locked its account row."""

        await self.hooks.before_policy_lock(operation, account_id)
        policy = await db.scalar(
            select(AccountPolicy)
            .where(AccountPolicy.account_id == account_id)
            .with_for_update()
        )
        if policy is not None:
            await self.hooks.after_policy_lock(operation, policy)
        return policy

    async def record_locked_account_heartbeat(
        self,
        *,
        db: AsyncSession,
        account_id: uuid.UUID | None,
        policy: AccountPolicy | None,
        heartbeat_id: str,
        received_at: datetime,
    ) -> TransitionResult:
        """Mutate a policy inside the caller-owned account transaction."""

        operation = "heartbeat"
        now = self.normalize_time(received_at)
        if policy is None:
            if account_id is None:
                raise InvalidAccountPolicyTransitionError(
                    "A linked account is required to create an account policy"
                )
            policy = await self._create_policy(db, account_id, now)

        idempotency_key = self._idempotency_key(policy.id, operation, heartbeat_id)
        duplicate = await self._duplicate_result(db, policy, idempotency_key)
        if duplicate is not None:
            return duplicate

        state = self._state(policy)
        terminal = self._heartbeat_terminal_result(state, policy)
        if terminal is not None:
            return terminal

        if state in {
            AccountPolicyState.PRE_WARNING,
            AccountPolicyState.GRACE_PERIOD,
        }:
            await self._cancel_notification_intents(db, policy.id, now)

        due_at = now + timedelta(seconds=policy.inactivity_window_seconds)
        event_type = (
            "account-policy-heartbeat-recorded"
            if state is AccountPolicyState.ACTIVE
            else "account-policy-heartbeat-reset"
        )
        return await self._write_mutation(
            db=db,
            policy=policy,
            operation=operation,
            target_state=AccountPolicyState.ACTIVE,
            event_type=event_type,
            idempotency_key=idempotency_key,
            now=now,
            values={
                "last_activity_at": now,
                "due_at": due_at,
                "warning_started_at": None,
                "owner_warning_proven_at": None,
                "grace_started_at": None,
                "released_at": None,
            },
            allow_same_state=True,
        )

    async def run_scheduler(
        self,
        db: AsyncSession,
        policy_id: uuid.UUID,
        scheduler_run_id: str,
    ) -> TransitionResult:
        """Evaluate at most one due transition for an at-least-once run."""

        operation = "scheduler"
        idempotency_key = self._idempotency_key(policy_id, operation, scheduler_run_id)
        async with transaction(db):
            policy = await self._lock_policy(db, policy_id, operation)
            duplicate = await self._duplicate_result(db, policy, idempotency_key)
            if duplicate is not None:
                return duplicate

            state = self._state(policy)
            now = self._now()
            if state is AccountPolicyState.ACTIVE:
                warning_at = policy.due_at - timedelta(
                    seconds=policy.warning_window_seconds
                )
                if now < warning_at:
                    return self._result(TransitionOutcome.NOOP, policy)
                return await self._write_mutation(
                    db=db,
                    policy=policy,
                    operation=operation,
                    target_state=AccountPolicyState.PRE_WARNING,
                    event_type="account-policy-pre-warning-started",
                    notification_type=OWNER_PRE_WARNING,
                    idempotency_key=idempotency_key,
                    now=now,
                    values={"warning_started_at": now},
                )

            if state is AccountPolicyState.PRE_WARNING:
                if now < policy.due_at:
                    return self._result(TransitionOutcome.NOOP, policy)
                return await self._write_mutation(
                    db=db,
                    policy=policy,
                    operation=operation,
                    target_state=AccountPolicyState.GRACE_PERIOD,
                    event_type="account-policy-grace-started",
                    notification_type=OWNER_GRACE_STARTED,
                    idempotency_key=idempotency_key,
                    now=now,
                    values={"grace_started_at": now},
                )

            if state is AccountPolicyState.GRACE_PERIOD:
                if policy.owner_warning_proven_at is None:
                    return self._result(TransitionOutcome.NOOP, policy)
                if policy.grace_started_at is None:
                    raise InvalidAccountPolicyTransitionError(
                        "GRACE_PERIOD requires grace_started_at"
                    )
                grace_baseline = max(
                    policy.grace_started_at, policy.owner_warning_proven_at
                )
                release_at = grace_baseline + timedelta(
                    seconds=policy.grace_window_seconds
                )
                if now < release_at:
                    return self._result(TransitionOutcome.NOOP, policy)
                return await self._write_mutation(
                    db=db,
                    policy=policy,
                    operation=operation,
                    target_state=AccountPolicyState.RELEASED,
                    event_type="account-policy-released",
                    notification_type=OWNER_RELEASE_AUTHORIZED,
                    idempotency_key=idempotency_key,
                    now=now,
                    values={"released_at": now},
                )

            return self._result(TransitionOutcome.NOOP, policy)

    async def confirm_owner_warning(
        self,
        db: AsyncSession,
        policy_id: uuid.UUID,
        proof_id: str,
    ) -> TransitionResult:
        """Record independently authenticated proof of a completed warning."""

        operation = "warning-proof"
        idempotency_key = self._idempotency_key(policy_id, operation, proof_id)
        async with transaction(db):
            policy = await self._lock_policy(db, policy_id, operation)
            duplicate = await self._duplicate_result(db, policy, idempotency_key)
            if duplicate is not None:
                return duplicate

            state = self._state(policy)
            if state not in {
                AccountPolicyState.PRE_WARNING,
                AccountPolicyState.GRACE_PERIOD,
            }:
                raise InvalidAccountPolicyTransitionError(
                    f"Owner warning proof is invalid while policy is {state.value}"
                )
            if policy.owner_warning_proven_at is not None:
                return self._result(TransitionOutcome.NOOP, policy)

            now = self._now()
            values = {"owner_warning_proven_at": now}
            if state is AccountPolicyState.GRACE_PERIOD:
                values["grace_started_at"] = now
            return await self._write_mutation(
                db=db,
                policy=policy,
                operation=operation,
                target_state=state,
                event_type="account-policy-owner-warning-proven",
                idempotency_key=idempotency_key,
                now=now,
                values=values,
                allow_same_state=True,
            )

    async def recover_from_outage(
        self,
        db: AsyncSession,
        policy_id: uuid.UUID,
        recovery_id: str,
    ) -> TransitionResult:
        """Restart warning and a full grace interval after an outage."""

        operation = "outage-recovery"
        idempotency_key = self._idempotency_key(policy_id, operation, recovery_id)
        async with transaction(db):
            policy = await self._lock_policy(db, policy_id, operation)
            duplicate = await self._duplicate_result(db, policy, idempotency_key)
            if duplicate is not None:
                return duplicate

            state = self._state(policy)
            if state is AccountPolicyState.RELEASED:
                return self._result(TransitionOutcome.RELEASED_REJECTED, policy)
            if state in {AccountPolicyState.DISABLED, AccountPolicyState.DELETED}:
                return self._result(TransitionOutcome.TERMINAL_REJECTED, policy)

            now = self._now()
            if (
                state
                in {
                    AccountPolicyState.ACTIVE,
                    AccountPolicyState.PRE_WARNING,
                }
                and now < policy.due_at
            ):
                return self._result(TransitionOutcome.NOOP, policy)

            await self._cancel_notification_intents(db, policy.id, now)
            return await self._write_mutation(
                db=db,
                policy=policy,
                operation=operation,
                target_state=AccountPolicyState.GRACE_PERIOD,
                event_type="account-policy-outage-warning-required",
                notification_type=OWNER_WARNING_REQUIRED,
                idempotency_key=idempotency_key,
                now=now,
                values={
                    "warning_started_at": now,
                    "owner_warning_proven_at": None,
                    "grace_started_at": now,
                    "released_at": None,
                },
                allow_recovery_transition=True,
                allow_same_state=True,
            )

    async def disable_policy(
        self,
        db: AsyncSession,
        policy_id: uuid.UUID,
        command_id: str,
    ) -> TransitionResult:
        """Stop an unreleased policy without permitting later reactivation."""

        return await self._apply_terminal_command(
            db,
            policy_id,
            command_id,
            AccountPolicyState.DISABLED,
            "disable",
            "account-policy-disabled",
        )

    async def delete_policy(
        self,
        db: AsyncSession,
        policy_id: uuid.UUID,
        command_id: str,
    ) -> TransitionResult:
        """Logically delete an unreleased or disabled policy."""

        return await self._apply_terminal_command(
            db,
            policy_id,
            command_id,
            AccountPolicyState.DELETED,
            "delete",
            "account-policy-deleted",
        )

    async def _apply_terminal_command(
        self,
        db: AsyncSession,
        policy_id: uuid.UUID,
        command_id: str,
        target_state: AccountPolicyState,
        operation: str,
        event_type: str,
    ) -> TransitionResult:
        idempotency_key = self._idempotency_key(policy_id, operation, command_id)
        async with transaction(db):
            policy = await self._lock_policy(db, policy_id, operation)
            duplicate = await self._duplicate_result(db, policy, idempotency_key)
            if duplicate is not None:
                return duplicate

            state = self._state(policy)
            if state is AccountPolicyState.RELEASED:
                return self._result(TransitionOutcome.RELEASED_REJECTED, policy)
            if state is AccountPolicyState.DELETED:
                return self._result(TransitionOutcome.TERMINAL_REJECTED, policy)
            if state is target_state:
                return self._result(TransitionOutcome.NOOP, policy)

            now = self._now()
            await self._cancel_notification_intents(db, policy.id, now)
            return await self._write_mutation(
                db=db,
                policy=policy,
                operation=operation,
                target_state=target_state,
                event_type=event_type,
                idempotency_key=idempotency_key,
                now=now,
                values={
                    "owner_warning_proven_at": None,
                    "grace_started_at": None,
                },
            )

    async def _create_policy(
        self,
        db: AsyncSession,
        account_id: uuid.UUID,
        now: datetime,
    ) -> AccountPolicy:
        policy = AccountPolicy(
            account_id=account_id,
            state=AccountPolicyState.ACTIVE.value,
            version=0,
            inactivity_window_seconds=DEFAULT_INACTIVITY_SECONDS,
            warning_window_seconds=DEFAULT_WARNING_SECONDS,
            grace_window_seconds=DEFAULT_GRACE_SECONDS,
            last_activity_at=now,
            due_at=now + timedelta(seconds=DEFAULT_INACTIVITY_SECONDS),
            state_changed_at=now,
        )
        db.add(policy)
        await db.flush()
        return policy

    async def _lock_policy(
        self, db: AsyncSession, policy_id: uuid.UUID, operation: str
    ) -> AccountPolicy:
        await self.hooks.before_policy_lock(operation, policy_id)
        account_id = await db.scalar(
            select(AccountPolicy.account_id).where(AccountPolicy.id == policy_id)
        )
        if account_id is not None:
            account = await db.scalar(
                select(AeternaAccount)
                .where(AeternaAccount.id == account_id)
                .with_for_update()
            )
            if account is None:
                raise AccountPolicyNotFoundError(
                    f"Account for policy {policy_id} was not found"
                )
        policy = await db.scalar(
            select(AccountPolicy).where(AccountPolicy.id == policy_id).with_for_update()
        )
        if policy is None:
            raise AccountPolicyNotFoundError(
                f"Account policy {policy_id} was not found"
            )
        await self.hooks.after_policy_lock(operation, policy)
        return policy

    async def _duplicate_result(
        self,
        db: AsyncSession,
        policy: AccountPolicy,
        idempotency_key: str,
    ) -> TransitionResult | None:
        event = await db.scalar(
            select(AccountPolicyOutboxEvent).where(
                AccountPolicyOutboxEvent.idempotency_key == idempotency_key
            )
        )
        if event is None:
            return None
        if event.account_policy_id != policy.id:
            raise InvalidAccountPolicyTransitionError(
                "Idempotency key is bound to a different account policy"
            )
        try:
            event_state = AccountPolicyState(event.to_state)
        except ValueError as exc:
            raise InvalidAccountPolicyTransitionError(
                f"Persisted Outbox target state is invalid: {event.to_state}"
            ) from exc
        return TransitionResult(
            outcome=TransitionOutcome.DUPLICATE,
            state=event_state,
            version=event.policy_version,
            outbox_event_id=event.id,
        )

    async def _cancel_notification_intents(
        self,
        db: AsyncSession,
        policy_id: uuid.UUID,
        now: datetime,
    ) -> None:
        await db.execute(
            update(AccountPolicyOutboxEvent)
            .where(
                AccountPolicyOutboxEvent.account_policy_id == policy_id,
                AccountPolicyOutboxEvent.notification_type.is_not(None),
                AccountPolicyOutboxEvent.status.in_(
                    {"pending", "queued", "acknowledged"}
                ),
            )
            .values(
                status="cancelled",
                cancelled_at=now,
                updated_at=now,
            )
            .execution_options(synchronize_session=False)
        )

    async def _write_mutation(
        self,
        *,
        db: AsyncSession,
        policy: AccountPolicy,
        operation: str,
        target_state: AccountPolicyState,
        event_type: str,
        idempotency_key: str,
        now: datetime,
        values: dict,
        notification_type: str | None = None,
        allow_recovery_transition: bool = False,
        allow_same_state: bool = False,
    ) -> TransitionResult:
        source_state = self._state(policy)
        self._validate_transition(
            source_state,
            target_state,
            allow_recovery_transition=allow_recovery_transition,
            allow_same_state=allow_same_state,
        )
        expected_version = policy.version
        new_version = expected_version + 1
        update_values = {
            **values,
            "state": target_state.value,
            "version": new_version,
            "updated_at": now,
        }
        if source_state is not target_state:
            update_values["state_changed_at"] = now

        result = await db.execute(
            update(AccountPolicy)
            .where(
                AccountPolicy.id == policy.id,
                AccountPolicy.state == source_state.value,
                AccountPolicy.version == expected_version,
            )
            .values(**update_values)
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            raise ConcurrentAccountPolicyTransitionError(
                "Account policy compare-and-set condition did not match"
            )
        await db.refresh(policy)
        await self.hooks.after_state_write(operation, policy)

        delivery_idempotency_key = None
        if notification_type is not None:
            delivery_idempotency_key = (
                f"account-policy-notification:{policy.id}:"
                f"{notification_type}:v{new_version}"
            )
        event = AccountPolicyOutboxEvent(
            account_policy_id=policy.id,
            event_type=event_type,
            idempotency_key=idempotency_key,
            from_state=source_state.value,
            to_state=target_state.value,
            policy_version=new_version,
            payload={
                "account_policy_id": str(policy.id),
                "from_state": source_state.value,
                "to_state": target_state.value,
                "policy_version": new_version,
                "occurred_at": now.isoformat(),
            },
            scheduled_at=now,
            status="pending",
            notification_type=notification_type,
            delivery_idempotency_key=delivery_idempotency_key,
            attempt_count=0,
        )
        db.add(event)
        await db.flush()
        await self.hooks.after_outbox_write(operation, event)
        return TransitionResult(
            outcome=TransitionOutcome.APPLIED,
            state=target_state,
            version=new_version,
            outbox_event_id=event.id,
        )

    def _validate_transition(
        self,
        source_state: AccountPolicyState,
        target_state: AccountPolicyState,
        *,
        allow_recovery_transition: bool,
        allow_same_state: bool,
    ) -> None:
        if source_state is target_state:
            if allow_same_state:
                return
            raise InvalidAccountPolicyTransitionError(
                f"Self-transition from {source_state.value} is not allowed"
            )
        if (
            allow_recovery_transition
            and source_state
            in {
                AccountPolicyState.ACTIVE,
                AccountPolicyState.PRE_WARNING,
                AccountPolicyState.GRACE_PERIOD,
            }
            and target_state is AccountPolicyState.GRACE_PERIOD
        ):
            return
        if target_state not in self._NORMAL_TRANSITIONS[source_state]:
            raise InvalidAccountPolicyTransitionError(
                f"Transition from {source_state.value} to {target_state.value} is invalid"
            )

    def normalize_time(self, value: datetime) -> datetime:
        """Validate and normalize an injected server instant to UTC."""

        if value.tzinfo is None or value.utcoffset() is None:
            raise InvalidServerTimeError(
                "The injected server clock must return timezone-aware UTC time"
            )
        return value.astimezone(UTC)

    def _now(self) -> datetime:
        return self.normalize_time(self.clock.now())

    def _state(self, policy: AccountPolicy) -> AccountPolicyState:
        try:
            return AccountPolicyState(policy.state)
        except ValueError as exc:
            raise InvalidAccountPolicyTransitionError(
                f"Persisted account policy state is invalid: {policy.state}"
            ) from exc

    def _heartbeat_terminal_result(
        self,
        state: AccountPolicyState,
        policy: AccountPolicy,
    ) -> TransitionResult | None:
        if state is AccountPolicyState.RELEASED:
            return self._result(TransitionOutcome.RELEASED_REJECTED, policy)
        if state in {AccountPolicyState.DISABLED, AccountPolicyState.DELETED}:
            return self._result(TransitionOutcome.TERMINAL_REJECTED, policy)
        return None

    def _result(
        self, outcome: TransitionOutcome, policy: AccountPolicy
    ) -> TransitionResult:
        return TransitionResult(
            outcome=outcome,
            state=self._state(policy),
            version=policy.version,
        )

    def _idempotency_key(
        self, policy_id: uuid.UUID, namespace: str, operation_id: str
    ) -> str:
        if not operation_id or not operation_id.strip():
            raise InvalidAccountPolicyTransitionError(
                "An idempotent operation identifier is required"
            )
        digest = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()
        return f"account-policy:{policy_id}:{namespace}:{digest}"


def get_account_policy_transition_service() -> AccountPolicyTransitionService:
    """Assemble the internal transition service dependency chain."""

    return AccountPolicyTransitionService(
        clock=SystemUtcClock(), hooks=AccountPolicyTransitionHooks()
    )
