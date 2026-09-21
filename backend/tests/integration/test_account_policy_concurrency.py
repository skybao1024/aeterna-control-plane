"""Real-PostgreSQL evidence for the I03 account-policy prototype."""

import asyncio
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select

from app.db.base import get_session_local
from app.models.account_policy import (
    AccountPolicy,
    AccountPolicyOutboxEvent,
    AccountPolicyState,
)
from app.services.internal.account_policy_transition import (
    AccountPolicyTransitionHooks,
    AccountPolicyTransitionService,
    InvalidAccountPolicyTransitionError,
    TransitionOutcome,
)

pytestmark = pytest.mark.asyncio(loop_scope="session")

INACTIVITY_SECONDS = 30 * 24 * 60 * 60
WARNING_SECONDS = 7 * 24 * 60 * 60
GRACE_SECONDS = 3 * 24 * 60 * 60


@dataclass
class MutableUtcClock:
    """Deterministic server clock used by integration tests."""

    current: datetime

    def now(self) -> datetime:
        return self.current


class AsyncBarrier:
    """Release all participants without relying on timing sleeps."""

    def __init__(self, participants: int):
        self.participants = participants
        self.arrived = 0
        self._lock = asyncio.Lock()
        self._released = asyncio.Event()

    async def wait(self) -> None:
        async with self._lock:
            self.arrived += 1
            if self.arrived == self.participants:
                self._released.set()
        await self._released.wait()


class BeforeLockBarrierHooks(AccountPolicyTransitionHooks):
    def __init__(self, barrier: AsyncBarrier):
        self.barrier = barrier

    async def before_policy_lock(self, operation: str, policy_id: uuid.UUID) -> None:
        await self.barrier.wait()


class BlockingAfterLockHooks(AccountPolicyTransitionHooks):
    def __init__(self):
        self.locked = asyncio.Event()
        self.proceed = asyncio.Event()

    async def after_policy_lock(self, operation: str, policy: AccountPolicy) -> None:
        self.locked.set()
        await self.proceed.wait()


class SignalBeforeLockHooks(AccountPolicyTransitionHooks):
    def __init__(self):
        self.started = asyncio.Event()

    async def before_policy_lock(self, operation: str, policy_id: uuid.UUID) -> None:
        self.started.set()


class FailingTransitionHooks(AccountPolicyTransitionHooks):
    def __init__(self, stage: str):
        self.stage = stage

    async def after_state_write(self, operation: str, policy: AccountPolicy) -> None:
        if self.stage == "state":
            raise RuntimeError("Injected interruption after state write")

    async def after_outbox_write(
        self, operation: str, event: AccountPolicyOutboxEvent
    ) -> None:
        if self.stage == "outbox":
            raise RuntimeError("Injected interruption after Outbox write")


@pytest_asyncio.fixture(autouse=True, loop_scope="session")
async def clean_policy_tables():
    session_factory = get_session_local()
    async with session_factory.begin() as db:
        await db.execute(delete(AccountPolicyOutboxEvent))
        await db.execute(delete(AccountPolicy))
    yield
    async with session_factory.begin() as db:
        await db.execute(delete(AccountPolicyOutboxEvent))
        await db.execute(delete(AccountPolicy))


async def create_policy(
    *,
    state: AccountPolicyState,
    now: datetime,
    due_at: datetime | None = None,
    warning_started_at: datetime | None = None,
    owner_warning_proven_at: datetime | None = None,
    grace_started_at: datetime | None = None,
) -> uuid.UUID:
    policy_id = uuid.uuid4()
    last_activity_at = now - timedelta(seconds=INACTIVITY_SECONDS)
    session_factory = get_session_local()
    async with session_factory.begin() as db:
        db.add(
            AccountPolicy(
                id=policy_id,
                state=state.value,
                version=0,
                inactivity_window_seconds=INACTIVITY_SECONDS,
                warning_window_seconds=WARNING_SECONDS,
                grace_window_seconds=GRACE_SECONDS,
                last_activity_at=last_activity_at,
                due_at=due_at
                or last_activity_at + timedelta(seconds=INACTIVITY_SECONDS),
                state_changed_at=now,
                warning_started_at=warning_started_at,
                owner_warning_proven_at=owner_warning_proven_at,
                grace_started_at=grace_started_at,
            )
        )
    return policy_id


async def load_policy(policy_id: uuid.UUID) -> AccountPolicy:
    session_factory = get_session_local()
    async with session_factory() as db:
        result = await db.execute(
            select(AccountPolicy).where(AccountPolicy.id == policy_id)
        )
        policy = result.scalar_one()
        db.expunge(policy)
        return policy


async def load_outbox_events(
    policy_id: uuid.UUID,
) -> list[AccountPolicyOutboxEvent]:
    session_factory = get_session_local()
    async with session_factory() as db:
        result = await db.execute(
            select(AccountPolicyOutboxEvent)
            .where(AccountPolicyOutboxEvent.account_policy_id == policy_id)
            .order_by(AccountPolicyOutboxEvent.created_at)
        )
        events = list(result.scalars())
        for event in events:
            db.expunge(event)
        return events


async def call_scheduler(
    service: AccountPolicyTransitionService,
    policy_id: uuid.UUID,
    scheduler_run_id: str,
):
    session_factory = get_session_local()
    async with session_factory() as db:
        return await service.run_scheduler(db, policy_id, scheduler_run_id)


async def call_heartbeat(
    service: AccountPolicyTransitionService,
    policy_id: uuid.UUID,
    heartbeat_id: str,
):
    session_factory = get_session_local()
    async with session_factory() as db:
        return await service.record_heartbeat(db, policy_id, heartbeat_id)


@pytest.mark.parametrize(
    "initial_state",
    [AccountPolicyState.PRE_WARNING, AccountPolicyState.GRACE_PERIOD],
)
async def test_heartbeat_atomically_cancels_warning_or_grace(initial_state):
    now = datetime(2026, 9, 21, 12, tzinfo=UTC)
    stale_time = now - timedelta(days=10)
    policy_id = await create_policy(
        state=initial_state,
        now=stale_time,
        due_at=stale_time,
        warning_started_at=stale_time,
        owner_warning_proven_at=(
            stale_time if initial_state is AccountPolicyState.GRACE_PERIOD else None
        ),
        grace_started_at=(
            stale_time if initial_state is AccountPolicyState.GRACE_PERIOD else None
        ),
    )
    service = AccountPolicyTransitionService(clock=MutableUtcClock(now))

    result = await call_heartbeat(service, policy_id, "heartbeat-0001")

    policy = await load_policy(policy_id)
    events = await load_outbox_events(policy_id)
    assert result.outcome is TransitionOutcome.APPLIED
    assert policy.state == AccountPolicyState.ACTIVE.value
    assert policy.last_activity_at == now
    assert policy.due_at == now + timedelta(seconds=INACTIVITY_SECONDS)
    assert policy.warning_started_at is None
    assert policy.owner_warning_proven_at is None
    assert policy.grace_started_at is None
    assert policy.released_at is None
    assert policy.version == 1
    assert len(events) == 1
    assert events[0].event_type == "account-policy-heartbeat-reset"
    assert events[0].policy_version == policy.version


async def test_release_wins_race_and_heartbeat_cannot_reverse_it():
    now = datetime(2026, 9, 21, 12, tzinfo=UTC)
    grace_started_at = now - timedelta(seconds=GRACE_SECONDS)
    policy_id = await create_policy(
        state=AccountPolicyState.GRACE_PERIOD,
        now=grace_started_at,
        due_at=grace_started_at,
        warning_started_at=grace_started_at,
        owner_warning_proven_at=grace_started_at,
        grace_started_at=grace_started_at,
    )
    clock = MutableUtcClock(now)
    release_hooks = BlockingAfterLockHooks()
    heartbeat_hooks = SignalBeforeLockHooks()
    release_service = AccountPolicyTransitionService(clock, release_hooks)
    heartbeat_service = AccountPolicyTransitionService(clock, heartbeat_hooks)

    release_task = asyncio.create_task(
        call_scheduler(release_service, policy_id, "release-race")
    )
    await release_hooks.locked.wait()
    heartbeat_task = asyncio.create_task(
        call_heartbeat(heartbeat_service, policy_id, "heartbeat-race")
    )
    await heartbeat_hooks.started.wait()
    release_hooks.proceed.set()
    release_result, heartbeat_result = await asyncio.gather(
        release_task, heartbeat_task
    )

    policy = await load_policy(policy_id)
    events = await load_outbox_events(policy_id)
    assert release_result.outcome is TransitionOutcome.APPLIED
    assert heartbeat_result.outcome is TransitionOutcome.RELEASED_REJECTED
    assert policy.state == AccountPolicyState.RELEASED.value
    assert policy.released_at == now
    assert [event.event_type for event in events] == ["account-policy-released"]


async def test_heartbeat_wins_race_and_makes_release_ineligible():
    now = datetime(2026, 9, 21, 12, tzinfo=UTC)
    grace_started_at = now - timedelta(seconds=GRACE_SECONDS)
    policy_id = await create_policy(
        state=AccountPolicyState.GRACE_PERIOD,
        now=grace_started_at,
        due_at=grace_started_at,
        warning_started_at=grace_started_at,
        owner_warning_proven_at=grace_started_at,
        grace_started_at=grace_started_at,
    )
    clock = MutableUtcClock(now)
    heartbeat_hooks = BlockingAfterLockHooks()
    scheduler_hooks = SignalBeforeLockHooks()
    heartbeat_service = AccountPolicyTransitionService(clock, heartbeat_hooks)
    scheduler_service = AccountPolicyTransitionService(clock, scheduler_hooks)

    heartbeat_task = asyncio.create_task(
        call_heartbeat(heartbeat_service, policy_id, "heartbeat-wins")
    )
    await heartbeat_hooks.locked.wait()
    scheduler_task = asyncio.create_task(
        call_scheduler(scheduler_service, policy_id, "release-loses")
    )
    await scheduler_hooks.started.wait()
    heartbeat_hooks.proceed.set()
    heartbeat_result, scheduler_result = await asyncio.gather(
        heartbeat_task, scheduler_task
    )

    policy = await load_policy(policy_id)
    events = await load_outbox_events(policy_id)
    assert heartbeat_result.outcome is TransitionOutcome.APPLIED
    assert scheduler_result.outcome is TransitionOutcome.NOOP
    assert policy.state == AccountPolicyState.ACTIVE.value
    assert policy.due_at == now + timedelta(seconds=INACTIVITY_SECONDS)
    assert [event.event_type for event in events] == ["account-policy-heartbeat-reset"]


async def test_concurrent_repeated_scheduler_run_has_one_effect_and_event():
    now = datetime(2026, 9, 21, 12, tzinfo=UTC)
    policy_id = await create_policy(
        state=AccountPolicyState.ACTIVE,
        now=now - timedelta(days=30),
        due_at=now + timedelta(days=1),
    )
    barrier = AsyncBarrier(participants=2)
    clock = MutableUtcClock(now)
    first_service = AccountPolicyTransitionService(
        clock, BeforeLockBarrierHooks(barrier)
    )
    second_service = AccountPolicyTransitionService(
        clock, BeforeLockBarrierHooks(barrier)
    )

    first_result, second_result = await asyncio.gather(
        call_scheduler(first_service, policy_id, "scheduler-run-0001"),
        call_scheduler(second_service, policy_id, "scheduler-run-0001"),
    )

    policy = await load_policy(policy_id)
    events = await load_outbox_events(policy_id)
    assert {first_result.outcome, second_result.outcome} == {
        TransitionOutcome.APPLIED,
        TransitionOutcome.DUPLICATE,
    }
    assert policy.state == AccountPolicyState.PRE_WARNING.value
    assert policy.version == 1
    assert len(events) == 1
    assert events[0].event_type == "account-policy-pre-warning-started"


async def test_normal_scheduler_path_requires_warning_proof_and_full_grace():
    due_at = datetime(2026, 10, 1, 12, tzinfo=UTC)
    warning_at = due_at - timedelta(seconds=WARNING_SECONDS)
    clock = MutableUtcClock(warning_at)
    policy_id = await create_policy(
        state=AccountPolicyState.ACTIVE,
        now=due_at - timedelta(seconds=INACTIVITY_SECONDS),
        due_at=due_at,
    )
    service = AccountPolicyTransitionService(clock)
    session_factory = get_session_local()

    pre_warning = await call_scheduler(service, policy_id, "normal-pre-warning")
    clock.current = due_at
    grace = await call_scheduler(service, policy_id, "normal-grace")
    clock.current = due_at + timedelta(seconds=GRACE_SECONDS * 2)
    unproven_release = await call_scheduler(service, policy_id, "unproven-release")

    proof_time = clock.current
    async with session_factory() as db:
        proof = await service.confirm_owner_warning(db, policy_id, "normal-proof")
    clock.current = proof_time + timedelta(seconds=GRACE_SECONDS - 1)
    early_release = await call_scheduler(service, policy_id, "normal-early-release")
    clock.current = proof_time + timedelta(seconds=GRACE_SECONDS)
    release = await call_scheduler(service, policy_id, "normal-release")

    policy = await load_policy(policy_id)
    events = await load_outbox_events(policy_id)
    assert pre_warning.outcome is TransitionOutcome.APPLIED
    assert grace.outcome is TransitionOutcome.APPLIED
    assert unproven_release.outcome is TransitionOutcome.NOOP
    assert proof.outcome is TransitionOutcome.APPLIED
    assert early_release.outcome is TransitionOutcome.NOOP
    assert release.outcome is TransitionOutcome.APPLIED
    assert policy.state == AccountPolicyState.RELEASED.value
    assert policy.released_at == clock.current
    assert [event.event_type for event in events] == [
        "account-policy-pre-warning-started",
        "account-policy-grace-started",
        "account-policy-owner-warning-proven",
        "account-policy-released",
    ]


@pytest.mark.parametrize("failure_stage", ["state", "outbox"])
async def test_interruption_rolls_back_state_and_outbox_together(failure_stage):
    now = datetime(2026, 9, 21, 12, tzinfo=UTC)
    policy_id = await create_policy(
        state=AccountPolicyState.ACTIVE,
        now=now - timedelta(days=30),
        due_at=now + timedelta(days=1),
    )
    service = AccountPolicyTransitionService(
        MutableUtcClock(now), FailingTransitionHooks(failure_stage)
    )

    with pytest.raises(RuntimeError, match="Injected interruption"):
        await call_scheduler(service, policy_id, f"failure-{failure_stage}")

    policy = await load_policy(policy_id)
    events = await load_outbox_events(policy_id)
    assert policy.state == AccountPolicyState.ACTIVE.value
    assert policy.version == 0
    assert events == []


async def test_outage_recovery_restarts_warning_and_complete_grace_period():
    recovery_time = datetime(2026, 9, 21, 12, tzinfo=UTC)
    stale_time = recovery_time - timedelta(days=20)
    policy_id = await create_policy(
        state=AccountPolicyState.GRACE_PERIOD,
        now=stale_time,
        due_at=stale_time,
        warning_started_at=stale_time,
        owner_warning_proven_at=stale_time,
        grace_started_at=stale_time,
    )
    clock = MutableUtcClock(recovery_time)
    service = AccountPolicyTransitionService(clock)
    session_factory = get_session_local()

    async with session_factory() as db:
        recovered = await service.recover_from_outage(db, policy_id, "outage-2026-09")
    async with session_factory() as db:
        duplicate = await service.recover_from_outage(db, policy_id, "outage-2026-09")
    immediate = await call_scheduler(service, policy_id, "post-outage-immediate")

    policy = await load_policy(policy_id)
    assert recovered.outcome is TransitionOutcome.APPLIED
    assert duplicate.outcome is TransitionOutcome.DUPLICATE
    assert immediate.outcome is TransitionOutcome.NOOP
    assert policy.state == AccountPolicyState.GRACE_PERIOD.value
    assert policy.warning_started_at == recovery_time
    assert policy.owner_warning_proven_at is None
    assert policy.grace_started_at == recovery_time

    proof_time = recovery_time + timedelta(hours=1)
    clock.current = proof_time
    async with session_factory() as db:
        proof = await service.confirm_owner_warning(db, policy_id, "warning-proof")
    clock.current = proof_time + timedelta(seconds=GRACE_SECONDS - 1)
    early = await call_scheduler(service, policy_id, "release-too-early")
    clock.current = proof_time + timedelta(seconds=GRACE_SECONDS)
    released = await call_scheduler(service, policy_id, "release-on-time")

    policy = await load_policy(policy_id)
    events = await load_outbox_events(policy_id)
    assert proof.outcome is TransitionOutcome.APPLIED
    assert early.outcome is TransitionOutcome.NOOP
    assert released.outcome is TransitionOutcome.APPLIED
    assert policy.state == AccountPolicyState.RELEASED.value
    assert policy.released_at == clock.current
    assert [event.event_type for event in events] == [
        "account-policy-outage-warning-required",
        "account-policy-owner-warning-proven",
        "account-policy-released",
    ]


async def test_invalid_transition_rolls_back_without_outbox_event():
    now = datetime(2026, 9, 21, 12, tzinfo=UTC)
    policy_id = await create_policy(state=AccountPolicyState.ACTIVE, now=now)
    service = AccountPolicyTransitionService(MutableUtcClock(now))
    session_factory = get_session_local()

    async with session_factory() as db:
        with pytest.raises(
            InvalidAccountPolicyTransitionError,
            match="Owner warning proof is invalid",
        ):
            await service.confirm_owner_warning(db, policy_id, "invalid-proof")

    policy = await load_policy(policy_id)
    assert policy.state == AccountPolicyState.ACTIVE.value
    assert policy.version == 0
    assert await load_outbox_events(policy_id) == []


async def test_repeated_heartbeat_idempotency_key_does_not_extend_twice():
    first_time = datetime(2026, 9, 21, 12, tzinfo=UTC)
    clock = MutableUtcClock(first_time)
    policy_id = await create_policy(
        state=AccountPolicyState.ACTIVE,
        now=first_time - timedelta(days=1),
    )
    service = AccountPolicyTransitionService(clock)

    first = await call_heartbeat(service, policy_id, "same-heartbeat")
    clock.current = first_time + timedelta(days=1)
    duplicate = await call_heartbeat(service, policy_id, "same-heartbeat")

    policy = await load_policy(policy_id)
    events = await load_outbox_events(policy_id)
    assert first.outcome is TransitionOutcome.APPLIED
    assert duplicate.outcome is TransitionOutcome.DUPLICATE
    assert policy.last_activity_at == first_time
    assert policy.due_at == first_time + timedelta(seconds=INACTIVITY_SECONDS)
    assert policy.version == 1
    assert len(events) == 1
    assert events[0].idempotency_key


async def test_outbox_idempotency_key_has_database_unique_enforcement():
    now = datetime(2026, 9, 21, 12, tzinfo=UTC)
    policy_id = await create_policy(state=AccountPolicyState.ACTIVE, now=now)
    service = AccountPolicyTransitionService(MutableUtcClock(now))

    first = await call_heartbeat(service, policy_id, "database-unique-key")
    duplicate = await call_heartbeat(service, policy_id, "database-unique-key")

    session_factory = get_session_local()
    async with session_factory() as db:
        event_count = await db.scalar(
            select(func.count(AccountPolicyOutboxEvent.id)).where(
                AccountPolicyOutboxEvent.account_policy_id == policy_id
            )
        )
    assert first.outcome is TransitionOutcome.APPLIED
    assert duplicate.outcome is TransitionOutcome.DUPLICATE
    assert event_count == 1
