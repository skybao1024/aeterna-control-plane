"""Celery entry points for the I11 account-policy and Outbox workflows."""

import asyncio

from celery import shared_task
from sqlalchemy import select

from app.db.base import create_scheduler_engine, create_scheduler_session_factory
from app.models.account_policy import (
    AccountPolicy,
    AccountPolicyOutboxEvent,
    AccountPolicyState,
)
from app.services.internal.account_policy_outbox import (
    get_account_policy_outbox_service,
)
from app.services.internal.account_policy_transition import (
    get_account_policy_transition_service,
)


async def scan_account_policies() -> dict[str, int]:
    """Advance each non-terminal policy at most once per persisted version."""

    engine = create_scheduler_engine()
    session_factory = create_scheduler_session_factory(engine)
    try:
        async with session_factory() as db:
            rows = list(
                (
                    await db.execute(
                        select(
                            AccountPolicy.id,
                            AccountPolicy.state,
                            AccountPolicy.version,
                        ).where(
                            AccountPolicy.state.in_(
                                {
                                    AccountPolicyState.ACTIVE.value,
                                    AccountPolicyState.PRE_WARNING.value,
                                    AccountPolicyState.GRACE_PERIOD.value,
                                }
                            )
                        )
                    )
                ).all()
            )

        applied = 0
        service = get_account_policy_transition_service()
        for policy_id, state, version in rows:
            scheduler_run_id = f"policy:{policy_id}:state:{state}:version:{version}"
            async with session_factory() as db:
                result = await service.run_scheduler(db, policy_id, scheduler_run_id)
                if result.outcome.value == "applied":
                    applied += 1
        return {"examined": len(rows), "applied": applied}
    finally:
        await engine.dispose()


async def prepare_account_policy_notifications() -> dict[str, int]:
    """Prepare committed notification intents without sending provider mail."""

    engine = create_scheduler_engine()
    session_factory = create_scheduler_session_factory(engine)
    try:
        async with session_factory() as db:
            rows = list(
                (
                    await db.execute(
                        select(
                            AccountPolicyOutboxEvent.id,
                            AccountPolicyOutboxEvent.attempt_count,
                        ).where(
                            AccountPolicyOutboxEvent.status == "pending",
                            AccountPolicyOutboxEvent.notification_type.is_not(None),
                        )
                    )
                ).all()
            )

        prepared = 0
        service = get_account_policy_outbox_service()
        for event_id, attempt_count in rows:
            task_id = f"outbox:{event_id}:attempt:{attempt_count + 1}"
            async with session_factory() as db:
                result = await service.prepare_delivery(db, event_id, task_id)
                if result.outcome.value == "prepared":
                    prepared += 1
        return {"examined": len(rows), "prepared": prepared}
    finally:
        await engine.dispose()


@shared_task(name="app.schedule.jobs.account_policy.scan")
def scan_account_policies_task() -> dict[str, int]:
    """Run the server-time policy sweep in a worker-owned event loop."""

    return asyncio.run(scan_account_policies())


@shared_task(name="app.schedule.jobs.account_policy.prepare_notifications")
def prepare_account_policy_notifications_task() -> dict[str, int]:
    """Queue durable intents only; external provider delivery belongs to I12."""

    return asyncio.run(prepare_account_policy_notifications())
