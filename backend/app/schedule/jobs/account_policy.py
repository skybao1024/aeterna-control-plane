"""Celery entry points for policy, Outbox, and I12 email workflows."""

import asyncio
from datetime import UTC, datetime

from celery import shared_task
from sqlalchemy import select

from app.db.base import create_scheduler_engine, create_scheduler_session_factory
from app.models.account_policy import (
    AccountPolicy,
    AccountPolicyOutboxEvent,
    AccountPolicyState,
)
from app.models.aeterna_notification import AeternaEmailOutboxEvent
from app.services.client.aeterna_notification import get_aeterna_notification_service
from app.services.internal.account_policy_outbox import (
    OutboxCallbackOutcome,
    get_account_policy_outbox_service,
)
from app.services.internal.account_policy_transition import (
    get_account_policy_transition_service,
)
from app.services.internal.aeterna_email_delivery import (
    get_aeterna_email_delivery_service,
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
    """Materialize I11 intents as I12 email events without claiming delivery."""

    engine = create_scheduler_engine()
    session_factory = create_scheduler_session_factory(engine)
    try:
        async with session_factory() as db:
            rows = list(
                (
                    await db.execute(
                        select(
                            AccountPolicyOutboxEvent.id,
                            AccountPolicyOutboxEvent.status,
                            AccountPolicyOutboxEvent.attempt_count,
                        ).where(
                            AccountPolicyOutboxEvent.status.in_({"pending", "queued"}),
                            AccountPolicyOutboxEvent.notification_type.is_not(None),
                        )
                    )
                ).all()
            )

        prepared = 0
        failed = 0
        outbox_service = get_account_policy_outbox_service()
        notification_service = get_aeterna_notification_service()
        for event_id, status, attempt_count in rows:
            delivery_attempt = attempt_count
            async with session_factory() as db:
                if status == "pending":
                    task_id = f"outbox:{event_id}:attempt:{attempt_count + 1}"
                    preparation = await outbox_service.prepare_delivery(
                        db, event_id, task_id
                    )
                    delivery_attempt = preparation.attempt_number
            try:
                async with session_factory() as db:
                    await notification_service.materialize_policy_event(db, event_id)
                async with session_factory() as db:
                    await outbox_service.record_callback(
                        db,
                        event_id,
                        f"i12-materialized:{event_id}",
                        OutboxCallbackOutcome.DISPATCH_ACCEPTED,
                    )
                prepared += 1
            except Exception:
                failed += 1
                async with session_factory() as db:
                    await outbox_service.record_callback(
                        db,
                        event_id,
                        f"i12-materialization-failed:{event_id}:{delivery_attempt}",
                        OutboxCallbackOutcome.DISPATCH_FAILED,
                    )
        return {"examined": len(rows), "prepared": prepared, "failed": failed}
    finally:
        await engine.dispose()


async def dispatch_aeterna_email_notifications() -> dict[str, int]:
    """Dispatch due I12 events through the injected provider adapter."""

    engine = create_scheduler_engine()
    session_factory = create_scheduler_session_factory(engine)
    try:
        now = datetime.now(UTC)
        async with session_factory() as db:
            rows = list(
                await db.scalars(
                    select(AeternaEmailOutboxEvent.id).where(
                        AeternaEmailOutboxEvent.status.in_({"queued", "retry_pending"}),
                        AeternaEmailOutboxEvent.next_attempt_at <= now,
                    )
                )
            )
        dispatched = 0
        failed = 0
        for event_id in rows:
            async with session_factory() as db:
                try:
                    result = await get_aeterna_email_delivery_service().dispatch_event(
                        db, event_id
                    )
                    if result.status in {"provider_accepted", "delivered"}:
                        dispatched += 1
                    elif result.status in {"failed", "ambiguous"}:
                        failed += 1
                except Exception:
                    failed += 1
        return {"examined": len(rows), "dispatched": dispatched, "failed": failed}
    finally:
        await engine.dispose()


@shared_task(name="app.schedule.jobs.account_policy.scan")
def scan_account_policies_task() -> dict[str, int]:
    """Run the server-time policy sweep in a worker-owned event loop."""

    return asyncio.run(scan_account_policies())


@shared_task(name="app.schedule.jobs.account_policy.prepare_notifications")
def prepare_account_policy_notifications_task() -> dict[str, int]:
    """Convert durable I11 intents into I12 email Outbox events."""

    return asyncio.run(prepare_account_policy_notifications())


@shared_task(name="app.schedule.jobs.account_policy.dispatch_email_notifications")
def dispatch_aeterna_email_notifications_task() -> dict[str, int]:
    """Send due I12 email events without treating transport as human reading."""

    return asyncio.run(dispatch_aeterna_email_notifications())
