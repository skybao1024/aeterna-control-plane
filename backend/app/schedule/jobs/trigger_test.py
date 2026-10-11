"""Independent test scheduling; normal policy queues and recovery grants are absent."""

import asyncio
from datetime import UTC, datetime, timedelta

from celery import shared_task
from sqlalchemy import select

from app.db.base import create_scheduler_engine, create_scheduler_session_factory
from app.models.aeterna_trigger_test import AeternaTriggerTest, AeternaTriggerTestMail
from app.services.client.aeterna_trigger_test import get_aeterna_trigger_test_service


async def run_trigger_tests() -> dict[str, int]:
    engine = create_scheduler_engine()
    sessions = create_scheduler_session_factory(engine)
    service = get_aeterna_trigger_test_service()
    failed = 0
    try:
        async with sessions() as db:
            ids = list(
                await db.scalars(
                    select(AeternaTriggerTest.id).where(
                        AeternaTriggerTest.state.not_in({"STOPPED", "EXPIRED"})
                    )
                )
            )
        for test_id in ids:
            async with sessions() as db:
                try:
                    await service.scan(db, test_id)
                except Exception:
                    failed += 1
        async with sessions() as db:
            mail_ids = list(
                await db.scalars(
                    select(AeternaTriggerTestMail.id).where(
                        AeternaTriggerTestMail.status == "queued"
                    )
                )
            )
            stale_ids = list(
                await db.scalars(
                    select(AeternaTriggerTestMail.id).where(
                        AeternaTriggerTestMail.status == "sending",
                        AeternaTriggerTestMail.sending_at
                        <= datetime.now(UTC) - timedelta(minutes=2),
                    )
                )
            )
        for mail_id in mail_ids + stale_ids:
            async with sessions() as db:
                try:
                    await service.dispatch(db, mail_id)
                except Exception:
                    failed += 1
        async with sessions() as db:
            await service.cleanup(db)
        return {
            "examined": len(ids),
            "mail_examined": len(mail_ids) + len(stale_ids),
            "failed": failed,
        }
    finally:
        await engine.dispose()


@shared_task(name="app.schedule.jobs.trigger_test.run")
def run_trigger_tests_task() -> dict[str, int]:
    return asyncio.run(run_trigger_tests())
