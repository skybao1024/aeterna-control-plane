import logging

from app.db.base import (create_scheduler_engine,
                         create_scheduler_session_factory)

logger = logging.getLogger(__name__)


async def demo():
    logger.info("Running scheduled task: demo")

    # Create dedicated database engine and session factory for this task
    scheduler_engine = create_scheduler_engine()
    SchedulerSessionLocal = create_scheduler_session_factory(scheduler_engine)

    # Use newly created session factory
    async with SchedulerSessionLocal() as db:
        try:
            pass

        except Exception as e:
            logger.error(f"Error in demo: {e}", exc_info=True)
        finally:
            # Close database engine
            await scheduler_engine.dispose()
