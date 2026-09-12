import logging
import os
import tempfile

from fastapi import FastAPI

# Import Celery app
from app.core.celery_app import celery_app

logger = logging.getLogger(__name__)


def setup_scheduler(app: FastAPI = None):
    """
    Initialize scheduled task scheduler using Celery

    Args:
        app: FastAPI application instance
    """
    if not app:
        logger.error("FastAPI app instance is required for scheduler setup")
        return

    # Use file lock to ensure only one process runs scheduler initialization
    lock_file_path = os.path.join(tempfile.gettempdir(), "tip_scheduler.lock")
    logger.info(f"Lock file path: {lock_file_path}")

    try:
        # Check if lock file exists
        if os.path.exists(lock_file_path):
            # Read process ID from lock file
            try:
                with open(lock_file_path, "r") as f:
                    pid = f.read().strip()

                # Check if the process is still running
                try:
                    os.kill(int(pid), 0)  # Check if process exists
                    logger.info(
                        f"Scheduler lock exists. Process {pid} is running the scheduler."
                    )
                    # This process will not run scheduler initialization
                    logger.info(
                        f"Process {os.getpid()} will not initialize the scheduler."
                    )
                    scheduler_enabled = False
                except ProcessLookupError:
                    # Process doesn't exist, remove stale lock file
                    logger.warning(
                        f"Process {pid} in lock file is not running. Removing stale lock file."
                    )
                    os.remove(lock_file_path)
                    # Create new lock file
                    with open(lock_file_path, "w") as f:
                        f.write(str(os.getpid()))
                    logger.info(
                        f"Acquired scheduler lock. This process (PID: {os.getpid()}) will initialize the scheduler."
                    )
                    scheduler_enabled = True
            except Exception as e:
                # If reading lock file fails, remove lock file and create new one
                logger.warning(
                    f"Could not read scheduler lock file: {e}. Creating new lock."
                )
                os.remove(lock_file_path)
                with open(lock_file_path, "w") as f:
                    f.write(str(os.getpid()))
                logger.info(
                    f"Acquired scheduler lock. This process (PID: {os.getpid()}) will initialize the scheduler."
                )
                scheduler_enabled = True
        else:
            # Lock file doesn't exist, create new lock file
            with open(lock_file_path, "w") as f:
                f.write(str(os.getpid()))
            logger.info(
                f"Acquired scheduler lock. This process (PID: {os.getpid()}) will initialize the scheduler."
            )
            scheduler_enabled = True
    except Exception as e:
        logger.error(f"Error handling scheduler lock: {e}")
        # Default to not enabling scheduler on error
        scheduler_enabled = False

    if scheduler_enabled:
        logger.info("Celery task scheduler initialized")
        # Store Celery app instance in FastAPI app state for access elsewhere if needed
        app.state.celery_app = celery_app


def shutdown_scheduler():
    """
    Shutdown scheduler - For Celery, no special actions needed
    because Celery worker and beat processes are independent processes
    """
    logger.info("Celery scheduler shutdown - no special actions needed")
