import os

from celery import Celery

from app.core.config import settings

# Configure Celery
celery_app = Celery(
    "tasks",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.schedule.celery_job",  # Main registry
        "app.schedule.jobs.demo",  # Add specific job modules here
    ],
)

# Configure Celery Beat (for scheduled tasks)
celery_app.conf.beat_schedule = {
    "demo-every-minute": {
        "task": "app.schedule.jobs.demo.execute",  # Updated to use the new task path
        "schedule": 60.0,  # Every minute
        "options": {"queue": "scheduled_tasks"},
    },
}

celery_app.conf.timezone = "UTC"
celery_app.conf.task_queues = {
    "scheduled_tasks": {
        "exchange": "scheduled_tasks",
        "routing_key": "scheduled_tasks",
    }
}

# Optional: Configure other Celery settings
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_track_started=True,
    worker_concurrency=os.cpu_count(),
    task_time_limit=30 * 60,  # 30 minutes time limit
    task_soft_time_limit=15 * 60,  # 15 minutes soft time limit
)
