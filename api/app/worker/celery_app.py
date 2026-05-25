from celery import Celery
from celery.schedules import crontab

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "vigil",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.worker.tasks"],
)

celery_app.conf.update(
    task_acks_late=True,
    task_default_queue="default",
    worker_prefetch_multiplier=1,
    timezone="UTC",
    beat_schedule={
        "daily-scan-all-accounts": {
            "task": "app.worker.tasks.scan_all_accounts",
            "schedule": crontab(hour=6, minute=0),
        },
        "weekly-digest-monday": {
            "task": "app.worker.tasks.send_weekly_digests",
            "schedule": crontab(hour=9, minute=0, day_of_week=1),  # Monday 9am UTC
        },
    },
)
