from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_ready

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
            "schedule": crontab(minute=0),  # hourly — per-org interval decides if due
        },
        "reap-stuck-scan-runs": {
            "task": "app.worker.tasks.reap_stuck_scan_runs",
            "schedule": crontab(minute="*/15"),
        },
        "weekly-digest-monday": {
            "task": "app.worker.tasks.send_weekly_digests",
            "schedule": crontab(hour=9, minute=0, day_of_week=1),  # Monday 9am UTC
        },
        "prune-assume-role-audit": {
            "task": "app.worker.tasks.prune_assume_role_audit",
            "schedule": crontab(hour=4, minute=30),  # daily 04:30 UTC, off-hours
        },
    },
)


@worker_ready.connect
def _reap_on_startup(**_kwargs):
    """Mark any ScanRun stuck in 'running' as failed when a worker boots.
    Prior in-flight scans don't survive worker restarts."""
    from app.worker.tasks import reap_stuck_scan_runs

    reap_stuck_scan_runs.delay(max_age_minutes=0)
