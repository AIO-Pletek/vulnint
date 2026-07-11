"""Celery application factory."""
from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery(
    "vulnint",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.workers.tasks.feeds",
        "app.workers.tasks.correlation",
        "app.workers.tasks.alerts",
        "app.workers.tasks.opensearch",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone=settings.TZ,
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_time_limit=60 * 30,
    task_soft_time_limit=60 * 25,
    broker_connection_retry_on_startup=True,
    task_routes={
        "feeds.*": {"queue": "feeds"},
        "correlation.*": {"queue": "correlation"},
        "alerts.*": {"queue": "alerts"},
        "opensearch.*": {"queue": "default"},
    },
)

celery_app.conf.beat_schedule = {
    "feed-nvd-hourly": {
        "task": "feeds.run",
        "schedule": crontab(minute=15),
        "args": ["nvd"],
    },
    "feed-cisa-kev-hourly": {
        "task": "feeds.run",
        "schedule": crontab(minute=20),
        "args": ["cisa_kev"],
    },
    "feed-ubuntu-2h": {
        "task": "feeds.run",
        "schedule": crontab(minute=25, hour="*/2"),
        "args": ["ubuntu_usn"],
    },
    "feed-debian-4h": {
        "task": "feeds.run",
        "schedule": crontab(minute=30, hour="*/4"),
        "args": ["debian"],
    },
    "feed-rhel-family-2h": {
        "task": "feeds.run_group",
        "schedule": crontab(minute=35, hour="*/2"),
        "args": [["almalinux", "rocky", "cloudlinux"]],
    },
    "feed-windows-cpanel-4h": {
        "task": "feeds.run_group",
        "schedule": crontab(minute=40, hour="*/4"),
        "args": [["msrc", "cpanel"]],
    },
    "feed-exploitdb-daily": {
        "task": "feeds.run",
        "schedule": crontab(minute=0, hour=3),
        "args": ["exploitdb"],
    },
    "correlate-all-30m": {
        "task": "correlation.run_all",
        "schedule": crontab(minute="*/30"),
    },
    "reindex-opensearch-hourly": {
        "task": "opensearch.reindex_modified",
        "schedule": crontab(minute=50),
    },
    "process-alerts-5m": {
        "task": "alerts.dispatch_pending",
        "schedule": crontab(minute="*/5"),
    },
}
