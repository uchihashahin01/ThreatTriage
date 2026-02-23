"""Celery application configuration for async task processing."""

from __future__ import annotations

from celery import Celery

from threattriage.config import get_settings

settings = get_settings()

celery_app = Celery(
    "threattriage",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    # Timezone
    timezone="UTC",
    enable_utc=True,
    # Task behaviour
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    # Result expiry
    result_expires=3600,  # 1 hour
    # Task routing
    task_routes={
        "threattriage.tasks.ingestion.*": {"queue": "ingestion"},
        "threattriage.tasks.enrichment.*": {"queue": "enrichment"},
        "threattriage.tasks.reporting.*": {"queue": "reporting"},
    },
    # Retry defaults
    task_default_retry_delay=30,
    task_max_retries=3,
)

# Auto-discover tasks
celery_app.autodiscover_tasks(["threattriage.tasks"])
