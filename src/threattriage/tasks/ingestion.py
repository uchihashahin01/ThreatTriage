"""Celery tasks for async log ingestion."""

from __future__ import annotations

import asyncio
from typing import Any

from threattriage.celery_app import celery_app


def _run_async(coro):
    """Run an async coroutine in a sync Celery worker."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(name="threattriage.tasks.ingestion.ingest_logs", bind=True, max_retries=3)
def ingest_logs_task(self, raw_logs: list[str], log_type: str | None = None, source_file: str | None = None) -> dict[str, Any]:
    """Background task for log ingestion + analysis pipeline."""
    from threattriage.parsers.base import create_registry
    from threattriage.analysis.detection import DetectionEngine
    from threattriage.analysis.anomaly import AnomalyDetector
    from threattriage.analysis.correlator import AlertCorrelator
    from threattriage.analysis.scorer import SeverityScorer
    from threattriage.models.base import LogType

    registry = create_registry()
    engine = DetectionEngine()
    anomaly_detector = AnomalyDetector()
    correlator = AlertCorrelator()
    scorer = SeverityScorer()

    lt = None
    if log_type:
        try:
            lt = LogType(log_type)
        except ValueError:
            pass

    parsed = registry.parse_batch(raw_logs, lt)
    detections = engine.evaluate_batch(parsed)
    anomalies = anomaly_detector.detect_anomalies(parsed)

    for det in detections:
        scored = scorer.score_detection(det)
        det.rule.severity = scored.severity

    incidents = correlator.correlate(detections, anomalies)

    return {
        "total_lines": len(raw_logs),
        "parsed": len(parsed),
        "suspicious": sum(1 for p in parsed if p.is_suspicious),
        "alerts_generated": len(detections) + len(anomalies),
        "incidents": len(incidents),
    }
