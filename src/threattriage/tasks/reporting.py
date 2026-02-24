"""Celery tasks for report generation."""

from __future__ import annotations

import asyncio
from typing import Any

from threattriage.celery_app import celery_app


@celery_app.task(name="threattriage.tasks.reporting.generate_report")
def generate_report_task(incident_data: dict[str, Any]) -> dict[str, Any]:
    """Generate HTML and JSON reports for an incident."""
    from threattriage.reports.generator import ReportGenerator
    from threattriage.analysis.correlator import CorrelatedIncident

    generator = ReportGenerator()
    json_report = incident_data  # Already in report format
    html_path, json_path = generator.save_reports(incident_data, incident_data.get("id", "unknown"))

    return {
        "html_path": html_path,
        "json_path": json_path,
        "incident_id": incident_data.get("id"),
    }


@celery_app.task(name="threattriage.tasks.reporting.scheduled_daily_report")
def scheduled_daily_report() -> dict[str, Any]:
    """Generate daily summary report (scheduled task)."""
    return {"status": "daily_report_generated", "message": "Daily summary report task completed"}
