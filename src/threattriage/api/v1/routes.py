"""Log ingestion & querying API endpoints."""

from __future__ import annotations

from collections import Counter
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, File, UploadFile, Form

from threattriage.api.deps import verify_api_key
from threattriage.analysis.anomaly import AnomalyDetector
from threattriage.analysis.correlator import AlertCorrelator
from threattriage.analysis.detection import DetectionEngine
from threattriage.analysis.mitre_mapper import MitreMapper
from threattriage.analysis.scorer import SeverityScorer
from threattriage.models.base import LogType, Severity
from threattriage.parsers.base import ParsedLog, create_registry
from threattriage.reports.generator import ReportGenerator
from threattriage.schemas.schemas import (
    AlertResponse,
    DashboardMetrics,
    LogEntryResponse,
    LogIngestRequest,
    LogIngestResponse,
    MitreHeatmapData,
)

router = APIRouter(prefix="/api/v1", tags=["logs"])

# In-memory stores (replace with DB in production)
_parsed_logs: list[ParsedLog] = []
_alerts: list[dict[str, Any]] = []
_incidents: list[dict[str, Any]] = []


@router.post("/logs/ingest", response_model=LogIngestResponse)
async def ingest_logs(
    request: LogIngestRequest,
    _api_key: str = Depends(verify_api_key),
) -> LogIngestResponse:
    """Ingest raw log lines, parse, detect threats, and generate alerts."""
    registry = create_registry()
    engine = DetectionEngine()
    anomaly_detector = AnomalyDetector()
    correlator = AlertCorrelator()
    scorer = SeverityScorer()

    # Parse
    parsed = registry.parse_batch(request.raw_logs, request.log_type)
    _parsed_logs.extend(parsed)

    # Detect
    detections = engine.evaluate_batch(parsed)
    anomalies = anomaly_detector.detect_anomalies(parsed)

    # Score detections
    for det in detections:
        scored = scorer.score_detection(det)
        det.rule.severity = scored.severity

    # Correlate
    incidents = correlator.correlate(detections, anomalies)

    # Build alert records
    alerts_generated = 0
    for det in detections:
        alert = {
            "id": str(uuid4()),
            "title": det.rule.name,
            "description": det.rule.description,
            "severity": det.rule.severity.value,
            "status": "new",
            "confidence": det.confidence,
            "rule_id": det.rule.id,
            "rule_name": det.rule.name,
            "detection_type": "rule",
            "source_ip": det.parsed_log.source_ip,
            "hostname": det.parsed_log.hostname,
            "username": det.parsed_log.username,
            "ioc_values": [v for _, v in det.parsed_log.ioc_values],
            "mitre_technique_ids": det.rule.mitre_technique_ids,
            "mitre_tactic": det.rule.mitre_tactic,
            "log_count": 1,
            "created_at": det.parsed_log.timestamp.isoformat() if det.parsed_log.timestamp else None,
        }
        _alerts.append(alert)
        alerts_generated += 1

    for anom in anomalies:
        alert = {
            "id": str(uuid4()),
            "title": anom.anomaly_type.replace("_", " ").title(),
            "description": anom.description,
            "severity": anom.severity.value,
            "status": "new",
            "confidence": 0.7,
            "rule_id": None,
            "rule_name": None,
            "detection_type": "anomaly",
            "source_ip": anom.source_ip,
            "hostname": None,
            "username": None,
            "ioc_values": [],
            "mitre_technique_ids": anom.mitre_technique_ids,
            "mitre_tactic": anom.mitre_tactic,
            "log_count": 1,
            "created_at": None,
        }
        _alerts.append(alert)
        alerts_generated += 1

    # Store incident data
    for inc in incidents:
        report_gen = ReportGenerator()
        report_data = report_gen.generate_json_report(inc)
        _incidents.append(report_data)

    suspicious_count = sum(1 for p in parsed if p.is_suspicious)

    return LogIngestResponse(
        total_lines=len(request.raw_logs),
        parsed=len(parsed),
        suspicious=suspicious_count,
        alerts_generated=alerts_generated,
    )


@router.post("/logs/upload", response_model=LogIngestResponse)
async def upload_log_file(
    file: UploadFile = File(...),
    log_type: str | None = Form(None),
    _api_key: str = Depends(verify_api_key),
) -> LogIngestResponse:
    """Upload a log file for analysis."""
    content = await file.read()
    lines = content.decode("utf-8", errors="replace").splitlines()

    lt = None
    if log_type:
        try:
            lt = LogType(log_type)
        except ValueError:
            pass

    request = LogIngestRequest(raw_logs=lines, log_type=lt, source_file=file.filename)
    return await ingest_logs(request)


@router.get("/logs")
async def list_logs(
    limit: int = 50,
    offset: int = 0,
    suspicious_only: bool = False,
    _api_key: str = Depends(verify_api_key),
) -> dict[str, Any]:
    """List parsed log entries."""
    filtered = _parsed_logs
    if suspicious_only:
        filtered = [p for p in filtered if p.is_suspicious]

    page = filtered[offset : offset + limit]
    return {
        "total": len(filtered),
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "raw": p.raw[:200],
                "log_type": p.log_type.value,
                "timestamp": p.timestamp.isoformat() if p.timestamp else None,
                "source_ip": p.source_ip,
                "hostname": p.hostname,
                "message": p.message,
                "is_suspicious": p.is_suspicious,
                "detection_tags": p.detection_tags,
            }
            for p in page
        ],
    }


@router.get("/alerts")
async def list_alerts(
    severity: str | None = None,
    status: str | None = None,
    limit: int = 50,
    _api_key: str = Depends(verify_api_key),
) -> dict[str, Any]:
    """List generated alerts with optional severity/status filtering."""
    filtered = _alerts
    if severity:
        filtered = [a for a in filtered if a["severity"] == severity]
    if status:
        filtered = [a for a in filtered if a["status"] == status]

    return {
        "total": len(filtered),
        "items": filtered[:limit],
    }


@router.get("/incidents")
async def list_incidents(
    _api_key: str = Depends(verify_api_key),
) -> dict[str, Any]:
    """List correlated incidents with full reports."""
    return {
        "total": len(_incidents),
        "items": [
            {
                "id": inc.get("report_metadata", {}).get("report_id"),
                "title": inc.get("executive_summary", {}).get("incident_title"),
                "severity": inc.get("executive_summary", {}).get("severity"),
                "total_alerts": inc.get("executive_summary", {}).get("total_alerts"),
                "total_iocs": inc.get("executive_summary", {}).get("total_iocs"),
                "mitre_tactics": inc.get("mitre_attack", {}).get("tactics"),
                "mitre_technique_count": len(inc.get("mitre_attack", {}).get("techniques", [])),
            }
            for inc in _incidents
        ],
    }


@router.get("/incidents/{incident_idx}/report")
async def get_incident_report(
    incident_idx: int,
    _api_key: str = Depends(verify_api_key),
) -> dict[str, Any]:
    """Get full incident report (JSON)."""
    if incident_idx < 0 or incident_idx >= len(_incidents):
        return {"error": "Incident not found"}
    return _incidents[incident_idx]


@router.get("/dashboard/metrics")
async def get_dashboard_metrics(
    _api_key: str = Depends(verify_api_key),
) -> dict[str, Any]:
    """Get SOC dashboard metrics."""
    sev_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    ip_counts: Counter[str] = Counter()
    technique_counts: Counter[str] = Counter()

    for alert in _alerts:
        sev_counts[alert["severity"]] += 1
        status_counts[alert["status"]] += 1
        if alert.get("source_ip"):
            ip_counts[alert["source_ip"]] += 1
        for tid in alert.get("mitre_technique_ids", []):
            technique_counts[tid] += 1

    return {
        "total_logs": len(_parsed_logs),
        "total_alerts": len(_alerts),
        "total_incidents": len(_incidents),
        "total_iocs": len({v for a in _alerts for v in (a.get("ioc_values") or [])}),
        "alerts_by_severity": dict(sev_counts),
        "alerts_by_status": dict(status_counts),
        "top_source_ips": [
            {"ip": ip, "count": cnt} for ip, cnt in ip_counts.most_common(10)
        ],
        "top_mitre_techniques": [
            {"technique_id": tid, "count": cnt}
            for tid, cnt in technique_counts.most_common(10)
        ],
        "recent_alerts": _alerts[-5:][::-1],
    }


@router.get("/dashboard/mitre")
async def get_mitre_heatmap(
    _api_key: str = Depends(verify_api_key),
) -> dict[str, Any]:
    """Get MITRE ATT&CK heatmap data."""
    technique_counts: Counter[str] = Counter()
    mapper = MitreMapper()

    for alert in _alerts:
        for tid in alert.get("mitre_technique_ids", []):
            technique_counts[tid] += 1

    techniques = []
    for tid, count in technique_counts.most_common():
        mapping = mapper.map_technique(tid)
        if mapping:
            techniques.append({
                "technique_id": tid,
                "name": mapping.technique_name,
                "tactic": mapping.tactic,
                "count": count,
                "url": mapping.url,
            })

    navigator_layer = mapper.generate_navigator_layer(dict(technique_counts))

    return {
        "techniques": techniques,
        "total_detections": sum(technique_counts.values()),
        "navigator_layer": navigator_layer,
    }
