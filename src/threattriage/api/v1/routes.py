"""Log ingestion & querying API endpoints — database-backed."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, File, UploadFile, Form
from sqlalchemy import func, text
from sqlmodel import select

from threattriage.api.deps import verify_api_key
from threattriage.api.v1.ws import manager
from threattriage.analysis.anomaly import AnomalyDetector
from threattriage.analysis.correlator import AlertCorrelator
from threattriage.analysis.detection import DetectionEngine
from threattriage.analysis.mitre_mapper import MitreMapper
from threattriage.analysis.scorer import SeverityScorer
from threattriage.database import async_session_factory
from threattriage.models.alert import Alert
from threattriage.models.base import AlertStatus, LogType, Severity
from threattriage.models.incident import Incident
from threattriage.models.log_entry import LogEntry
from threattriage.parsers.base import ParsedLog, create_registry
from threattriage.reports.generator import ReportGenerator
from threattriage.schemas.schemas import (
    LogIngestRequest,
    LogIngestResponse,
)

router = APIRouter(prefix="/api/v1", tags=["logs"])


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _parsed_to_log_entry(p: ParsedLog, source_file: str | None = None) -> LogEntry:
    """Convert a ParsedLog dataclass to a LogEntry DB model."""
    return LogEntry(
        raw=p.raw[:2000],  # truncate very long lines
        log_type=p.log_type,
        source_file=source_file,
        timestamp=p.timestamp,
        source_ip=p.source_ip,
        hostname=p.hostname,
        username=p.username,
        process_name=p.process_name,
        pid=p.pid,
        message=p.message,
        http_method=p.http_method,
        http_path=p.http_path,
        http_status=p.http_status,
        http_user_agent=p.http_user_agent,
        is_suspicious=p.is_suspicious,
        detection_tags=p.detection_tags or [],
    )


def _detection_to_alert_dict(det, scored=None) -> dict[str, Any]:
    """Build an alert dict from a Detection result (for WebSocket broadcast)."""
    return {
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
        "created_at": (det.parsed_log.timestamp.isoformat()
                       if det.parsed_log.timestamp else
                       datetime.now(timezone.utc).isoformat()),
    }


def _anomaly_to_alert_dict(anom) -> dict[str, Any]:
    """Build an alert dict from an AnomalyResult."""
    return {
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
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def _alert_dict_to_model(alert_dict: dict[str, Any]) -> Alert:
    """Convert alert dict to Alert DB model."""
    return Alert(
        title=alert_dict["title"],
        description=alert_dict["description"],
        severity=Severity(alert_dict["severity"]),
        status=AlertStatus.NEW,
        confidence=alert_dict.get("confidence", 0.5),
        rule_id=alert_dict.get("rule_id"),
        rule_name=alert_dict.get("rule_name"),
        detection_type=alert_dict.get("detection_type", "rule"),
        source_ip=alert_dict.get("source_ip"),
        hostname=alert_dict.get("hostname"),
        username=alert_dict.get("username"),
        ioc_values=alert_dict.get("ioc_values", []),
        mitre_technique_ids=alert_dict.get("mitre_technique_ids", []),
        mitre_tactic=alert_dict.get("mitre_tactic"),
        log_count=alert_dict.get("log_count", 1),
    )


def _incident_report_to_model(report: dict[str, Any]) -> Incident:
    """Convert an incident report dict to an Incident DB model."""
    exec_summary = report.get("executive_summary", {})
    mitre = report.get("mitre_attack", {})

    return Incident(
        title=exec_summary.get("incident_title", "Unknown Incident"),
        summary=exec_summary.get("summary", ""),
        severity=Severity(exec_summary.get("severity", "medium")),
        alert_count=exec_summary.get("total_alerts", 0),
        ioc_count=exec_summary.get("total_iocs", 0),
        mitre_techniques=[t["id"] for t in mitre.get("techniques", [])],
        mitre_tactics=mitre.get("tactics", []),
        attack_narrative=exec_summary.get("summary", ""),
        timeline=report.get("timeline", []),
        recommendations=[r.get("mitigation", "") for r in report.get("recommendations", [])],
        ioc_blocklist=report.get("ioc_blocklist", []),
    )


# ─── Endpoints ────────────────────────────────────────────────────────────────

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

    # Detect
    detections = engine.evaluate_batch(parsed)
    anomalies = anomaly_detector.detect_anomalies(parsed)

    # Score detections
    for det in detections:
        scored = scorer.score_detection(det)
        det.rule.severity = scored.severity

    # Correlate
    incidents = correlator.correlate(detections, anomalies)

    # ── Persist to database ───────────────────────────────────────────────
    alerts_generated = 0
    async with async_session_factory() as session:
        # Store log entries
        for p in parsed:
            log_entry = _parsed_to_log_entry(p, request.source_file)
            session.add(log_entry)

        # Store alerts from detections
        alert_dicts_for_ws = []
        for det in detections:
            alert_dict = _detection_to_alert_dict(det)
            alert_model = _alert_dict_to_model(alert_dict)
            session.add(alert_model)
            alert_dicts_for_ws.append(alert_dict)
            alerts_generated += 1

        # Store alerts from anomalies
        for anom in anomalies:
            alert_dict = _anomaly_to_alert_dict(anom)
            alert_model = _alert_dict_to_model(alert_dict)
            session.add(alert_model)
            alert_dicts_for_ws.append(alert_dict)
            alerts_generated += 1

        # Store incidents
        incident_reports = []
        for inc in incidents:
            report_gen = ReportGenerator()
            report_data = report_gen.generate_json_report(inc)
            incident_model = _incident_report_to_model(report_data)
            session.add(incident_model)
            incident_reports.append(report_data)

        await session.commit()

    # ── Broadcast via WebSocket ───────────────────────────────────────────
    for alert_dict in alert_dicts_for_ws:
        await manager.broadcast_alert(alert_dict)

    # Broadcast stats update
    suspicious_count = sum(1 for p in parsed if p.is_suspicious)
    await manager.broadcast_stats_update({
        "new_alerts": alerts_generated,
        "new_logs": len(parsed),
        "new_incidents": len(incidents),
    })

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
    """List parsed log entries from database."""
    async with async_session_factory() as session:
        # Count query
        count_stmt = select(func.count()).select_from(LogEntry)
        if suspicious_only:
            count_stmt = count_stmt.where(LogEntry.is_suspicious == True)
        total = (await session.execute(count_stmt)).scalar() or 0

        # Data query
        stmt = select(LogEntry).order_by(LogEntry.created_at.desc())
        if suspicious_only:
            stmt = stmt.where(LogEntry.is_suspicious == True)
        stmt = stmt.offset(offset).limit(limit)
        results = (await session.execute(stmt)).scalars().all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "id": str(log.id),
                "raw": log.raw[:200],
                "log_type": log.log_type.value,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "source_ip": log.source_ip,
                "hostname": log.hostname,
                "message": log.message,
                "is_suspicious": log.is_suspicious,
                "detection_tags": log.detection_tags or [],
                "created_at": log.created_at.isoformat() if log.created_at else None,
            }
            for log in results
        ],
    }


@router.get("/alerts")
async def list_alerts(
    severity: str | None = None,
    status: str | None = None,
    limit: int = 50,
    _api_key: str = Depends(verify_api_key),
) -> dict[str, Any]:
    """List generated alerts from database."""
    async with async_session_factory() as session:
        stmt = select(Alert).order_by(Alert.created_at.desc())
        count_stmt = select(func.count()).select_from(Alert)

        if severity:
            try:
                sev = Severity(severity)
                stmt = stmt.where(Alert.severity == sev)
                count_stmt = count_stmt.where(Alert.severity == sev)
            except ValueError:
                pass
        if status:
            try:
                st = AlertStatus(status)
                stmt = stmt.where(Alert.status == st)
                count_stmt = count_stmt.where(Alert.status == st)
            except ValueError:
                pass

        total = (await session.execute(count_stmt)).scalar() or 0
        results = (await session.execute(stmt.limit(limit))).scalars().all()

    return {
        "total": total,
        "items": [
            {
                "id": str(a.id),
                "title": a.title,
                "description": a.description,
                "severity": a.severity.value,
                "status": a.status.value,
                "confidence": a.confidence,
                "rule_id": a.rule_id,
                "rule_name": a.rule_name,
                "detection_type": a.detection_type,
                "source_ip": a.source_ip,
                "hostname": a.hostname,
                "username": a.username,
                "ioc_values": a.ioc_values or [],
                "mitre_technique_ids": a.mitre_technique_ids or [],
                "mitre_tactic": a.mitre_tactic,
                "log_count": a.log_count,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in results
        ],
    }


@router.get("/incidents")
async def list_incidents(
    _api_key: str = Depends(verify_api_key),
) -> dict[str, Any]:
    """List correlated incidents from database."""
    async with async_session_factory() as session:
        stmt = select(Incident).order_by(Incident.created_at.desc())
        results = (await session.execute(stmt)).scalars().all()

    return {
        "total": len(results),
        "items": [
            {
                "id": str(inc.id),
                "title": inc.title,
                "severity": inc.severity.value,
                "status": inc.status.value,
                "total_alerts": inc.alert_count,
                "total_iocs": inc.ioc_count,
                "mitre_tactics": inc.mitre_tactics or [],
                "mitre_technique_count": len(inc.mitre_techniques or []),
                "created_at": inc.created_at.isoformat() if inc.created_at else None,
            }
            for inc in results
        ],
    }


@router.get("/incidents/{incident_id}/report")
async def get_incident_report(
    incident_id: str,
    _api_key: str = Depends(verify_api_key),
) -> dict[str, Any]:
    """Get full incident report from database."""
    async with async_session_factory() as session:
        stmt = select(Incident)
        results = (await session.execute(stmt)).scalars().all()

        # Support both UUID and index-based lookup
        incident = None
        try:
            idx = int(incident_id)
            if 0 <= idx < len(results):
                incident = results[idx]
        except ValueError:
            for inc in results:
                if str(inc.id) == incident_id:
                    incident = inc
                    break

    if not incident:
        return {"error": "Incident not found"}

    # Rebuild the report structure from the DB model
    mapper = MitreMapper()
    techniques = []
    for tid in (incident.mitre_techniques or []):
        mapping = mapper.map_technique(tid)
        if mapping:
            techniques.append({
                "id": tid,
                "name": mapping.technique_name,
                "tactic": mapping.tactic,
                "url": mapping.url,
                "detection_count": 0,
            })

    return {
        "executive_summary": {
            "incident_title": incident.title,
            "severity": incident.severity.value,
            "summary": incident.summary or incident.attack_narrative or "",
            "total_alerts": incident.alert_count,
            "total_iocs": incident.ioc_count,
        },
        "mitre_attack": {
            "tactics": incident.mitre_tactics or [],
            "techniques": techniques,
        },
        "timeline": incident.timeline or [],
        "recommendations": [
            {
                "mitigation": rec,
                "priority": "high",
                "addresses_techniques": incident.mitre_techniques[:2] if incident.mitre_techniques else [],
            }
            for rec in (incident.recommendations or [])
        ],
        "ioc_blocklist": incident.ioc_blocklist or [],
    }


@router.get("/dashboard/metrics")
async def get_dashboard_metrics(
    _api_key: str = Depends(verify_api_key),
) -> dict[str, Any]:
    """Get SOC dashboard metrics from database."""
    async with async_session_factory() as session:
        total_logs = (await session.execute(
            select(func.count()).select_from(LogEntry)
        )).scalar() or 0

        total_alerts = (await session.execute(
            select(func.count()).select_from(Alert)
        )).scalar() or 0

        total_incidents = (await session.execute(
            select(func.count()).select_from(Incident)
        )).scalar() or 0

        # Get all alerts for aggregation
        all_alerts = (await session.execute(
            select(Alert).order_by(Alert.created_at.desc())
        )).scalars().all()

    # Aggregate in Python (SQLite doesn't support JSON array ops well)
    sev_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    ip_counts: Counter[str] = Counter()
    technique_counts: Counter[str] = Counter()
    all_iocs: set[str] = set()

    for alert in all_alerts:
        sev_counts[alert.severity.value] += 1
        status_counts[alert.status.value] += 1
        if alert.source_ip:
            ip_counts[alert.source_ip] += 1
        for tid in (alert.mitre_technique_ids or []):
            technique_counts[tid] += 1
        for ioc in (alert.ioc_values or []):
            all_iocs.add(ioc)

    recent_alerts = [
        {
            "id": str(a.id),
            "title": a.title,
            "severity": a.severity.value,
            "status": a.status.value,
            "source_ip": a.source_ip,
            "detection_type": a.detection_type,
            "mitre_technique_ids": a.mitre_technique_ids or [],
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in all_alerts[:5]
    ]

    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "total_incidents": total_incidents,
        "total_iocs": len(all_iocs),
        "alerts_by_severity": dict(sev_counts),
        "alerts_by_status": dict(status_counts),
        "top_source_ips": [
            {"ip": ip, "count": cnt} for ip, cnt in ip_counts.most_common(10)
        ],
        "top_mitre_techniques": [
            {"technique_id": tid, "count": cnt}
            for tid, cnt in technique_counts.most_common(10)
        ],
        "recent_alerts": recent_alerts,
    }


@router.get("/dashboard/mitre")
async def get_mitre_heatmap(
    _api_key: str = Depends(verify_api_key),
) -> dict[str, Any]:
    """Get MITRE ATT&CK heatmap data from database."""
    async with async_session_factory() as session:
        all_alerts = (await session.execute(select(Alert))).scalars().all()

    technique_counts: Counter[str] = Counter()
    mapper = MitreMapper()

    for alert in all_alerts:
        for tid in (alert.mitre_technique_ids or []):
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

    return {
        "techniques": techniques,
        "total_detections": sum(technique_counts.values()),
        "navigator_layer": mapper.generate_navigator_layer(dict(technique_counts)),
    }


@router.patch("/alerts/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    body: dict[str, str],
    _api_key: str = Depends(verify_api_key),
) -> dict[str, Any]:
    """Update alert status (new → investigating → resolved)."""
    new_status = body.get("status", "")
    try:
        status = AlertStatus(new_status)
    except ValueError:
        return {"error": f"Invalid status: {new_status}"}

    async with async_session_factory() as session:
        stmt = select(Alert).where(Alert.id == alert_id)
        result = await session.execute(stmt)
        alert = result.scalar_one_or_none()

        if not alert:
            return {"error": "Alert not found"}

        alert.status = status
        alert.updated_at = datetime.now(timezone.utc)
        await session.commit()

    return {"id": str(alert.id), "status": status.value, "updated": True}
