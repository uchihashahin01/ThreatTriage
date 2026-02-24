"""Admin, SOAR, GeoIP, cold-storage, audit-log, and PDF-report endpoints."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID as _UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlmodel import select, func

from threattriage.api.deps import get_current_user, verify_api_key
from threattriage.database import async_session_factory
from threattriage.logging import get_logger
from threattriage.models.audit_log import AuditLog

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["admin"])


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def write_audit_log(
    user: dict,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
) -> None:
    """Persist an audit log entry."""
    async with async_session_factory() as session:
        entry = AuditLog(
            user_id=user.get("user_id", "system"),
            username=user.get("username", "system"),
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=ip_address,
        )
        session.add(entry)
        await session.commit()


# ─── Schemas ──────────────────────────────────────────────────────────────────

class PlaybookExecuteRequest(BaseModel):
    playbook_id: str
    alert_data: dict[str, Any]


class UserRoleUpdateRequest(BaseModel):
    role: str


# ─── SOAR Endpoints ──────────────────────────────────────────────────────────

@router.get("/soar/playbooks", tags=["soar"])
async def list_playbooks(
    _user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """List all available SOAR playbooks."""
    from threattriage.soar.playbooks import get_playbooks_summary
    return {"playbooks": get_playbooks_summary()}


@router.get("/soar/history", tags=["soar"])
async def soar_execution_history(
    limit: int = Query(50, ge=1, le=500),
    _user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Get SOAR playbook execution history."""
    from threattriage.soar.playbooks import get_execution_history
    history = get_execution_history()
    return {"total": len(history), "items": history[-limit:]}


@router.post("/soar/execute", tags=["soar"])
async def execute_playbook(
    body: PlaybookExecuteRequest,
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Manually trigger a SOAR playbook against alert data."""
    from threattriage.soar.playbooks import PlaybookEngine

    engine = PlaybookEngine()
    results = engine.evaluate_alert(body.alert_data)

    await write_audit_log(
        user,
        "soar_manual_execute",
        "playbook",
        body.playbook_id,
        {"alert_title": body.alert_data.get("title", ""), "results": len(results)},
    )

    return {
        "executed": len(results),
        "results": [
            {
                "playbook_id": r.playbook_id,
                "playbook_name": r.playbook_name,
                "triggered": r.triggered,
                "actions_total": r.actions_total,
                "actions_succeeded": r.actions_succeeded,
                "actions_failed": r.actions_failed,
                "results": r.action_results,
                "executed_at": r.executed_at,
            }
            for r in results
        ],
    }


# ─── GeoIP Endpoints ─────────────────────────────────────────────────────────

@router.get("/dashboard/geoip", tags=["geoip"])
async def get_geoip_data(
    _key: str = Depends(verify_api_key),
) -> dict[str, Any]:
    """Get GeoIP mapping for all source IPs in alerts."""
    from threattriage.intel.geoip import get_geoip_service
    from threattriage.models.alert import Alert

    async with async_session_factory() as session:
        results = (await session.execute(select(Alert))).scalars().all()

    unique_ips = {a.source_ip for a in results if a.source_ip}
    svc = get_geoip_service()
    map_data = svc.to_map_data(list(unique_ips))

    return {
        "total_ips": len(unique_ips),
        "locations": map_data,
    }


# ─── ML Anomaly Endpoints ────────────────────────────────────────────────────

@router.get("/ml/status", tags=["ml"])
async def ml_detector_status(
    _user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Get ML anomaly detector status."""
    from threattriage.analysis.ml_detector import MLAnomalyDetector
    det = MLAnomalyDetector()
    return {
        "trained": det._is_trained,
        "contamination": det.contamination,
        "n_estimators": det.n_estimators,
    }


@router.post("/ml/detect", tags=["ml"])
async def ml_detect_anomalies(
    _user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Run ML anomaly detection on recent log entries."""
    from threattriage.analysis.ml_detector import MLAnomalyDetector
    from threattriage.models.log_entry import LogEntry

    async with async_session_factory() as session:
        stmt = select(LogEntry).order_by(LogEntry.created_at.desc()).limit(1000)
        logs = (await session.execute(stmt)).scalars().all()

    if not logs:
        return {"anomalies": [], "total_analyzed": 0}

    # ML detector expects ParsedLog-like objects — LogEntry has the same attrs
    detector = MLAnomalyDetector()
    try:
        results = detector.detect(logs)
    except Exception as exc:
        logger.warning("ml_detection_failed", error=str(exc))
        return {"anomalies": [], "total_analyzed": len(logs), "error": str(exc)}

    anomalies = [
        {
            "source_ip": r.ip,
            "anomaly_score": round(r.anomaly_score, 4),
            "normalized_score": r.normalized_score,
            "severity": r.severity.value,
            "features": r.features,
        }
        for r in results
    ]

    return {
        "anomalies": anomalies,
        "total_analyzed": len(logs),
        "total_anomalies": len(anomalies),
    }


# ─── Cold Storage Endpoints ──────────────────────────────────────────────────

@router.get("/admin/storage/stats", tags=["storage"])
async def storage_stats(
    _user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Get storage statistics (active logs, archives)."""
    from threattriage.tasks.cold_storage import get_storage_stats
    return await get_storage_stats()


@router.post("/admin/storage/rotate", tags=["storage"])
async def rotate_storage(
    retention_days: int = Query(7, ge=1, le=365),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Rotate old logs to cold storage."""
    from threattriage.tasks.cold_storage import rotate_logs

    result = await rotate_logs(retention_days=retention_days)

    await write_audit_log(
        user,
        "storage_rotate",
        "logs",
        details={"retention_days": retention_days, "archived": result.get("archived_count", 0)},
    )

    return result


@router.get("/admin/storage/archives", tags=["storage"])
async def list_archives(
    _user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """List all cold storage archives."""
    from threattriage.tasks.cold_storage import list_archives as _list_archives
    return {"archives": _list_archives()}


# ─── Audit Log Endpoints ─────────────────────────────────────────────────────

@router.get("/admin/audit-logs", tags=["audit"])
async def get_audit_logs(
    limit: int = Query(100, ge=1, le=1000),
    user_filter: str | None = None,
    action_filter: str | None = None,
    _user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Get audit log entries."""
    async with async_session_factory() as session:
        stmt = select(AuditLog).order_by(AuditLog.created_at.desc())

        if user_filter:
            stmt = stmt.where(AuditLog.username == user_filter)
        if action_filter:
            stmt = stmt.where(AuditLog.action == action_filter)

        stmt = stmt.limit(limit)
        results = (await session.execute(stmt)).scalars().all()

    return {
        "total": len(results),
        "items": [
            {
                "id": str(e.id),
                "user_id": e.user_id,
                "username": e.username,
                "action": e.action,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
                "details": e.details,
                "ip_address": e.ip_address,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in results
        ],
    }


# ─── User Management (RBAC) ──────────────────────────────────────────────────

@router.get("/admin/users", tags=["admin"])
async def list_users(
    _user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """List all users (admin only)."""
    from threattriage.models.user import User
    from threattriage.config import get_settings

    if get_settings().demo_mode:
        return {
            "users": [
                {"id": "demo", "username": "demo", "email": "demo@threattriage.local",
                 "role": "admin", "is_active": True, "full_name": "Demo User"},
            ]
        }

    async with async_session_factory() as session:
        results = (await session.execute(select(User))).scalars().all()

    return {
        "users": [
            {
                "id": str(u.id),
                "username": u.username,
                "email": u.email,
                "role": u.role,
                "is_active": u.is_active,
                "full_name": u.full_name,
            }
            for u in results
        ],
    }


@router.patch("/admin/users/{user_id}/role", tags=["admin"])
async def update_user_role(
    user_id: str,
    body: UserRoleUpdateRequest,
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Update a user's role (admin only)."""
    from threattriage.models.user import User

    valid_roles = {"admin", "analyst", "readonly"}
    if body.role not in valid_roles:
        raise HTTPException(400, f"Invalid role. Must be one of: {valid_roles}")

    async with async_session_factory() as session:
        try:
            uid = _UUID(user_id)
        except ValueError:
            raise HTTPException(400, "Invalid user ID")

        result = await session.execute(select(User).where(User.id == uid))
        target = result.scalar_one_or_none()
        if not target:
            raise HTTPException(404, "User not found")

        target.role = body.role
        session.add(target)
        await session.commit()

    await write_audit_log(
        user,
        "role_update",
        "user",
        user_id,
        {"new_role": body.role},
    )

    return {"status": "updated", "user_id": user_id, "new_role": body.role}


# ─── PDF Report Generation ───────────────────────────────────────────────────

@router.post("/incidents/{incident_id}/pdf", tags=["reports"])
async def generate_incident_pdf(
    incident_id: str,
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Generate a PDF report for an incident."""
    from threattriage.models.incident import Incident
    from threattriage.analysis.mitre_mapper import MitreMapper
    from threattriage.reports.pdf_generator import generate_pdf_report

    async with async_session_factory() as session:
        stmt = select(Incident)
        results = (await session.execute(stmt)).scalars().all()

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
        raise HTTPException(404, "Incident not found")

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

    report_data = {
        "report_metadata": {
            "report_id": str(incident.id),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "ThreatTriage v1.0",
        },
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
        "indicators_of_compromise": [
            {"type": "unknown", "value": ioc}
            for ioc in (incident.ioc_blocklist or [])
        ],
    }

    result = generate_pdf_report(report_data)

    await write_audit_log(
        user, "pdf_report_generated", "incident", str(incident.id),
        {"format": result.get("format"), "engine": result.get("engine")},
    )

    return result
