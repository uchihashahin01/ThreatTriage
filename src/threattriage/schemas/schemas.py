"""Pydantic schemas for API request/response models."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from threattriage.models.base import (
    AlertStatus,
    IOCType,
    IncidentStatus,
    LogType,
    Severity,
)


# ─── Common ───────────────────────────────────────────────────────────────────


class PaginatedResponse(BaseModel):
    """Generic paginated response wrapper."""
    items: list[Any]
    total: int
    page: int = 1
    page_size: int = 50
    pages: int = 1


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str
    demo_mode: bool


# ─── Log Schemas ──────────────────────────────────────────────────────────────


class LogIngestRequest(BaseModel):
    """Request to ingest raw log lines."""
    raw_logs: list[str] = Field(description="List of raw log lines")
    log_type: LogType | None = Field(default=None, description="Force log type (auto-detect if omitted)")
    source_file: str | None = None


class LogIngestResponse(BaseModel):
    """Summary of log ingestion results."""
    total_lines: int
    parsed: int
    suspicious: int
    alerts_generated: int
    task_id: str | None = Field(default=None, description="Celery task ID for async processing")


class LogEntryResponse(BaseModel):
    id: UUID
    raw: str
    log_type: LogType
    timestamp: datetime | None
    source_ip: str | None
    hostname: str | None
    message: str | None
    is_suspicious: bool
    detection_tags: list[str] | None
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Alert Schemas ────────────────────────────────────────────────────────────


class AlertResponse(BaseModel):
    id: UUID
    title: str
    description: str
    severity: Severity
    status: AlertStatus
    confidence: float
    rule_name: str | None
    detection_type: str
    source_ip: str | None
    hostname: str | None
    username: str | None
    ioc_values: list[str] | None
    mitre_technique_ids: list[str] | None
    mitre_tactic: str | None
    log_count: int
    enrichment_data: dict[str, Any] | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertUpdateRequest(BaseModel):
    status: AlertStatus | None = None
    analyst_notes: str | None = None


# ─── IOC Schemas ──────────────────────────────────────────────────────────────


class IOCLookupRequest(BaseModel):
    """Request to look up an IOC against TI providers."""
    ioc_type: IOCType
    value: str


class IOCResponse(BaseModel):
    id: UUID
    ioc_type: IOCType
    value: str
    reputation_score: float | None
    is_malicious: bool
    tags: list[str] | None
    country: str | None
    asn: str | None
    org: str | None
    first_seen: datetime
    last_seen: datetime
    times_seen: int
    enriched_at: datetime | None

    model_config = {"from_attributes": True}


class IOCEnrichmentResponse(BaseModel):
    """Result from TI enrichment."""
    ioc_type: IOCType
    value: str
    reputation_score: float
    is_malicious: bool
    providers_queried: list[str]
    virustotal: dict[str, Any] | None = None
    alienvault: dict[str, Any] | None = None
    abuseipdb: dict[str, Any] | None = None


# ─── Incident Schemas ─────────────────────────────────────────────────────────


class IncidentResponse(BaseModel):
    id: UUID
    title: str
    summary: str
    severity: Severity
    status: IncidentStatus
    alert_count: int
    ioc_count: int
    affected_hosts: list[str] | None
    mitre_techniques: list[str] | None
    mitre_tactics: list[str] | None
    attack_narrative: str | None
    recommendations: list[str] | None
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Dashboard Schemas ────────────────────────────────────────────────────────


class DashboardMetrics(BaseModel):
    """SOC dashboard overview metrics."""
    total_logs: int
    total_alerts: int
    total_incidents: int
    total_iocs: int

    alerts_by_severity: dict[str, int]
    alerts_by_status: dict[str, int]
    incidents_by_status: dict[str, int]

    top_source_ips: list[dict[str, Any]]
    top_mitre_techniques: list[dict[str, Any]]
    recent_alerts: list[AlertResponse]

    # SOC KPIs
    mean_time_to_detect_seconds: float | None = None
    mean_time_to_resolve_seconds: float | None = None
    false_positive_rate: float | None = None


class MitreHeatmapData(BaseModel):
    """MITRE ATT&CK technique detection frequency for heatmap."""
    techniques: list[dict[str, Any]]
    total_detections: int
