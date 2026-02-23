"""Incident model — groups correlated alerts into investigations."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import JSON
from sqlmodel import Column, Field, SQLModel

from threattriage.models.base import IncidentStatus, Severity, TimestampMixin, generate_uuid


class Incident(TimestampMixin, SQLModel, table=True):
    """An incident that groups correlated alerts into a single investigation."""

    __tablename__ = "incidents"

    id: UUID = Field(default_factory=generate_uuid, primary_key=True)

    # ── Core ──────────────────────────────────────────────────────────────
    title: str = Field(description="Auto-generated or analyst-provided title")
    summary: str = Field(default="", description="Executive summary of the incident")
    severity: Severity = Field(index=True)
    status: IncidentStatus = Field(default=IncidentStatus.OPEN, index=True)

    # ── Scope ─────────────────────────────────────────────────────────────
    alert_count: int = Field(default=0)
    ioc_count: int = Field(default=0)
    affected_hosts: list[str] | None = Field(
        default=None,
        sa_column=Column(JSON, nullable=True),
    )
    affected_users: list[str] | None = Field(
        default=None,
        sa_column=Column(JSON, nullable=True),
    )

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────
    mitre_techniques: list[str] | None = Field(
        default=None,
        sa_column=Column(JSON, nullable=True),
        description="All MITRE ATT&CK techniques observed across alerts",
    )
    mitre_tactics: list[str] | None = Field(
        default=None,
        sa_column=Column(JSON, nullable=True),
        description="All MITRE ATT&CK tactics observed",
    )
    attack_narrative: str | None = Field(
        default=None,
        description="Narrative description of the attack chain",
    )

    # ── Timeline ──────────────────────────────────────────────────────────
    timeline: list[dict[str, Any]] | None = Field(
        default=None,
        sa_column=Column(JSON, nullable=True),
        description="Chronological event timeline",
    )

    # ── Recommendations ───────────────────────────────────────────────────
    recommendations: list[str] | None = Field(
        default=None,
        sa_column=Column(JSON, nullable=True),
        description="Recommended response actions",
    )
    ioc_blocklist: list[str] | None = Field(
        default=None,
        sa_column=Column(JSON, nullable=True),
        description="IOCs recommended for blocking",
    )

    # ── Report ────────────────────────────────────────────────────────────
    report_generated: bool = Field(default=False)
    report_path: str | None = Field(default=None)
