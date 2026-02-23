"""IOC (Indicator of Compromise) model — tracks extracted IOCs and TI enrichment."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import JSON
from sqlmodel import Column, Field, SQLModel

from threattriage.models.base import IOCType, TimestampMixin, generate_uuid


class IOC(TimestampMixin, SQLModel, table=True):
    """An extracted Indicator of Compromise with threat intelligence enrichment."""

    __tablename__ = "iocs"

    id: UUID = Field(default_factory=generate_uuid, primary_key=True)
    ioc_type: IOCType = Field(index=True, description="Type of indicator")
    value: str = Field(index=True, description="The IOC value (IP, hash, domain, etc.)")

    # ── Threat Intelligence Enrichment ────────────────────────────────────
    reputation_score: float | None = Field(
        default=None,
        ge=0.0,
        le=100.0,
        description="Aggregated reputation score (0=clean, 100=malicious)",
    )
    is_malicious: bool = Field(default=False, index=True)
    tags: list[str] | None = Field(default=None, sa_column=Column(JSON, nullable=True))

    # ── Per-provider results ──────────────────────────────────────────────
    virustotal_result: dict[str, Any] | None = Field(
        default=None, sa_column=Column(JSON, nullable=True),
    )
    alienvault_result: dict[str, Any] | None = Field(
        default=None, sa_column=Column(JSON, nullable=True),
    )
    abuseipdb_result: dict[str, Any] | None = Field(
        default=None, sa_column=Column(JSON, nullable=True),
    )

    # ── Temporal ──────────────────────────────────────────────────────────
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    enriched_at: datetime | None = Field(default=None, description="Last TI enrichment timestamp")
    times_seen: int = Field(default=1, description="Number of times this IOC appeared in logs")

    # ── Context ──────────────────────────────────────────────────────────
    country: str | None = Field(default=None, description="GeoIP country code")
    asn: str | None = Field(default=None, description="Autonomous System Number")
    org: str | None = Field(default=None, description="Organization name from WHOIS/GeoIP")
