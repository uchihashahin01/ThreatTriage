"""LogEntry model — stores raw and parsed log data."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlmodel import Column, Field, SQLModel

from sqlalchemy import JSON

from threattriage.models.base import LogType, TimestampMixin, generate_uuid


class LogEntry(TimestampMixin, SQLModel, table=True):
    """A single ingested log entry with raw text and parsed fields."""

    __tablename__ = "log_entries"

    id: UUID = Field(default_factory=generate_uuid, primary_key=True)
    raw: str = Field(description="Original raw log line")
    log_type: LogType = Field(index=True, description="Detected/specified log format")
    source_file: str | None = Field(default=None, description="Original filename if uploaded")

    # ── Parsed Fields ─────────────────────────────────────────────────────
    timestamp: datetime | None = Field(default=None, index=True, description="Parsed event timestamp")
    source_ip: str | None = Field(default=None, index=True, description="Source IP from log")
    destination_ip: str | None = Field(default=None, description="Destination IP if present")
    hostname: str | None = Field(default=None, index=True)
    username: str | None = Field(default=None, index=True)
    process_name: str | None = Field(default=None)
    pid: int | None = Field(default=None)
    message: str | None = Field(default=None, description="Parsed message body")

    # HTTP-specific
    http_method: str | None = Field(default=None)
    http_path: str | None = Field(default=None)
    http_status: int | None = Field(default=None)
    http_user_agent: str | None = Field(default=None)

    # DB-specific
    db_query: str | None = Field(default=None)
    db_database: str | None = Field(default=None)

    # ── Flexible parsed data (JSONB) ──────────────────────────────────────
    parsed_data: dict[str, Any] | None = Field(
        default=None,
        sa_column=Column(JSON, nullable=True),
        description="Full parsed data as JSON",
    )

    # ── Analysis flags ────────────────────────────────────────────────────
    is_suspicious: bool = Field(default=False, index=True)
    detection_tags: list[str] | None = Field(
        default=None,
        sa_column=Column(JSON, nullable=True),
        description="Tags from detection rules that flagged this entry",
    )
