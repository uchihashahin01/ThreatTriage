"""Shared enumerations and base model for all SQLModel models."""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlmodel import Field, SQLModel


class LogType(str, enum.Enum):
    """Supported log format types."""
    SYSLOG = "syslog"
    HTTP_ACCESS = "http_access"
    DB_AUDIT = "db_audit"
    GENERIC = "generic"


class Severity(str, enum.Enum):
    """Alert severity levels aligned with CVSS-style scoring."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    """Lifecycle status of an alert."""
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ESCALATED = "escalated"


class IOCType(str, enum.Enum):
    """Types of Indicators of Compromise."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "md5"
    FILE_HASH_SHA1 = "sha1"
    FILE_HASH_SHA256 = "sha256"
    EMAIL = "email"
    USER_AGENT = "user_agent"


class IncidentStatus(str, enum.Enum):
    """Incident investigation status."""
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


# ─── Base Model ───────────────────────────────────────────────────────────────


class TimestampMixin(SQLModel):
    """Mixin that adds created_at / updated_at timestamps."""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


def generate_uuid() -> UUID:
    return uuid4()
