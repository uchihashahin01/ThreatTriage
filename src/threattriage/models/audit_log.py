"""Audit log model — tracks all analyst and system actions."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import JSON
from sqlmodel import Column, Field, SQLModel

from threattriage.models.base import TimestampMixin, generate_uuid


class AuditLog(TimestampMixin, SQLModel, table=True):
    """Immutable audit trail for all significant actions."""

    __tablename__ = "audit_logs"

    id: UUID = Field(default_factory=generate_uuid, primary_key=True)
    user_id: str = Field(index=True, description="User who performed the action")
    username: str = Field(index=True)
    action: str = Field(index=True, description="Action type (e.g., alert.status_change)")
    resource_type: str = Field(index=True, description="Resource type (alert, incident, user, playbook)")
    resource_id: str | None = Field(default=None, index=True)
    details: dict[str, Any] | None = Field(
        default=None,
        sa_column=Column(JSON, nullable=True),
        description="Action-specific metadata",
    )
    ip_address: str | None = Field(default=None, description="Client IP address")
