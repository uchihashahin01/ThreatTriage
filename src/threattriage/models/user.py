"""User model for authentication and RBAC."""

from __future__ import annotations

from uuid import UUID

from sqlmodel import Field, SQLModel

from threattriage.models.base import TimestampMixin, generate_uuid


class UserRole:
    ADMIN = "admin"
    ANALYST = "analyst"
    READONLY = "readonly"


class User(TimestampMixin, SQLModel, table=True):
    """Application user with role-based access."""

    __tablename__ = "users"

    id: UUID = Field(default_factory=generate_uuid, primary_key=True)
    username: str = Field(unique=True, index=True, min_length=3, max_length=50)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    full_name: str | None = Field(default=None)
    role: str = Field(default=UserRole.ANALYST, index=True)
    is_active: bool = Field(default=True)
    is_superuser: bool = Field(default=False)
