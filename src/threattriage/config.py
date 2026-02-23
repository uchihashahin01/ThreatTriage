"""Centralised configuration via pydantic-settings.

All settings are loaded from environment variables or a .env file.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# ─── Paths ────────────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parent.parent.parent  # project root
SRC_DIR = ROOT_DIR / "src"

# ─── Enums ────────────────────────────────────────────────────────────────────


class AppEnv(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


# ─── Settings ─────────────────────────────────────────────────────────────────


class Settings(BaseSettings):
    """Application settings loaded from environment / .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ───────────────────────────────────────────────────────
    app_name: str = "ThreatTriage"
    app_env: AppEnv = AppEnv.DEVELOPMENT
    debug: bool = True
    log_level: str = "DEBUG"
    secret_key: str = "change-me-to-a-random-secret-key"

    # ── Database ──────────────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./threattriage.db"

    # ── Redis ─────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Celery ────────────────────────────────────────────────────────────
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # ── Threat Intelligence ───────────────────────────────────────────────
    virustotal_api_key: str = ""
    alienvault_api_key: str = ""
    abuseipdb_api_key: str = ""

    # ── Feature Flags ─────────────────────────────────────────────────────
    demo_mode: bool = True
    enable_ti_enrichment: bool = True
    enable_anomaly_detection: bool = True

    # ── API ────────────────────────────────────────────────────────────────
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_key: str = "threat-triage-dev-key"
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    # ── Derived helpers ───────────────────────────────────────────────────

    @property
    def is_production(self) -> bool:
        return self.app_env == AppEnv.PRODUCTION

    @property
    def is_testing(self) -> bool:
        return self.app_env == AppEnv.TESTING

    @property
    def ti_providers_available(self) -> dict[str, bool]:
        """Check which TI providers have API keys configured."""
        return {
            "virustotal": bool(self.virustotal_api_key),
            "alienvault": bool(self.alienvault_api_key),
            "abuseipdb": bool(self.abuseipdb_api_key),
        }

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid:
            msg = f"Invalid log level: {v}. Must be one of {valid}"
            raise ValueError(msg)
        return upper


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()
