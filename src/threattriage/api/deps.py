"""API dependencies — authentication, DB session, etc."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader

from threattriage.config import get_settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str | None = Security(api_key_header)) -> str:
    """Validate API key from request header."""
    settings = get_settings()

    # In demo mode, allow unauthenticated access
    if settings.demo_mode:
        return "demo"

    if not api_key or api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return api_key
