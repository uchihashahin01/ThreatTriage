"""API dependencies — authentication, DB session, etc."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from threattriage.config import get_settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


async def verify_api_key(
    api_key: str | None = Security(api_key_header),
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> str:
    """Validate API key or JWT Bearer token."""
    settings = get_settings()

    # In demo mode, allow unauthenticated access
    if settings.demo_mode:
        return "demo"

    # Try JWT Bearer token first
    if credentials and credentials.credentials:
        from threattriage.auth import decode_access_token
        payload = decode_access_token(credentials.credentials)
        if payload:
            return payload.get("username", "jwt_user")

    # Fall back to API key
    if api_key and api_key == settings.api_key:
        return api_key

    raise HTTPException(status_code=401, detail="Invalid or missing API key / Bearer token")


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> dict:
    """Extract current user from JWT. Requires authentication."""
    settings = get_settings()

    if settings.demo_mode:
        return {"user_id": "demo", "username": "demo", "role": "admin"}

    if not credentials or not credentials.credentials:
        raise HTTPException(401, "Authentication required")

    from threattriage.auth import decode_access_token
    payload = decode_access_token(credentials.credentials)
    if not payload:
        raise HTTPException(401, "Invalid or expired token")

    return {
        "user_id": payload.get("sub"),
        "username": payload.get("username"),
        "role": payload.get("role"),
    }
