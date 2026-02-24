"""JWT authentication and password hashing utilities."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from uuid import UUID

import bcrypt
from jose import JWTError, jwt

from threattriage.config import get_settings

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 hours


def _pre_hash(password: str) -> str:
    """Pre-hash passwords that exceed bcrypt's 72-byte limit via SHA-256."""
    if len(password.encode("utf-8")) > 72:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()
    return password


def hash_password(password: str) -> str:
    pw = _pre_hash(password).encode("utf-8")
    return bcrypt.hashpw(pw, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    pw = _pre_hash(plain).encode("utf-8")
    return bcrypt.checkpw(pw, hashed.encode("utf-8"))


def create_access_token(
    user_id: str,
    username: str,
    role: str,
    expires_delta: timedelta | None = None,
) -> str:
    settings = get_settings()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": expire,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    settings = get_settings()
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    except JWTError:
        return None
