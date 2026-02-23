"""Async database engine, session factory, and dependency injection."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlmodel import SQLModel

from threattriage.config import get_settings

settings = get_settings()

# ─── Engine ───────────────────────────────────────────────────────────────────
engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    future=True,
    pool_pre_ping=True,
)

# ─── Session Factory ─────────────────────────────────────────────────────────
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ─── Dependency ───────────────────────────────────────────────────────────────
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async DB session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ─── Init ─────────────────────────────────────────────────────────────────────
async def init_db() -> None:
    """Create all tables (dev/testing only — use Alembic in production)."""
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
