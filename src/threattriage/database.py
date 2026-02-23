"""Async database engine, session factory, and dependency injection."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlmodel import SQLModel

from threattriage.config import get_settings

settings = get_settings()

# ─── Engine ───────────────────────────────────────────────────────────────────
# SQLite doesn't support pool_pre_ping or pool args; handle both cases.
_is_sqlite = settings.database_url.startswith("sqlite")

_engine_kwargs: dict = {
    "echo": settings.debug and False,  # set True for SQL debugging
    "future": True,
}

if not _is_sqlite:
    _engine_kwargs["pool_pre_ping"] = True

if _is_sqlite:
    # SQLite needs check_same_thread=False for async usage
    _engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_async_engine(settings.database_url, **_engine_kwargs)

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
    # Import all models so SQLModel knows about them
    from threattriage.models import alert, incident, log_entry, ioc  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
