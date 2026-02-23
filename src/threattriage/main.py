"""FastAPI application entry point."""

from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse

from threattriage import __version__
from threattriage.config import get_settings
from threattriage.logging import setup_logging, get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application startup/shutdown lifecycle."""
    setup_logging()
    settings = get_settings()

    logger.info(
        "threattriage_starting",
        version=__version__,
        env=settings.app_env.value,
        demo_mode=settings.demo_mode,
        ti_providers=settings.ti_providers_available,
    )

    yield

    logger.info("threattriage_shutting_down")


def create_app() -> FastAPI:
    """Application factory."""
    settings = get_settings()

    app = FastAPI(
        title="ThreatTriage",
        description=(
            "Automated SOC Alert & Log Analysis Engine — "
            "Ingest, parse, and analyze enterprise logs with integrated "
            "Threat Intelligence and MITRE ATT&CK mapping."
        ),
        version=__version__,
        lifespan=lifespan,
        default_response_class=ORJSONResponse,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routers
    from threattriage.api.v1.routes import router as main_router
    from threattriage.api.v1.intel import router as intel_router

    app.include_router(main_router)
    app.include_router(intel_router)

    # Health check
    @app.get("/health", tags=["system"])
    async def health_check() -> dict[str, str | bool]:
        return {
            "status": "healthy",
            "version": __version__,
            "demo_mode": settings.demo_mode,
        }

    # Root
    @app.get("/", tags=["system"])
    async def root() -> dict[str, str]:
        return {
            "name": "ThreatTriage",
            "version": __version__,
            "description": "Automated SOC Alert & Log Analysis Engine",
            "docs": "/docs",
        }

    return app


app = create_app()
