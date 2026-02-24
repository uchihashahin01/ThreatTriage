"""Celery tasks for threat intelligence enrichment."""

from __future__ import annotations

import asyncio
from typing import Any

from threattriage.celery_app import celery_app


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(name="threattriage.tasks.enrichment.enrich_ioc", bind=True, max_retries=3)
def enrich_ioc_task(self, ioc_type: str, value: str) -> dict[str, Any]:
    """Background task for IOC enrichment via TI providers."""
    from threattriage.intel.enrichment import EnrichmentEngine

    async def _enrich():
        engine = EnrichmentEngine()
        return await engine.enrich_ioc(ioc_type, value)

    return _run_async(_enrich())


@celery_app.task(name="threattriage.tasks.enrichment.batch_enrich")
def batch_enrich_task(iocs: list[dict[str, str]]) -> dict[str, Any]:
    """Batch enrich multiple IOCs."""
    from threattriage.intel.enrichment import EnrichmentEngine

    async def _batch():
        engine = EnrichmentEngine()
        results = []
        for ioc in iocs:
            result = await engine.enrich_ioc(ioc["type"], ioc["value"])
            results.append(result)
        return results

    results = _run_async(_batch())
    return {"total": len(results), "results": results}
