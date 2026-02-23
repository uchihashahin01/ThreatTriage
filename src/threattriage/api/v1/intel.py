"""TI lookup and enrichment API endpoints."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends

from threattriage.api.deps import verify_api_key
from threattriage.intel.enrichment import EnrichmentEngine
from threattriage.schemas.schemas import IOCLookupRequest

router = APIRouter(prefix="/api/v1/intel", tags=["threat-intelligence"])


@router.post("/lookup")
async def lookup_ioc(
    request: IOCLookupRequest,
    _api_key: str = Depends(verify_api_key),
) -> dict[str, Any]:
    """Look up an IOC against all configured Threat Intelligence providers."""
    engine = EnrichmentEngine()
    result = await engine.enrich_ioc(
        ioc_type=request.ioc_type.value,
        value=request.value,
    )
    return result


@router.post("/lookup/batch")
async def batch_lookup(
    iocs: list[IOCLookupRequest],
    _api_key: str = Depends(verify_api_key),
) -> dict[str, Any]:
    """Batch lookup multiple IOCs concurrently."""
    engine = EnrichmentEngine()

    tasks = [
        engine.enrich_ioc(ioc.ioc_type.value, ioc.value)
        for ioc in iocs
    ]
    results = await asyncio.gather(*tasks)

    return {
        "total": len(results),
        "results": list(results),
    }
