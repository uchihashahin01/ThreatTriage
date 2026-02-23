"""Multi-provider IOC enrichment pipeline.

Queries all configured TI providers, aggregates scores, and provides a
unified enrichment result. Includes demo-mode fallback with realistic mock data.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

from threattriage.config import get_settings
from threattriage.intel.abuseipdb import AbuseIPDBProvider
from threattriage.intel.alienvault import AlienVaultProvider
from threattriage.intel.base import ThreatIntelProvider, TIResult
from threattriage.intel.virustotal import VirusTotalProvider
from threattriage.logging import get_logger

logger = get_logger(__name__)


# ─── Demo Mode Mock Data ─────────────────────────────────────────────────────

_DEMO_MALICIOUS_IPS = {
    "185.220.101.1", "45.33.32.156", "192.42.116.16", "23.129.64.1",
    "171.25.193.9", "198.51.100.1", "203.0.113.50",
}

_DEMO_MALICIOUS_DOMAINS = {
    "malware-distribution.com", "phishing-site.net", "c2-server.evil",
    "ransomware-payment.xyz", "data-exfil.ru",
}


def _get_demo_result(ioc_type: str, value: str) -> TIResult:
    """Generate realistic demo enrichment data."""
    is_known_bad = False
    if ioc_type == "ip":
        is_known_bad = value in _DEMO_MALICIOUS_IPS
    elif ioc_type == "domain":
        is_known_bad = value in _DEMO_MALICIOUS_DOMAINS

    if is_known_bad:
        return TIResult(
            provider="demo",
            ioc_type=ioc_type,
            value=value,
            reputation_score=85.0,
            is_malicious=True,
            confidence=0.9,
            tags=["malicious", "known-bad", "demo"],
            categories=["malware", "c2"],
            country="RU",
            description=f"[DEMO] Known malicious {ioc_type} — flagged by multiple TI feeds",
            raw_data={"demo": True, "note": "This is simulated data for demonstration"},
        )

    return TIResult(
        provider="demo",
        ioc_type=ioc_type,
        value=value,
        reputation_score=5.0,
        is_malicious=False,
        confidence=0.3,
        tags=["clean", "demo"],
        description=f"[DEMO] No significant threat indicators for this {ioc_type}",
        raw_data={"demo": True},
    )


# ─── Enrichment Engine ───────────────────────────────────────────────────────


class EnrichmentEngine:
    """Multi-provider IOC enrichment with score aggregation."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.providers: list[ThreatIntelProvider] = []

        # Register available providers
        vt = VirusTotalProvider()
        if vt.enabled:
            self.providers.append(vt)

        av = AlienVaultProvider()
        if av.enabled:
            self.providers.append(av)

        abuse = AbuseIPDBProvider()
        if abuse.enabled:
            self.providers.append(abuse)

        logger.info(
            "enrichment_engine_initialized",
            providers=[p.name for p in self.providers],
            demo_mode=self.settings.demo_mode,
        )

    async def enrich_ioc(self, ioc_type: str, value: str) -> dict[str, Any]:
        """
        Enrich an IOC across all configured providers.

        Returns a unified result with per-provider data and aggregated score.
        """
        if not self.providers and not self.settings.demo_mode:
            return {
                "ioc_type": ioc_type,
                "value": value,
                "reputation_score": 0,
                "is_malicious": False,
                "providers_queried": [],
                "error": "No TI providers configured",
            }

        # Use demo mode if no providers or demo mode enabled
        if self.settings.demo_mode and not self.providers:
            demo = _get_demo_result(ioc_type, value)
            return self._result_to_dict(demo, providers_queried=["demo"])

        # Query all providers concurrently
        lookup_method = f"lookup_{ioc_type}"
        tasks = []
        for provider in self.providers:
            method = getattr(provider, lookup_method, None)
            if method:
                tasks.append(self._safe_lookup(provider.name, method, value))

        results: list[TIResult] = await asyncio.gather(*tasks)

        # Aggregate results
        return self._aggregate_results(ioc_type, value, results)

    async def _safe_lookup(
        self, provider_name: str, method: Any, value: str
    ) -> TIResult:
        """Execute a lookup with error handling."""
        try:
            return await asyncio.wait_for(method(value), timeout=30.0)
        except asyncio.TimeoutError:
            logger.warning("ti_lookup_timeout", provider=provider_name, value=value)
            return TIResult(
                provider=provider_name, ioc_type="", value=value,
                success=False, error="Timeout",
            )
        except Exception as e:
            logger.error("ti_lookup_error", provider=provider_name, error=str(e))
            return TIResult(
                provider=provider_name, ioc_type="", value=value,
                success=False, error=str(e),
            )

    def _aggregate_results(
        self, ioc_type: str, value: str, results: list[TIResult]
    ) -> dict[str, Any]:
        """Aggregate multiple provider results into a unified enrichment."""
        successful = [r for r in results if r.success]

        if not successful:
            # Fallback to demo if all providers failed
            if self.settings.demo_mode:
                demo = _get_demo_result(ioc_type, value)
                return self._result_to_dict(demo, providers_queried=["demo_fallback"])
            return {
                "ioc_type": ioc_type,
                "value": value,
                "reputation_score": 0,
                "is_malicious": False,
                "providers_queried": [r.provider for r in results],
                "errors": {r.provider: r.error for r in results if r.error},
            }

        # Weighted average of reputation scores
        total_weight = 0.0
        weighted_score = 0.0
        for r in successful:
            weight = r.confidence if r.confidence > 0 else 0.5
            weighted_score += r.reputation_score * weight
            total_weight += weight

        avg_score = round(weighted_score / max(total_weight, 0.01), 2)
        any_malicious = any(r.is_malicious for r in successful)

        # Merge tags and categories
        all_tags = set()
        all_categories = set()
        for r in successful:
            all_tags.update(r.tags)
            all_categories.update(r.categories)

        # Take first available network context
        country = next((r.country for r in successful if r.country), None)
        asn = next((r.asn for r in successful if r.asn), None)
        org = next((r.org for r in successful if r.org), None)

        enrichment = {
            "ioc_type": ioc_type,
            "value": value,
            "reputation_score": avg_score,
            "is_malicious": any_malicious,
            "confidence": round(max(r.confidence for r in successful), 2),
            "providers_queried": [r.provider for r in results],
            "tags": sorted(all_tags),
            "categories": sorted(all_categories),
            "country": country,
            "asn": asn,
            "org": org,
            "enriched_at": datetime.now(timezone.utc).isoformat(),
            "per_provider": {},
        }

        # Add per-provider details
        for r in results:
            enrichment["per_provider"][r.provider] = {
                "success": r.success,
                "reputation_score": r.reputation_score,
                "is_malicious": r.is_malicious,
                "description": r.description,
                "error": r.error,
                "raw_data": r.raw_data,
            }

        return enrichment

    @staticmethod
    def _result_to_dict(result: TIResult, providers_queried: list[str]) -> dict[str, Any]:
        return {
            "ioc_type": result.ioc_type,
            "value": result.value,
            "reputation_score": result.reputation_score,
            "is_malicious": result.is_malicious,
            "confidence": result.confidence,
            "providers_queried": providers_queried,
            "tags": result.tags,
            "categories": result.categories,
            "country": result.country,
            "asn": result.asn,
            "org": result.org,
            "description": result.description,
            "enriched_at": datetime.now(timezone.utc).isoformat(),
            "per_provider": {
                result.provider: {
                    "success": result.success,
                    "reputation_score": result.reputation_score,
                    "is_malicious": result.is_malicious,
                    "description": result.description,
                    "raw_data": result.raw_data,
                }
            },
        }
