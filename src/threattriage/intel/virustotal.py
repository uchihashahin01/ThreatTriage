"""VirusTotal API v3 integration.

Uses the official vt-py library for IP, domain, hash, and URL lookups.
Respects free-tier rate limits (4 requests/minute).
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from threattriage.config import get_settings
from threattriage.intel.base import ThreatIntelProvider, TIResult
from threattriage.logging import get_logger

logger = get_logger(__name__)

VT_API_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal v3 threat intelligence provider."""

    name = "virustotal"

    def __init__(self) -> None:
        settings = get_settings()
        self.api_key = settings.virustotal_api_key
        self.enabled = bool(self.api_key)
        self._rate_limiter = asyncio.Semaphore(4)  # max 4 concurrent

    async def _request(self, endpoint: str) -> dict[str, Any] | None:
        """Make an authenticated request to VT API v3."""
        if not self.enabled:
            return None

        async with self._rate_limiter:
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.get(
                        f"{VT_API_BASE}/{endpoint}",
                        headers={"x-apikey": self.api_key},
                    )
                    if resp.status_code == 200:
                        return resp.json()
                    if resp.status_code == 429:
                        logger.warning("virustotal_rate_limited", endpoint=endpoint)
                        await asyncio.sleep(60)
                        return None
                    logger.warning(
                        "virustotal_error",
                        endpoint=endpoint,
                        status=resp.status_code,
                    )
                    return None
            except httpx.HTTPError as e:
                logger.error("virustotal_request_failed", error=str(e))
                return None

    async def lookup_ip(self, ip: str) -> TIResult:
        data = await self._request(f"ip_addresses/{ip}")
        if not data:
            return TIResult(
                provider=self.name, ioc_type="ip", value=ip,
                success=False, error="No data returned",
            )

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 1

        score = (malicious / max(total, 1)) * 100

        return TIResult(
            provider=self.name,
            ioc_type="ip",
            value=ip,
            reputation_score=round(score, 2),
            is_malicious=score >= 10,
            confidence=min(total / 90, 1.0),
            tags=attrs.get("tags", []),
            country=attrs.get("country"),
            asn=str(attrs.get("asn", "")),
            org=attrs.get("as_owner"),
            description=f"{malicious}/{total} engines flagged as malicious",
            raw_data={
                "last_analysis_stats": stats,
                "reputation": attrs.get("reputation"),
                "last_analysis_date": attrs.get("last_analysis_date"),
                "network": attrs.get("network"),
                "whois": attrs.get("whois", "")[:500],
            },
        )

    async def lookup_domain(self, domain: str) -> TIResult:
        data = await self._request(f"domains/{domain}")
        if not data:
            return TIResult(
                provider=self.name, ioc_type="domain", value=domain,
                success=False, error="No data returned",
            )

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 1
        score = (malicious / max(total, 1)) * 100

        return TIResult(
            provider=self.name,
            ioc_type="domain",
            value=domain,
            reputation_score=round(score, 2),
            is_malicious=score >= 10,
            confidence=min(total / 90, 1.0),
            tags=attrs.get("tags", []),
            categories=list(attrs.get("categories", {}).values()),
            description=f"{malicious}/{total} engines flagged as malicious",
            raw_data={
                "last_analysis_stats": stats,
                "reputation": attrs.get("reputation"),
                "registrar": attrs.get("registrar"),
                "creation_date": attrs.get("creation_date"),
            },
        )

    async def lookup_hash(self, file_hash: str) -> TIResult:
        data = await self._request(f"files/{file_hash}")
        if not data:
            return TIResult(
                provider=self.name, ioc_type="hash", value=file_hash,
                success=False, error="No data returned",
            )

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 1
        score = (malicious / max(total, 1)) * 100

        return TIResult(
            provider=self.name,
            ioc_type="hash",
            value=file_hash,
            reputation_score=round(score, 2),
            is_malicious=score >= 10,
            confidence=min(total / 70, 1.0),
            tags=attrs.get("tags", []),
            categories=attrs.get("type_tags", []),
            description=f"{malicious}/{total} engines detected — {attrs.get('meaningful_name', 'unknown')}",
            raw_data={
                "last_analysis_stats": stats,
                "type_description": attrs.get("type_description"),
                "meaningful_name": attrs.get("meaningful_name"),
                "size": attrs.get("size"),
                "sha256": attrs.get("sha256"),
            },
        )

    async def lookup_url(self, url: str) -> TIResult:
        """URL lookups use the URL identifier (base64-encoded URL without padding)."""
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        data = await self._request(f"urls/{url_id}")
        if not data:
            return TIResult(
                provider=self.name, ioc_type="url", value=url,
                success=False, error="No data returned",
            )

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 1
        score = (malicious / max(total, 1)) * 100

        return TIResult(
            provider=self.name,
            ioc_type="url",
            value=url,
            reputation_score=round(score, 2),
            is_malicious=score >= 10,
            confidence=min(total / 90, 1.0),
            tags=attrs.get("tags", []),
            categories=list(attrs.get("categories", {}).values()),
            description=f"{malicious}/{total} engines flagged as malicious",
            raw_data={
                "last_analysis_stats": stats,
                "last_final_url": attrs.get("last_final_url"),
                "title": attrs.get("title"),
            },
        )
