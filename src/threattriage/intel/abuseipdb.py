"""AbuseIPDB integration — IP abuse confidence scoring.

AbuseIPDB specialises in IP reputation. Domain/hash/URL lookups return
a stub result since the API only supports IP addresses.
"""

from __future__ import annotations

from typing import Any

import httpx

from threattriage.config import get_settings
from threattriage.intel.base import ThreatIntelProvider, TIResult
from threattriage.logging import get_logger

logger = get_logger(__name__)

ABUSEIPDB_API_BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB threat intelligence provider (IP-only)."""

    name = "abuseipdb"

    def __init__(self) -> None:
        settings = get_settings()
        self.api_key = settings.abuseipdb_api_key
        self.enabled = bool(self.api_key)

    async def lookup_ip(self, ip: str) -> TIResult:
        if not self.enabled:
            return TIResult(provider=self.name, ioc_type="ip", value=ip, success=False, error="API key not configured")

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{ABUSEIPDB_API_BASE}/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                    headers={
                        "Key": self.api_key,
                        "Accept": "application/json",
                    },
                )

                if resp.status_code != 200:
                    logger.warning("abuseipdb_error", ip=ip, status=resp.status_code)
                    return TIResult(
                        provider=self.name, ioc_type="ip", value=ip,
                        success=False, error=f"HTTP {resp.status_code}",
                    )

                data = resp.json().get("data", {})

        except httpx.HTTPError as e:
            logger.error("abuseipdb_request_failed", error=str(e))
            return TIResult(provider=self.name, ioc_type="ip", value=ip, success=False, error=str(e))

        abuse_score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        is_public = data.get("isPublic", True)

        # Build categories
        categories = []
        for report in data.get("reports", [])[:10]:
            categories.extend([str(c) for c in report.get("categories", [])])

        return TIResult(
            provider=self.name,
            ioc_type="ip",
            value=ip,
            reputation_score=float(abuse_score),
            is_malicious=abuse_score >= 25,
            confidence=min(total_reports / 20, 1.0),
            tags=[f"abuse_score:{abuse_score}"],
            categories=list(set(categories))[:10],
            country=data.get("countryCode"),
            org=data.get("isp"),
            description=(
                f"Abuse confidence: {abuse_score}% | "
                f"{total_reports} reports | "
                f"ISP: {data.get('isp', 'unknown')} | "
                f"Usage: {data.get('usageType', 'unknown')}"
            ),
            raw_data={
                "abuseConfidenceScore": abuse_score,
                "totalReports": total_reports,
                "numDistinctUsers": data.get("numDistinctUsers", 0),
                "lastReportedAt": data.get("lastReportedAt"),
                "isp": data.get("isp"),
                "usageType": data.get("usageType"),
                "domain": data.get("domain"),
                "hostnames": data.get("hostnames", []),
                "isPublic": is_public,
                "isWhitelisted": data.get("isWhitelisted"),
            },
        )

    async def lookup_domain(self, domain: str) -> TIResult:
        return TIResult(
            provider=self.name, ioc_type="domain", value=domain,
            success=False, error="AbuseIPDB only supports IP lookups",
        )

    async def lookup_hash(self, file_hash: str) -> TIResult:
        return TIResult(
            provider=self.name, ioc_type="hash", value=file_hash,
            success=False, error="AbuseIPDB only supports IP lookups",
        )

    async def lookup_url(self, url: str) -> TIResult:
        return TIResult(
            provider=self.name, ioc_type="url", value=url,
            success=False, error="AbuseIPDB only supports IP lookups",
        )
