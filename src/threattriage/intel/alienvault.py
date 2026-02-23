"""AlienVault OTX (Open Threat Exchange) integration.

Queries OTX for IP, domain, hash, and URL reputation via their DirectConnect API.
"""

from __future__ import annotations

from typing import Any

import httpx

from threattriage.config import get_settings
from threattriage.intel.base import ThreatIntelProvider, TIResult
from threattriage.logging import get_logger

logger = get_logger(__name__)

OTX_API_BASE = "https://otx.alienvault.com/api/v1"


class AlienVaultProvider(ThreatIntelProvider):
    """AlienVault OTX threat intelligence provider."""

    name = "alienvault"

    def __init__(self) -> None:
        settings = get_settings()
        self.api_key = settings.alienvault_api_key
        self.enabled = bool(self.api_key)

    async def _request(self, endpoint: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{OTX_API_BASE}/{endpoint}",
                    headers={"X-OTX-API-KEY": self.api_key},
                )
                if resp.status_code == 200:
                    return resp.json()
                logger.warning("alienvault_error", endpoint=endpoint, status=resp.status_code)
                return None
        except httpx.HTTPError as e:
            logger.error("alienvault_request_failed", error=str(e))
            return None

    async def lookup_ip(self, ip: str) -> TIResult:
        general = await self._request(f"indicators/IPv4/{ip}/general")
        reputation = await self._request(f"indicators/IPv4/{ip}/reputation")

        if not general:
            return TIResult(provider=self.name, ioc_type="ip", value=ip, success=False, error="No data")

        pulse_count = general.get("pulse_info", {}).get("count", 0)
        rep_data = reputation or {}

        # Score based on pulse count and reputation data
        score = min(pulse_count * 10, 100)
        if rep_data.get("reputation"):
            rep_score = rep_data["reputation"].get("threat_score", 0)
            score = max(score, rep_score)

        tags = []
        for pulse in general.get("pulse_info", {}).get("pulses", [])[:5]:
            tags.extend(pulse.get("tags", []))

        return TIResult(
            provider=self.name,
            ioc_type="ip",
            value=ip,
            reputation_score=round(score, 2),
            is_malicious=pulse_count > 0,
            confidence=min(pulse_count / 10, 1.0),
            tags=list(set(tags))[:20],
            country=general.get("country_code"),
            asn=general.get("asn"),
            description=f"Found in {pulse_count} OTX pulses",
            raw_data={
                "pulse_count": pulse_count,
                "indicator": general.get("indicator"),
                "country_name": general.get("country_name"),
                "city": general.get("city"),
                "asn": general.get("asn"),
            },
        )

    async def lookup_domain(self, domain: str) -> TIResult:
        general = await self._request(f"indicators/domain/{domain}/general")

        if not general:
            return TIResult(provider=self.name, ioc_type="domain", value=domain, success=False, error="No data")

        pulse_count = general.get("pulse_info", {}).get("count", 0)
        score = min(pulse_count * 10, 100)

        tags = []
        for pulse in general.get("pulse_info", {}).get("pulses", [])[:5]:
            tags.extend(pulse.get("tags", []))

        return TIResult(
            provider=self.name,
            ioc_type="domain",
            value=domain,
            reputation_score=round(score, 2),
            is_malicious=pulse_count > 0,
            confidence=min(pulse_count / 10, 1.0),
            tags=list(set(tags))[:20],
            description=f"Found in {pulse_count} OTX pulses",
            raw_data={
                "pulse_count": pulse_count,
                "alexa": general.get("alexa"),
                "whois": general.get("whois", "")[:500] if general.get("whois") else None,
            },
        )

    async def lookup_hash(self, file_hash: str) -> TIResult:
        general = await self._request(f"indicators/file/{file_hash}/general")

        if not general:
            return TIResult(provider=self.name, ioc_type="hash", value=file_hash, success=False, error="No data")

        pulse_count = general.get("pulse_info", {}).get("count", 0)
        score = min(pulse_count * 15, 100)

        tags = []
        for pulse in general.get("pulse_info", {}).get("pulses", [])[:5]:
            tags.extend(pulse.get("tags", []))

        return TIResult(
            provider=self.name,
            ioc_type="hash",
            value=file_hash,
            reputation_score=round(score, 2),
            is_malicious=pulse_count > 0,
            confidence=min(pulse_count / 5, 1.0),
            tags=list(set(tags))[:20],
            description=f"Found in {pulse_count} OTX pulses",
            raw_data={"pulse_count": pulse_count},
        )

    async def lookup_url(self, url: str) -> TIResult:
        general = await self._request(f"indicators/url/{url}/general")

        if not general:
            return TIResult(provider=self.name, ioc_type="url", value=url, success=False, error="No data")

        pulse_count = general.get("pulse_info", {}).get("count", 0)
        score = min(pulse_count * 15, 100)

        return TIResult(
            provider=self.name,
            ioc_type="url",
            value=url,
            reputation_score=round(score, 2),
            is_malicious=pulse_count > 0,
            confidence=min(pulse_count / 5, 1.0),
            description=f"Found in {pulse_count} OTX pulses",
            raw_data={"pulse_count": pulse_count},
        )
