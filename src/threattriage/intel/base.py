"""Abstract base class for Threat Intelligence providers."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TIResult:
    """Standardised result from any TI provider lookup."""

    provider: str
    ioc_type: str
    value: str

    # Verdict
    reputation_score: float = 0.0  # 0 = clean → 100 = malicious
    is_malicious: bool = False
    confidence: float = 0.0  # 0.0 → 1.0

    # Enrichment
    tags: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    description: str = ""

    # Network context
    country: str | None = None
    asn: str | None = None
    org: str | None = None

    # Raw vendor data
    raw_data: dict[str, Any] = field(default_factory=dict)

    # Error
    error: str | None = None
    success: bool = True


class ThreatIntelProvider(abc.ABC):
    """Abstract base class for all Threat Intelligence providers."""

    name: str = "base"
    enabled: bool = True

    @abc.abstractmethod
    async def lookup_ip(self, ip: str) -> TIResult:
        """Look up an IP address."""

    @abc.abstractmethod
    async def lookup_domain(self, domain: str) -> TIResult:
        """Look up a domain name."""

    @abc.abstractmethod
    async def lookup_hash(self, file_hash: str) -> TIResult:
        """Look up a file hash (MD5/SHA1/SHA256)."""

    @abc.abstractmethod
    async def lookup_url(self, url: str) -> TIResult:
        """Look up a URL."""

    async def is_available(self) -> bool:
        """Check if provider is configured and available."""
        return self.enabled
