"""GeoIP lookup service for mapping IPs to geographic locations.

Uses MaxMind GeoLite2 database when available, falls back to a
built-in IP-to-country mapping for common threat IPs.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from threattriage.logging import get_logger

logger = get_logger(__name__)

GEOIP_DB_PATH = Path(__file__).parent.parent.parent.parent / "data" / "GeoLite2-City.mmdb"


@dataclass
class GeoLocation:
    """Geographic location data for an IP address."""
    ip: str
    country_code: str
    country_name: str
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: str | None = None
    org: str | None = None
    is_private: bool = False


# ── Built-in fallback database for common threat IPs ─────────────────────────
# Country codes for well-known threat infrastructure IP ranges
_FALLBACK_RANGES: list[tuple[str, str, str]] = [
    ("185.220.0.0/16", "DE", "Germany"),
    ("45.33.0.0/16", "US", "United States"),
    ("192.42.116.0/24", "NL", "Netherlands"),
    ("171.25.193.0/24", "SE", "Sweden"),
    ("104.244.0.0/16", "LU", "Luxembourg"),
    ("162.247.0.0/16", "US", "United States"),
    ("23.129.0.0/16", "US", "United States"),
    ("51.15.0.0/16", "FR", "France"),
    ("198.98.0.0/16", "US", "United States"),
    ("5.2.0.0/16", "RO", "Romania"),
    ("91.219.0.0/16", "UA", "Ukraine"),
    ("77.247.181.0/24", "NL", "Netherlands"),
    ("209.141.0.0/16", "US", "United States"),
    ("176.10.99.0/24", "CH", "Switzerland"),
    ("46.166.0.0/16", "NL", "Netherlands"),
    ("10.0.0.0/8", "__", "Private Network"),
    ("172.16.0.0/12", "__", "Private Network"),
    ("192.168.0.0/16", "__", "Private Network"),
    ("127.0.0.0/8", "__", "Loopback"),
]


def _is_private(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def _fallback_lookup(ip_str: str) -> GeoLocation | None:
    """Look up IP against built-in ranges."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None

    if addr.is_private or addr.is_loopback:
        return GeoLocation(
            ip=ip_str,
            country_code="--",
            country_name="Private Network",
            is_private=True,
        )

    for cidr, cc, name in _FALLBACK_RANGES:
        if addr in ipaddress.ip_network(cidr, strict=False):
            return GeoLocation(
                ip=ip_str,
                country_code=cc,
                country_name=name,
            )

    return None


class GeoIPService:
    """Resolves IP addresses to geographic locations."""

    def __init__(self) -> None:
        self._reader = None
        self._maxmind_available = False

        # Try to load MaxMind database
        if GEOIP_DB_PATH.exists():
            try:
                import geoip2.database
                self._reader = geoip2.database.Reader(str(GEOIP_DB_PATH))
                self._maxmind_available = True
                logger.info("geoip_maxmind_loaded", path=str(GEOIP_DB_PATH))
            except Exception as exc:
                logger.warning("geoip_maxmind_failed", error=str(exc))
        else:
            logger.info("geoip_using_fallback", reason="MaxMind DB not found")

    def lookup(self, ip: str) -> GeoLocation:
        """Resolve an IP address to a geographic location."""
        if _is_private(ip):
            return GeoLocation(
                ip=ip, country_code="--", country_name="Private Network", is_private=True
            )

        if self._maxmind_available and self._reader:
            try:
                resp = self._reader.city(ip)
                return GeoLocation(
                    ip=ip,
                    country_code=resp.country.iso_code or "??",
                    country_name=resp.country.name or "Unknown",
                    city=resp.city.name,
                    latitude=resp.location.latitude,
                    longitude=resp.location.longitude,
                )
            except Exception:
                pass

        # Fallback
        result = _fallback_lookup(ip)
        if result:
            return result

        return GeoLocation(ip=ip, country_code="??", country_name="Unknown")

    def lookup_batch(self, ips: list[str]) -> dict[str, GeoLocation]:
        """Resolve multiple IPs."""
        return {ip: self.lookup(ip) for ip in set(ips) if ip}

    def to_map_data(self, ips: list[str]) -> list[dict[str, Any]]:
        """Generate map-ready data with coordinates for visualization."""
        # Well-known coordinate estimates for countries (used when MaxMind unavailable)
        country_coords: dict[str, tuple[float, float]] = {
            "US": (39.8, -98.5), "DE": (51.2, 10.4), "NL": (52.1, 5.3),
            "SE": (60.1, 18.6), "FR": (46.2, 2.2), "GB": (55.4, -3.4),
            "RO": (45.9, 25.0), "UA": (48.4, 31.2), "RU": (61.5, 105.3),
            "CN": (35.9, 104.2), "KR": (35.9, 127.8), "JP": (36.2, 138.3),
            "BR": (-14.2, -51.9), "IN": (20.6, 79.0), "AU": (-25.3, 133.8),
            "LU": (49.8, 6.1), "CH": (46.8, 8.2), "IR": (32.4, 53.7),
            "KP": (40.3, 127.5),
        }

        locations = self.lookup_batch(ips)
        results = []
        seen_coords: set[str] = set()

        for ip, geo in locations.items():
            if geo.is_private:
                continue

            lat = geo.latitude
            lng = geo.longitude

            if lat is None or lng is None:
                coords = country_coords.get(geo.country_code)
                if coords:
                    lat, lng = coords
                else:
                    continue

            key = f"{lat:.1f},{lng:.1f}"
            if key in seen_coords:
                # Slightly offset overlapping points
                lat += 0.5
                lng += 0.5
            seen_coords.add(key)

            results.append({
                "ip": ip,
                "country_code": geo.country_code,
                "country_name": geo.country_name,
                "city": geo.city,
                "lat": lat,
                "lng": lng,
            })

        return results

    def close(self) -> None:
        if self._reader:
            self._reader.close()


@lru_cache(maxsize=1)
def get_geoip_service() -> GeoIPService:
    """Return cached GeoIP service singleton."""
    return GeoIPService()
