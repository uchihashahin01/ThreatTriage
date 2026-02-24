"""Firewall log parser (iptables, pfSense, Palo Alto, generic)."""

from __future__ import annotations

import re
from datetime import datetime
from typing import ClassVar

from threattriage.models.base import LogType
from threattriage.parsers.base import LogParser, ParsedLog


# ─── Firewall Log Patterns ───────────────────────────────────────────────────

# iptables/netfilter
_IPTABLES_PATTERN = re.compile(
    r"(?:iptables|kernel|netfilter).*?"
    r"(?:IN=(\S*)\s+OUT=(\S*)).*?"
    r"SRC=(\d+\.\d+\.\d+\.\d+)\s+DST=(\d+\.\d+\.\d+\.\d+).*?"
    r"PROTO=(\S+).*?(?:SPT=(\d+))?.*?(?:DPT=(\d+))?",
    re.IGNORECASE,
)

# pfSense filterlog (CSV format)
_PFSENSE_PATTERN = re.compile(
    r"filterlog\[\d+\]:\s*(.+)",
    re.IGNORECASE,
)

# Palo Alto traffic log
_PALOALTO_PATTERN = re.compile(
    r"(?:TRAFFIC|THREAT),.*?(\d+\.\d+\.\d+\.\d+),(\d+\.\d+\.\d+\.\d+),.*?(\d+),(\d+),",
    re.IGNORECASE,
)

# Generic firewall patterns
_GENERIC_FW_PATTERN = re.compile(
    r"(?:BLOCK|DROP|DENY|REJECT|ACCEPT|ALLOW|PASS).*?"
    r"(?:src|source|SRC)[=:\s]+(\d+\.\d+\.\d+\.\d+).*?"
    r"(?:dst|dest|DST)[=:\s]+(\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)

# Suspicious ports
_SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 7777, 8888, 1337, 31337,  # Common backdoor ports
    3389,  # RDP
    445, 139,  # SMB
    23,  # Telnet
    21,  # FTP
    1433, 3306, 5432,  # DB ports
    6379,  # Redis
    27017,  # MongoDB
    9200,  # Elasticsearch
}

_SUSPICIOUS_ACTION = re.compile(r"\b(?:DROP|BLOCK|DENY|REJECT)\b", re.IGNORECASE)


class FirewallParser(LogParser):
    """Parser for firewall logs (iptables, pfSense, Palo Alto, generic)."""

    log_type: ClassVar[LogType] = LogType.GENERIC
    name: ClassVar[str] = "firewall"
    description: ClassVar[str] = "Firewall logs (iptables, pfSense, Palo Alto)"

    def can_parse(self, raw_line: str) -> bool:
        return bool(
            _IPTABLES_PATTERN.search(raw_line)
            or (_PFSENSE_PATTERN.search(raw_line) and "filterlog" in raw_line)
            or _PALOALTO_PATTERN.search(raw_line)
            or _GENERIC_FW_PATTERN.search(raw_line)
        )

    def parse(self, raw_line: str) -> ParsedLog | None:
        # Try iptables
        m = _IPTABLES_PATTERN.search(raw_line)
        if m:
            return self._parse_iptables(m, raw_line)

        # Try pfSense
        m = _PFSENSE_PATTERN.search(raw_line)
        if m and "filterlog" in raw_line:
            return self._parse_pfsense(m, raw_line)

        # Try Palo Alto
        m = _PALOALTO_PATTERN.search(raw_line)
        if m:
            return self._parse_paloalto(m, raw_line)

        # Try generic
        m = _GENERIC_FW_PATTERN.search(raw_line)
        if m:
            return self._parse_generic(m, raw_line)

        return None

    def _parse_iptables(self, m: re.Match, raw: str) -> ParsedLog:
        in_iface, out_iface, src_ip, dst_ip, proto, src_port, dst_port = m.groups()
        dst_port_int = int(dst_port) if dst_port else None

        is_suspicious, tags = self._analyze(src_ip, dst_ip, dst_port_int, raw)
        action = "BLOCK" if _SUSPICIOUS_ACTION.search(raw) else "ALLOW"

        return ParsedLog(
            raw=raw,
            log_type=LogType.GENERIC,
            timestamp=datetime.now(),
            source_ip=src_ip,
            destination_ip=dst_ip,
            message=f"iptables {action}: {src_ip}:{src_port or '?'} → {dst_ip}:{dst_port or '?'} ({proto})",
            is_suspicious=is_suspicious,
            detection_tags=tags,
            ioc_values=[("ip", src_ip)],
            parsed_data={
                "format": "iptables",
                "action": action,
                "protocol": proto,
                "src_port": int(src_port) if src_port else None,
                "dst_port": dst_port_int,
                "interface_in": in_iface,
                "interface_out": out_iface,
            },
        )

    def _parse_pfsense(self, m: re.Match, raw: str) -> ParsedLog:
        csvdata = m.group(1)
        fields = csvdata.split(",")

        src_ip = dst_ip = proto = None
        dst_port_int = None

        # pfSense filterlog CSV format varies by version, but common fields:
        if len(fields) >= 20:
            action_field = fields[6] if len(fields) > 6 else ""
            proto = fields[16] if len(fields) > 16 else None
            src_ip = fields[18] if len(fields) > 18 else None
            dst_ip = fields[19] if len(fields) > 19 else None
            dst_port = fields[21] if len(fields) > 21 else None
            dst_port_int = int(dst_port) if dst_port and dst_port.isdigit() else None

        is_suspicious, tags = self._analyze(src_ip, dst_ip, dst_port_int, raw)

        return ParsedLog(
            raw=raw,
            log_type=LogType.GENERIC,
            timestamp=datetime.now(),
            source_ip=src_ip,
            destination_ip=dst_ip,
            message=f"pfSense: {src_ip} → {dst_ip}:{dst_port_int or '?'} ({proto or '?'})",
            is_suspicious=is_suspicious,
            detection_tags=tags,
            ioc_values=[("ip", src_ip)] if src_ip else [],
            parsed_data={"format": "pfsense", "protocol": proto, "dst_port": dst_port_int},
        )

    def _parse_paloalto(self, m: re.Match, raw: str) -> ParsedLog:
        src_ip, dst_ip, src_port, dst_port = m.groups()
        dst_port_int = int(dst_port) if dst_port else None

        is_suspicious, tags = self._analyze(src_ip, dst_ip, dst_port_int, raw)

        return ParsedLog(
            raw=raw,
            log_type=LogType.GENERIC,
            timestamp=datetime.now(),
            source_ip=src_ip,
            destination_ip=dst_ip,
            message=f"PaloAlto: {src_ip}:{src_port} → {dst_ip}:{dst_port}",
            is_suspicious=is_suspicious,
            detection_tags=tags,
            ioc_values=[("ip", src_ip)],
            parsed_data={"format": "paloalto", "src_port": int(src_port), "dst_port": dst_port_int},
        )

    def _parse_generic(self, m: re.Match, raw: str) -> ParsedLog:
        src_ip, dst_ip = m.groups()
        port_m = re.search(r"(?:dpt|dst_port|dport|DPT)[=:\s]+(\d+)", raw, re.IGNORECASE)
        dst_port_int = int(port_m.group(1)) if port_m else None

        is_suspicious, tags = self._analyze(src_ip, dst_ip, dst_port_int, raw)
        action = "BLOCK" if _SUSPICIOUS_ACTION.search(raw) else "ALLOW"

        return ParsedLog(
            raw=raw,
            log_type=LogType.GENERIC,
            timestamp=datetime.now(),
            source_ip=src_ip,
            destination_ip=dst_ip,
            message=f"Firewall {action}: {src_ip} → {dst_ip}:{dst_port_int or '?'}",
            is_suspicious=is_suspicious,
            detection_tags=tags,
            ioc_values=[("ip", src_ip)],
            parsed_data={"format": "generic_firewall", "action": action, "dst_port": dst_port_int},
        )

    @staticmethod
    def _analyze(src_ip: str | None, dst_ip: str | None, dst_port: int | None, raw: str) -> tuple[bool, list[str]]:
        tags = ["firewall"]
        is_suspicious = False

        if dst_port and dst_port in _SUSPICIOUS_PORTS:
            is_suspicious = True
            tags.append("suspicious_port")

        if _SUSPICIOUS_ACTION.search(raw):
            tags.append("blocked")

        # Port scan detection hint (many dropped connections from same source)
        if "DROP" in raw.upper() or "BLOCK" in raw.upper():
            is_suspicious = True
            tags.append("blocked_traffic")

        return is_suspicious, tags
