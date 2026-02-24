"""IDS alert parser (Suricata/Snort EVE JSON and fast.log)."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, ClassVar

from threattriage.models.base import LogType
from threattriage.parsers.base import LogParser, ParsedLog


# Suricata EVE JSON has event_type field
# Snort fast.log format: [**] [1:2000001:1] ET MALWARE ... [**] [Classification: ...] [Priority: N] {TCP} 1.2.3.4:5678 -> 5.6.7.8:80

_SNORT_FAST_PATTERN = re.compile(
    r"\[\*\*\]\s*\[(\d+:\d+:\d+)\]\s*(.+?)\s*\[\*\*\]"
    r".*?\[Classification:\s*(.+?)\].*?\[Priority:\s*(\d+)\]"
    r".*?\{(\w+)\}\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+):(\d+)",
    re.IGNORECASE,
)

# Severity mapping from Suricata/Snort priority
_PRIORITY_TAGS = {
    1: ["critical_alert"],
    2: ["high_alert"],
    3: ["medium_alert"],
    4: ["low_alert"],
}

# Known malicious classification keywords
_SUSPICIOUS_CLASSIFICATIONS = {
    "trojan", "malware", "exploit", "shellcode", "c2", "command-and-control",
    "botnet", "backdoor", "ransomware", "miner", "crypto", "exfiltration",
    "phishing", "dga", "dns tunneling", "web attack", "sql injection",
}


class IDSAlertParser(LogParser):
    """Parser for IDS alerts (Suricata EVE JSON and Snort fast.log)."""

    log_type: ClassVar[LogType] = LogType.GENERIC
    name: ClassVar[str] = "ids_alert"
    description: ClassVar[str] = "Suricata/Snort IDS alert parser"

    def can_parse(self, raw_line: str) -> bool:
        stripped = raw_line.strip()
        # Suricata EVE JSON
        if stripped.startswith("{"):
            try:
                data = json.loads(stripped)
                return "event_type" in data and ("alert" in data or data.get("event_type") == "alert")
            except (json.JSONDecodeError, ValueError):
                pass
        # Snort fast.log
        return bool(_SNORT_FAST_PATTERN.search(raw_line))

    def parse(self, raw_line: str) -> ParsedLog | None:
        stripped = raw_line.strip()

        # Try Suricata EVE JSON
        if stripped.startswith("{"):
            try:
                data = json.loads(stripped)
                if "event_type" in data:
                    return self._parse_eve(data, raw_line)
            except (json.JSONDecodeError, ValueError):
                pass

        # Try Snort fast.log
        m = _SNORT_FAST_PATTERN.search(raw_line)
        if m:
            return self._parse_snort_fast(m, raw_line)

        return None

    def _parse_eve(self, data: dict[str, Any], raw: str) -> ParsedLog:
        alert_data = data.get("alert", {})
        signature = alert_data.get("signature", "Unknown Alert")
        severity = alert_data.get("severity", 3)
        category = alert_data.get("category", "")
        sid = alert_data.get("signature_id", 0)

        src_ip = data.get("src_ip")
        dest_ip = data.get("dest_ip")
        src_port = data.get("src_port")
        dest_port = data.get("dest_port")
        proto = data.get("proto", "")
        timestamp = self._parse_timestamp(data.get("timestamp"))

        is_suspicious = True
        tags = _PRIORITY_TAGS.get(severity, ["alert"])
        ioc_values = []

        # Check for highly suspicious classifications
        cat_lower = category.lower()
        for kw in _SUSPICIOUS_CLASSIFICATIONS:
            if kw in cat_lower:
                tags.append("malicious")
                break

        if src_ip:
            ioc_values.append(("ip", src_ip))
        if dest_ip:
            ioc_values.append(("ip", dest_ip))

        return ParsedLog(
            raw=raw,
            log_type=LogType.GENERIC,
            timestamp=timestamp,
            source_ip=src_ip,
            destination_ip=dest_ip,
            message=f"[Suricata SID:{sid}] {signature} ({category}) - {src_ip}:{src_port} → {dest_ip}:{dest_port} ({proto})",
            is_suspicious=is_suspicious,
            detection_tags=tags,
            ioc_values=ioc_values,
            parsed_data={
                "format": "suricata_eve",
                "signature": signature,
                "signature_id": sid,
                "severity": severity,
                "category": category,
                "protocol": proto,
                "src_port": src_port,
                "dst_port": dest_port,
            },
        )

    def _parse_snort_fast(self, m: re.Match, raw: str) -> ParsedLog:
        sid, signature, classification, priority, proto, src_ip, src_port, dst_ip, dst_port = m.groups()
        priority_int = int(priority)

        is_suspicious = True
        tags = _PRIORITY_TAGS.get(priority_int, ["alert"])
        ioc_values = [("ip", src_ip), ("ip", dst_ip)]

        cls_lower = classification.lower()
        for kw in _SUSPICIOUS_CLASSIFICATIONS:
            if kw in cls_lower:
                tags.append("malicious")
                break

        return ParsedLog(
            raw=raw,
            log_type=LogType.GENERIC,
            timestamp=datetime.now(),
            source_ip=src_ip,
            destination_ip=dst_ip,
            message=f"[Snort {sid}] {signature} ({classification}) P{priority} - {src_ip}:{src_port} → {dst_ip}:{dst_port} ({proto})",
            is_suspicious=is_suspicious,
            detection_tags=tags,
            ioc_values=ioc_values,
            parsed_data={
                "format": "snort_fast",
                "sid": sid,
                "signature": signature,
                "classification": classification,
                "priority": priority_int,
                "protocol": proto,
                "src_port": int(src_port),
                "dst_port": int(dst_port),
            },
        )

    @staticmethod
    def _parse_timestamp(ts: str | None) -> datetime | None:
        if not ts:
            return None
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
        ):
            try:
                return datetime.strptime(ts, fmt)
            except (ValueError, TypeError):
                continue
        return None
