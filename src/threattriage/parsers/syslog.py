"""Syslog parser — RFC 3164 and RFC 5424 format support.

Detects: authentication failures, privilege escalation, suspicious commands.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import ClassVar

from threattriage.models.base import LogType
from threattriage.parsers.base import LogParser, ParsedLog

# ─── RFC 3164 (BSD Syslog) ────────────────────────────────────────────────────
# Example: Mar  5 12:34:56 myhost sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
_RFC3164_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

# ─── RFC 5424 ─────────────────────────────────────────────────────────────────
# Example: <34>1 2024-03-05T12:34:56.789Z myhost sshd 1234 - - Failed password ...
_RFC5424_PATTERN = re.compile(
    r"^<(?P<priority>\d{1,3})>(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<structured_data>(?:\[.+?\]|-)+)\s*"
    r"(?P<message>.*)$"
)

# ─── Suspicious Pattern Detection ─────────────────────────────────────────────
_SUSPICIOUS_PATTERNS: list[tuple[re.Pattern[str], str, list[str]]] = [
    # (pattern, detection_tag, mitre_technique_ids)
    (
        re.compile(r"Failed password|authentication failure|invalid user", re.IGNORECASE),
        "brute_force_attempt",
        ["T1110", "T1110.001"],
    ),
    (
        re.compile(r"Accepted password for root|session opened for user root", re.IGNORECASE),
        "root_login",
        ["T1078"],
    ),
    (
        re.compile(r"sudo:\s+\S+\s+:", re.IGNORECASE),
        "privilege_escalation",
        ["T1548.003"],
    ),
    (
        re.compile(r"COMMAND=.*(curl|wget|nc |ncat|python|perl|bash -i|/dev/tcp)", re.IGNORECASE),
        "suspicious_command_execution",
        ["T1059", "T1059.004"],
    ),
    (
        re.compile(r"segfault|buffer overflow|stack smashing", re.IGNORECASE),
        "potential_exploit",
        ["T1203"],
    ),
    (
        re.compile(r"UFW BLOCK|iptables.*DROP|DENIED", re.IGNORECASE),
        "firewall_block",
        ["T1046"],
    ),
    (
        re.compile(r"new user:|useradd|adduser", re.IGNORECASE),
        "account_creation",
        ["T1136.001"],
    ),
    (
        re.compile(r"cron.*\(root\)|crontab.*REPLACE", re.IGNORECASE),
        "persistence_cron",
        ["T1053.003"],
    ),
    (
        re.compile(r"ssh.*reverse|tunnel|port.?forward", re.IGNORECASE),
        "ssh_tunneling",
        ["T1572"],
    ),
]

# ─── IP Extraction ────────────────────────────────────────────────────────────
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_FAILED_FROM_IP = re.compile(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})")


class SyslogParser(LogParser):
    """Parser for syslog messages (RFC 3164 and RFC 5424)."""

    log_type: ClassVar[LogType] = LogType.SYSLOG
    name: ClassVar[str] = "syslog"
    description: ClassVar[str] = "Parses RFC 3164 (BSD) and RFC 5424 syslog formats"

    def can_parse(self, raw_line: str) -> bool:
        """Check if line matches syslog format."""
        return bool(_RFC3164_PATTERN.match(raw_line) or _RFC5424_PATTERN.match(raw_line))

    def parse(self, raw_line: str) -> ParsedLog | None:
        """Parse a syslog line."""
        result = self._try_rfc5424(raw_line)
        if result:
            return result
        return self._try_rfc3164(raw_line)

    def _try_rfc3164(self, raw_line: str) -> ParsedLog | None:
        match = _RFC3164_PATTERN.match(raw_line)
        if not match:
            return None

        groups = match.groupdict()
        timestamp = self._parse_bsd_timestamp(groups["timestamp"])

        parsed = ParsedLog(
            raw=raw_line,
            log_type=LogType.SYSLOG,
            timestamp=timestamp,
            hostname=groups["hostname"],
            process_name=groups["process"],
            pid=int(groups["pid"]) if groups.get("pid") else None,
            message=groups["message"],
            parsed_data={
                "format": "rfc3164",
                **{k: v for k, v in groups.items() if v is not None},
            },
        )

        # Extract source IP
        ip_match = _FAILED_FROM_IP.search(groups["message"])
        if ip_match:
            parsed.source_ip = ip_match.group(1)
        else:
            ips = _IP_PATTERN.findall(groups["message"])
            if ips:
                parsed.source_ip = ips[0]

        # Run suspicious pattern detection
        self._detect_suspicious(parsed, groups["message"])

        return parsed

    def _try_rfc5424(self, raw_line: str) -> ParsedLog | None:
        match = _RFC5424_PATTERN.match(raw_line)
        if not match:
            return None

        groups = match.groupdict()

        try:
            timestamp = datetime.fromisoformat(groups["timestamp"].replace("Z", "+00:00"))
        except (ValueError, TypeError):
            timestamp = None

        pid_str = groups.get("procid", "-")
        pid = int(pid_str) if pid_str and pid_str != "-" and pid_str.isdigit() else None

        parsed = ParsedLog(
            raw=raw_line,
            log_type=LogType.SYSLOG,
            timestamp=timestamp,
            hostname=groups["hostname"],
            process_name=groups["appname"] if groups["appname"] != "-" else None,
            pid=pid,
            message=groups["message"],
            parsed_data={
                "format": "rfc5424",
                "priority": int(groups["priority"]),
                "version": int(groups["version"]),
                **{k: v for k, v in groups.items() if v is not None and v != "-"},
            },
        )

        # Extract IPs
        if groups["message"]:
            ip_match = _FAILED_FROM_IP.search(groups["message"])
            if ip_match:
                parsed.source_ip = ip_match.group(1)
            else:
                ips = _IP_PATTERN.findall(groups["message"])
                if ips:
                    parsed.source_ip = ips[0]

            self._detect_suspicious(parsed, groups["message"])

        return parsed

    def _detect_suspicious(self, parsed: ParsedLog, message: str) -> None:
        """Run all suspicious pattern detections on the message."""
        for pattern, tag, techniques in _SUSPICIOUS_PATTERNS:
            if pattern.search(message):
                parsed.is_suspicious = True
                parsed.detection_tags.append(tag)
                # Store technique IDs in parsed_data for later MITRE mapping
                if "mitre_techniques" not in parsed.parsed_data:
                    parsed.parsed_data["mitre_techniques"] = []
                parsed.parsed_data["mitre_techniques"].extend(techniques)

        # Extract IOCs
        if parsed.source_ip:
            parsed.ioc_values.append(("ip", parsed.source_ip))

    @staticmethod
    def _parse_bsd_timestamp(ts_str: str) -> datetime | None:
        """Parse BSD syslog timestamp (e.g., 'Mar  5 12:34:56')."""
        try:
            current_year = datetime.now().year
            return datetime.strptime(f"{current_year} {ts_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
