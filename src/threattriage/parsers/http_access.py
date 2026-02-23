"""HTTP access log parser — Apache/Nginx combined and common log format.

Detects: SQL injection, XSS, path traversal, scanner signatures, anomalous status codes.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import ClassVar
from urllib.parse import unquote

from threattriage.models.base import LogType
from threattriage.parsers.base import LogParser, ParsedLog

# ─── Common/Combined Log Format ──────────────────────────────────────────────
# 192.168.1.100 - admin [05/Mar/2024:12:34:56 +0000] "GET /api/users HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0 ..."
_COMBINED_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)")?'
    r'(?:\s+"(?P<user_agent>[^"]*)")?'
)

# ─── Attack Pattern Detection ─────────────────────────────────────────────────
_ATTACK_PATTERNS: list[tuple[re.Pattern[str], str, str, list[str]]] = [
    # (pattern, tag, description, mitre_techniques)

    # SQL Injection
    (
        re.compile(
            r"(?:union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|"
            r"or\s+1\s*=\s*1|'\s*or\s*'|;\s*--|\b(?:exec|execute)\b.*\bxp_)",
            re.IGNORECASE,
        ),
        "sql_injection",
        "SQL injection attempt detected in HTTP request",
        ["T1190", "T1190"],
    ),

    # XSS
    (
        re.compile(
            r"<script|javascript:|onerror\s*=|onload\s*=|eval\s*\(|alert\s*\(|"
            r"document\.cookie|document\.write",
            re.IGNORECASE,
        ),
        "xss_attempt",
        "Cross-Site Scripting (XSS) attempt detected",
        ["T1189", "T1059.007"],
    ),

    # Path Traversal / LFI
    (
        re.compile(r"\.\./|\.\.\\|%2e%2e|/etc/passwd|/etc/shadow|/proc/self", re.IGNORECASE),
        "path_traversal",
        "Path traversal / Local File Inclusion attempt",
        ["T1083"],
    ),

    # Command Injection
    (
        re.compile(r"[;|`]\s*(?:cat|ls|id|whoami|uname|wget|curl|nc\s|bash|sh\s)", re.IGNORECASE),
        "command_injection",
        "OS command injection attempt",
        ["T1059"],
    ),

    # Known Scanner Signatures (User-Agent)
    (
        re.compile(
            r"(?:nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz|burp|ZAP|"
            r"acunetix|nessus|qualys|openvas|nuclei)",
            re.IGNORECASE,
        ),
        "scanner_detected",
        "Security scanner/tool detected",
        ["T1595.002"],
    ),

    # Admin/Sensitive Path Access
    (
        re.compile(
            r"(?:/admin|/wp-admin|/phpmyadmin|/\.env|/\.git|/config|/backup|"
            r"/api/v\d+/admin|/actuator|/debug|/console)",
            re.IGNORECASE,
        ),
        "sensitive_path_access",
        "Access attempt to sensitive/admin path",
        ["T1083", "T1190"],
    ),

    # Shell Upload
    (
        re.compile(r"\.(?:php|jsp|asp|aspx|cgi|sh|py|pl|rb)\?|upload.*\.(?:php|jsp|asp)", re.IGNORECASE),
        "webshell_upload",
        "Potential web shell upload or access",
        ["T1505.003"],
    ),

    # Log4Shell
    (
        re.compile(r"\$\{jndi:|ldap://|rmi://", re.IGNORECASE),
        "log4shell",
        "Log4Shell (CVE-2021-44228) exploitation attempt",
        ["T1190"],
    ),
]

# Suspicious HTTP status codes
_SUSPICIOUS_STATUS_CODES = {
    400: "bad_request",
    401: "unauthorized_access",
    403: "forbidden_access",
    500: "server_error",
    502: "bad_gateway",
    503: "service_unavailable",
}


class HttpAccessParser(LogParser):
    """Parser for Apache/Nginx combined and common access log format."""

    log_type: ClassVar[LogType] = LogType.HTTP_ACCESS
    name: ClassVar[str] = "http_access"
    description: ClassVar[str] = "Parses Apache/Nginx combined/common log format"

    def can_parse(self, raw_line: str) -> bool:
        return bool(_COMBINED_PATTERN.match(raw_line))

    def parse(self, raw_line: str) -> ParsedLog | None:
        match = _COMBINED_PATTERN.match(raw_line)
        if not match:
            return None

        groups = match.groupdict()

        timestamp = self._parse_clf_timestamp(groups["timestamp"])
        status = int(groups["status"])
        size_str = groups["size"]
        size = int(size_str) if size_str != "-" else 0
        user = groups["user"] if groups["user"] != "-" else None

        parsed = ParsedLog(
            raw=raw_line,
            log_type=LogType.HTTP_ACCESS,
            timestamp=timestamp,
            source_ip=groups["ip"],
            username=user,
            message=f'{groups["method"]} {groups["path"]} → {status}',
            http_method=groups["method"],
            http_path=groups["path"],
            http_status=status,
            http_user_agent=groups.get("user_agent"),
            parsed_data={
                "ip": groups["ip"],
                "method": groups["method"],
                "path": groups["path"],
                "protocol": groups["protocol"],
                "status": status,
                "size": size,
                "referrer": groups.get("referrer", "-"),
                "user_agent": groups.get("user_agent", "-"),
            },
        )

        # Decode URL for pattern matching
        decoded_path = unquote(groups["path"])
        decoded_ua = unquote(groups.get("user_agent", "") or "")
        combined_text = f"{decoded_path} {decoded_ua}"

        # Run attack pattern detection
        for pattern, tag, _desc, techniques in _ATTACK_PATTERNS:
            if pattern.search(combined_text):
                parsed.is_suspicious = True
                parsed.detection_tags.append(tag)
                if "mitre_techniques" not in parsed.parsed_data:
                    parsed.parsed_data["mitre_techniques"] = []
                parsed.parsed_data["mitre_techniques"].extend(techniques)

        # Flag suspicious status codes (high volume of 401/403)
        if status in _SUSPICIOUS_STATUS_CODES:
            parsed.detection_tags.append(_SUSPICIOUS_STATUS_CODES[status])

        # Large response — potential data exfiltration
        if size > 10_000_000:  # >10 MB
            parsed.is_suspicious = True
            parsed.detection_tags.append("large_response")
            if "mitre_techniques" not in parsed.parsed_data:
                parsed.parsed_data["mitre_techniques"] = []
            parsed.parsed_data["mitre_techniques"].append("T1041")

        # Extract IOCs
        parsed.ioc_values.append(("ip", groups["ip"]))
        if groups.get("user_agent") and groups["user_agent"] != "-":
            # Only add scanner user agents as IOCs
            for pattern, tag, _, _ in _ATTACK_PATTERNS:
                if tag == "scanner_detected" and pattern.search(decoded_ua):
                    parsed.ioc_values.append(("user_agent", groups["user_agent"]))
                    break

        return parsed

    @staticmethod
    def _parse_clf_timestamp(ts_str: str) -> datetime | None:
        """Parse Common Log Format timestamp: 05/Mar/2024:12:34:56 +0000"""
        try:
            return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            try:
                return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                return None
