"""Rule-based detection engine with YAML-defined Sigma-inspired rules.

Each rule specifies matching conditions, severity, MITRE mapping, and
a human-readable description. Rules are evaluated against parsed log data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from threattriage.models.base import Severity
from threattriage.parsers.base import ParsedLog
from threattriage.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DetectionRule:
    """A detection rule definition."""
    id: str
    name: str
    description: str
    severity: Severity
    mitre_technique_ids: list[str] = field(default_factory=list)
    mitre_tactic: str = ""
    tags: list[str] = field(default_factory=list)
    # Conditions
    log_types: list[str] = field(default_factory=list)  # empty = any
    field_conditions: dict[str, Any] = field(default_factory=dict)
    pattern: str = ""
    _compiled: re.Pattern[str] | None = field(default=None, repr=False)

    def compile(self) -> None:
        if self.pattern:
            self._compiled = re.compile(self.pattern, re.IGNORECASE)


@dataclass
class DetectionResult:
    """Result from a detection rule match."""
    rule: DetectionRule
    parsed_log: ParsedLog
    matched_fields: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.8


# ─── Built-in Detection Rules ────────────────────────────────────────────────

BUILTIN_RULES: list[DetectionRule] = [
    DetectionRule(
        id="TT-001",
        name="Brute Force — SSH Failed Logins",
        description="Multiple SSH authentication failures from the same source, indicating a brute force attack.",
        severity=Severity.HIGH,
        mitre_technique_ids=["T1110", "T1110.001"],
        mitre_tactic="Credential Access",
        tags=["brute_force", "ssh", "authentication"],
        log_types=["syslog"],
        pattern=r"Failed password|authentication failure",
    ),
    DetectionRule(
        id="TT-002",
        name="SQL Injection Attempt",
        description="SQL injection attack pattern detected in HTTP request path or parameters.",
        severity=Severity.CRITICAL,
        mitre_technique_ids=["T1190"],
        mitre_tactic="Initial Access",
        tags=["sql_injection", "web_attack"],
        log_types=["http_access"],
        pattern=r"(?:union\s+select|select\s+.*from|drop\s+table|or\s+1\s*=\s*1|;\s*--)",
    ),
    DetectionRule(
        id="TT-003",
        name="Path Traversal / LFI Attempt",
        description="Directory traversal or local file inclusion attempt detected.",
        severity=Severity.HIGH,
        mitre_technique_ids=["T1083"],
        mitre_tactic="Discovery",
        tags=["path_traversal", "lfi", "web_attack"],
        log_types=["http_access"],
        pattern=r"\.\./|\.\.\\|%2e%2e|/etc/passwd|/etc/shadow",
    ),
    DetectionRule(
        id="TT-004",
        name="Web Shell Access",
        description="Potential web shell upload or access detected.",
        severity=Severity.CRITICAL,
        mitre_technique_ids=["T1505.003"],
        mitre_tactic="Persistence",
        tags=["webshell", "persistence"],
        log_types=["http_access"],
        pattern=r"\.(?:php|jsp|asp|aspx)\?(?:cmd|exec|command|shell)=",
    ),
    DetectionRule(
        id="TT-005",
        name="Security Scanner Detected",
        description="Known security scanner or vulnerability assessment tool detected in User-Agent or request patterns.",
        severity=Severity.MEDIUM,
        mitre_technique_ids=["T1595.002"],
        mitre_tactic="Reconnaissance",
        tags=["scanner", "recon"],
        log_types=["http_access"],
        pattern=r"nikto|sqlmap|nmap|dirbuster|gobuster|wfuzz|burp|ZAP|acunetix|nuclei",
    ),
    DetectionRule(
        id="TT-006",
        name="Privilege Escalation — sudo/su Usage",
        description="Privilege escalation via sudo or su detected in system logs.",
        severity=Severity.MEDIUM,
        mitre_technique_ids=["T1548.003"],
        mitre_tactic="Privilege Escalation",
        tags=["privilege_escalation", "sudo"],
        log_types=["syslog"],
        pattern=r"sudo:\s+\S+\s+:.*COMMAND=|su\[\d+\]:\s+",
    ),
    DetectionRule(
        id="TT-007",
        name="Suspicious Command Execution",
        description="Potentially malicious command execution detected (reverse shells, download cradles).",
        severity=Severity.CRITICAL,
        mitre_technique_ids=["T1059", "T1059.004"],
        mitre_tactic="Execution",
        tags=["command_execution", "reverse_shell"],
        log_types=["syslog"],
        pattern=r"(?:curl|wget)\s+.*\|\s*(?:bash|sh)|/dev/tcp/|bash\s+-i|nc\s+-e",
    ),
    DetectionRule(
        id="TT-008",
        name="Database Bulk Data Exfiltration",
        description="Bulk data access to sensitive database tables detected.",
        severity=Severity.HIGH,
        mitre_technique_ids=["T1530", "T1005"],
        mitre_tactic="Collection",
        tags=["data_exfiltration", "database"],
        log_types=["db_audit"],
        pattern=r"SELECT\s+\*\s+FROM\s+.*(?:users?|credentials?|passwords?|accounts?|customers?)",
    ),
    DetectionRule(
        id="TT-009",
        name="Destructive Database Operation",
        description="Destructive DDL operation (DROP/TRUNCATE) detected.",
        severity=Severity.CRITICAL,
        mitre_technique_ids=["T1485", "T1561"],
        mitre_tactic="Impact",
        tags=["destructive", "ddl", "database"],
        log_types=["db_audit"],
        pattern=r"(?:DROP|TRUNCATE)\s+(?:TABLE|DATABASE|SCHEMA)",
    ),
    DetectionRule(
        id="TT-010",
        name="Unauthorized Account Creation",
        description="New user account created in system or database.",
        severity=Severity.HIGH,
        mitre_technique_ids=["T1136", "T1136.001"],
        mitre_tactic="Persistence",
        tags=["account_creation", "persistence"],
        log_types=["syslog", "db_audit"],
        pattern=r"(?:useradd|adduser|CREATE\s+USER|INSERT\s+INTO\s+.*users)",
    ),
    DetectionRule(
        id="TT-011",
        name="Log4Shell Exploitation Attempt",
        description="Log4Shell (CVE-2021-44228) exploitation attempt via JNDI injection.",
        severity=Severity.CRITICAL,
        mitre_technique_ids=["T1190", "T1059"],
        mitre_tactic="Initial Access",
        tags=["log4shell", "cve-2021-44228", "jndi"],
        log_types=["http_access"],
        pattern=r"\$\{jndi:|ldap://|rmi://",
    ),
    DetectionRule(
        id="TT-012",
        name="Cron-based Persistence",
        description="Crontab modification detected, potential persistence mechanism.",
        severity=Severity.MEDIUM,
        mitre_technique_ids=["T1053.003"],
        mitre_tactic="Persistence",
        tags=["persistence", "cron", "scheduled_task"],
        log_types=["syslog"],
        pattern=r"crontab.*(?:REPLACE|EDIT)|cron\.\w+.*\(root\)",
    ),
    DetectionRule(
        id="TT-013",
        name="SSH Tunneling / Port Forwarding",
        description="SSH tunneling or port forwarding activity detected.",
        severity=Severity.MEDIUM,
        mitre_technique_ids=["T1572"],
        mitre_tactic="Command and Control",
        tags=["ssh_tunnel", "port_forward", "c2"],
        log_types=["syslog"],
        pattern=r"ssh.*(?:reverse|tunnel|port.?forward|-[LRD]\s)",
    ),
    DetectionRule(
        id="TT-014",
        name="XSS Attempt",
        description="Cross-Site Scripting (XSS) attempt detected in HTTP request.",
        severity=Severity.HIGH,
        mitre_technique_ids=["T1189", "T1059.007"],
        mitre_tactic="Initial Access",
        tags=["xss", "web_attack"],
        log_types=["http_access"],
        pattern=r"<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(",
    ),
    DetectionRule(
        id="TT-015",
        name="Sensitive Admin Path Probe",
        description="Attempts to access known sensitive administrative paths.",
        severity=Severity.LOW,
        mitre_technique_ids=["T1083"],
        mitre_tactic="Discovery",
        tags=["recon", "admin_probe"],
        log_types=["http_access"],
        pattern=r"/(?:admin|wp-admin|phpmyadmin|\.env|\.git/|config\.php|backup)",
    ),
]


class DetectionEngine:
    """Evaluates parsed logs against detection rules."""

    def __init__(self, extra_rules: list[DetectionRule] | None = None) -> None:
        self.rules = list(BUILTIN_RULES)
        if extra_rules:
            self.rules.extend(extra_rules)
        # Compile all regex patterns
        for rule in self.rules:
            rule.compile()
        logger.info("detection_engine_initialized", rule_count=len(self.rules))

    def evaluate(self, parsed: ParsedLog) -> list[DetectionResult]:
        """Evaluate a single parsed log against all rules. Returns list of matches."""
        results = []
        for rule in self.rules:
            if self._matches(rule, parsed):
                results.append(DetectionResult(
                    rule=rule,
                    parsed_log=parsed,
                    matched_fields=self._extract_match_context(rule, parsed),
                ))
        return results

    def evaluate_batch(self, logs: list[ParsedLog]) -> list[DetectionResult]:
        """Evaluate a batch of parsed logs. Returns all matches."""
        all_results = []
        for parsed in logs:
            all_results.extend(self.evaluate(parsed))
        return all_results

    def _matches(self, rule: DetectionRule, parsed: ParsedLog) -> bool:
        """Check if a parsed log matches a rule's conditions."""
        # Check log type filter
        if rule.log_types and parsed.log_type.value not in rule.log_types:
            return False

        # Check regex pattern
        if rule._compiled:
            text_to_check = self._get_searchable_text(parsed)
            if not rule._compiled.search(text_to_check):
                return False

        # Check field conditions
        for field_name, expected in rule.field_conditions.items():
            actual = getattr(parsed, field_name, None)
            if actual is None:
                return False
            if isinstance(expected, str) and actual != expected:
                return False
            if isinstance(expected, list) and actual not in expected:
                return False

        return True

    @staticmethod
    def _get_searchable_text(parsed: ParsedLog) -> str:
        """Combine relevant fields into searchable text (URL-decoded)."""
        parts = [
            parsed.raw,
            parsed.message or "",
            parsed.http_path or "",
            parsed.http_user_agent or "",
            parsed.db_query or "",
        ]
        combined = " ".join(p for p in parts if p)
        # URL-decode so encoded attack payloads (%20UNION%20SELECT) are matched
        return unquote(combined)

    @staticmethod
    def _extract_match_context(rule: DetectionRule, parsed: ParsedLog) -> dict[str, Any]:
        """Extract context about what matched."""
        ctx: dict[str, Any] = {}
        if parsed.source_ip:
            ctx["source_ip"] = parsed.source_ip
        if parsed.hostname:
            ctx["hostname"] = parsed.hostname
        if parsed.username:
            ctx["username"] = parsed.username
        if parsed.http_path:
            ctx["http_path"] = parsed.http_path
        if parsed.http_user_agent:
            ctx["user_agent"] = parsed.http_user_agent
        if parsed.db_query:
            ctx["query"] = parsed.db_query[:200]
        return ctx
