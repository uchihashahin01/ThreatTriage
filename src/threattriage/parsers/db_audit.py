"""Database audit log parser — MySQL/PostgreSQL audit log formats.

Detects: mass data exfiltration, DDL changes, privilege grants, unusual queries.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import ClassVar

from threattriage.models.base import LogType
from threattriage.parsers.base import LogParser, ParsedLog

# ─── Generic DB Audit Pattern ─────────────────────────────────────────────────
# Format: 2024-03-05T12:34:56.789Z [user@host] [database] QUERY: SELECT * FROM users
_GENERIC_DB_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?:\[?(?P<user>\S+?)(?:@(?P<host>\S+?))?\]?\s+)?"
    r"(?:\[?(?P<database>\S+?)\]?\s+)?"
    r"(?:(?P<action>QUERY|CONNECT|DISCONNECT|CREATE|ALTER|DROP|GRANT|REVOKE|INSERT|UPDATE|DELETE|SELECT):?\s+)?"
    r"(?P<query>.+)$"
)

# MySQL general_log style: 240305 12:34:56	   12 Query	SELECT * FROM users
_MYSQL_PATTERN = re.compile(
    r"^(?P<timestamp>\d{6}\s+\d{1,2}:\d{2}:\d{2})\s+"
    r"(?P<thread_id>\d+)\s+"
    r"(?P<command>\S+)\s+"
    r"(?P<query>.*)$"
)

# PostgreSQL log style: 2024-03-05 12:34:56 UTC [1234] user@db LOG:  statement: SELECT ...
_POSTGRES_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\S+)\s+"
    r"\[(?P<pid>\d+)\]\s+"
    r"(?P<user>\S+?)@(?P<database>\S+?)\s+"
    r"(?P<level>\S+):\s+"
    r"(?:statement|query):\s+"
    r"(?P<query>.+)$",
    re.IGNORECASE,
)

# ─── Suspicious Query Detection ───────────────────────────────────────────────
_SUSPICIOUS_QUERIES: list[tuple[re.Pattern[str], str, str, list[str]]] = [
    # Data Exfiltration
    (
        re.compile(r"SELECT\s+\*\s+FROM\s+.*(?:users?|credentials?|passwords?|accounts?|customers?)", re.IGNORECASE),
        "bulk_data_access",
        "Bulk access to sensitive tables (users/credentials)",
        ["T1530", "T1005"],
    ),

    # DDL Changes
    (
        re.compile(r"(?:DROP|TRUNCATE)\s+(?:TABLE|DATABASE|SCHEMA)", re.IGNORECASE),
        "destructive_ddl",
        "Destructive DDL operation (DROP/TRUNCATE)",
        ["T1485", "T1561"],
    ),

    # Privilege Escalation
    (
        re.compile(r"GRANT\s+(?:ALL|SUPER|DBA|ADMIN)", re.IGNORECASE),
        "privilege_grant",
        "Suspicious privilege grant operation",
        ["T1078", "T1548"],
    ),

    # Creating backdoor users
    (
        re.compile(r"(?:CREATE|INSERT\s+INTO)\s+.*(?:users?|accounts?|admins?)", re.IGNORECASE),
        "account_manipulation",
        "Database account creation/manipulation",
        ["T1136"],
    ),

    # Sensitive data export
    (
        re.compile(r"(?:INTO\s+OUTFILE|INTO\s+DUMPFILE|COPY\s+.*\s+TO\s+')", re.IGNORECASE),
        "data_export",
        "Data export to file detected",
        ["T1048"],
    ),

    # Information Schema Enumeration
    (
        re.compile(r"(?:information_schema|pg_catalog|sys\.tables|sysobjects|all_tables)", re.IGNORECASE),
        "schema_enumeration",
        "Database schema enumeration detected",
        ["T1083"],
    ),

    # Stack-based SQL injection in logs
    (
        re.compile(r"(?:UNION\s+SELECT|SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY|xp_cmdshell)", re.IGNORECASE),
        "sql_injection_in_db",
        "SQL injection attempt reached the database layer",
        ["T1190"],
    ),

    # Mass UPDATE/DELETE without WHERE
    (
        re.compile(r"(?:UPDATE|DELETE\s+FROM)\s+\S+\s*(?:;|$)", re.IGNORECASE),
        "unrestricted_modification",
        "UPDATE/DELETE without WHERE clause",
        ["T1485"],
    ),
]


class DbAuditParser(LogParser):
    """Parser for database audit logs (MySQL, PostgreSQL, generic)."""

    log_type: ClassVar[LogType] = LogType.DB_AUDIT
    name: ClassVar[str] = "db_audit"
    description: ClassVar[str] = "Parses MySQL/PostgreSQL audit log formats"

    def can_parse(self, raw_line: str) -> bool:
        return bool(
            _POSTGRES_PATTERN.match(raw_line)
            or _MYSQL_PATTERN.match(raw_line)
            or _GENERIC_DB_PATTERN.match(raw_line)
        )

    def parse(self, raw_line: str) -> ParsedLog | None:
        result = self._try_postgres(raw_line)
        if result:
            return result
        result = self._try_mysql(raw_line)
        if result:
            return result
        return self._try_generic(raw_line)

    def _try_postgres(self, raw_line: str) -> ParsedLog | None:
        match = _POSTGRES_PATTERN.match(raw_line)
        if not match:
            return None

        groups = match.groupdict()
        timestamp = self._parse_timestamp(groups["timestamp"])

        parsed = ParsedLog(
            raw=raw_line,
            log_type=LogType.DB_AUDIT,
            timestamp=timestamp,
            username=groups["user"],
            pid=int(groups["pid"]) if groups.get("pid") else None,
            message=groups["query"],
            db_query=groups["query"],
            db_database=groups["database"],
            parsed_data={
                "format": "postgresql",
                "level": groups["level"],
                **{k: v for k, v in groups.items() if v is not None},
            },
        )
        self._detect_suspicious(parsed, groups["query"])
        return parsed

    def _try_mysql(self, raw_line: str) -> ParsedLog | None:
        match = _MYSQL_PATTERN.match(raw_line)
        if not match:
            return None

        groups = match.groupdict()
        timestamp = self._parse_mysql_timestamp(groups["timestamp"])

        parsed = ParsedLog(
            raw=raw_line,
            log_type=LogType.DB_AUDIT,
            timestamp=timestamp,
            message=groups["query"],
            db_query=groups["query"],
            parsed_data={
                "format": "mysql",
                "thread_id": int(groups["thread_id"]),
                "command": groups["command"],
            },
        )
        self._detect_suspicious(parsed, groups["query"])
        return parsed

    def _try_generic(self, raw_line: str) -> ParsedLog | None:
        match = _GENERIC_DB_PATTERN.match(raw_line)
        if not match:
            return None

        groups = match.groupdict()
        timestamp = self._parse_timestamp(groups["timestamp"])

        parsed = ParsedLog(
            raw=raw_line,
            log_type=LogType.DB_AUDIT,
            timestamp=timestamp,
            username=groups.get("user"),
            hostname=groups.get("host"),
            message=groups["query"],
            db_query=groups["query"],
            db_database=groups.get("database"),
            parsed_data={
                "format": "generic",
                "action": groups.get("action"),
                **{k: v for k, v in groups.items() if v is not None},
            },
        )
        self._detect_suspicious(parsed, groups["query"])
        return parsed

    def _detect_suspicious(self, parsed: ParsedLog, query: str) -> None:
        """Check query against suspicious patterns."""
        for pattern, tag, _desc, techniques in _SUSPICIOUS_QUERIES:
            if pattern.search(query):
                parsed.is_suspicious = True
                parsed.detection_tags.append(tag)
                if "mitre_techniques" not in parsed.parsed_data:
                    parsed.parsed_data["mitre_techniques"] = []
                parsed.parsed_data["mitre_techniques"].extend(techniques)

    @staticmethod
    def _parse_timestamp(ts_str: str) -> datetime | None:
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S.%f %Z",
            "%Y-%m-%d %H:%M:%S %Z",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                return datetime.strptime(ts_str.strip(), fmt)
            except ValueError:
                continue
        return None

    @staticmethod
    def _parse_mysql_timestamp(ts_str: str) -> datetime | None:
        try:
            return datetime.strptime(ts_str.strip(), "%y%m%d %H:%M:%S")
        except ValueError:
            return None
