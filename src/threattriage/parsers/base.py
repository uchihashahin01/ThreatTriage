"""Abstract base parser and auto-discovery parser registry."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

from threattriage.models.base import LogType


@dataclass
class ParsedLog:
    """Standardized output from any parser."""

    raw: str
    log_type: LogType
    timestamp: datetime | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    hostname: str | None = None
    username: str | None = None
    process_name: str | None = None
    pid: int | None = None
    message: str | None = None

    # HTTP-specific
    http_method: str | None = None
    http_path: str | None = None
    http_status: int | None = None
    http_user_agent: str | None = None

    # DB-specific
    db_query: str | None = None
    db_database: str | None = None

    # Full parsed data
    parsed_data: dict[str, Any] = field(default_factory=dict)

    # Detection
    is_suspicious: bool = False
    detection_tags: list[str] = field(default_factory=list)
    ioc_values: list[tuple[str, str]] = field(default_factory=list)  # (type, value)


class LogParser(abc.ABC):
    """Abstract base class for all log parsers."""

    # Subclasses set this
    log_type: ClassVar[LogType]
    name: ClassVar[str]
    description: ClassVar[str] = ""

    @abc.abstractmethod
    def parse(self, raw_line: str) -> ParsedLog | None:
        """Parse a raw log line. Return None if unparseable."""

    @abc.abstractmethod
    def can_parse(self, raw_line: str) -> bool:
        """Check if this parser can handle the given raw line."""


class ParserRegistry:
    """
    Auto-discovery registry for log parsers.

    Usage:
        registry = ParserRegistry()
        registry.register(SyslogParser())
        registry.register(HttpAccessParser())

        parsed = registry.parse("Mar  5 12:34:56 host sshd[1234]: ...")
    """

    def __init__(self) -> None:
        self._parsers: list[LogParser] = []

    def register(self, parser: LogParser) -> None:
        """Register a parser instance."""
        self._parsers.append(parser)

    def detect_and_parse(self, raw_line: str) -> ParsedLog | None:
        """Auto-detect log format and parse with the matching parser."""
        for parser in self._parsers:
            if parser.can_parse(raw_line):
                return parser.parse(raw_line)
        return None

    def parse_with_type(self, raw_line: str, log_type: LogType) -> ParsedLog | None:
        """Parse using a specific parser type."""
        for parser in self._parsers:
            if parser.log_type == log_type:
                return parser.parse(raw_line)
        return None

    def parse_batch(
        self, lines: list[str], log_type: LogType | None = None
    ) -> list[ParsedLog]:
        """Parse a batch of lines, optionally forcing a log type."""
        results = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if log_type:
                parsed = self.parse_with_type(stripped, log_type)
            else:
                parsed = self.detect_and_parse(stripped)
            if parsed:
                results.append(parsed)
        return results

    @property
    def registered_parsers(self) -> list[str]:
        return [p.name for p in self._parsers]


def create_registry() -> ParserRegistry:
    """Create a parser registry with all built-in parsers registered."""
    from threattriage.parsers.db_audit import DbAuditParser
    from threattriage.parsers.http_access import HttpAccessParser
    from threattriage.parsers.syslog import SyslogParser
    from threattriage.parsers.windows_event import WindowsEventParser
    from threattriage.parsers.json_structured import JsonStructuredParser
    from threattriage.parsers.firewall import FirewallParser
    from threattriage.parsers.ids import IDSAlertParser

    registry = ParserRegistry()
    registry.register(SyslogParser())
    registry.register(HttpAccessParser())
    registry.register(DbAuditParser())
    registry.register(WindowsEventParser())
    registry.register(JsonStructuredParser())
    registry.register(FirewallParser())
    registry.register(IDSAlertParser())
    return registry
