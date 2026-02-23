"""Tests for log parsers — syslog, HTTP, and DB audit."""

from __future__ import annotations

import pytest

from threattriage.models.base import LogType
from threattriage.parsers.base import create_registry
from threattriage.parsers.syslog import SyslogParser
from threattriage.parsers.http_access import HttpAccessParser
from threattriage.parsers.db_audit import DbAuditParser


class TestSyslogParser:
    """Test suite for the syslog parser."""

    def setup_method(self):
        self.parser = SyslogParser()

    def test_can_parse_rfc3164(self, syslog_failed_ssh):
        assert self.parser.can_parse(syslog_failed_ssh) is True

    def test_can_parse_rejects_http(self, http_normal):
        assert self.parser.can_parse(http_normal) is False

    def test_parse_failed_ssh(self, syslog_failed_ssh):
        result = self.parser.parse(syslog_failed_ssh)
        assert result is not None
        assert result.log_type == LogType.SYSLOG
        assert result.hostname == "webserver01"
        assert result.process_name == "sshd"
        assert result.pid == 12345
        assert result.source_ip == "185.220.101.1"
        assert result.is_suspicious is True
        assert "brute_force_attempt" in result.detection_tags

    def test_parse_sudo_command(self, syslog_sudo):
        result = self.parser.parse(syslog_sudo)
        assert result is not None
        assert result.is_suspicious is True
        assert "privilege_escalation" in result.detection_tags or "suspicious_command_execution" in result.detection_tags

    def test_parse_extracts_iocs(self, syslog_failed_ssh):
        result = self.parser.parse(syslog_failed_ssh)
        assert result is not None
        ioc_types = [t for t, v in result.ioc_values]
        assert "ip" in ioc_types

    def test_mitre_techniques_tagged(self, syslog_failed_ssh):
        result = self.parser.parse(syslog_failed_ssh)
        assert result is not None
        assert "mitre_techniques" in result.parsed_data
        assert "T1110" in result.parsed_data["mitre_techniques"]


class TestHttpAccessParser:
    """Test suite for the HTTP access log parser."""

    def setup_method(self):
        self.parser = HttpAccessParser()

    def test_can_parse_combined(self, http_sqli):
        assert self.parser.can_parse(http_sqli) is True

    def test_can_parse_rejects_syslog(self, syslog_failed_ssh):
        assert self.parser.can_parse(syslog_failed_ssh) is False

    def test_parse_sqli(self, http_sqli):
        result = self.parser.parse(http_sqli)
        assert result is not None
        assert result.log_type == LogType.HTTP_ACCESS
        assert result.source_ip == "45.33.32.156"
        assert result.http_method == "GET"
        assert result.http_status == 200
        assert result.is_suspicious is True
        assert "sql_injection" in result.detection_tags

    def test_parse_path_traversal(self, http_path_traversal):
        result = self.parser.parse(http_path_traversal)
        assert result is not None
        assert result.is_suspicious is True
        assert "path_traversal" in result.detection_tags

    def test_parse_normal_traffic(self, http_normal):
        result = self.parser.parse(http_normal)
        assert result is not None
        assert result.http_status == 200
        # Normal traffic should not trigger SQLi/XSS/traversal
        critical_tags = {"sql_injection", "xss_attempt", "path_traversal", "command_injection"}
        assert not (set(result.detection_tags) & critical_tags)

    def test_scanner_detection(self, http_sqli):
        result = self.parser.parse(http_sqli)
        assert result is not None
        assert "scanner_detected" in result.detection_tags


class TestDbAuditParser:
    """Test suite for database audit log parser."""

    def setup_method(self):
        self.parser = DbAuditParser()

    def test_can_parse_postgres(self, db_bulk_select):
        assert self.parser.can_parse(db_bulk_select) is True

    def test_parse_bulk_select(self, db_bulk_select):
        result = self.parser.parse(db_bulk_select)
        assert result is not None
        assert result.log_type == LogType.DB_AUDIT
        assert result.username == "appuser"
        assert result.db_database == "production"
        assert result.is_suspicious is True
        assert "bulk_data_access" in result.detection_tags

    def test_parse_drop_table(self, db_drop_table):
        result = self.parser.parse(db_drop_table)
        assert result is not None
        assert result.is_suspicious is True
        assert "destructive_ddl" in result.detection_tags

    def test_mitre_mapped_for_drop(self, db_drop_table):
        result = self.parser.parse(db_drop_table)
        assert result is not None
        assert "mitre_techniques" in result.parsed_data
        assert "T1485" in result.parsed_data["mitre_techniques"]


class TestParserRegistry:
    """Test the parser registry and auto-detection."""

    def test_auto_detect_syslog(self, syslog_failed_ssh):
        registry = create_registry()
        result = registry.detect_and_parse(syslog_failed_ssh)
        assert result is not None
        assert result.log_type == LogType.SYSLOG

    def test_auto_detect_http(self, http_sqli):
        registry = create_registry()
        result = registry.detect_and_parse(http_sqli)
        assert result is not None
        assert result.log_type == LogType.HTTP_ACCESS

    def test_auto_detect_db(self, db_bulk_select):
        registry = create_registry()
        result = registry.detect_and_parse(db_bulk_select)
        assert result is not None
        assert result.log_type == LogType.DB_AUDIT

    def test_batch_parse(self, syslog_failed_ssh, http_sqli, db_bulk_select):
        registry = create_registry()
        lines = [syslog_failed_ssh, http_sqli, db_bulk_select]
        results = registry.parse_batch(lines)
        assert len(results) == 3

    def test_registered_parsers(self):
        registry = create_registry()
        assert "syslog" in registry.registered_parsers
        assert "http_access" in registry.registered_parsers
        assert "db_audit" in registry.registered_parsers
