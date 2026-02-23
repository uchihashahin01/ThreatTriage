"""Tests for analysis engines — detection, anomaly, correlation, scoring, MITRE."""

from __future__ import annotations

import pytest

from threattriage.models.base import LogType, Severity
from threattriage.parsers.base import ParsedLog, create_registry
from threattriage.analysis.detection import DetectionEngine
from threattriage.analysis.anomaly import AnomalyDetector
from threattriage.analysis.correlator import AlertCorrelator
from threattriage.analysis.mitre_mapper import MitreMapper
from threattriage.analysis.scorer import SeverityScorer


class TestDetectionEngine:
    """Test the rule-based detection engine."""

    def test_detects_sql_injection(self, detection_engine, http_sqli):
        registry = create_registry()
        parsed = registry.detect_and_parse(http_sqli)
        assert parsed is not None
        results = detection_engine.evaluate(parsed)
        rule_names = [r.rule.name for r in results]
        assert any("SQL Injection" in name for name in rule_names)

    def test_detects_brute_force(self, detection_engine, syslog_failed_ssh):
        registry = create_registry()
        parsed = registry.detect_and_parse(syslog_failed_ssh)
        assert parsed is not None
        results = detection_engine.evaluate(parsed)
        assert len(results) > 0
        rule_ids = [r.rule.id for r in results]
        assert "TT-001" in rule_ids

    def test_detects_destructive_db(self, detection_engine, db_drop_table):
        registry = create_registry()
        parsed = registry.detect_and_parse(db_drop_table)
        assert parsed is not None
        results = detection_engine.evaluate(parsed)
        rule_ids = [r.rule.id for r in results]
        assert "TT-009" in rule_ids

    def test_normal_traffic_no_alerts(self, detection_engine, http_normal):
        registry = create_registry()
        parsed = registry.detect_and_parse(http_normal)
        assert parsed is not None
        results = detection_engine.evaluate(parsed)
        # Should not trigger critical attack rules
        critical_rules = {"TT-002", "TT-004", "TT-007", "TT-009", "TT-011"}
        detected_ids = {r.rule.id for r in results}
        assert not (detected_ids & critical_rules)


class TestAnomalyDetector:
    """Test statistical anomaly detection."""

    def test_detects_volume_spike(self, anomaly_detector):
        """One IP with many more requests than others should trigger volume spike."""
        from datetime import datetime

        logs = []
        # Normal IPs: 5 requests each
        for i in range(5):
            for _ in range(5):
                logs.append(ParsedLog(
                    raw="test", log_type=LogType.HTTP_ACCESS,
                    source_ip=f"10.0.0.{i}",
                    timestamp=datetime(2024, 3, 5, 12, 0, 0),
                ))
        # Anomalous IP: 100 requests
        for _ in range(100):
            logs.append(ParsedLog(
                raw="test", log_type=LogType.HTTP_ACCESS,
                source_ip="evil.ip.1.1",
                timestamp=datetime(2024, 3, 5, 12, 0, 0),
            ))

        anomalies = anomaly_detector.detect_anomalies(logs)
        volume_spikes = [a for a in anomalies if a.anomaly_type == "volume_spike"]
        assert len(volume_spikes) > 0
        assert volume_spikes[0].source_ip == "evil.ip.1.1"


class TestAlertCorrelator:
    """Test alert correlation."""

    def test_groups_by_source_ip(self, correlator, detection_engine):
        registry = create_registry()

        lines = [
            'Mar  5 08:23:41 host sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2',
            'Mar  5 08:23:42 host sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2',
        ]

        parsed = registry.parse_batch(lines)
        detections = detection_engine.evaluate_batch(parsed)
        incidents = correlator.correlate(detections, [])

        assert len(incidents) >= 1
        assert "1.2.3.4" in incidents[0].source_ips


class TestMitreMapper:
    """Test MITRE ATT&CK mapping."""

    def test_maps_known_technique(self, mitre_mapper):
        mapping = mitre_mapper.map_technique("T1110")
        assert mapping is not None
        assert mapping.technique_name == "Brute Force"
        assert mapping.tactic == "Credential Access"

    def test_returns_none_for_unknown(self, mitre_mapper):
        mapping = mitre_mapper.map_technique("T9999")
        assert mapping is None

    def test_generates_navigator_layer(self, mitre_mapper):
        layer = mitre_mapper.generate_navigator_layer({"T1110": 5, "T1190": 3})
        assert layer["domain"] == "enterprise-attack"
        assert len(layer["techniques"]) == 2

    def test_recommendations(self, mitre_mapper):
        recs = mitre_mapper.get_recommendations(["T1110", "T1110.001"])
        assert len(recs) > 0
        assert any(r["mitigation"] == "Multi-factor Authentication" for r in recs)


class TestSeverityScorer:
    """Test multi-factor severity scoring."""

    def test_high_ti_increases_score(self, scorer, detection_engine, syslog_failed_ssh):
        registry = create_registry()
        parsed = registry.detect_and_parse(syslog_failed_ssh)
        assert parsed is not None
        detections = detection_engine.evaluate(parsed)
        assert len(detections) > 0

        score_no_ti = scorer.score_detection(detections[0], ti_score=0)
        score_high_ti = scorer.score_detection(detections[0], ti_score=90)
        assert score_high_ti.score > score_no_ti.score

    def test_repeat_offender_increases_score(self, scorer, detection_engine, syslog_failed_ssh):
        registry = create_registry()
        parsed = registry.detect_and_parse(syslog_failed_ssh)
        assert parsed is not None
        detections = detection_engine.evaluate(parsed)
        assert len(detections) > 0

        score_normal = scorer.score_detection(detections[0])
        score_repeat = scorer.score_detection(detections[0], is_repeat_offender=True)
        assert score_repeat.score > score_normal.score
