"""Alert correlation engine — groups related alerts into incidents."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from threattriage.analysis.detection import DetectionResult
from threattriage.analysis.anomaly import AnomalyResult
from threattriage.models.base import Severity, IncidentStatus
from threattriage.logging import get_logger

logger = get_logger(__name__)


@dataclass
class CorrelatedIncident:
    """A group of correlated alerts forming an incident."""
    id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    summary: str = ""
    severity: Severity = Severity.MEDIUM
    status: IncidentStatus = IncidentStatus.OPEN

    # Grouped data
    detection_results: list[DetectionResult] = field(default_factory=list)
    anomaly_results: list[AnomalyResult] = field(default_factory=list)

    # Scope
    source_ips: set[str] = field(default_factory=set)
    hostnames: set[str] = field(default_factory=set)
    usernames: set[str] = field(default_factory=set)
    mitre_techniques: set[str] = field(default_factory=set)
    mitre_tactics: set[str] = field(default_factory=set)

    # Timing
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    # IOCs
    ioc_values: list[tuple[str, str]] = field(default_factory=list)

    @property
    def alert_count(self) -> int:
        return len(self.detection_results) + len(self.anomaly_results)


class AlertCorrelator:
    """
    Correlates alerts by source IP, time window, and attack pattern.

    Correlation strategy:
    1. Group by source IP within a time window
    2. Escalate severity when multiple rule types fire for the same IP
    3. Build attack narrative from MITRE tactics
    """

    CORRELATION_WINDOW = timedelta(minutes=30)

    def correlate(
        self,
        detections: list[DetectionResult],
        anomalies: list[AnomalyResult],
    ) -> list[CorrelatedIncident]:
        """Correlate detections and anomalies into incidents."""

        # Group detections by source IP
        ip_detections: defaultdict[str, list[DetectionResult]] = defaultdict(list)
        no_ip_detections: list[DetectionResult] = []

        for det in detections:
            ip = det.parsed_log.source_ip
            if ip:
                ip_detections[ip].append(det)
            else:
                no_ip_detections.append(det)

        # Group anomalies by source IP
        ip_anomalies: defaultdict[str, list[AnomalyResult]] = defaultdict(list)
        no_ip_anomalies: list[AnomalyResult] = []

        for anom in anomalies:
            if anom.source_ip:
                ip_anomalies[anom.source_ip].append(anom)
            else:
                no_ip_anomalies.append(anom)

        # Create incidents per source IP
        incidents: list[CorrelatedIncident] = []

        all_ips = set(ip_detections.keys()) | set(ip_anomalies.keys())
        for ip in all_ips:
            dets = ip_detections.get(ip, [])
            anoms = ip_anomalies.get(ip, [])

            incident = self._build_incident(ip, dets, anoms)
            incidents.append(incident)

        # Handle detections/anomalies without IPs
        if no_ip_detections or no_ip_anomalies:
            incident = self._build_incident(None, no_ip_detections, no_ip_anomalies)
            if incident.alert_count > 0:
                incidents.append(incident)

        # Sort by severity (critical first)
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        incidents.sort(key=lambda i: severity_order.get(i.severity, 5))

        logger.info(
            "correlation_complete",
            detections=len(detections),
            anomalies=len(anomalies),
            incidents=len(incidents),
        )

        return incidents

    def _build_incident(
        self,
        source_ip: str | None,
        detections: list[DetectionResult],
        anomalies: list[AnomalyResult],
    ) -> CorrelatedIncident:
        """Build an incident from grouped detections and anomalies."""
        incident = CorrelatedIncident(
            detection_results=detections,
            anomaly_results=anomalies,
        )

        if source_ip:
            incident.source_ips.add(source_ip)

        # Gather MITRE data and scope
        for det in detections:
            incident.mitre_techniques.update(det.rule.mitre_technique_ids)
            if det.rule.mitre_tactic:
                incident.mitre_tactics.add(det.rule.mitre_tactic)
            if det.parsed_log.hostname:
                incident.hostnames.add(det.parsed_log.hostname)
            if det.parsed_log.username:
                incident.usernames.add(det.parsed_log.username)
            if det.parsed_log.source_ip:
                incident.source_ips.add(det.parsed_log.source_ip)
            incident.ioc_values.extend(det.parsed_log.ioc_values)

            if det.parsed_log.timestamp:
                if not incident.first_seen or det.parsed_log.timestamp < incident.first_seen:
                    incident.first_seen = det.parsed_log.timestamp
                if not incident.last_seen or det.parsed_log.timestamp > incident.last_seen:
                    incident.last_seen = det.parsed_log.timestamp

        for anom in anomalies:
            incident.mitre_techniques.update(anom.mitre_technique_ids)
            if anom.mitre_tactic:
                incident.mitre_tactics.add(anom.mitre_tactic)

        # Determine severity (highest among all alerts)
        all_severities = [det.rule.severity for det in detections] + [anom.severity for anom in anomalies]
        if all_severities:
            incident.severity = self._max_severity(all_severities)

        # Escalate if multiple attack types from same IP
        unique_tactics = incident.mitre_tactics
        if len(unique_tactics) >= 3 and incident.severity != Severity.CRITICAL:
            incident.severity = Severity.CRITICAL

        # Generate title and summary
        incident.title = self._generate_title(incident, source_ip)
        incident.summary = self._generate_summary(incident)

        return incident

    def _generate_title(self, incident: CorrelatedIncident, source_ip: str | None) -> str:
        tactics = sorted(incident.mitre_tactics)
        if len(tactics) >= 2:
            title = f"Multi-Stage Attack: {' → '.join(tactics[:3])}"
        elif tactics:
            title = f"{tactics[0]} Activity Detected"
        elif incident.detection_results:
            title = incident.detection_results[0].rule.name
        else:
            title = "Anomalous Activity Detected"

        if source_ip:
            title += f" from {source_ip}"
        return title

    def _generate_summary(self, incident: CorrelatedIncident) -> str:
        parts = []
        parts.append(f"**{incident.alert_count} alerts** correlated into this incident.")

        if incident.source_ips:
            parts.append(f"Source IPs: {', '.join(sorted(incident.source_ips)[:5])}")
        if incident.mitre_techniques:
            parts.append(f"MITRE Techniques: {', '.join(sorted(incident.mitre_techniques)[:8])}")
        if incident.mitre_tactics:
            parts.append(f"Tactics: {' → '.join(sorted(incident.mitre_tactics))}")

        for det in incident.detection_results[:3]:
            parts.append(f"- [{det.rule.severity.value.upper()}] {det.rule.name}")
        for anom in incident.anomaly_results[:3]:
            parts.append(f"- [{anom.severity.value.upper()}] {anom.description[:80]}")

        return "\n".join(parts)

    @staticmethod
    def _max_severity(severities: list[Severity]) -> Severity:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for sev in order:
            if sev in severities:
                return sev
        return Severity.INFO
