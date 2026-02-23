"""Incident response report generator.

Builds structured reports in JSON and HTML formats containing:
- Executive summary
- Alert breakdown with MITRE ATT&CK mapping
- IOC table with TI enrichment
- Timeline
- Remediation recommendations
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from threattriage.analysis.correlator import CorrelatedIncident
from threattriage.analysis.mitre_mapper import MitreMapper
from threattriage.logging import get_logger

logger = get_logger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    """Generates incident response reports."""

    def __init__(self) -> None:
        self.mitre_mapper = MitreMapper()
        self._jinja_env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )

    def generate_json_report(self, incident: CorrelatedIncident) -> dict[str, Any]:
        """Generate a structured JSON report."""
        technique_ids = list(incident.mitre_techniques)
        mitre_mappings = self.mitre_mapper.map_techniques(technique_ids)

        # Build technique count map
        technique_counts: Counter[str] = Counter()
        for det in incident.detection_results:
            for tid in det.rule.mitre_technique_ids:
                technique_counts[tid] += 1

        recommendations = self.mitre_mapper.get_recommendations(technique_ids)
        navigator_layer = self.mitre_mapper.generate_navigator_layer(
            dict(technique_counts),
            name=f"Incident: {incident.title}",
        )

        # Build timeline
        timeline = []
        for det in sorted(
            incident.detection_results,
            key=lambda d: d.parsed_log.timestamp or datetime.min,
        ):
            timeline.append({
                "timestamp": det.parsed_log.timestamp.isoformat() if det.parsed_log.timestamp else "unknown",
                "event": det.rule.name,
                "severity": det.rule.severity.value,
                "source_ip": det.parsed_log.source_ip,
                "details": det.matched_fields,
            })

        for anom in incident.anomaly_results:
            timeline.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": anom.anomaly_type,
                "severity": anom.severity.value,
                "source_ip": anom.source_ip,
                "details": anom.details,
            })

        # Collect IOCs
        iocs = []
        seen_iocs: set[str] = set()
        for det in incident.detection_results:
            for ioc_type, ioc_value in det.parsed_log.ioc_values:
                key = f"{ioc_type}:{ioc_value}"
                if key not in seen_iocs:
                    seen_iocs.add(key)
                    iocs.append({"type": ioc_type, "value": ioc_value})

        return {
            "report_metadata": {
                "report_id": incident.id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "generator": "ThreatTriage v1.0.0",
            },
            "executive_summary": {
                "incident_title": incident.title,
                "severity": incident.severity.value,
                "status": incident.status.value,
                "total_alerts": incident.alert_count,
                "total_iocs": len(iocs),
                "affected_hosts": sorted(incident.hostnames),
                "affected_users": sorted(incident.usernames),
                "source_ips": sorted(incident.source_ips),
                "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
                "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
                "summary": incident.summary,
            },
            "mitre_attack": {
                "techniques": [
                    {
                        "id": m.technique_id,
                        "name": m.technique_name,
                        "tactic": m.tactic,
                        "url": m.url,
                        "description": m.description,
                        "detection_count": technique_counts.get(m.technique_id, 0),
                    }
                    for m in mitre_mappings
                ],
                "tactics": sorted(incident.mitre_tactics),
                "navigator_layer": navigator_layer,
            },
            "alerts": [
                {
                    "rule_id": det.rule.id,
                    "rule_name": det.rule.name,
                    "description": det.rule.description,
                    "severity": det.rule.severity.value,
                    "source_ip": det.parsed_log.source_ip,
                    "timestamp": det.parsed_log.timestamp.isoformat() if det.parsed_log.timestamp else None,
                    "raw_log": det.parsed_log.raw[:500],
                    "mitre_techniques": det.rule.mitre_technique_ids,
                }
                for det in incident.detection_results
            ],
            "anomalies": [
                {
                    "type": anom.anomaly_type,
                    "description": anom.description,
                    "severity": anom.severity.value,
                    "score": anom.score,
                    "source_ip": anom.source_ip,
                    "details": anom.details,
                }
                for anom in incident.anomaly_results
            ],
            "indicators_of_compromise": iocs,
            "timeline": timeline,
            "recommendations": recommendations,
        }

    def generate_html_report(self, incident: CorrelatedIncident) -> str:
        """Generate an HTML report from a Jinja2 template."""
        report_data = self.generate_json_report(incident)
        template = self._jinja_env.get_template("incident_report.html")
        return template.render(report=report_data)

    def save_reports(
        self,
        incident: CorrelatedIncident,
        output_dir: Path,
    ) -> dict[str, Path]:
        """Save JSON and HTML reports to disk."""
        output_dir.mkdir(parents=True, exist_ok=True)

        json_data = self.generate_json_report(incident)
        json_path = output_dir / f"incident_{incident.id}.json"
        json_path.write_text(json.dumps(json_data, indent=2, default=str))

        html_content = self.generate_html_report(incident)
        html_path = output_dir / f"incident_{incident.id}.html"
        html_path.write_text(html_content)

        # Save navigator layer separately
        layer_path = output_dir / f"mitre_layer_{incident.id}.json"
        layer_path.write_text(
            json.dumps(json_data["mitre_attack"]["navigator_layer"], indent=2)
        )

        logger.info(
            "reports_saved",
            incident_id=incident.id,
            json_path=str(json_path),
            html_path=str(html_path),
        )

        return {"json": json_path, "html": html_path, "mitre_layer": layer_path}
