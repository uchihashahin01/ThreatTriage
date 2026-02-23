"""MITRE ATT&CK mapping engine.

Maps detected techniques to the ATT&CK knowledge base and generates
ATT&CK Navigator layer JSON for visualization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from threattriage.logging import get_logger

logger = get_logger(__name__)


# ─── Embedded ATT&CK Technique Database ──────────────────────────────────────
# Pre-loaded subset of frequently-detected techniques to avoid requiring
# the full STIX dataset at runtime. The mitreattack-python library is
# used for comprehensive lookups when available.

TECHNIQUE_DB: dict[str, dict[str, Any]] = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
        "platforms": ["Windows", "Linux", "macOS", "Azure AD", "Office 365"],
        "mitigations": ["Account Lockout", "Multi-factor Authentication", "Password Policies"],
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
        "description": "Adversaries may guess passwords to attempt access to accounts.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": ["Account Lockout", "Multi-factor Authentication"],
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Adversaries may exploit vulnerabilities in internet-facing applications.",
        "platforms": ["Windows", "Linux", "macOS", "Containers"],
        "mitigations": ["Application Isolation", "Exploit Protection", "Vulnerability Scanning"],
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/",
        "description": "Adversaries may abuse command and script interpreters to execute commands.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": ["Execution Prevention", "Code Signing", "Disable or Remove Feature"],
    },
    "T1059.004": {
        "name": "Unix Shell",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/004/",
        "description": "Adversaries may use Unix shell commands and scripts for execution.",
        "platforms": ["Linux", "macOS"],
        "mitigations": ["Execution Prevention"],
    },
    "T1059.007": {
        "name": "JavaScript",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/007/",
        "description": "Adversaries may abuse JavaScript for execution.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": ["Disable or Remove Feature"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1078/",
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
        "platforms": ["Windows", "Linux", "macOS", "Azure AD"],
        "mitigations": ["Multi-factor Authentication", "Privileged Account Management"],
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1083/",
        "description": "Adversaries may enumerate files and directories on endpoints.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": [],
    },
    "T1136": {
        "name": "Create Account",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1136/",
        "description": "Adversaries may create an account to maintain access.",
        "platforms": ["Windows", "Linux", "macOS", "Azure AD"],
        "mitigations": ["Multi-factor Authentication", "Privileged Account Management"],
    },
    "T1136.001": {
        "name": "Create Account: Local Account",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1136/001/",
        "description": "Adversaries may create a local account to maintain persistence.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": ["Privileged Account Management"],
    },
    "T1189": {
        "name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1189/",
        "description": "Adversaries may gain access through users visiting compromised websites.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": ["Exploit Protection", "Restrict Web-Based Content"],
    },
    "T1203": {
        "name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1203/",
        "description": "Adversaries may exploit software vulnerabilities in client applications.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": ["Exploit Protection", "Application Isolation"],
    },
    "T1485": {
        "name": "Data Destruction",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1485/",
        "description": "Adversaries may destroy data and files on specific systems.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": ["Data Backup"],
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1498/",
        "description": "Adversaries may perform network DoS attacks.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": ["Filter Network Traffic"],
    },
    "T1505.003": {
        "name": "Server Software Component: Web Shell",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1505/003/",
        "description": "Adversaries may install a web shell on a web server.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": ["Disable or Remove Feature", "File Integrity Monitoring"],
    },
    "T1530": {
        "name": "Data from Cloud Storage",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1530/",
        "description": "Adversaries may access data from cloud storage.",
        "platforms": ["Azure AD", "AWS", "GCP"],
        "mitigations": ["Audit", "Encrypt Sensitive Information"],
    },
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1005/",
        "description": "Adversaries may search local file systems for data.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": ["Data Loss Prevention"],
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1041/",
        "description": "Adversaries may exfiltrate data over their existing command and control channel.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": ["Data Loss Prevention", "Network Intrusion Prevention"],
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1048/",
        "description": "Adversaries may exfiltrate data using a different protocol than the primary C2.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": ["Data Loss Prevention", "Network Segmentation"],
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "description": "Adversaries may scan for services available on hosts in a network.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": ["Disable or Remove Feature", "Network Segmentation"],
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1548/",
        "description": "Adversaries may circumvent mechanisms designed to control elevate privileges.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": ["Execution Prevention", "Privileged Account Management"],
    },
    "T1548.003": {
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1548/003/",
        "description": "Adversaries may abuse sudo for privilege escalation.",
        "platforms": ["Linux", "macOS"],
        "mitigations": ["Privileged Account Management", "Restrict File and Directory Permissions"],
    },
    "T1053.003": {
        "name": "Scheduled Task/Job: Cron",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1053/003/",
        "description": "Adversaries may abuse cron to execute malicious tasks at scheduled times.",
        "platforms": ["Linux", "macOS"],
        "mitigations": ["Audit", "User Account Management"],
    },
    "T1561": {
        "name": "Disk Wipe",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1561/",
        "description": "Adversaries may wipe or corrupt raw disk data on specific systems.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": ["Data Backup"],
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1572/",
        "description": "Adversaries may tunnel network communications within another protocol.",
        "platforms": ["Windows", "Linux", "macOS"],
        "mitigations": ["Filter Network Traffic", "Network Intrusion Prevention"],
    },
    "T1595": {
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/",
        "description": "Adversaries may actively scan victim infrastructure.",
        "platforms": ["PRE"],
        "mitigations": ["Pre-compromise"],
    },
    "T1595.002": {
        "name": "Active Scanning: Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/002/",
        "description": "Adversaries may scan for vulnerabilities in victim infrastructure.",
        "platforms": ["PRE"],
        "mitigations": ["Pre-compromise"],
    },
    "T1110.004": {
        "name": "Brute Force: Credential Stuffing",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/004/",
        "description": "Adversaries may use previously compromised credentials in stuffing attacks.",
        "platforms": ["Windows", "Linux", "macOS", "Azure AD"],
        "mitigations": ["Account Lockout", "Multi-factor Authentication"],
    },
}


@dataclass
class MitreMapping:
    """A mapping of a detection to MITRE ATT&CK."""
    technique_id: str
    technique_name: str
    tactic: str
    url: str
    description: str
    mitigations: list[str]
    detection_count: int = 1


class MitreMapper:
    """Maps detections to MITRE ATT&CK and generates navigator layers."""

    def __init__(self) -> None:
        self.technique_db = TECHNIQUE_DB
        logger.info("mitre_mapper_initialized", techniques_loaded=len(self.technique_db))

    def map_technique(self, technique_id: str) -> MitreMapping | None:
        """Look up a technique by ID."""
        info = self.technique_db.get(technique_id)
        if not info:
            logger.debug("mitre_technique_not_found", technique_id=technique_id)
            return None

        return MitreMapping(
            technique_id=technique_id,
            technique_name=info["name"],
            tactic=info["tactic"],
            url=info["url"],
            description=info["description"],
            mitigations=info.get("mitigations", []),
        )

    def map_techniques(self, technique_ids: list[str]) -> list[MitreMapping]:
        """Map a list of technique IDs."""
        mappings = []
        seen = set()
        for tid in technique_ids:
            if tid not in seen:
                m = self.map_technique(tid)
                if m:
                    mappings.append(m)
                seen.add(tid)
        return mappings

    def generate_navigator_layer(
        self,
        technique_counts: dict[str, int],
        name: str = "ThreatTriage Detections",
        description: str = "Techniques detected by ThreatTriage analysis engine",
    ) -> dict[str, Any]:
        """
        Generate an ATT&CK Navigator-compatible JSON layer.

        This can be imported into https://mitre-attack.github.io/attack-navigator/
        """
        max_count = max(technique_counts.values()) if technique_counts else 1

        techniques = []
        for tid, count in technique_counts.items():
            info = self.technique_db.get(tid, {})
            # Color intensity based on count (1=light red, max=dark red)
            intensity = count / max_count
            color = self._score_to_color(intensity)

            techniques.append({
                "techniqueID": tid,
                "tactic": info.get("tactic", "").lower().replace(" ", "-"),
                "color": color,
                "comment": f"Detected {count} time(s)",
                "enabled": True,
                "metadata": [],
                "links": [],
                "showSubtechniques": True,
                "score": count,
            })

        return {
            "name": name,
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": description,
            "filters": {"platforms": ["Linux", "macOS", "Windows"]},
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
                "showAggregateScores": False,
                "countUnscored": False,
            },
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#ffe0e0", "#ff0000"],
                "minValue": 0,
                "maxValue": max_count,
            },
            "legendItems": [
                {"label": f"1 detection", "color": "#ffe0e0"},
                {"label": f"{max_count} detections", "color": "#ff0000"},
            ],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
        }

    @staticmethod
    def _score_to_color(intensity: float) -> str:
        """Convert a 0–1 intensity to a red-scale hex color."""
        r = 255
        gb = int(255 * (1 - intensity * 0.85))
        return f"#{r:02x}{gb:02x}{gb:02x}"

    def get_recommendations(self, technique_ids: list[str]) -> list[dict[str, Any]]:
        """Get remediation recommendations for detected techniques."""
        recommendations = []
        seen_mitigations: set[str] = set()

        for tid in technique_ids:
            info = self.technique_db.get(tid, {})
            for mit in info.get("mitigations", []):
                if mit not in seen_mitigations:
                    seen_mitigations.add(mit)
                    recommendations.append({
                        "mitigation": mit,
                        "addresses_techniques": [
                            t for t in technique_ids
                            if mit in self.technique_db.get(t, {}).get("mitigations", [])
                        ],
                        "priority": "high" if len([
                            t for t in technique_ids
                            if mit in self.technique_db.get(t, {}).get("mitigations", [])
                        ]) > 1 else "medium",
                    })

        recommendations.sort(key=lambda r: len(r["addresses_techniques"]), reverse=True)
        return recommendations
