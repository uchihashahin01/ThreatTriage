"""Sigma YAML rule loader — load community detection rules from YAML files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from threattriage.analysis.detection import DetectionRule
from threattriage.models.base import Severity
from threattriage.logging import get_logger

logger = get_logger(__name__)

# Mapping from Sigma severity strings to our Severity enum
_SEVERITY_MAP = {
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def load_sigma_rule(data: dict[str, Any]) -> DetectionRule | None:
    """Convert a parsed Sigma YAML dict to a DetectionRule."""
    try:
        title = data.get("title", "Unnamed Rule")
        rule_id = data.get("id", title.lower().replace(" ", "_")[:20])
        description = data.get("description", "")
        level = data.get("level", "medium")
        severity = _SEVERITY_MAP.get(level, Severity.MEDIUM)

        # Extract tags → MITRE technique IDs
        tags = data.get("tags", [])
        mitre_ids = []
        mitre_tactic = ""
        for tag in tags:
            if isinstance(tag, str):
                # Sigma tags use attack.tXXXX format
                if tag.startswith("attack.t"):
                    tid = tag.replace("attack.", "").upper()
                    mitre_ids.append(tid)
                elif tag.startswith("attack."):
                    tactic = tag.replace("attack.", "").replace("_", " ").title()
                    if not mitre_tactic:
                        mitre_tactic = tactic

        # Extract detection patterns
        detection = data.get("detection", {})
        pattern = _extract_pattern(detection)

        # Extract log source
        logsource = data.get("logsource", {})
        log_types = _map_logsource(logsource)

        rule = DetectionRule(
            id=f"SIGMA-{rule_id[:30]}",
            name=title,
            description=description,
            severity=severity,
            mitre_technique_ids=mitre_ids,
            mitre_tactic=mitre_tactic,
            tags=[t for t in tags if isinstance(t, str)],
            log_types=log_types,
            pattern=pattern,
        )
        rule.compile()
        return rule

    except Exception as e:
        logger.warning("sigma_rule_parse_error", error=str(e), rule=data.get("title"))
        return None


def load_sigma_file(path: Path) -> DetectionRule | None:
    """Load a single Sigma YAML rule file."""
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            return None
        return load_sigma_rule(data)
    except Exception as e:
        logger.warning("sigma_file_load_error", path=str(path), error=str(e))
        return None


def load_sigma_directory(directory: Path) -> list[DetectionRule]:
    """Load all Sigma rules from a directory (recursive)."""
    rules = []
    if not directory.exists():
        logger.info("sigma_directory_not_found", path=str(directory))
        return rules

    for path in sorted(directory.rglob("*.yml")):
        rule = load_sigma_file(path)
        if rule:
            rules.append(rule)

    for path in sorted(directory.rglob("*.yaml")):
        rule = load_sigma_file(path)
        if rule:
            rules.append(rule)

    logger.info("sigma_rules_loaded", count=len(rules), directory=str(directory))
    return rules


def _extract_pattern(detection: dict[str, Any]) -> str:
    """Extract a regex pattern from Sigma detection block."""
    patterns = []

    for key, value in detection.items():
        if key == "condition":
            continue

        if isinstance(value, dict):
            for field_name, field_value in value.items():
                if field_name.startswith("_"):
                    continue
                if isinstance(field_value, str):
                    patterns.append(_sigma_to_regex(field_value))
                elif isinstance(field_value, list):
                    sub_patterns = [_sigma_to_regex(v) for v in field_value if isinstance(v, str)]
                    if sub_patterns:
                        patterns.append("(?:" + "|".join(sub_patterns) + ")")

        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    patterns.append(_sigma_to_regex(item))
                elif isinstance(item, dict):
                    for fv in item.values():
                        if isinstance(fv, str):
                            patterns.append(_sigma_to_regex(fv))
                        elif isinstance(fv, list):
                            sub = [_sigma_to_regex(v) for v in fv if isinstance(v, str)]
                            if sub:
                                patterns.append("(?:" + "|".join(sub) + ")")

    if patterns:
        return "|".join(patterns)
    return ""


def _sigma_to_regex(sigma_pattern: str) -> str:
    """Convert a Sigma wildcard pattern to regex."""
    import re as _re
    result = _re.escape(sigma_pattern)
    result = result.replace(r"\*", ".*")
    result = result.replace(r"\?", ".")
    return result


def _map_logsource(logsource: dict[str, Any]) -> list[str]:
    """Map Sigma logsource category to our log_types."""
    category = logsource.get("category", "")
    product = logsource.get("product", "")

    mapping = {
        "webserver": ["http_access"],
        "web": ["http_access"],
        "proxy": ["http_access"],
        "firewall": ["generic"],
        "linux": ["syslog"],
        "syslog": ["syslog"],
        "windows": ["generic"],
        "database": ["db_audit"],
        "dns": ["generic"],
        "ids": ["generic"],
    }

    for key in (category, product):
        if key in mapping:
            return mapping[key]

    return []  # Match all types
