"""Severity scoring algorithm — multi-factor scoring for alerts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from threattriage.models.base import Severity
from threattriage.analysis.detection import DetectionResult
from threattriage.analysis.anomaly import AnomalyResult


# Severity numeric weights
SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.8,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.2,
    Severity.INFO: 0.1,
}


@dataclass
class ScoredAlert:
    """An alert with a calculated priority score."""
    score: float  # 0.0 – 100.0
    severity: Severity
    factors: dict[str, float]
    detection: DetectionResult | None = None
    anomaly: AnomalyResult | None = None


class SeverityScorer:
    """
    Multi-factor severity scoring.

    Score = base_severity × ti_multiplier × anomaly_factor × context_weight

    Factors:
    - base_severity: Rule severity weight (0.1–1.0)
    - ti_reputation: TI enrichment score (0–100) → normalised
    - anomaly_score: Statistical deviation score
    - context_weight: Asset criticality, repeat offender, etc.
    """

    def score_detection(
        self,
        detection: DetectionResult,
        ti_score: float = 0.0,
        is_repeat_offender: bool = False,
    ) -> ScoredAlert:
        """Score a detection result."""
        base = SEVERITY_WEIGHTS.get(detection.rule.severity, 0.5)

        # TI reputation multiplier (0–100 → 1.0–2.0)
        ti_mult = 1.0 + (ti_score / 100.0) if ti_score > 0 else 1.0

        # Context weight
        context = 1.0
        if is_repeat_offender:
            context += 0.3
        if detection.rule.mitre_tactic in ("Initial Access", "Execution", "Impact"):
            context += 0.2

        score = min(base * ti_mult * context * 100, 100.0)

        # Determine final severity
        if score >= 90:
            severity = Severity.CRITICAL
        elif score >= 70:
            severity = Severity.HIGH
        elif score >= 40:
            severity = Severity.MEDIUM
        elif score >= 20:
            severity = Severity.LOW
        else:
            severity = Severity.INFO

        return ScoredAlert(
            score=round(score, 2),
            severity=severity,
            factors={
                "base_severity": round(base, 2),
                "ti_multiplier": round(ti_mult, 2),
                "context_weight": round(context, 2),
            },
            detection=detection,
        )

    def score_anomaly(
        self,
        anomaly: AnomalyResult,
        ti_score: float = 0.0,
    ) -> ScoredAlert:
        """Score an anomaly result."""
        base = SEVERITY_WEIGHTS.get(anomaly.severity, 0.5)
        z_factor = min(anomaly.score / 5.0, 2.0) if anomaly.score > 0 else 1.0
        ti_mult = 1.0 + (ti_score / 100.0) if ti_score > 0 else 1.0

        score = min(base * z_factor * ti_mult * 100, 100.0)

        if score >= 90:
            severity = Severity.CRITICAL
        elif score >= 70:
            severity = Severity.HIGH
        elif score >= 40:
            severity = Severity.MEDIUM
        elif score >= 20:
            severity = Severity.LOW
        else:
            severity = Severity.INFO

        return ScoredAlert(
            score=round(score, 2),
            severity=severity,
            factors={
                "base_severity": round(base, 2),
                "z_factor": round(z_factor, 2),
                "ti_multiplier": round(ti_mult, 2),
            },
            anomaly=anomaly,
        )
