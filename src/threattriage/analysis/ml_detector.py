"""Machine Learning anomaly detection using Scikit-Learn Isolation Forest.

Trains on feature vectors extracted from log data to detect mathematically
anomalous patterns that rule-based detection might miss.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import numpy as np

from threattriage.logging import get_logger
from threattriage.models.base import Severity
from threattriage.parsers.base import ParsedLog

logger = get_logger(__name__)


@dataclass
class MLAnomalyResult:
    """Result from ML-based anomaly detection."""
    ip: str
    anomaly_score: float  # -1 = anomalous, 1 = normal (Isolation Forest convention)
    normalized_score: float  # 0-100 human-readable score (100 = most anomalous)
    severity: Severity
    description: str
    features: dict[str, float] = field(default_factory=dict)
    mitre_technique_ids: list[str] = field(default_factory=list)
    mitre_tactic: str = ""


def _extract_features(logs: list[ParsedLog]) -> tuple[list[str], Any]:
    """Extract feature vectors from parsed logs, grouped by source IP.

    Features per IP:
    - request_count: total number of requests
    - unique_paths: number of distinct HTTP paths accessed
    - error_rate: fraction of requests with HTTP 4xx/5xx
    - avg_request_size: average path length (proxy for payload size)
    - off_hours_ratio: fraction of requests outside business hours (08-18)
    - unique_methods: number of distinct HTTP methods
    - suspicious_ratio: fraction of requests flagged as suspicious by parsers
    - path_entropy: Shannon entropy of path distribution
    """
    ip_data: defaultdict[str, dict[str, Any]] = defaultdict(lambda: {
        "count": 0,
        "paths": Counter(),
        "errors": 0,
        "path_lengths": [],
        "off_hours": 0,
        "methods": set(),
        "suspicious": 0,
    })

    for log in logs:
        ip = log.source_ip
        if not ip:
            continue

        d = ip_data[ip]
        d["count"] += 1

        if log.http_path:
            d["paths"][log.http_path] += 1
            d["path_lengths"].append(len(log.http_path))

        if log.http_status and log.http_status >= 400:
            d["errors"] += 1

        if log.timestamp:
            hour = log.timestamp.hour
            if hour < 8 or hour >= 18:
                d["off_hours"] += 1

        if log.http_method:
            d["methods"].add(log.http_method)

        if log.is_suspicious:
            d["suspicious"] += 1

    ips = []
    feature_vectors = []

    for ip, d in ip_data.items():
        count = d["count"]
        if count < 2:
            continue

        # Shannon entropy of path distribution
        path_total = sum(d["paths"].values())
        entropy = 0.0
        if path_total > 0:
            for c in d["paths"].values():
                p = c / path_total
                if p > 0:
                    entropy -= p * math.log2(p)

        features = [
            count,
            len(d["paths"]),
            d["errors"] / count if count > 0 else 0,
            sum(d["path_lengths"]) / len(d["path_lengths"]) if d["path_lengths"] else 0,
            d["off_hours"] / count if count > 0 else 0,
            len(d["methods"]),
            d["suspicious"] / count if count > 0 else 0,
            entropy,
        ]

        ips.append(ip)
        feature_vectors.append(features)

    if not feature_vectors:
        return [], np.array([])

    return ips, np.array(feature_vectors, dtype=np.float64)


FEATURE_NAMES = [
    "request_count",
    "unique_paths",
    "error_rate",
    "avg_path_length",
    "off_hours_ratio",
    "unique_methods",
    "suspicious_ratio",
    "path_entropy",
]


class MLAnomalyDetector:
    """ML-based anomaly detection using Isolation Forest."""

    def __init__(
        self,
        contamination: float = 0.1,
        n_estimators: int = 100,
        random_state: int = 42,
    ) -> None:
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self._model = None
        self._scaler = None
        self._is_trained = False

    def _ensure_model(self) -> None:
        """Lazily initialize the model to avoid import overhead."""
        if self._model is None:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler

            self._model = IsolationForest(
                contamination=self.contamination,
                n_estimators=self.n_estimators,
                random_state=self.random_state,
                n_jobs=-1,
            )
            self._scaler = StandardScaler()

    def train(self, logs: list[ParsedLog]) -> dict[str, Any]:
        """Train the model on 'normal' log data to build a baseline."""
        self._ensure_model()

        ips, features = _extract_features(logs)
        if len(ips) < 5:
            return {"status": "insufficient_data", "samples": len(ips)}

        scaled = self._scaler.fit_transform(features)
        self._model.fit(scaled)
        self._is_trained = True

        logger.info("ml_model_trained", samples=len(ips), features=features.shape[1])

        return {
            "status": "trained",
            "samples": len(ips),
            "features": FEATURE_NAMES,
            "contamination": self.contamination,
        }

    def detect(self, logs: list[ParsedLog]) -> list[MLAnomalyResult]:
        """Run anomaly detection on incoming logs.

        If the model hasn't been trained yet, it performs unsupervised
        fit_predict on the current batch (semi-supervised mode).
        """
        self._ensure_model()

        ips, features = _extract_features(logs)
        if len(ips) < 3:
            return []

        scaled = self._scaler.fit_transform(features)

        if self._is_trained:
            predictions = self._model.predict(scaled)
            scores = self._model.decision_function(scaled)
        else:
            # Semi-supervised: fit and predict on same batch
            predictions = self._model.fit_predict(scaled)
            scores = self._model.decision_function(scaled)

        anomalies: list[MLAnomalyResult] = []

        for i, (ip, pred, score) in enumerate(zip(ips, predictions, scores)):
            if pred == -1:  # Anomalous
                # Normalize score: lower decision_function = more anomalous
                # Typical range: -0.5 to 0.5; map to 0-100
                normalized = max(0, min(100, (0.5 - score) * 100))

                # Determine severity from normalized score
                if normalized >= 80:
                    severity = Severity.CRITICAL
                elif normalized >= 60:
                    severity = Severity.HIGH
                elif normalized >= 40:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW

                feature_dict = {
                    name: round(float(features[i][j]), 4)
                    for j, name in enumerate(FEATURE_NAMES)
                }

                # Determine likely attack type from features
                mitre_ids = []
                tactic = "Discovery"

                error_rate = feature_dict.get("error_rate", 0)
                suspicious_ratio = feature_dict.get("suspicious_ratio", 0)
                unique_paths = feature_dict.get("unique_paths", 0)

                if error_rate > 0.5:
                    mitre_ids.extend(["T1110", "T1595"])
                    tactic = "Credential Access"
                elif unique_paths > 20:
                    mitre_ids.extend(["T1046", "T1595.002"])
                    tactic = "Reconnaissance"
                elif suspicious_ratio > 0.3:
                    mitre_ids.extend(["T1190", "T1059"])
                    tactic = "Initial Access"
                else:
                    mitre_ids.append("T1071")

                anomalies.append(MLAnomalyResult(
                    ip=ip,
                    anomaly_score=float(score),
                    normalized_score=round(normalized, 2),
                    severity=severity,
                    description=(
                        f"ML Isolation Forest flagged IP {ip} as anomalous "
                        f"(score: {normalized:.0f}/100). "
                        f"Key features: {feature_dict.get('request_count', 0):.0f} requests, "
                        f"{error_rate:.0%} error rate, "
                        f"{feature_dict.get('off_hours_ratio', 0):.0%} off-hours"
                    ),
                    features=feature_dict,
                    mitre_technique_ids=mitre_ids,
                    mitre_tactic=tactic,
                ))

        logger.info(
            "ml_anomaly_detection_complete",
            total_ips=len(ips),
            anomalies_found=len(anomalies),
        )

        return sorted(anomalies, key=lambda a: a.normalized_score, reverse=True)
