"""Statistical anomaly detection for log traffic patterns.

Detects deviations from baselines using Z-scores and time-based analysis.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from threattriage.models.base import Severity
from threattriage.parsers.base import ParsedLog
from threattriage.logging import get_logger

logger = get_logger(__name__)


@dataclass
class AnomalyResult:
    """A detected anomaly."""
    anomaly_type: str
    description: str
    severity: Severity
    score: float  # z-score or deviation measure
    source_ip: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    mitre_technique_ids: list[str] = field(default_factory=list)
    mitre_tactic: str = ""


class AnomalyDetector:
    """Detects statistical anomalies in log data."""

    # Z-score threshold for anomaly
    Z_THRESHOLD = 2.0
    # Business hours (used for time-based anomaly)
    BUSINESS_START = 8  # 08:00
    BUSINESS_END = 18   # 18:00

    def __init__(self) -> None:
        # Baseline counters
        self._ip_request_counts: Counter[str] = Counter()
        self._ip_error_counts: Counter[str] = Counter()
        self._hourly_counts: Counter[int] = Counter()
        self._endpoint_counts: Counter[str] = Counter()
        self._baseline_built = False

    def build_baseline(self, logs: list[ParsedLog]) -> dict[str, Any]:
        """Build traffic baselines from historical logs."""
        self._ip_request_counts.clear()
        self._ip_error_counts.clear()
        self._hourly_counts.clear()
        self._endpoint_counts.clear()

        for log in logs:
            if log.source_ip:
                self._ip_request_counts[log.source_ip] += 1
                if log.http_status and log.http_status >= 400:
                    self._ip_error_counts[log.source_ip] += 1
            if log.timestamp:
                self._hourly_counts[log.timestamp.hour] += 1
            if log.http_path:
                self._endpoint_counts[log.http_path] += 1

        self._baseline_built = True

        return {
            "unique_ips": len(self._ip_request_counts),
            "total_requests": sum(self._ip_request_counts.values()),
            "busiest_hour": self._hourly_counts.most_common(1)[0] if self._hourly_counts else None,
            "top_endpoints": self._endpoint_counts.most_common(10),
        }

    def detect_anomalies(self, logs: list[ParsedLog]) -> list[AnomalyResult]:
        """Detect anomalies in a batch of logs."""
        anomalies: list[AnomalyResult] = []

        anomalies.extend(self._detect_volume_spike(logs))
        anomalies.extend(self._detect_error_spike(logs))
        anomalies.extend(self._detect_off_hours_activity(logs))
        anomalies.extend(self._detect_ip_diversity_anomaly(logs))
        anomalies.extend(self._detect_rapid_endpoint_scan(logs))

        return anomalies

    def _detect_volume_spike(self, logs: list[ParsedLog]) -> list[AnomalyResult]:
        """Detect unusual volume of requests from a single IP."""
        ip_counts: Counter[str] = Counter()
        for log in logs:
            if log.source_ip:
                ip_counts[log.source_ip] += 1

        if len(ip_counts) < 3:
            return []

        counts = list(ip_counts.values())
        mean = sum(counts) / len(counts)
        variance = sum((c - mean) ** 2 for c in counts) / len(counts)
        std = math.sqrt(variance) if variance > 0 else 1

        anomalies = []
        for ip, count in ip_counts.items():
            z_score = (count - mean) / std if std > 0 else 0
            if z_score > self.Z_THRESHOLD:
                anomalies.append(AnomalyResult(
                    anomaly_type="volume_spike",
                    description=f"IP {ip} generated {count} requests (z-score: {z_score:.2f}), "
                                f"significantly above average of {mean:.1f}",
                    severity=Severity.HIGH if z_score > 4 else Severity.MEDIUM,
                    score=round(z_score, 2),
                    source_ip=ip,
                    details={"request_count": count, "mean": round(mean, 2), "std": round(std, 2)},
                    mitre_technique_ids=["T1498", "T1046"],
                    mitre_tactic="Impact",
                ))
        return anomalies

    def _detect_error_spike(self, logs: list[ParsedLog]) -> list[AnomalyResult]:
        """Detect unusual rate of HTTP errors from a single IP."""
        ip_errors: Counter[str] = Counter()
        ip_total: Counter[str] = Counter()

        for log in logs:
            if log.source_ip:
                ip_total[log.source_ip] += 1
                if log.http_status and log.http_status >= 400:
                    ip_errors[log.source_ip] += 1

        anomalies = []
        for ip, errors in ip_errors.items():
            total = ip_total[ip]
            if total < 5:
                continue
            error_rate = errors / total
            if error_rate > 0.7 and errors >= 10:
                anomalies.append(AnomalyResult(
                    anomaly_type="error_spike",
                    description=f"IP {ip}: {errors}/{total} requests ({error_rate:.0%}) returned errors — "
                                f"possible brute force or scanning",
                    severity=Severity.HIGH,
                    score=round(error_rate * 100, 2),
                    source_ip=ip,
                    details={"error_count": errors, "total": total, "rate": round(error_rate, 3)},
                    mitre_technique_ids=["T1110", "T1595"],
                    mitre_tactic="Credential Access",
                ))
        return anomalies

    def _detect_off_hours_activity(self, logs: list[ParsedLog]) -> list[AnomalyResult]:
        """Detect significant activity outside normal business hours."""
        off_hours: defaultdict[str, int] = defaultdict(int)

        for log in logs:
            if log.timestamp and log.source_ip:
                hour = log.timestamp.hour
                if hour < self.BUSINESS_START or hour >= self.BUSINESS_END:
                    off_hours[log.source_ip] += 1

        anomalies = []
        for ip, count in off_hours.items():
            if count >= 20:
                anomalies.append(AnomalyResult(
                    anomaly_type="off_hours_activity",
                    description=f"IP {ip}: {count} requests outside business hours (00:00–08:00, 18:00–24:00)",
                    severity=Severity.MEDIUM,
                    score=float(count),
                    source_ip=ip,
                    details={"off_hours_requests": count},
                    mitre_technique_ids=["T1078"],
                    mitre_tactic="Initial Access",
                ))
        return anomalies

    def _detect_ip_diversity_anomaly(self, logs: list[ParsedLog]) -> list[AnomalyResult]:
        """Detect multiple unique IPs accessing the same sensitive endpoint."""
        endpoint_ips: defaultdict[str, set[str]] = defaultdict(set)
        sensitive_paths = {"/admin", "/login", "/api/auth", "/wp-login.php", "/api/v1/admin"}

        for log in logs:
            if log.http_path and log.source_ip:
                path = log.http_path.split("?")[0]  # remove query string
                if any(path.startswith(s) for s in sensitive_paths):
                    endpoint_ips[path].add(log.source_ip)

        anomalies = []
        for path, ips in endpoint_ips.items():
            if len(ips) >= 10:
                anomalies.append(AnomalyResult(
                    anomaly_type="distributed_attack",
                    description=f"Endpoint {path} accessed by {len(ips)} unique IPs — possible distributed attack",
                    severity=Severity.HIGH,
                    score=float(len(ips)),
                    details={"endpoint": path, "unique_ips": len(ips), "sample_ips": list(ips)[:5]},
                    mitre_technique_ids=["T1110.004"],
                    mitre_tactic="Credential Access",
                ))
        return anomalies

    def _detect_rapid_endpoint_scan(self, logs: list[ParsedLog]) -> list[AnomalyResult]:
        """Detect rapid scanning of many different endpoints from one IP."""
        ip_paths: defaultdict[str, set[str]] = defaultdict(set)

        for log in logs:
            if log.source_ip and log.http_path:
                ip_paths[log.source_ip].add(log.http_path.split("?")[0])

        anomalies = []
        for ip, paths in ip_paths.items():
            if len(paths) >= 50:
                anomalies.append(AnomalyResult(
                    anomaly_type="endpoint_scan",
                    description=f"IP {ip} accessed {len(paths)} unique endpoints — directory/endpoint enumeration",
                    severity=Severity.HIGH,
                    score=float(len(paths)),
                    source_ip=ip,
                    details={"unique_paths": len(paths), "sample_paths": sorted(list(paths))[:10]},
                    mitre_technique_ids=["T1595.002", "T1083"],
                    mitre_tactic="Reconnaissance",
                ))
        return anomalies
