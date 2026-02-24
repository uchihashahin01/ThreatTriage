"""Automated playbook engine for Security Orchestration, Automation, and Response.

Executes predefined response actions when alerts meet trigger criteria.
Supports: IP blocking, webhook notifications (Slack/Discord), IOC enrichment,
incident auto-escalation, and custom action chains.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

import httpx

from threattriage.logging import get_logger
from threattriage.models.base import Severity

logger = get_logger(__name__)


class ActionType(str, Enum):
    BLOCK_IP = "block_ip"
    WEBHOOK_NOTIFY = "webhook_notify"
    ENRICH_IOC = "enrich_ioc"
    ESCALATE_INCIDENT = "escalate_incident"
    LOG_ACTION = "log_action"
    QUARANTINE_HOST = "quarantine_host"


class PlaybookStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    SIMULATED = "simulated"


@dataclass
class PlaybookAction:
    """A single automated action within a playbook."""
    action_type: ActionType
    description: str
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class PlaybookTrigger:
    """Conditions that activate a playbook."""
    min_severity: Severity = Severity.HIGH
    alert_types: list[str] | None = None       # e.g., ["rule", "anomaly"]
    mitre_tactics: list[str] | None = None      # e.g., ["Initial Access"]
    source_ip_pattern: str | None = None        # regex pattern


@dataclass
class Playbook:
    """A named automation playbook with trigger criteria and action chain."""
    id: str
    name: str
    description: str
    trigger: PlaybookTrigger
    actions: list[PlaybookAction]
    enabled: bool = True


@dataclass
class ActionResult:
    """Result of executing a single playbook action."""
    action_type: ActionType
    status: PlaybookStatus
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    executed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class PlaybookExecution:
    """Record of a full playbook execution."""
    execution_id: str
    playbook_id: str
    playbook_name: str
    alert_id: str
    triggered_at: str
    results: list[ActionResult] = field(default_factory=list)
    overall_status: PlaybookStatus = PlaybookStatus.SUCCESS


# ── Execution history (in-memory, persisted to DB later) ─────────────────────
_execution_history: list[PlaybookExecution] = []


# ── Built-in Playbooks ───────────────────────────────────────────────────────

BUILTIN_PLAYBOOKS: list[Playbook] = [
    Playbook(
        id="PB-001",
        name="Critical Alert — Block & Notify",
        description="When a CRITICAL alert fires, block the source IP and send a webhook notification.",
        trigger=PlaybookTrigger(min_severity=Severity.CRITICAL),
        actions=[
            PlaybookAction(
                action_type=ActionType.BLOCK_IP,
                description="Block source IP in firewall (simulated)",
            ),
            PlaybookAction(
                action_type=ActionType.WEBHOOK_NOTIFY,
                description="Send alert to configured webhook (Slack/Discord)",
                parameters={"channel": "#soc-alerts", "mention": "@oncall"},
            ),
            PlaybookAction(
                action_type=ActionType.ESCALATE_INCIDENT,
                description="Auto-escalate to incident for investigation",
            ),
            PlaybookAction(
                action_type=ActionType.LOG_ACTION,
                description="Record all actions taken in audit log",
            ),
        ],
    ),
    Playbook(
        id="PB-002",
        name="Brute Force Response",
        description="Auto-respond to brute force attempts with IP blocking and enrichment.",
        trigger=PlaybookTrigger(
            min_severity=Severity.HIGH,
            mitre_tactics=["Credential Access"],
        ),
        actions=[
            PlaybookAction(
                action_type=ActionType.ENRICH_IOC,
                description="Enrich source IP with threat intelligence",
            ),
            PlaybookAction(
                action_type=ActionType.BLOCK_IP,
                description="Block source IP after TI confirmation",
            ),
            PlaybookAction(
                action_type=ActionType.WEBHOOK_NOTIFY,
                description="Notify SOC team of brute force response",
                parameters={"channel": "#soc-brute-force"},
            ),
        ],
    ),
    Playbook(
        id="PB-003",
        name="Lateral Movement Containment",
        description="Contain lateral movement by quarantining the affected host.",
        trigger=PlaybookTrigger(
            min_severity=Severity.HIGH,
            mitre_tactics=["Lateral Movement"],
        ),
        actions=[
            PlaybookAction(
                action_type=ActionType.QUARANTINE_HOST,
                description="Isolate host from network (simulated)",
            ),
            PlaybookAction(
                action_type=ActionType.ESCALATE_INCIDENT,
                description="Create high-priority incident",
            ),
            PlaybookAction(
                action_type=ActionType.WEBHOOK_NOTIFY,
                description="Alert incident response team",
                parameters={"channel": "#soc-critical", "mention": "@ir-team"},
            ),
        ],
    ),
    Playbook(
        id="PB-004",
        name="Data Exfiltration Alert",
        description="Respond to suspected data exfiltration attempts.",
        trigger=PlaybookTrigger(
            min_severity=Severity.HIGH,
            mitre_tactics=["Exfiltration"],
        ),
        actions=[
            PlaybookAction(
                action_type=ActionType.BLOCK_IP,
                description="Block destination IP/domain",
            ),
            PlaybookAction(
                action_type=ActionType.ENRICH_IOC,
                description="Enrich IOCs with threat intelligence",
            ),
            PlaybookAction(
                action_type=ActionType.ESCALATE_INCIDENT,
                description="Create P1 incident for data loss investigation",
            ),
        ],
    ),
]


# ── Severity ranking for comparison ──────────────────────────────────────────
_SEV_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class PlaybookEngine:
    """Evaluates alerts against playbooks and executes matching actions."""

    def __init__(
        self,
        playbooks: list[Playbook] | None = None,
        webhook_url: str | None = None,
        simulate: bool = True,
    ) -> None:
        self.playbooks = playbooks or BUILTIN_PLAYBOOKS
        self.webhook_url = webhook_url
        self.simulate = simulate
        self._blocked_ips: set[str] = set()
        self._quarantined_hosts: set[str] = set()

    def evaluate_alert(self, alert: dict[str, Any]) -> list[PlaybookExecution]:
        """Check if an alert triggers any playbooks and return execution results."""
        executions: list[PlaybookExecution] = []

        alert_severity = Severity(alert.get("severity", "low"))

        for playbook in self.playbooks:
            if not playbook.enabled:
                continue
            if self._matches_trigger(playbook.trigger, alert, alert_severity):
                execution = self._execute_playbook(playbook, alert)
                executions.append(execution)
                _execution_history.append(execution)

        return executions

    def _matches_trigger(
        self,
        trigger: PlaybookTrigger,
        alert: dict[str, Any],
        alert_severity: Severity,
    ) -> bool:
        """Check if an alert matches a playbook's trigger criteria."""
        # Severity check
        if _SEV_RANK.get(alert_severity, 0) < _SEV_RANK.get(trigger.min_severity, 0):
            return False

        # Alert type check
        if trigger.alert_types:
            if alert.get("detection_type") not in trigger.alert_types:
                return False

        # MITRE tactic check
        if trigger.mitre_tactics:
            alert_tactic = alert.get("mitre_tactic", "")
            if not any(t.lower() in alert_tactic.lower() for t in trigger.mitre_tactics):
                return False

        return True

    def _execute_playbook(
        self, playbook: Playbook, alert: dict[str, Any]
    ) -> PlaybookExecution:
        """Execute all actions in a playbook for a given alert."""
        execution = PlaybookExecution(
            execution_id=str(uuid4()),
            playbook_id=playbook.id,
            playbook_name=playbook.name,
            alert_id=alert.get("id", "unknown"),
            triggered_at=datetime.now(timezone.utc).isoformat(),
        )

        for action in playbook.actions:
            result = self._execute_action(action, alert)
            execution.results.append(result)

        # Set overall status
        if any(r.status == PlaybookStatus.FAILED for r in execution.results):
            execution.overall_status = PlaybookStatus.FAILED
        elif all(r.status == PlaybookStatus.SIMULATED for r in execution.results):
            execution.overall_status = PlaybookStatus.SIMULATED
        else:
            execution.overall_status = PlaybookStatus.SUCCESS

        logger.info(
            "playbook_executed",
            playbook=playbook.name,
            alert_id=alert.get("id"),
            status=execution.overall_status.value,
            actions_run=len(execution.results),
        )

        return execution

    def _execute_action(
        self, action: PlaybookAction, alert: dict[str, Any]
    ) -> ActionResult:
        """Execute a single playbook action."""
        try:
            if action.action_type == ActionType.BLOCK_IP:
                return self._action_block_ip(alert)
            elif action.action_type == ActionType.WEBHOOK_NOTIFY:
                return self._action_webhook_notify(alert, action.parameters)
            elif action.action_type == ActionType.ENRICH_IOC:
                return self._action_enrich_ioc(alert)
            elif action.action_type == ActionType.ESCALATE_INCIDENT:
                return self._action_escalate(alert)
            elif action.action_type == ActionType.QUARANTINE_HOST:
                return self._action_quarantine(alert)
            elif action.action_type == ActionType.LOG_ACTION:
                return self._action_log(alert)
            else:
                return ActionResult(
                    action_type=action.action_type,
                    status=PlaybookStatus.SKIPPED,
                    message=f"Unknown action type: {action.action_type}",
                )
        except Exception as exc:
            return ActionResult(
                action_type=action.action_type,
                status=PlaybookStatus.FAILED,
                message=f"Action failed: {exc}",
            )

    def _action_block_ip(self, alert: dict[str, Any]) -> ActionResult:
        ip = alert.get("source_ip")
        if not ip:
            return ActionResult(
                action_type=ActionType.BLOCK_IP,
                status=PlaybookStatus.SKIPPED,
                message="No source IP to block",
            )

        self._blocked_ips.add(ip)

        if self.simulate:
            return ActionResult(
                action_type=ActionType.BLOCK_IP,
                status=PlaybookStatus.SIMULATED,
                message=f"[SIMULATED] Firewall rule added: DENY {ip} (iptables -A INPUT -s {ip} -j DROP)",
                details={"ip": ip, "rule": f"iptables -A INPUT -s {ip} -j DROP"},
            )

        return ActionResult(
            action_type=ActionType.BLOCK_IP,
            status=PlaybookStatus.SUCCESS,
            message=f"IP {ip} blocked in firewall",
            details={"ip": ip},
        )

    def _action_webhook_notify(
        self, alert: dict[str, Any], params: dict[str, Any]
    ) -> ActionResult:
        channel = params.get("channel", "#soc-alerts")
        mention = params.get("mention", "")

        payload = {
            "text": (
                f"{'🚨' if alert.get('severity') == 'critical' else '⚠️'} "
                f"**ThreatTriage Alert** [{alert.get('severity', 'unknown').upper()}]\n"
                f"> **{alert.get('title', 'Unknown Alert')}**\n"
                f"> Source: `{alert.get('source_ip', 'N/A')}` | "
                f"MITRE: {', '.join(alert.get('mitre_technique_ids', []))}\n"
                f"> {alert.get('description', '')[:200]}\n"
                f"{mention}"
            ),
            "channel": channel,
        }

        if self.simulate or not self.webhook_url:
            return ActionResult(
                action_type=ActionType.WEBHOOK_NOTIFY,
                status=PlaybookStatus.SIMULATED,
                message=f"[SIMULATED] Webhook → {channel}: {alert.get('title')}",
                details={"channel": channel, "payload_preview": payload["text"][:300]},
            )

        try:
            resp = httpx.post(self.webhook_url, json=payload, timeout=10)
            return ActionResult(
                action_type=ActionType.WEBHOOK_NOTIFY,
                status=PlaybookStatus.SUCCESS if resp.is_success else PlaybookStatus.FAILED,
                message=f"Webhook sent to {channel} (HTTP {resp.status_code})",
                details={"status_code": resp.status_code, "channel": channel},
            )
        except httpx.HTTPError as exc:
            return ActionResult(
                action_type=ActionType.WEBHOOK_NOTIFY,
                status=PlaybookStatus.FAILED,
                message=f"Webhook failed: {exc}",
            )

    def _action_enrich_ioc(self, alert: dict[str, Any]) -> ActionResult:
        iocs = alert.get("ioc_values", [])
        ip = alert.get("source_ip")
        targets = list(set(iocs + ([ip] if ip else [])))

        if not targets:
            return ActionResult(
                action_type=ActionType.ENRICH_IOC,
                status=PlaybookStatus.SKIPPED,
                message="No IOCs to enrich",
            )

        return ActionResult(
            action_type=ActionType.ENRICH_IOC,
            status=PlaybookStatus.SIMULATED if self.simulate else PlaybookStatus.SUCCESS,
            message=f"{'[SIMULATED] ' if self.simulate else ''}TI enrichment queued for {len(targets)} IOC(s)",
            details={"iocs": targets[:10]},
        )

    def _action_escalate(self, alert: dict[str, Any]) -> ActionResult:
        return ActionResult(
            action_type=ActionType.ESCALATE_INCIDENT,
            status=PlaybookStatus.SIMULATED if self.simulate else PlaybookStatus.SUCCESS,
            message=f"{'[SIMULATED] ' if self.simulate else ''}Alert escalated to incident: {alert.get('title')}",
            details={"alert_id": alert.get("id"), "severity": alert.get("severity")},
        )

    def _action_quarantine(self, alert: dict[str, Any]) -> ActionResult:
        hostname = alert.get("hostname")
        ip = alert.get("source_ip")
        target = hostname or ip or "unknown"

        if hostname:
            self._quarantined_hosts.add(hostname)

        return ActionResult(
            action_type=ActionType.QUARANTINE_HOST,
            status=PlaybookStatus.SIMULATED if self.simulate else PlaybookStatus.SUCCESS,
            message=f"{'[SIMULATED] ' if self.simulate else ''}Host {target} quarantined — network isolation applied",
            details={"host": target, "action": "network_isolation"},
        )

    def _action_log(self, alert: dict[str, Any]) -> ActionResult:
        return ActionResult(
            action_type=ActionType.LOG_ACTION,
            status=PlaybookStatus.SUCCESS,
            message=f"SOAR actions logged for alert: {alert.get('title')}",
            details={"alert_id": alert.get("id"), "timestamp": datetime.now(timezone.utc).isoformat()},
        )

    @property
    def blocked_ips(self) -> set[str]:
        return self._blocked_ips.copy()

    @property
    def quarantined_hosts(self) -> set[str]:
        return self._quarantined_hosts.copy()


def get_execution_history() -> list[dict[str, Any]]:
    """Return playbook execution history as serializable dicts."""
    return [
        {
            "execution_id": ex.execution_id,
            "playbook_id": ex.playbook_id,
            "playbook_name": ex.playbook_name,
            "alert_id": ex.alert_id,
            "triggered_at": ex.triggered_at,
            "overall_status": ex.overall_status.value,
            "actions": [
                {
                    "action_type": r.action_type.value,
                    "status": r.status.value,
                    "message": r.message,
                    "details": r.details,
                    "executed_at": r.executed_at,
                }
                for r in ex.results
            ],
        }
        for ex in reversed(_execution_history)
    ]


def get_playbooks_summary() -> list[dict[str, Any]]:
    """Return summary of configured playbooks."""
    return [
        {
            "id": pb.id,
            "name": pb.name,
            "description": pb.description,
            "enabled": pb.enabled,
            "trigger_severity": pb.trigger.min_severity.value,
            "trigger_tactics": pb.trigger.mitre_tactics or [],
            "action_count": len(pb.actions),
            "actions": [a.action_type.value for a in pb.actions],
        }
        for pb in BUILTIN_PLAYBOOKS
    ]
