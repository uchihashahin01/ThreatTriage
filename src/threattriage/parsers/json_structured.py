"""JSON structured log parser (CloudTrail, Azure Activity, generic JSON logs)."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, ClassVar

from threattriage.models.base import LogType
from threattriage.parsers.base import LogParser, ParsedLog


# ─── Suspicious CloudTrail Events ────────────────────────────────────────────
_SUSPICIOUS_CLOUDTRAIL_EVENTS = {
    "ConsoleLogin": (["authentication"], ["T1078"]),
    "CreateUser": (["persistence", "account_creation"], ["T1136"]),
    "AttachUserPolicy": (["privilege_escalation"], ["T1098"]),
    "PutBucketPolicy": (["defense_evasion"], ["T1562"]),
    "StopLogging": (["defense_evasion"], ["T1562.001"]),
    "DeleteTrail": (["defense_evasion"], ["T1070"]),
    "CreateAccessKey": (["persistence"], ["T1098.001"]),
    "RunInstances": (["execution"], ["T1059"]),
    "AuthorizeSecurityGroupIngress": (["defense_evasion"], ["T1562.007"]),
    "GetSecretValue": (["credential_access"], ["T1528"]),
    "AssumeRole": (["privilege_escalation"], ["T1078"]),
    "CreateLoginProfile": (["persistence"], ["T1136"]),
    "DeactivateMFADevice": (["defense_evasion"], ["T1556"]),
    "DeleteBucket": (["impact"], ["T1485"]),
}

# Suspicious Azure operations
_SUSPICIOUS_AZURE_OPS = {
    "Microsoft.Authorization/roleAssignments/write": (["privilege_escalation"], ["T1098"]),
    "Microsoft.Compute/virtualMachines/write": (["execution"], ["T1059"]),
    "Microsoft.KeyVault/vaults/secrets/getSecret/action": (["credential_access"], ["T1528"]),
    "Microsoft.Storage/storageAccounts/delete": (["impact"], ["T1485"]),
    "Microsoft.Network/networkSecurityGroups/securityRules/write": (["defense_evasion"], ["T1562.007"]),
}


class JsonStructuredParser(LogParser):
    """Parser for JSON-structured logs (CloudTrail, Azure, generic)."""

    log_type: ClassVar[LogType] = LogType.GENERIC
    name: ClassVar[str] = "json_structured"
    description: ClassVar[str] = "JSON structured logs (CloudTrail, Azure Activity, generic)"

    def can_parse(self, raw_line: str) -> bool:
        stripped = raw_line.strip()
        if not stripped.startswith("{"):
            return False
        try:
            data = json.loads(stripped)
            return isinstance(data, dict)
        except (json.JSONDecodeError, ValueError):
            return False

    def parse(self, raw_line: str) -> ParsedLog | None:
        try:
            data = json.loads(raw_line.strip())
        except (json.JSONDecodeError, ValueError):
            return None

        if not isinstance(data, dict):
            return None

        # Detect log type
        if "eventSource" in data and "awsRegion" in data:
            return self._parse_cloudtrail(data, raw_line)
        elif "operationName" in data and "resourceId" in data:
            return self._parse_azure(data, raw_line)
        else:
            return self._parse_generic_json(data, raw_line)

    def _parse_cloudtrail(self, data: dict[str, Any], raw: str) -> ParsedLog:
        event_name = data.get("eventName", "")
        source_ip = data.get("sourceIPAddress")
        user_identity = data.get("userIdentity", {})
        username = user_identity.get("userName") or user_identity.get("arn", "")
        timestamp = self._parse_timestamp(data.get("eventTime"))
        error_code = data.get("errorCode")
        region = data.get("awsRegion", "")

        is_suspicious = False
        tags = []
        ioc_values = []

        if event_name in _SUSPICIOUS_CLOUDTRAIL_EVENTS:
            info = _SUSPICIOUS_CLOUDTRAIL_EVENTS[event_name]
            is_suspicious = True
            tags = list(info[0])

        if error_code == "AccessDenied":
            tags.append("access_denied")

        if source_ip and not source_ip.startswith("AWS Internal"):
            ioc_values.append(("ip", source_ip))

        return ParsedLog(
            raw=raw,
            log_type=LogType.GENERIC,
            timestamp=timestamp,
            source_ip=source_ip if source_ip and not source_ip.startswith("AWS") else None,
            username=username,
            message=f"CloudTrail: {event_name} by {username} from {source_ip or 'internal'} ({region})",
            is_suspicious=is_suspicious,
            detection_tags=tags,
            ioc_values=ioc_values,
            parsed_data={
                "format": "cloudtrail",
                "event_name": event_name,
                "event_source": data.get("eventSource"),
                "region": region,
                "error_code": error_code,
                "request_parameters": data.get("requestParameters"),
            },
        )

    def _parse_azure(self, data: dict[str, Any], raw: str) -> ParsedLog:
        operation = data.get("operationName", "")
        caller = data.get("caller", "")
        resource_id = data.get("resourceId", "")
        status = data.get("status", {})
        status_value = status.get("value", "") if isinstance(status, dict) else str(status)
        timestamp = self._parse_timestamp(data.get("time") or data.get("eventTimestamp"))

        # Extract caller IP
        http_request = data.get("httpRequest", {})
        source_ip = http_request.get("clientIpAddress") if isinstance(http_request, dict) else None

        is_suspicious = False
        tags = []
        ioc_values = []

        for pattern, info in _SUSPICIOUS_AZURE_OPS.items():
            if pattern in operation:
                is_suspicious = True
                tags = list(info[0])
                break

        if source_ip:
            ioc_values.append(("ip", source_ip))

        return ParsedLog(
            raw=raw,
            log_type=LogType.GENERIC,
            timestamp=timestamp,
            source_ip=source_ip,
            username=caller,
            message=f"Azure: {operation} by {caller} on {resource_id} ({status_value})",
            is_suspicious=is_suspicious,
            detection_tags=tags,
            ioc_values=ioc_values,
            parsed_data={
                "format": "azure_activity",
                "operation": operation,
                "resource_id": resource_id,
                "status": status_value,
            },
        )

    def _parse_generic_json(self, data: dict[str, Any], raw: str) -> ParsedLog:
        # Try common field names
        source_ip = (
            data.get("source_ip")
            or data.get("src_ip")
            or data.get("clientIP")
            or data.get("remote_addr")
            or data.get("ip")
        )
        timestamp = self._parse_timestamp(
            data.get("timestamp") or data.get("@timestamp") or data.get("time") or data.get("date")
        )
        message = data.get("message") or data.get("msg") or data.get("log") or str(data)[:300]
        hostname = data.get("hostname") or data.get("host") or data.get("computer")
        username = data.get("user") or data.get("username") or data.get("actor")
        level = (data.get("level") or data.get("severity") or "").lower()

        is_suspicious = level in ("error", "critical", "alert", "emergency")

        return ParsedLog(
            raw=raw,
            log_type=LogType.GENERIC,
            timestamp=timestamp,
            source_ip=source_ip,
            hostname=hostname,
            username=username,
            message=message[:500] if isinstance(message, str) else str(message)[:500],
            is_suspicious=is_suspicious,
            detection_tags=["json_log"],
            ioc_values=[("ip", source_ip)] if source_ip else [],
            parsed_data={"format": "generic_json", "data": data},
        )

    @staticmethod
    def _parse_timestamp(ts: str | None) -> datetime | None:
        if not ts:
            return None
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                return datetime.strptime(ts, fmt)
            except (ValueError, TypeError):
                continue
        return None
