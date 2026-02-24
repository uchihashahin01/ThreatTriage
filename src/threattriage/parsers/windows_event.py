"""Windows Event Log (EVTX XML) parser."""

from __future__ import annotations

import re
from datetime import datetime
from typing import ClassVar

from threattriage.models.base import LogType
from threattriage.parsers.base import LogParser, ParsedLog


# ─── Suspicious Event IDs ────────────────────────────────────────────────────
_SUSPICIOUS_EVENT_IDS = {
    4625: ("Failed logon", ["brute_force", "credential_access"], ["T1110"]),
    4624: ("Successful logon", [], []),
    4648: ("Explicit credential logon", ["lateral_movement"], ["T1078"]),
    4672: ("Special privileges assigned", ["privilege_escalation"], ["T1078"]),
    4688: ("Process creation", ["execution"], ["T1059"]),
    4697: ("Service installed", ["persistence"], ["T1543.003"]),
    4698: ("Scheduled task created", ["persistence"], ["T1053"]),
    4720: ("User account created", ["persistence"], ["T1136"]),
    4728: ("Member added to security group", ["persistence"], ["T1098"]),
    4732: ("Member added to local group", ["persistence"], ["T1098"]),
    4768: ("Kerberos TGT requested", ["credential_access"], ["T1558"]),
    4769: ("Kerberos service ticket requested", ["lateral_movement"], ["T1558"]),
    4771: ("Kerberos pre-auth failed", ["credential_access"], ["T1110"]),
    7045: ("Service installed (System)", ["persistence"], ["T1543.003"]),
    1102: ("Audit log cleared", ["defense_evasion"], ["T1070.001"]),
    4104: ("PowerShell script block", ["execution"], ["T1059.001"]),
}

_EVTX_XML_PATTERN = re.compile(
    r"<Event\s.*?<EventID>(\d+)</EventID>.*?</Event>",
    re.DOTALL | re.IGNORECASE,
)
_EVTX_ONELINE_PATTERN = re.compile(
    r"(?:EventID|Event\s*ID)[=:\s]+(\d+).*?(?:Source|Provider)[=:\s]+(\S+)",
    re.IGNORECASE,
)
_EVTX_SIMPLE_PATTERN = re.compile(
    r"(?:Microsoft-Windows-\w+|Security|System|Application)\s*[/\\]\s*(?:Audit|Operational).*?(?:Event\s*ID|EventID)[=:\s]*(\d+)",
    re.IGNORECASE,
)

# PowerShell suspicious patterns
_PS_SUSPICIOUS = re.compile(
    r"(?:Invoke-Expression|IEX|Invoke-WebRequest|DownloadString|DownloadFile|"
    r"EncodedCommand|FromBase64String|Invoke-Mimikatz|Invoke-Shellcode|"
    r"New-Object\s+Net\.WebClient|Start-Process\s+.*-WindowStyle\s+Hidden)",
    re.IGNORECASE,
)


class WindowsEventParser(LogParser):
    """Parser for Windows Event Log entries (XML and text formats)."""

    log_type: ClassVar[LogType] = LogType.GENERIC
    name: ClassVar[str] = "windows_event"
    description: ClassVar[str] = "Windows Event Log (EVTX XML and text formats)"

    def can_parse(self, raw_line: str) -> bool:
        return bool(
            "<Event" in raw_line
            or _EVTX_ONELINE_PATTERN.search(raw_line)
            or _EVTX_SIMPLE_PATTERN.search(raw_line)
            or "Microsoft-Windows-" in raw_line
        )

    def parse(self, raw_line: str) -> ParsedLog | None:
        event_id = None
        source = None
        computer = None
        user = None
        message = raw_line

        # Try XML format
        xml_match = _EVTX_XML_PATTERN.search(raw_line)
        if xml_match:
            event_id = int(xml_match.group(1))
            # Extract fields from XML
            provider_m = re.search(r'Name=["\']([^"\']+)', raw_line)
            if provider_m:
                source = provider_m.group(1)
            computer_m = re.search(r"<Computer>([^<]+)", raw_line)
            if computer_m:
                computer = computer_m.group(1)
            user_m = re.search(r"<TargetUserName>([^<]+)", raw_line)
            if user_m:
                user = user_m.group(1)
        else:
            # Try one-line format
            oneline_m = _EVTX_ONELINE_PATTERN.search(raw_line)
            if oneline_m:
                event_id = int(oneline_m.group(1))
                source = oneline_m.group(2)
            else:
                simple_m = _EVTX_SIMPLE_PATTERN.search(raw_line)
                if simple_m:
                    event_id = int(simple_m.group(1))

        if event_id is None:
            return None

        # Detect source IP
        ip_match = re.search(r"(?:Source\s*(?:Network\s*)?Address|IpAddress)[=:\s]+(\d+\.\d+\.\d+\.\d+)", raw_line, re.IGNORECASE)
        source_ip = ip_match.group(1) if ip_match else None

        # Build parsed log
        is_suspicious = False
        tags = []
        ioc_values = []
        mitre_ids = []

        if event_id in _SUSPICIOUS_EVENT_IDS:
            info = _SUSPICIOUS_EVENT_IDS[event_id]
            if info[1]:  # has tags
                is_suspicious = True
                tags = list(info[1])
                mitre_ids = list(info[2])

        # Check PowerShell content
        if event_id == 4104 and _PS_SUSPICIOUS.search(raw_line):
            is_suspicious = True
            tags.append("malicious_powershell")
            if "T1059.001" not in mitre_ids:
                mitre_ids.append("T1059.001")

        if source_ip:
            ioc_values.append(("ip", source_ip))

        return ParsedLog(
            raw=raw_line,
            log_type=LogType.GENERIC,
            timestamp=datetime.now(),
            source_ip=source_ip,
            hostname=computer,
            username=user,
            process_name=source,
            message=f"EventID={event_id} {message[:200]}",
            is_suspicious=is_suspicious,
            detection_tags=tags,
            ioc_values=ioc_values,
            parsed_data={
                "event_id": event_id,
                "source": source,
                "format": "windows_event",
                "mitre_technique_ids": mitre_ids,
            },
        )
