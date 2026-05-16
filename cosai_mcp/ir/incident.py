"""IncidentRecord — structured IR artifact for compromised MCP servers.

An IncidentRecord captures:
- Target server URL and scan context
- Triggering findings (probe_id, threat_id, severity)
- Recommended containment actions
- Machine-readable metadata for SIEM/SOAR playbooks

IncidentRecords are serialised as JSON and can be consumed by:
  ``cosai ir contain <incident.json>``
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ContainmentAction(str, Enum):
    """Available automated containment responses."""

    EMIT_INCIDENT = "emit_incident"
    """POST an OCSF Security Incident (class_uid 2001) to a SIEM webhook."""

    QUARANTINE_REPORT = "quarantine_report"
    """Write a signed JSON incident report to disk for human review."""

    BLOCK_EGRESS = "block_egress"
    """Generate firewall block commands (printed; not executed automatically)."""

    SESSION_KILL = "session_kill"
    """Attempt a best-effort protocol-level close of the MCP connection."""


class IncidentSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# OCSF severity_id mapping
_OCSF_SEV: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
}

_SEV_RANK: dict[str, int] = {
    "info": 0, "informational": 0,
    "low": 1, "medium": 2, "high": 3, "critical": 4,
}


@dataclass(frozen=True)
class FindingSummary:
    """Minimal finding record embedded in an IncidentRecord."""

    probe_id: str
    threat_id: str
    severity: str  # lowercase string matching _OCSF_SEV keys


@dataclass(frozen=True)
class IncidentRecord:
    """Immutable incident record produced after a cosai-mcp scan.

    Parameters
    ----------
    incident_id:
        UUID-based unique identifier for this incident.
    target_url:
        The MCP server that triggered the incident.
    scan_timestamp:
        ISO-8601 UTC timestamp of the scan that produced this incident.
    triggered_at_ms:
        Unix epoch milliseconds when the incident was created.
    findings:
        Probe results that triggered the incident (non-passing probes).
    anomaly_rules:
        Names of AnomalyRule values that fired (e.g. "high_finding_rate").
    severity:
        Worst-case severity across all findings.
    recommended_actions:
        Ordered list of ContainmentAction values the operator should take.
    """

    incident_id: str
    target_url: str
    scan_timestamp: str
    triggered_at_ms: int
    findings: tuple[FindingSummary, ...]
    anomaly_rules: tuple[str, ...]
    severity: IncidentSeverity
    recommended_actions: tuple[ContainmentAction, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "target_url": self.target_url,
            "scan_timestamp": self.scan_timestamp,
            "triggered_at_ms": self.triggered_at_ms,
            "findings": [
                {"probe_id": f.probe_id, "threat_id": f.threat_id, "severity": f.severity}
                for f in self.findings
            ],
            "anomaly_rules": list(self.anomaly_rules),
            "severity": self.severity.value,
            "recommended_actions": [a.value for a in self.recommended_actions],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "IncidentRecord":
        return cls(
            incident_id=str(d["incident_id"]),
            target_url=str(d["target_url"]),
            scan_timestamp=str(d["scan_timestamp"]),
            triggered_at_ms=int(d["triggered_at_ms"]),
            findings=tuple(
                FindingSummary(
                    probe_id=str(f["probe_id"]),
                    threat_id=str(f["threat_id"]),
                    severity=str(f.get("severity", "medium")),
                )
                for f in d.get("findings", [])
            ),
            anomaly_rules=tuple(str(r) for r in d.get("anomaly_rules", [])),
            severity=IncidentSeverity(d.get("severity", "high")),
            recommended_actions=tuple(
                ContainmentAction(a) for a in d.get("recommended_actions", [])
            ),
        )


def build_incident(
    target_url: str,
    scan_timestamp: str,
    findings: list[dict[str, Any]],
    anomaly_rules: list[str] | None = None,
    probe_severity: dict[str, str] | None = None,
) -> IncidentRecord:
    """Construct an IncidentRecord from scan artefacts.

    Parameters
    ----------
    target_url:
        MCP server that was scanned.
    scan_timestamp:
        ISO-8601 UTC timestamp of the scan.
    findings:
        List of dicts with at least ``probe_id`` and ``threat_id``; optionally
        ``severity``.  Non-passing probe results from the scan engine.
    anomaly_rules:
        Names of anomaly rules that fired (from AnomalyDetector).
    probe_severity:
        Optional mapping of probe_id → severity string to enrich findings.
    """
    probe_severity = probe_severity or {}
    anomaly_rules = anomaly_rules or []

    summaries = tuple(
        FindingSummary(
            probe_id=str(f["probe_id"]),
            threat_id=str(f["threat_id"]),
            severity=probe_severity.get(str(f["probe_id"]), f.get("severity", "medium")),
        )
        for f in findings
    )

    # Worst-case severity across all findings
    worst = max(
        (_SEV_RANK.get(s.severity, 0) for s in summaries),
        default=_SEV_RANK["medium"],
    )
    severity_str = next(
        k for k, v in _SEV_RANK.items() if v == worst and k in {e.value for e in IncidentSeverity}
    )

    # Default recommended actions ordered by urgency
    actions: list[ContainmentAction] = [
        ContainmentAction.EMIT_INCIDENT,
        ContainmentAction.QUARANTINE_REPORT,
    ]
    if worst >= _SEV_RANK["high"]:
        actions.insert(0, ContainmentAction.SESSION_KILL)
        actions.append(ContainmentAction.BLOCK_EGRESS)

    return IncidentRecord(
        incident_id=str(uuid.uuid4()),
        target_url=target_url,
        scan_timestamp=scan_timestamp,
        triggered_at_ms=int(time.time() * 1000),
        findings=summaries,
        anomaly_rules=tuple(anomaly_rules),
        severity=IncidentSeverity(severity_str),
        recommended_actions=tuple(actions),
    )
