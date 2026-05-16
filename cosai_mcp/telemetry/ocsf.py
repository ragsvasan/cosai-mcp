"""OCSF Detection Finding schema builder (class_uid 2004).

Converts cosai-mcp ProbeResult objects into OCSF-compliant event dicts that
can be ingested by any OCSF-compatible SIEM (Splunk, Elastic, Panther, etc.).

OCSF class: Detection Finding (2004)
OCSF category: Findings (2)
OCSF type: Detection Finding: Create (200401)

References:
    https://schema.ocsf.io/2.0.0/classes/detection_finding
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

# OCSF severity_id mapping (1=Informational … 5=Critical, 99=Other)
_SEVERITY_MAP: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
}

# OCSF status_id: 1=New, 2=In Progress, 3=Suppressed, 4=Resolved, 99=Other
_STATUS_NEW = 1

# OCSF class / type constants
_CLASS_UID = 2004           # Detection Finding
_CLASS_NAME = "Detection Finding"
_CATEGORY_UID = 2           # Findings
_CATEGORY_NAME = "Findings"
_TYPE_UID = 200401          # Detection Finding: Create
_TYPE_NAME = "Detection Finding: Create"

_PRODUCT_NAME = "cosai-mcp"
_VENDOR_NAME = "CoSAI"
_SCHEMA_VERSION = "2.0.0"


@dataclass(frozen=True)
class OcsfEvent:
    """Thin wrapper around an OCSF Detection Finding dict."""

    data: dict  # the raw OCSF event

    def to_dict(self) -> dict[str, Any]:
        return dict(self.data)


def build_detection_finding(
    *,
    probe_id: str,
    threat_id: str,
    passed: bool,
    target: str,
    duration_seconds: float = 0.0,
    severity: str = "medium",
    category: str | None = None,
    description: str | None = None,
    remediation: str | None = None,
    timestamp_ms: int | None = None,
) -> OcsfEvent:
    """Build an OCSF Detection Finding event from a cosai-mcp probe result.

    Parameters
    ----------
    probe_id:
        Unique probe identifier (e.g. ``"T01-001-p1"``).
    threat_id:
        Threat catalog ID (e.g. ``"T01-001"``).
    passed:
        ``True`` if the server passed the probe (no finding).
        ``False`` if a security finding was detected.
    target:
        MCP server URL that was probed.
    duration_seconds:
        Probe execution time.
    severity:
        CoSAI severity string (``"critical"``, ``"high"``, ``"medium"``,
        ``"low"``, ``"informational"``).
    category:
        CoSAI threat category (e.g. ``"T1"``).
    description:
        Human-readable description of the finding.
    remediation:
        Remediation guidance.
    timestamp_ms:
        Unix epoch milliseconds.  Defaults to ``time.time_ns() // 1_000_000``.
    """
    ts_ms = timestamp_ms if timestamp_ms is not None else int(time.time() * 1000)
    severity_id = _SEVERITY_MAP.get(severity.lower(), 99)
    status_id = _STATUS_NEW

    # The finding uid is the probe_id — unique per probe per scan.
    finding: dict[str, Any] = {
        "uid": probe_id,
        "title": threat_id,
        "types": ["Security Finding"],
        "created_time": ts_ms,
    }
    if description:
        finding["desc"] = description

    # Rule object maps to the catalog threat entry
    rule: dict[str, Any] = {"uid": threat_id, "name": threat_id}
    if category:
        rule["category"] = category
    if description:
        rule["desc"] = description

    finding["rule"] = rule

    if remediation:
        finding["remediation"] = {"desc": remediation}

    # Resource is the probed MCP server
    resource: dict[str, Any] = {"uid": target, "name": "MCP Server", "type": "Other"}

    event: dict[str, Any] = {
        "class_uid": _CLASS_UID,
        "class_name": _CLASS_NAME,
        "category_uid": _CATEGORY_UID,
        "category_name": _CATEGORY_NAME,
        "type_uid": _TYPE_UID,
        "type_name": _TYPE_NAME,
        "time": ts_ms,
        "severity_id": severity_id,
        "severity": severity.capitalize(),
        "status_id": status_id,
        "status": "New",
        "activity_id": 1,  # Create
        "activity_name": "Create",
        "finding": finding,
        "resources": [resource],
        "metadata": {
            "version": _SCHEMA_VERSION,
            "product": {
                "name": _PRODUCT_NAME,
                "vendor_name": _VENDOR_NAME,
            },
            "log_provider": _VENDOR_NAME,
        },
        "unmapped": {
            "passed": passed,
            "duration_seconds": round(duration_seconds, 4),
            "probe_id": probe_id,
            "threat_id": threat_id,
        },
    }

    return OcsfEvent(data=event)


def probe_result_to_ocsf(
    result: Any,  # ProbeResult — imported lazily to avoid circular deps
    target: str,
    severity: str = "medium",
    category: str | None = None,
    description: str | None = None,
    remediation: str | None = None,
) -> OcsfEvent:
    """Convert a ProbeResult to an OCSF Detection Finding event."""
    return build_detection_finding(
        probe_id=result.probe_id,
        threat_id=result.threat_id,
        passed=result.passed,
        target=target,
        duration_seconds=result.duration_seconds,
        severity=severity,
        category=category,
        description=description,
        remediation=remediation,
    )
