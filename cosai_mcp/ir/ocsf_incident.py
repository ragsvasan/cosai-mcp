"""OCSF Security Incident schema builder (class_uid 2001).

Converts an IncidentRecord into an OCSF-compliant Security Incident event
that can be ingested by any OCSF-compatible SIEM to trigger IR playbooks.

OCSF class: Security Incident (2001)
OCSF category: Findings (2)
OCSF type: Security Incident: Create (200101)

References:
    https://schema.ocsf.io/2.0.0/classes/security_incident
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from cosai_mcp.ir.incident import IncidentRecord, _OCSF_SEV

_CLASS_UID = 2001
_CLASS_NAME = "Security Incident"
_CATEGORY_UID = 2
_CATEGORY_NAME = "Findings"
_TYPE_UID = 200101
_TYPE_NAME = "Security Incident: Create"

_PRODUCT_NAME = "cosai-mcp"
_VENDOR_NAME = "CoSAI"
_SCHEMA_VERSION = "2.0.0"

# OCSF verdict_id: 1=true_positive (we only build incidents for confirmed findings)
_VERDICT_TRUE_POSITIVE = 1


@dataclass(frozen=True)
class OcsfIncident:
    """Thin wrapper around an OCSF Security Incident dict."""

    data: dict

    def to_dict(self) -> dict[str, Any]:
        return dict(self.data)


def build_ocsf_incident(incident: IncidentRecord) -> OcsfIncident:
    """Build an OCSF Security Incident event from an IncidentRecord.

    Parameters
    ----------
    incident:
        The IR incident record produced by ``build_incident()``.

    Returns
    -------
    OcsfIncident
        Thin wrapper over the OCSF-compliant event dict.
    """
    ts_ms = incident.triggered_at_ms or int(time.time() * 1000)
    severity_id = _OCSF_SEV.get(incident.severity.value, 99)

    finding_info: dict[str, Any] = {
        "uid": incident.incident_id,
        "title": f"MCP Server Security Incident: {incident.target_url}",
        "types": ["Security Incident"],
        "created_time": ts_ms,
        "related_events": [
            {"uid": f.probe_id} for f in incident.findings
        ],
    }

    if incident.anomaly_rules:
        finding_info["desc"] = (
            "Anomaly rules fired: " + ", ".join(incident.anomaly_rules)
        )

    resource: dict[str, Any] = {
        "uid": incident.target_url,
        "name": "MCP Server",
        "type": "Other",
    }

    event: dict[str, Any] = {
        "class_uid": _CLASS_UID,
        "class_name": _CLASS_NAME,
        "category_uid": _CATEGORY_UID,
        "category_name": _CATEGORY_NAME,
        "type_uid": _TYPE_UID,
        "type_name": _TYPE_NAME,
        "time": ts_ms,
        "severity_id": severity_id,
        "severity": incident.severity.value.capitalize(),
        "status_id": 1,  # New
        "status": "New",
        "activity_id": 1,  # Create
        "activity_name": "Create",
        "verdict_id": _VERDICT_TRUE_POSITIVE,
        "verdict": "True Positive",
        "finding_info": finding_info,
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
            "incident_id": incident.incident_id,
            "scan_timestamp": incident.scan_timestamp,
            "target_url": incident.target_url,
            "finding_count": len(incident.findings),
            "anomaly_rules": list(incident.anomaly_rules),
            "recommended_actions": [a.value for a in incident.recommended_actions],
        },
    }

    return OcsfIncident(data=event)
