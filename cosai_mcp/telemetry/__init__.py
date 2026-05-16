"""SIEM/SOAR telemetry emitter for cosai-mcp scan findings.

Three sub-modules:
* emitter   — TelemetryEmitter protocol + NullEmitter + HttpEmitter
* ocsf      — OCSF Detection Finding schema builder (class_uid 2004)
* anomaly   — threshold-based anomaly rules over emitted events
"""
from cosai_mcp.telemetry.emitter import (
    TelemetryEmitter,
    NullEmitter,
    HttpEmitter,
    EmitResult,
)
from cosai_mcp.telemetry.ocsf import OcsfEvent, build_detection_finding
from cosai_mcp.telemetry.anomaly import (
    AnomalyRule,
    AnomalyAlert,
    AnomalyDetector,
)

__all__ = [
    "TelemetryEmitter",
    "NullEmitter",
    "HttpEmitter",
    "EmitResult",
    "OcsfEvent",
    "build_detection_finding",
    "AnomalyRule",
    "AnomalyAlert",
    "AnomalyDetector",
]
