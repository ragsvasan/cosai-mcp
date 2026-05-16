"""Tool inventory capture, signing, and drift detection.

Three sub-modules:
* snapshot   — capture a ToolInventory from a live MCP server
* signing    — Ed25519 sign/verify inventory artifacts (per-installation key)
* drift      — compare two ToolInventory snapshots, return DriftReport
"""
from cosai_mcp.inventory.snapshot import ToolInventory, ToolRecord, capture
from cosai_mcp.inventory.signing import sign_inventory, verify_inventory
from cosai_mcp.inventory.drift import DriftReport, DriftKind, detect_drift

__all__ = [
    "ToolInventory",
    "ToolRecord",
    "capture",
    "sign_inventory",
    "verify_inventory",
    "DriftReport",
    "DriftKind",
    "detect_drift",
]
