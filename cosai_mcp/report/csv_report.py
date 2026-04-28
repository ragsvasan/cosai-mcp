"""CSV report writer — one row per probe result, Excel-compatible."""
from __future__ import annotations

import csv
import io
from pathlib import Path

from cosai_mcp.api import ScanResult
from cosai_mcp.catalog.models import ThreatDefinition
from cosai_mcp.report.remediation import get_remediation

_CATEGORY_NAMES: dict[str, str] = {
    "T1":  "Improper Authentication",
    "T2":  "Missing Access Control",
    "T3":  "Input Validation Failures",
    "T4":  "Data/Control Boundary",
    "T5":  "Inadequate Data Protection",
    "T6":  "Integrity / Verification Failures",
    "T7":  "Session Security Failures",
    "T8":  "Network Binding Failures",
    "T9":  "Trust Boundary Failures",
    "T10": "Resource Management",
    "T11": "Supply Chain / Lifecycle",
    "T12": "Insufficient Logging",
}

_HEADERS = [
    "probe_id",
    "threat_id",
    "category",
    "category_name",
    "severity",
    "engine",
    "status",
    "assertion_target",
    "assertion_operator",
    "assertion_expected",
    "assertion_actual",
    "assertion_passed",
    "response_body",
    "error",
    "duration_seconds",
    "remediation",
    "remediation_spec_ref",
    "remediation_fix_shape",
]


def write_csv_report(result: ScanResult, path: Path) -> None:
    """Write a CSV findings report to *path*.

    One row per probe result.  Scenario results get one row per step.
    All fields are plain text — no formulas, no macros — safe to open in Excel.
    """
    threat_by_id: dict[str, ThreatDefinition] = {t.id: t for t in result.threats}

    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL)
    writer.writerow(_HEADERS)

    # --- probe results ---
    for r in result.probe_results:
        threat = threat_by_id.get(r.threat_id)
        category = threat.category if threat else ""
        severity = threat.severity.value if threat else ""
        remediation = getattr(threat, "remediation", "") if threat else ""
        rem_block = get_remediation(r.probe_id)
        rem_spec_ref = rem_block.spec_ref if rem_block else ""
        rem_fix_shape = rem_block.fix_shape if rem_block else ""

        # One row per failed assertion; one row total if all passed (or error)
        if r.assertions:
            for a in r.assertions:
                writer.writerow([
                    r.probe_id,
                    r.threat_id,
                    category,
                    _CATEGORY_NAMES.get(category, category),
                    severity,
                    "prober",
                    "PASS" if r.passed else "FINDING",
                    a.target,
                    a.operator,
                    _safe_cell(str(a.expected)),
                    _safe_cell(str(a.actual)),
                    "yes" if a.passed else "no",
                    _safe_cell(_truncate(r.response_body, 500)),
                    _safe_cell(r.error or ""),
                    f"{r.duration_seconds:.2f}",
                    remediation,
                    rem_spec_ref,
                    rem_fix_shape,
                ])
        else:
            writer.writerow([
                r.probe_id,
                r.threat_id,
                category,
                _CATEGORY_NAMES.get(category, category),
                severity,
                "prober",
                "PASS" if r.passed else ("ERROR" if r.error else "FINDING"),
                "", "", "", "", "",
                _safe_cell(_truncate(r.response_body, 500)),
                _safe_cell(r.error or ""),
                f"{r.duration_seconds:.2f}",
                remediation,
                rem_spec_ref,
                rem_fix_shape,
            ])

    # --- scenario results (one row per step) ---
    for sr in result.scenario_results:
        category = sr.threat_categories[0] if sr.threat_categories else ""
        for step in sr.step_results:
            if step.failures:
                for f in step.failures:
                    writer.writerow([
                        sr.scenario_id,
                        sr.scenario_id,
                        category,
                        _CATEGORY_NAMES.get(category, category),
                        "high",
                        "stateful",
                        "PASS" if step.passed else "FINDING",
                        f.target,
                        f.operator,
                        str(f.expected),
                        str(f.actual),
                        "no",
                        "",
                        step.error or "",
                        "",
                        f"Step {step.step_index}: {step.description}",
                        "",  # remediation_spec_ref
                        "",  # remediation_fix_shape
                    ])
            else:
                writer.writerow([
                    sr.scenario_id,
                    sr.scenario_id,
                    category,
                    _CATEGORY_NAMES.get(category, category),
                    "high",
                    "stateful",
                    "PASS" if step.passed else ("ERROR" if step.error else "FINDING"),
                    "", "", "", "", "",
                    "",
                    step.error or "",
                    "",
                    f"Step {step.step_index}: {step.description}",
                    "",  # remediation_spec_ref
                    "",  # remediation_fix_shape
                ])

    path.write_text(buf.getvalue(), encoding="utf-8-sig")  # utf-8-sig = Excel-compatible BOM


def _truncate(s: str, max_len: int) -> str:
    if not s:
        return ""
    if len(s) > max_len:
        return s[:max_len] + "…"
    return s


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _safe_cell(s: str) -> str:
    """Prefix cells that start with formula-injection characters with a tab.

    Excel treats cells starting with ``=``, ``+``, ``-``, ``@`` as formulas.
    Prefixing with a tab character disarms the injection while preserving content.
    This applies to all attacker-controlled string fields (response_body, error,
    assertion actual values) — not to scanner-authored fields like probe_id.
    """
    if not s:
        return s
    if s[0] in _FORMULA_PREFIXES:
        return "\t" + s
    return s
