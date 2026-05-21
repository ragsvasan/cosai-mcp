"""SARIF 2.1.0 structured builder — attacker bytes confined to message.text only."""
from __future__ import annotations

import html as _html_stdlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from cosai_mcp.catalog.models import Severity
from cosai_mcp.harness.result import ProbeResult

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
_TOOL_NAME = "cosai-mcp"
_TOOL_VERSION = "0.1.0"
_MAX_MESSAGE_CHARS = 4096

# Valid ruleIds: standard (T01-001 … T12-999) and adversarial (T03-ADV-001 etc.)
_RULE_ID_RE = re.compile(r"^T\d{2}(-[A-Z]{2,5})?-\d{3}$")

# WP8: compliance mapping is trimmed to CoSAI + NIST AI RMF only. The former
# MITRE ATLAS technique mapping was removed here and from the docs.


def _strip_control_chars(s: str) -> str:
    """Remove C0/C1/Cf control chars and Unicode line/paragraph separators.

    Keeps tab, LF, CR. Drops RTL/LTR bidi overrides (Cf) — these are
    stripped because unicodedata.category returns "C*" for them.
    Drops Zl (line separator U+2028) and Zp (paragraph separator U+2029)
    which are not control chars but act as implicit line breaks in some
    SARIF viewers and could be used for visual spoofing.
    """
    return "".join(
        ch for ch in s
        if (unicodedata.category(ch)[0] != "C" or ch in "\t\n\r")
        and unicodedata.category(ch) not in ("Zl", "Zp")
    )


def _sanitize_message(s: str) -> str:
    """Make a string safe for SARIF message.text.

    Steps:
    1. NFKC normalization — folds confusable homoglyphs (e.g. Cyrillic а → a).
    2. Strip C0/C1/Cf control chars and Unicode line/paragraph separators.
    3. Cap at _MAX_MESSAGE_CHARS.
    """
    s = unicodedata.normalize("NFKC", s)
    s = _strip_control_chars(s)
    if len(s) > _MAX_MESSAGE_CHARS:
        s = s[:_MAX_MESSAGE_CHARS] + "…[truncated]"
    return s


def _severity_to_level(severity: Severity) -> str:
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


@dataclass(frozen=True)
class ScanContext:
    """Metadata for the scan invocation — all scanner-controlled, none from responses.

    Frozen so SARIF output cannot be silently altered after builder construction.
    """
    target_url: str
    scan_timestamp: str   # ISO-8601
    catalog_hash: str     # SHA-256 hex of the loaded catalog content
    execution_successful: bool = True
    exit_code: int = 0


class SarifBuilder:
    """Build a SARIF 2.1.0 document from ProbeResult objects.

    Security invariants (enforced by build_json via _validate_sarif_structure):
    - Attacker-controlled bytes appear ONLY in result.message.text.
    - ruleId is always the catalog threat-definition ID (scanner-generated).
    - suppressions and partialFingerprints are never populated from response data.
    - executionSuccessful is driven by the scanner's own exit code.
    """

    def __init__(self, context: ScanContext) -> None:
        self._context = context
        self._rules: dict[str, dict[str, Any]] = {}
        self._results: list[dict[str, Any]] = []

    def add_result(
        self,
        result: ProbeResult,
        severity: Severity,
        rule_id: str,
        rule_name: str,
        rule_description: str,
        owasp_ref: str = "",
        cwe: tuple = (),
        confidence: str = "medium",
    ) -> None:
        """Register a probe result.

        Only FAILED probes produce SARIF findings. rule_id must be a valid
        catalog threat-definition ID (e.g. "T01-001"); caller is responsible
        for passing the catalog value, not response-derived content.

        owasp_ref and cwe must come from the signed catalog — never from
        response content. They are placed in rule properties, which are
        scanner-controlled fields.
        """
        if not _RULE_ID_RE.match(rule_id):
            raise ValueError(
                f"rule_id {rule_id!r} is not a valid catalog threat ID (expected T##-###)"
            )

        if rule_id not in self._rules:
            # Sanitize rule metadata before storing — caller may not be catalog-loader.
            rule_dict: dict[str, Any] = {
                "id": rule_id,
                "name": _sanitize_message(rule_name)[:128],
                "shortDescription": {"text": _sanitize_message(rule_description)[:512]},
                "defaultConfiguration": {"level": _severity_to_level(severity)},
            }

            # Framework metadata — all scanner-controlled (from signed catalog).
            # Never populated from response content.
            props: dict[str, Any] = {}
            if cwe:
                props["cwe"] = list(cwe)
            if owasp_ref:
                props["owasp_ref"] = owasp_ref
            # Confidence is scanner-controlled (from signed catalog) and is a
            # reporting label only — it never affects level/gating. "medium" is
            # the implicit default and is omitted so it does not synthesize an
            # otherwise-empty properties dict (only low/high carry signal).
            if confidence in ("low", "high"):
                props["confidence"] = confidence
            if props:
                rule_dict["properties"] = props
            # helpUri — standard SARIF field, points to OWASP MCP Top 10 project
            if owasp_ref:
                rule_dict["helpUri"] = "https://github.com/OWASP/www-project-mcp-top-10"

            self._rules[rule_id] = rule_dict

        if result.passed or result.inconclusive_reason:
            return

        # Build message text from assertion failures. response_body / assertion
        # .actual fields are pre-escaped at ingestion (make_probe_result) but we
        # still run _sanitize_message here to strip control chars and cap length.
        failed_assertions = [a for a in result.assertions if not a.passed]
        if failed_assertions:
            # AssertionResult.actual and .expected are HTML-escaped at ingestion
            # (make_probe_result). Unescape before embedding in SARIF plain-text
            # message.text — SARIF consumers display the literal string, not HTML.
            parts = [
                f"{a.target} {a.operator} "
                f"{_html_stdlib.unescape(a.expected)!r} "
                f"(got {_html_stdlib.unescape(a.actual)!r})"
                for a in failed_assertions
            ]
            raw = "; ".join(parts)
        elif result.error:
            raw = f"Probe error: {_html_stdlib.unescape(result.error)}"
        else:
            raw = "Probe failed (no assertion details)"

        sarif_result: dict[str, Any] = {
            # scanner-generated — never derived from response
            "ruleId": rule_id,
            "level": _severity_to_level(severity),
            # attacker bytes confined here, sanitized
            "message": {"text": _sanitize_message(raw)},
            # scanner-generated properties only
            "properties": {
                "probe_id": result.probe_id,
                "threat_id": result.threat_id,
                "duration_seconds": result.duration_seconds,
            },
        }
        # suppressions: absent — never populated from response content
        # partialFingerprints: absent — never populated from response content
        self._results.append(sarif_result)

    def build(self) -> dict[str, Any]:
        """Assemble and return the SARIF 2.1.0 document dict."""
        ctx = self._context
        invocation: dict[str, Any] = {
            "executionSuccessful": ctx.execution_successful,
            "commandLine": f"cosai scan {ctx.target_url}",
            "startTimeUtc": ctx.scan_timestamp,
            "properties": {
                "catalogHash": ctx.catalog_hash,
                "targetUrl": ctx.target_url,
            },
        }
        if not ctx.execution_successful:
            invocation["exitCode"] = ctx.exit_code

        return {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": _TOOL_NAME,
                            "version": _TOOL_VERSION,
                            "informationUri": "https://github.com/cosai-oasis/cosai-mcp",
                            "rules": list(self._rules.values()),
                        }
                    },
                    "results": self._results,
                    "invocations": [invocation],
                }
            ],
        }

    def build_json(self, indent: int = 2) -> str:
        """Build, validate structure, and return compact SARIF JSON."""
        doc = self.build()
        _validate_sarif_structure(doc)
        return json.dumps(doc, indent=indent, ensure_ascii=True)


def _validate_sarif_structure(doc: dict[str, Any]) -> None:
    """Structural validation of the SARIF document.

    Raises ValueError on any violation that would indicate attacker-controlled
    content leaked into scanner-controlled fields.
    """
    if doc.get("version") != _SARIF_VERSION:
        raise ValueError(f"SARIF version must be {_SARIF_VERSION!r}")

    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError("SARIF must have at least one run")

    run = runs[0]
    if "tool" not in run or "driver" not in run.get("tool", {}):
        raise ValueError("SARIF run must have tool.driver")
    if "results" not in run:
        raise ValueError("SARIF run must have results array")
    if "invocations" not in run:
        raise ValueError("SARIF run must have invocations array")

    for result in run["results"]:
        rule_id = result.get("ruleId", "")
        if not _RULE_ID_RE.match(rule_id):
            raise ValueError(
                f"SARIF result ruleId {rule_id!r} is not a valid catalog threat ID"
            )
        if "suppressions" in result:
            raise ValueError(
                "SARIF result must not contain suppressions field "
                "(must be scanner-generated only, never from response content)"
            )
        if "partialFingerprints" in result:
            raise ValueError(
                "SARIF result must not contain partialFingerprints field "
                "(must be scanner-generated only, never from response content)"
            )
