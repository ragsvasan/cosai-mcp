"""ProbeResult and AssertionResult — frozen, HTML-escaped, JSON-serializable."""
from __future__ import annotations

import html
import warnings
from dataclasses import dataclass
from typing import Any

from cosai_mcp.exceptions import OutputTruncatedWarning

# Matching the stdio 10 MB cap from locked architecture
_BODY_SIZE_CAP = 10 * 1024 * 1024  # 10 MB


@dataclass(frozen=True)
class AssertionResult:
    """Outcome of a single assertion evaluation.

    All string fields are HTML-escaped at construction time (in evaluate_assertion).
    """
    target: str
    operator: str
    expected: str     # HTML-escaped str representation
    actual: str       # HTML-escaped str representation
    passed: bool
    message: str      # HTML-escaped

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "operator": self.operator,
            "expected": self.expected,
            "actual": self.actual,
            "passed": self.passed,
            "message": self.message,
        }


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of executing one probe against an MCP server.

    All captured response content is HTML-escaped at construction time.
    This object is immutable — no fields can be changed after creation.

    ``inconclusive_reason``: set when the probe could not test the security
    property because the server rejected the payload for an unrelated reason
    (e.g. schema validation, unknown argument).  An inconclusive result is
    neither a PASS nor a FINDING — it means the test could not run.
    Inconclusive results do NOT trigger exit code 1.
    """
    probe_id: str
    threat_id: str
    passed: bool
    status_code: int | None
    response_body: str        # HTML-escaped, capped at _BODY_SIZE_CAP
    error: str | None         # HTML-escaped; set if the probe itself errored
    assertions: tuple[AssertionResult, ...]
    duration_seconds: float
    inconclusive_reason: str | None = None  # HTML-escaped
    synthesis_attempted: bool = False  # True when adaptive retry was attempted
    canary_detected: bool = False  # True when canary string was found in response (adversarial mode)

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "threat_id": self.threat_id,
            "passed": self.passed,
            "status_code": self.status_code,
            "response_body": self.response_body,
            "error": self.error,
            "assertions": [a.to_dict() for a in self.assertions],
            "duration_seconds": self.duration_seconds,
            "inconclusive_reason": self.inconclusive_reason,
            "synthesis_attempted": self.synthesis_attempted,
            "canary_detected": self.canary_detected,
        }


def _html_escape(text: object) -> str:
    """Convert to str, cap at _BODY_SIZE_CAP, then HTML-escape.

    The cap prevents memory exhaustion when a hostile server returns a huge body.
    The escape prevents second-order XSS when results are rendered in HTML reports.
    """
    if text is None:
        return ""
    s = str(text)
    if len(s) > _BODY_SIZE_CAP:
        warnings.warn(
            f"Response content truncated from {len(s)} to {_BODY_SIZE_CAP} bytes",
            OutputTruncatedWarning,
            stacklevel=2,
        )
        s = s[:_BODY_SIZE_CAP]
    return html.escape(s, quote=True)


def make_probe_result(
    *,
    probe_id: str,
    threat_id: str,
    passed: bool,
    assertions: tuple[AssertionResult, ...],
    response: dict[str, Any] | None = None,
    error: str | None = None,
    duration_seconds: float = 0.0,
    inconclusive_reason: str | None = None,
    synthesis_attempted: bool = False,
) -> ProbeResult:
    """Construct a ProbeResult, HTML-escaping all captured response content.

    Response body is read from ``response["_body"]`` — context.py is the
    canonical source for populating ``_body`` via _extract_target semantics.
    """
    status_code: int | None = None
    body: str = ""

    if response is not None:
        status_code = response.get("_status_code")
        raw_body = response.get("_body", "")
        body = _html_escape(raw_body)

    return ProbeResult(
        probe_id=probe_id,
        threat_id=threat_id,
        passed=passed,
        status_code=status_code,
        response_body=body,
        error=_html_escape(error) if error else None,
        assertions=assertions,
        duration_seconds=duration_seconds,
        inconclusive_reason=_html_escape(inconclusive_reason) if inconclusive_reason else None,
        synthesis_attempted=synthesis_attempted,
    )
