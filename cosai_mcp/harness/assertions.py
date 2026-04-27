"""Assertion evaluator — maps Assertion + response dict → AssertionResult."""
from __future__ import annotations

from typing import Any

from cosai_mcp.catalog.models import Assertion, Operator
from cosai_mcp.harness.result import AssertionResult, _html_escape


def _extract_target(response: dict[str, Any], target_path: str) -> Any:
    """Extract the value named by target_path from a response dict.

    Recognised paths:
    - ``response.error``       → bool: True only when 'error' key is present AND non-null
    - ``response.error_code``  → int | None (response.error.code)
    - ``response.body``        → str: canonical body from response["_body"] (set by context.py)
    - ``response.status_code`` → int | None (added by transport via _status_code)
    - Any dotted sub-path, e.g. ``response.result.content``
    """
    if target_path == "response.error":
        # Check key presence AND non-null: some buggy servers send "error": null
        # alongside "result", which is not a real error per JSON-RPC 2.0.
        error_val = response.get("error")
        return error_val is not None and error_val is not False

    if target_path == "response.error_code":
        error = response.get("error")
        if isinstance(error, dict):
            return error.get("code")
        return None

    if target_path == "response.body":
        # Single canonical source: _body is populated by context.py before assertions run
        return response.get("_body", "")

    if target_path == "response.status_code":
        return response.get("_status_code")

    # Generic dotted walk: "response.result.content" → response["result"]["content"]
    parts = target_path.split(".")
    current: Any = response
    for part in parts[1:]:  # skip the leading "response" segment
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def evaluate_assertion(assertion: Assertion, response: dict[str, Any]) -> AssertionResult:
    """Evaluate one assertion against a response dict.

    Returns an AssertionResult with passed=True if the assertion holds.
    All string fields in the returned AssertionResult are HTML-escaped.
    Never raises — any evaluation error is captured in the result.
    """
    actual = _extract_target(response, assertion.target)
    op = assertion.operator
    expected = assertion.value

    try:
        if op == Operator.EQ:
            passed = actual == expected
        elif op == Operator.NE:
            passed = actual != expected
        elif op == Operator.CONTAINS:
            passed = str(expected) in str(actual if actual is not None else "")
        elif op == Operator.NOT_CONTAINS:
            passed = str(expected) not in str(actual if actual is not None else "")
        elif op == Operator.MATCHES_REGEX:
            pattern = assertion.compiled_pattern
            target_str = str(actual if actual is not None else "")
            passed = bool(pattern.search(target_str)) if pattern else False  # type: ignore[union-attr]
        elif op in (Operator.STATUS_IN, Operator.ERROR_CODE_IN):
            passed = actual in expected  # type: ignore[operator]
        else:
            passed = False

        message = "passed" if passed else (
            f"expected {op.value!r} {expected!r}, got {actual!r}"
        )
    except Exception as exc:
        passed = False
        message = f"assertion evaluation error: {exc}"

    # HTML-escape all string fields at construction time (OWASP: store safe)
    return AssertionResult(
        target=assertion.target,
        operator=op.value,
        expected=_html_escape(str(expected)),
        actual=_html_escape(str(actual)),
        passed=passed,
        message=_html_escape(message),
    )
