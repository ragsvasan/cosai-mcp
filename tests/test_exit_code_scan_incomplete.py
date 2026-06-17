"""Regression tests for _determine_exit_code exit-2 (scan-incomplete) semantics.

Scope: exit 2 fires when ALL non-suppressed, non-passed probes above the threshold
have r.error set (timed out / crashed). Inconclusive probes (couldn't test the
condition) do NOT trigger exit 2 — they are distinct from errors.
"""
from __future__ import annotations

from cosai_mcp.api import _determine_exit_code
from cosai_mcp.harness.result import ProbeResult


def _make_probe(
    probe_id: str = "T01-001",
    threat_id: str = "T01",
    passed: bool = True,
    error: str | None = None,
    inconclusive_reason: str | None = None,
    suppressed: bool = False,
) -> ProbeResult:
    return ProbeResult(
        probe_id=probe_id,
        threat_id=threat_id,
        passed=passed,
        status_code=None,
        response_body="",
        error=error,
        assertions=(),
        duration_seconds=0.1,
        inconclusive_reason=inconclusive_reason,
        suppressed=suppressed,
    )


def test_regression_all_timeout_returns_exit2() -> None:
    """Adversarial server delays every response — all probes error with timeout.
    _determine_exit_code must return 2, not 0."""
    probe_results = [
        _make_probe(probe_id=f"T01-00{i}", passed=False, error="timed out after 10.0s")
        for i in range(1, 5)
    ]
    code = _determine_exit_code(
        probe_results=probe_results,
        scenario_results=[],
        fail_on="critical",
    )
    assert code == 2, f"Expected exit 2 (scan-incomplete), got {code}"


def test_regression_all_inconclusive_returns_exit0() -> None:
    """Inconclusive probes (tool not found) are not the same as errors.
    All-inconclusive must NOT trigger exit 2 — the scanner ran fine, the
    tool-under-test was simply absent."""
    probe_results = [
        _make_probe(
            probe_id=f"T03-00{i}",
            threat_id="T03",
            passed=False,
            inconclusive_reason="tool not found: ping",
        )
        for i in range(1, 4)
    ]
    code = _determine_exit_code(
        probe_results=probe_results,
        scenario_results=[],
        fail_on="critical",
    )
    assert code == 0, f"All-inconclusive should be exit 0 (not scan-incomplete), got {code}"


def test_mixed_some_clean_returns_exit0() -> None:
    """One clean pass alongside one errored probe — a real verdict exists.
    Must return 0, not 2."""
    probe_results = [
        _make_probe(probe_id="T01-001", passed=True),
        _make_probe(probe_id="T01-002", passed=False, error="timed out after 10.0s"),
    ]
    code = _determine_exit_code(
        probe_results=probe_results,
        scenario_results=[],
        fail_on="critical",
    )
    assert code == 0, f"Expected exit 0 (clean verdict exists), got {code}"


def test_empty_probe_results_returns_exit0() -> None:
    """No probes at all — nothing to be incomplete about. Must return 0."""
    code = _determine_exit_code(
        probe_results=[],
        scenario_results=[],
        fail_on="critical",
    )
    assert code == 0, f"Expected exit 0 (nothing to scan), got {code}"


def test_suppressed_probes_excluded_from_qualifying() -> None:
    """Suppressed (baseline-accepted) probes are not qualifying.
    If only suppressed probes exist and all are errored, must still return 0."""
    probe_results = [
        _make_probe(probe_id="T01-001", passed=False, error="timed out after 10.0s", suppressed=True),  # noqa: E501
    ]
    code = _determine_exit_code(
        probe_results=probe_results,
        scenario_results=[],
        fail_on="critical",
    )
    assert code == 0, f"Suppressed probes should not trigger exit 2, got {code}"


def test_all_timeout_with_threat_severity_returns_exit2() -> None:
    """With threat_severity map provided, qualifying includes threshold check.
    All above-threshold probes timing out still returns exit 2."""
    from cosai_mcp.catalog.models import Severity

    threat_severity = {"T01": Severity("critical")}
    probe_results = [
        _make_probe(probe_id="T01-001", threat_id="T01", passed=False, error="timed out after 10.0s"),  # noqa: E501
    ]
    code = _determine_exit_code(
        probe_results=probe_results,
        scenario_results=[],
        fail_on="critical",
        threat_severity=threat_severity,
    )
    assert code == 2, f"Expected exit 2 (scan-incomplete), got {code}"


def test_regression_passed_probe_with_inconclusive_reason_not_exit2() -> None:
    """Panel FIX [1/2]: a passed=True probe with inconclusive_reason set must not
    be treated as 'unverified'. The passing verdict is real."""
    probe_results = [
        _make_probe(probe_id="T01-001", passed=True, inconclusive_reason="note: partial"),
        _make_probe(probe_id="T01-002", passed=False, error="timed out after 10.0s"),
    ]
    code = _determine_exit_code(
        probe_results=probe_results,
        scenario_results=[],
        fail_on="critical",
    )
    assert code == 0, f"passed=True probe must not be in qualifying, got {code}"


def test_regression_passed_probe_with_inconclusive_reason_not_exit2_with_severity_map() -> None:
    """Panel FIX [2]: same check with threat_severity map provided."""
    from cosai_mcp.catalog.models import Severity

    threat_severity = {"T01": Severity("critical")}
    probe_results = [
        _make_probe(probe_id="T01-001", threat_id="T01", passed=True, inconclusive_reason="note: partial"),  # noqa: E501
        _make_probe(probe_id="T01-002", threat_id="T01", passed=False, error="timed out after 10.0s"),  # noqa: E501
    ]
    code = _determine_exit_code(
        probe_results=probe_results,
        scenario_results=[],
        fail_on="critical",
        threat_severity=threat_severity,
    )
    assert code == 0, f"passed=True probe with severity map must not be in qualifying, got {code}"
