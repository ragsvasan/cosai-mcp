"""Python API tests — Scanner, ScanResult, scrub_env, COVERAGE_MATRIX."""
from __future__ import annotations

import os
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

import pytest

from cosai_mcp.api import (
    CATALOG_ROOT,
    COVERAGE_MATRIX,
    MIDDLEWARE_ONLY_CATEGORIES,
    ScanResult,
    Scanner,
    _catalog_hash,
    _determine_exit_code,
    _normalise_categories,
    _parse_target,
    scrub_env,
)
from cosai_mcp.catalog.models import Severity
from cosai_mcp.exceptions import TargetUnreachableError


# ---------------------------------------------------------------------------
# _parse_target
# ---------------------------------------------------------------------------

class TestParseTarget:
    def test_http_default_port(self) -> None:
        host, port, url = _parse_target("http://localhost:8000")
        assert host == "localhost"
        assert port == 8000
        assert url == "http://localhost:8000"

    def test_https_default_port(self) -> None:
        host, port, url = _parse_target("https://mcp.example.com")
        assert host == "mcp.example.com"
        assert port == 443

    def test_http_no_port_defaults_to_80(self) -> None:
        host, port, _ = _parse_target("http://example.com")
        assert port == 80

    def test_invalid_url_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid target URL"):
            _parse_target("not-a-url")


# ---------------------------------------------------------------------------
# _normalise_categories
# ---------------------------------------------------------------------------

class TestNormaliseCategories:
    def test_none_returns_none(self) -> None:
        assert _normalise_categories(None) is None

    def test_all_string_returns_none(self) -> None:
        assert _normalise_categories(["all"]) is None
        assert _normalise_categories(["ALL"]) is None

    def test_specific_categories_normalised(self) -> None:
        result = _normalise_categories(["t1", "T3"])
        assert result == frozenset({"T1", "T3"})


# ---------------------------------------------------------------------------
# _catalog_hash
# ---------------------------------------------------------------------------

class TestCatalogHash:
    def test_deterministic(self) -> None:
        from cosai_mcp.catalog.models import ThreatDefinition, Severity, Provenance

        def _make_threat(id_: str) -> ThreatDefinition:
            return ThreatDefinition(
                schema_version="1.0",
                id=id_,
                category="T1",
                severity=Severity.CRITICAL,
                cosai_ref="T1",
                owasp_ref="MCP-A1",
                cwe=("CWE-287",),
                probes=(),
                remediation="Fix it.",
                references=(),
                provenance=Provenance.OFFICIAL,
            )

        t1 = _make_threat("T01-001")
        t2 = _make_threat("T01-002")

        hash1 = _catalog_hash([t1, t2])
        hash2 = _catalog_hash([t2, t1])  # order should not matter
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex

    def test_empty_catalog(self) -> None:
        h = _catalog_hash([])
        assert len(h) == 64


# ---------------------------------------------------------------------------
# _determine_exit_code
# ---------------------------------------------------------------------------

class TestDetermineExitCode:
    def _make_probe_result(self, *, passed: bool, error: str | None = None):
        from cosai_mcp.harness.result import ProbeResult
        return ProbeResult(
            probe_id="T01-001-p1",
            threat_id="T01-001",
            passed=passed,
            status_code=200 if passed else 400,
            response_body="",
            error=error,
            assertions=(),
            duration_seconds=0.1,
        )

    def _make_scenario_result(self, *, passed: bool, status: str = "complete"):
        from cosai_mcp.stateful.harness import ScenarioResult
        return ScenarioResult(
            scenario_id="T2-SC-001",
            scenario_name="test",
            threat_categories=("T2",),
            status=status,  # type: ignore[arg-type]
            passed=passed,
            step_results=(),
        )

    def test_clean_returns_0(self) -> None:
        r = self._make_probe_result(passed=True)
        code = _determine_exit_code([r], [], "critical")
        assert code == 0

    def test_finding_returns_1(self) -> None:
        r = self._make_probe_result(passed=False)
        code = _determine_exit_code([r], [], "critical")
        assert code == 1

    def test_probe_error_returns_2(self) -> None:
        r = self._make_probe_result(passed=False, error="subprocess crashed")
        code = _determine_exit_code([r], [], "critical")
        assert code == 2

    def test_scan_incomplete_returns_2(self) -> None:
        r = self._make_scenario_result(passed=False, status="scan-incomplete")
        code = _determine_exit_code([], [r], "critical")
        assert code == 2

    def test_no_results_returns_0(self) -> None:
        assert _determine_exit_code([], [], "critical") == 0


# ---------------------------------------------------------------------------
# ScanResult properties
# ---------------------------------------------------------------------------

class TestScanResult:
    def _make(self, **kwargs) -> ScanResult:
        defaults = dict(
            target_url="http://t:8000",
            threats=(),
            probe_results=(),
            scenario_results=(),
            scan_timestamp="2026-01-01T00:00:00+00:00",
            catalog_hash="abc",
            exit_code=0,
        )
        defaults.update(kwargs)
        return ScanResult(**defaults)

    def test_has_findings_false_when_all_pass(self) -> None:
        from cosai_mcp.harness.result import ProbeResult
        pr = ProbeResult(
            probe_id="T01-001-p1", threat_id="T01-001", passed=True,
            status_code=200, response_body="", error=None, assertions=(),
            duration_seconds=0.0,
        )
        r = self._make(probe_results=(pr,))
        assert not r.has_findings

    def test_has_findings_true_when_probe_fails(self) -> None:
        from cosai_mcp.harness.result import ProbeResult
        pr = ProbeResult(
            probe_id="T01-001-p1", threat_id="T01-001", passed=False,
            status_code=200, response_body="", error=None, assertions=(),
            duration_seconds=0.0,
        )
        r = self._make(probe_results=(pr,))
        assert r.has_findings

    def test_is_incomplete_true_for_scan_incomplete(self) -> None:
        from cosai_mcp.stateful.harness import ScenarioResult
        sr = ScenarioResult(
            scenario_id="S1", scenario_name="t", threat_categories=(),
            status="scan-incomplete", passed=False, step_results=(),
        )
        r = self._make(scenario_results=(sr,))
        assert r.is_incomplete

    def test_is_incomplete_false_for_complete(self) -> None:
        from cosai_mcp.stateful.harness import ScenarioResult
        sr = ScenarioResult(
            scenario_id="S1", scenario_name="t", threat_categories=(),
            status="complete", passed=True, step_results=(),
        )
        r = self._make(scenario_results=(sr,))
        assert not r.is_incomplete

    def test_frozen_immutable(self) -> None:
        r = self._make()
        with pytest.raises((TypeError, AttributeError)):
            r.exit_code = 99  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Scanner.run()
# ---------------------------------------------------------------------------

class TestScanner:
    def test_python_api_scanner_run(self) -> None:
        """Scanner(...).run(categories=["T1"]) returns ScanResult."""
        mock_result = ScanResult(
            target_url="http://localhost:8000",
            threats=(),
            probe_results=(),
            scenario_results=(),
            scan_timestamp="2026-01-01T00:00:00+00:00",
            catalog_hash="abc123",
            exit_code=0,
        )
        with patch("cosai_mcp.api._run_scan", return_value=mock_result) as mock_fn:
            scanner = Scanner("http://localhost:8000")
            result = scanner.run(categories=["T1"])

        assert isinstance(result, ScanResult)
        mock_fn.assert_called_once()
        call_kwargs = mock_fn.call_args.kwargs
        assert call_kwargs["target"] == "http://localhost:8000"
        assert call_kwargs["categories"] == ["T1"]

    def test_scanner_uses_instance_categories_when_run_not_overridden(self) -> None:
        mock_result = ScanResult(
            target_url="http://t:8000", threats=(), probe_results=(),
            scenario_results=(), scan_timestamp="t", catalog_hash="h", exit_code=0,
        )
        with patch("cosai_mcp.api._run_scan", return_value=mock_result) as mock_fn:
            scanner = Scanner("http://t:8000", categories=["T3"])
            scanner.run()

        call_kwargs = mock_fn.call_args.kwargs
        assert call_kwargs["categories"] == ["T3"]

    def test_scanner_default_engine_is_all(self) -> None:
        mock_result = ScanResult(
            target_url="http://t:8000", threats=(), probe_results=(),
            scenario_results=(), scan_timestamp="t", catalog_hash="h", exit_code=0,
        )
        with patch("cosai_mcp.api._run_scan", return_value=mock_result) as mock_fn:
            Scanner("http://t:8000").run()

        assert mock_fn.call_args.kwargs["engine"] == "all"


# ---------------------------------------------------------------------------
# scrub_env (API-level)
# ---------------------------------------------------------------------------

class TestScrubEnvApi:
    def test_scrub_env_returns_dict(self) -> None:
        result = scrub_env({"HOME": "/x", "SECRET_KEY": "s3cr3t"})
        assert isinstance(result, dict)

    def test_all_patterns_match_their_targets(self) -> None:
        sensitive = {
            "GITHUB_TOKEN": "t",
            "GH_TOKEN": "t",
            "AWS_ACCESS_KEY_ID": "t",
            "AWS_SECRET_ACCESS_KEY": "t",
            "AZURE_CLIENT_SECRET": "t",
            "GCP_SERVICE_ACCOUNT_KEY": "t",
            "DATABASE_PASSWORD": "t",
            "MY_API_KEY": "t",
            "MY_API_TOKEN": "t",
            "MY_CREDENTIAL_FILE": "t",
        }
        scrubbed = scrub_env(sensitive)
        assert scrubbed == {}

    def test_regression_github_token_scrubbed(self) -> None:
        """Regression test: GITHUB_TOKEN must be stripped (P8 panel finding)."""
        assert "GITHUB_TOKEN" not in scrub_env({"GITHUB_TOKEN": "ghp_token"})

    def test_regression_connection_strings_scrubbed(self) -> None:
        """Regression: FIX [3] — connection-string vars embed credentials."""
        env = {
            "DATABASE_URL": "postgres://user:pass@host/db",
            "MONGO_URI": "mongodb://user:pass@host/db",
            "REDIS_URL": "redis://:password@host:6379/0",
            "HOME": "/home/user",
        }
        scrubbed = scrub_env(env)
        assert "DATABASE_URL" not in scrubbed
        assert "MONGO_URI" not in scrubbed
        assert "REDIS_URL" not in scrubbed
        assert "HOME" in scrubbed

    def test_regression_scrub_does_not_mutate_os_environ(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Regression: FIX [2] — scrub_env must not mutate os.environ."""
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKID_TEST")
        before = dict(os.environ)
        scrub_env()  # calling without args reads os.environ
        after = dict(os.environ)
        assert before == after, "scrub_env() must not mutate os.environ"

    def test_regression_api_run_preserves_caller_environ(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Regression: FIX [2] — Scanner.run() must not delete caller env vars."""
        import cosai_mcp.api as api_mod
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKID_PRESERVED")
        mock_result = ScanResult(
            target_url="http://t:8000", threats=(), probe_results=(),
            scenario_results=(), scan_timestamp="t", catalog_hash="h", exit_code=0,
        )
        with patch("cosai_mcp.api._run_scan", return_value=mock_result):
            Scanner("http://t:8000").run()
        assert os.environ.get("AWS_ACCESS_KEY_ID") == "AKID_PRESERVED"


class TestDetermineExitCodeWithSeverity:
    """Regression tests for FIX [5] — fail_on threshold must be applied."""

    def _make_probe(self, *, passed: bool, threat_id: str = "T01-001") -> ProbeResult:
        from cosai_mcp.harness.result import ProbeResult
        return ProbeResult(
            probe_id=f"{threat_id}-p1", threat_id=threat_id, passed=passed,
            status_code=200, response_body="", error=None, assertions=(),
            duration_seconds=0.0,
        )

    def test_regression_fail_on_critical_ignores_low_severity_finding(self) -> None:
        """fail_on=critical: low-severity failing probe → exit 0."""
        probe = self._make_probe(passed=False, threat_id="T03-001")
        threat_severity = {"T03-001": Severity.LOW}
        code = _determine_exit_code([probe], [], "critical", threat_severity)
        assert code == 0, "low severity finding must not fail when fail_on=critical"

    def test_regression_fail_on_low_catches_low_severity_finding(self) -> None:
        """fail_on=low: low-severity failing probe → exit 1."""
        probe = self._make_probe(passed=False, threat_id="T03-001")
        threat_severity = {"T03-001": Severity.LOW}
        code = _determine_exit_code([probe], [], "low", threat_severity)
        assert code == 1

    def test_fail_on_critical_flags_critical_finding(self) -> None:
        probe = self._make_probe(passed=False, threat_id="T01-001")
        threat_severity = {"T01-001": Severity.CRITICAL}
        code = _determine_exit_code([probe], [], "critical", threat_severity)
        assert code == 1

    def test_fail_on_high_ignores_medium_finding(self) -> None:
        probe = self._make_probe(passed=False, threat_id="T03-001")
        threat_severity = {"T03-001": Severity.MEDIUM}
        code = _determine_exit_code([probe], [], "high", threat_severity)
        assert code == 0

    def test_unknown_severity_counts_as_finding(self) -> None:
        """Probes with unknown threat_id default to conservative (count as finding)."""
        probe = self._make_probe(passed=False, threat_id="T99-999")
        code = _determine_exit_code([probe], [], "critical", threat_severity={})
        assert code == 1
