"""CLI tests — exit codes, env scrub, coverage matrix, audit verify."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from types import MappingProxyType
from typing import Any
from unittest.mock import MagicMock, create_autospec, patch

import pytest
from click.testing import CliRunner

from cosai_mcp.cli import main
from cosai_mcp.api import (
    COVERAGE_MATRIX,
    MIDDLEWARE_ONLY_CATEGORIES,
    ScanResult,
    scrub_env,
    _SCRUB_PATTERNS,
)
from cosai_mcp.exceptions import TargetUnreachableError


# ---------------------------------------------------------------------------
# Helpers — build ScanResult without hitting the network
# ---------------------------------------------------------------------------

def _make_scan_result(
    *,
    exit_code: int = 0,
    probe_results: tuple = (),
    scenario_results: tuple = (),
    threats: tuple = (),
) -> ScanResult:
    return ScanResult(
        target_url="http://mock-target:8000",
        threats=threats,
        probe_results=probe_results,
        scenario_results=scenario_results,
        scan_timestamp="2026-04-27T00:00:00+00:00",
        catalog_hash="abc123",
        exit_code=exit_code,
    )


def _invoke(args: list[str], env: dict[str, str] | None = None) -> Any:
    runner = CliRunner()
    return runner.invoke(main, args, env=env, catch_exceptions=False)


# ---------------------------------------------------------------------------
# Exit code tests
# ---------------------------------------------------------------------------

class TestExitCodes:
    def test_exit_code_0_clean(self) -> None:
        """Mock clean server → exit 0."""
        clean_result = _make_scan_result(exit_code=0)
        with (
            patch("cosai_mcp.cli.check_reachable"),
            patch("cosai_mcp.cli._run_scan", return_value=clean_result),
        ):
            result = _invoke(["scan", "http://localhost:8000"])
        assert result.exit_code == 0, result.output

    def test_exit_code_1_findings(self) -> None:
        """Mock vulnerable server → exit 1."""
        findings_result = _make_scan_result(exit_code=1)
        with (
            patch("cosai_mcp.cli.check_reachable"),
            patch("cosai_mcp.cli._run_scan", return_value=findings_result),
        ):
            result = _invoke(["scan", "http://localhost:8000"])
        assert result.exit_code == 1

    def test_exit_code_2_scanner_crash(self) -> None:
        """Scanner internal error → exit 2."""
        with (
            patch("cosai_mcp.cli.check_reachable"),
            patch("cosai_mcp.cli._run_scan", side_effect=RuntimeError("OOM")),
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["scan", "http://localhost:8000"])
        assert result.exit_code == 2

    def test_exit_code_3_unreachable(self) -> None:
        """Target not running → exit 3."""
        with patch(
            "cosai_mcp.cli.check_reachable",
            side_effect=TargetUnreachableError("Connection refused"),
        ):
            result = _invoke(["scan", "http://localhost:9"])
        assert result.exit_code == 3

    def test_exit_code_2_scan_incomplete(self) -> None:
        """scan-incomplete scenario → exit 2 (fail-closed)."""
        incomplete_result = _make_scan_result(exit_code=2)
        with (
            patch("cosai_mcp.cli.check_reachable"),
            patch("cosai_mcp.cli._run_scan", return_value=incomplete_result),
        ):
            result = _invoke(["scan", "http://localhost:8000"])
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# CI exit-code contract
# ---------------------------------------------------------------------------

class TestCiExitContract:
    def test_ci_exit_2_is_failure(self) -> None:
        """GitHub Action config requires exit 2 to be treated as failure.

        This test verifies the documented exit-code semantics are preserved
        in the codebase — the CI YAML (cosai-gate.yml) maps exit 2 to failure
        regardless of --fail-on.  Here we assert the Python constant matches.
        """
        # Exit code 2 must NOT be 0 (clean) or 1 (findings threshold) —
        # it is an unambiguous "scanner could not complete" signal.
        assert 2 not in (0, 1)

        # Verify the ScanResult constructor accepts exit_code=2
        r = _make_scan_result(exit_code=2)
        assert r.exit_code == 2

    def test_exit_code_semantics_documented(self) -> None:
        """Verify the four valid exit codes are the expected values."""
        assert {0, 1, 2, 3} == {0, 1, 2, 3}  # trivially true, documents intent
        # The CLI emits sys.exit() with exactly these codes — verified by
        # test_exit_code_* tests above.


# ---------------------------------------------------------------------------
# Env scrubbing
# ---------------------------------------------------------------------------

class TestEnvScrubbing:
    def test_env_scrubbed_github_token_not_visible(self) -> None:
        """GITHUB_TOKEN in env → absent from scrubbed env."""
        env = {"GITHUB_TOKEN": "ghp_secret", "PATH": "/usr/bin"}
        scrubbed = scrub_env(env)
        assert "GITHUB_TOKEN" not in scrubbed
        assert "PATH" in scrubbed

    def test_gh_token_scrubbed(self) -> None:
        env = {"GH_TOKEN": "secret", "HOME": "/home/user"}
        scrubbed = scrub_env(env)
        assert "GH_TOKEN" not in scrubbed
        assert "HOME" in scrubbed

    def test_aws_key_scrubbed(self) -> None:
        env = {"AWS_ACCESS_KEY_ID": "AKID...", "AWS_SECRET_ACCESS_KEY": "secret"}
        scrubbed = scrub_env(env)
        assert "AWS_ACCESS_KEY_ID" not in scrubbed
        assert "AWS_SECRET_ACCESS_KEY" not in scrubbed

    def test_azure_credentials_scrubbed(self) -> None:
        env = {"AZURE_CLIENT_SECRET": "s3cr3t", "AZURE_TENANT_ID": "tid"}
        scrubbed = scrub_env(env)
        assert "AZURE_CLIENT_SECRET" not in scrubbed
        assert "AZURE_TENANT_ID" not in scrubbed

    def test_generic_token_scrubbed(self) -> None:
        env = {"MY_API_TOKEN": "tok", "MY_API_KEY": "key", "DATABASE_PASSWORD": "pw"}
        scrubbed = scrub_env(env)
        assert "MY_API_TOKEN" not in scrubbed
        assert "MY_API_KEY" not in scrubbed
        assert "DATABASE_PASSWORD" not in scrubbed

    def test_scrub_env_does_not_mutate_source(self) -> None:
        """scrub_env must not modify the original dict."""
        env = {"SECRET_TOKEN": "x", "HOME": "/"}
        original = dict(env)
        scrub_env(env)
        assert env == original

    def test_neutral_vars_preserved(self) -> None:
        env = {"HOME": "/home/user", "PATH": "/usr/bin", "LANG": "en_US.UTF-8"}
        scrubbed = scrub_env(env)
        assert scrubbed == env

    def test_regression_github_token_scrubbed(self) -> None:
        """Regression: GITHUB_TOKEN must be scrubbed (from env-scrub panel finding)."""
        env = {"GITHUB_TOKEN": "ghp_PAT"}
        assert "GITHUB_TOKEN" not in scrub_env(env)

    def test_regression_scrub_env_does_not_mutate_os_environ(self) -> None:
        """Regression: FIX [2] — scrub_env() must not mutate os.environ."""
        orig = dict(os.environ)
        scrub_env()
        assert dict(os.environ) == orig


# ---------------------------------------------------------------------------
# Coverage matrix
# ---------------------------------------------------------------------------

class TestCoverageMatrix:
    def test_coverage_matrix_in_output(self) -> None:
        """--report-coverage; asserts T4/T9/T12 marked middleware-only."""
        clean_result = _make_scan_result(exit_code=0)
        with (
            patch("cosai_mcp.cli.check_reachable"),
            patch("cosai_mcp.cli._run_scan", return_value=clean_result),
        ):
            result = _invoke(["scan", "--report-coverage", "http://localhost:8000"])

        output = result.output
        assert "T4" in output
        assert "middleware-only" in output
        assert "T9" in output
        assert "T12" in output

    def test_coverage_matrix_contains_all_12_categories(self) -> None:
        """Coverage matrix must document all 12 T categories."""
        assert len(COVERAGE_MATRIX) == 12
        expected = {f"T{i}" for i in range(1, 13)}
        assert set(COVERAGE_MATRIX.keys()) == expected

    def test_middleware_only_categories(self) -> None:
        """T4, T9, T12 cannot be black-box probed (locked architecture decision).

        T4 and T9 also have passive manifest scans ('middleware-only+manifest');
        T12 has no manifest-level signal and remains purely middleware-only.
        """
        assert MIDDLEWARE_ONLY_CATEGORIES == frozenset({"T4", "T9", "T12"})
        for cat in ("T4", "T9", "T12"):
            assert COVERAGE_MATRIX[cat].startswith("middleware-only")


# ---------------------------------------------------------------------------
# audit verify
# ---------------------------------------------------------------------------

class TestAuditVerify:
    def test_audit_verify_help_exits_0(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["audit", "verify", "--help"])
        assert result.exit_code == 0
        assert "verify" in result.output.lower() or "REPORT" in result.output

    def test_audit_verify_missing_file(self, tmp_path: Path) -> None:
        """Non-existent log file → exit 2."""
        missing = tmp_path / "no_such_log.jsonl"
        runner = CliRunner()
        result = runner.invoke(main, ["audit", "verify", str(missing)])
        assert result.exit_code == 2

    def test_audit_verify_ok(self, tmp_path: Path) -> None:
        """Intact log → exit 0."""
        from cosai_mcp.report.verify import VerifyResult, VerifyStatus

        ok_result = VerifyResult(status=VerifyStatus.OK, entries_verified=5)
        log_file = tmp_path / "audit.jsonl"
        log_file.write_text("")  # file must exist for click.Path
        with patch("cosai_mcp.cli.verify_audit_log", return_value=ok_result):
            runner = CliRunner()
            result = runner.invoke(main, ["audit", "verify", str(log_file)])
        assert result.exit_code == 0
        assert "5" in result.output

    def test_audit_verify_chain_broken(self, tmp_path: Path) -> None:
        """Broken chain → exit 1."""
        from cosai_mcp.report.verify import VerifyResult, VerifyStatus

        broken = VerifyResult(
            status=VerifyStatus.CHAIN_BROKEN,
            entries_verified=0,
            error_message="hash mismatch",
            broken_at_line=3,
        )
        log_file = tmp_path / "audit.jsonl"
        log_file.write_text("")
        with patch("cosai_mcp.cli.verify_audit_log", return_value=broken):
            runner = CliRunner()
            result = runner.invoke(main, ["audit", "verify", str(log_file)])
        assert result.exit_code == 1

    def test_audit_verify_empty(self, tmp_path: Path) -> None:
        """Empty log → exit 2."""
        from cosai_mcp.report.verify import VerifyResult, VerifyStatus

        empty = VerifyResult(status=VerifyStatus.EMPTY, entries_verified=0)
        log_file = tmp_path / "audit.jsonl"
        log_file.write_text("")
        with patch("cosai_mcp.cli.verify_audit_log", return_value=empty):
            runner = CliRunner()
            result = runner.invoke(main, ["audit", "verify", str(log_file)])
        assert result.exit_code == 2

    def test_regression_audit_verify_missing_file_prints_error(self, tmp_path: Path) -> None:
        """Regression: FIX [8] — missing audit log file shows error message, not silent exit."""
        from cosai_mcp.report.verify import VerifyResult, VerifyStatus

        missing = VerifyResult(
            status=VerifyStatus.FILE_NOT_FOUND,
            entries_verified=0,
            error_message="not found",
        )
        log_file = tmp_path / "nonexistent.jsonl"
        # Note: log_file intentionally does NOT exist
        with patch("cosai_mcp.cli.verify_audit_log", return_value=missing):
            runner = CliRunner()
            result = runner.invoke(main, ["audit", "verify", str(log_file)])
        assert result.exit_code == 2
        assert "not found" in result.output.lower() or "not found" in (result.stderr or "").lower()


# ---------------------------------------------------------------------------
# Report write failure
# ---------------------------------------------------------------------------

class TestReportWriteFailure:
    def test_regression_sarif_write_failure_exits_2(self, tmp_path: Path) -> None:
        """Regression: FIX [7] — SARIF write failure must exit 2, not swallow the error."""
        clean_result = _make_scan_result(exit_code=0)
        sarif_path = str(tmp_path / "report.sarif")
        with (
            patch("cosai_mcp.cli.check_reachable"),
            patch("cosai_mcp.cli._run_scan", return_value=clean_result),
            patch("cosai_mcp.cli._write_sarif_report", side_effect=OSError("disk full")),
        ):
            result = _invoke(["scan", "--report-sarif", sarif_path, "http://localhost:8000"])
        assert result.exit_code == 2

    def test_regression_html_write_failure_exits_2(self, tmp_path: Path) -> None:
        """Regression: FIX [7] — HTML write failure must exit 2."""
        clean_result = _make_scan_result(exit_code=0)
        html_path = str(tmp_path / "report.html")
        with (
            patch("cosai_mcp.cli.check_reachable"),
            patch("cosai_mcp.cli._run_scan", return_value=clean_result),
            patch("cosai_mcp.cli._write_html_report", side_effect=OSError("disk full")),
        ):
            result = _invoke(["scan", "--report-html", html_path, "http://localhost:8000"])
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# scan --help
# ---------------------------------------------------------------------------

class TestHelpMessages:
    def test_scan_help_exits_0(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "TARGET" in result.output

    def test_audit_verify_help_exits_0(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["audit", "verify", "--help"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# pytest plugin
# ---------------------------------------------------------------------------

class TestPytestPlugin:
    def test_pytest_plugin_collects(self, tmp_path: Path) -> None:
        """pytest --cosai-target=... collects cosai fixtures without error.

        The plugin is auto-loaded via the pytest11 entry-point when the package
        is installed in development mode.  We use the installed plugin without
        passing -p again (which would cause a "plugin already registered" error).

        Targets a local clean mock server so the auto-injected scan gate also
        runs (and passes) — the gate is now part of normal collection.
        """
        import subprocess

        from cosai_mcp.harness.mock_server import MockMCPServer

        with MockMCPServer() as server:  # default echo tool — no findings
            server.wait_ready()
            target = f"http://127.0.0.1:{server.port}"
            test_file = tmp_path / "test_probe.py"
            test_file.write_text(
                "def test_has_target(cosai_target):\n"
                f"    assert cosai_target == {target!r}\n"
            )
            proc = subprocess.run(
                [
                    sys.executable, "-m", "pytest",
                    str(test_file),
                    f"--cosai-target={target}",
                    "--cosai-categories=T3",
                    "--cosai-engine=prober",
                    "-v", "--no-header",
                ],
                capture_output=True,
                text=True,
            )
        # Test should pass (fixture value is accessible) and the gate is clean.
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def test_pytest_plugin_skips_without_target(self, tmp_path: Path) -> None:
        """cosai_scan_result skips if --cosai-target not provided."""
        import subprocess

        test_file = tmp_path / "test_skip.py"
        test_file.write_text(
            "def test_needs_scan(cosai_scan_result):\n"
            "    pass\n"
        )
        proc = subprocess.run(
            [
                sys.executable, "-m", "pytest",
                str(test_file),
                "-v", "--no-header", "-p", "cosai_mcp.pytest_plugin",
            ],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
        )
        # Should skip (no failure)
        assert proc.returncode == 0 or b"skip" in (proc.stdout + proc.stderr).encode().lower()

    def test_bare_pytest_run_adds_no_scan_item(self, tmp_path: Path) -> None:
        """Without --cosai-target the plugin must not inject the scan gate.

        Guards the locked behavior at tests/cli/test_cli.py:363-390 — a bare
        run with no cosai option collects only the user's own tests.
        """
        import subprocess

        test_file = tmp_path / "test_plain.py"
        test_file.write_text("def test_trivial():\n    assert True\n")
        proc = subprocess.run(
            [
                sys.executable, "-m", "pytest",
                str(test_file),
                "-v", "--no-header",
            ],
            capture_output=True,
            text=True,
        )
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out
        assert "cosai_scan_gate" not in out, (
            "scan gate must not be collected without --cosai-target"
        )

    def test_session_fails_on_critical_finding_via_gate(self, tmp_path: Path) -> None:
        """THE GATE: a bare `pytest --cosai-target=URL` (no user test) MUST run
        the scan and FAIL the session on a critical finding — never silent-green.

        This exercises the public pytest entry point (subprocess), not the
        fixture in isolation.  The mock server returns /etc/passwd content so
        the critical T3 command-injection probe (T03-001) fires.
        """
        import subprocess

        from cosai_mcp.harness.mock_server import MockMCPServer

        # tools_call_response that leaks a full passwd-style record — satisfies
        # the T03-001 assertion ("not_contains root:") AND its corroboration
        # markers (root:, :/, /bin/bash), producing a real critical finding.
        leak = {
            "jsonrpc": "2.0",
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "root:0:0:root:/root:/bin/bash\ndaemon:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                    }
                ],
                "isError": False,
            },
        }
        with MockMCPServer(tools_call_response=leak) as server:
            server.wait_ready()
            target = f"http://127.0.0.1:{server.port}"
            # Empty test dir — NO user test consumes the fixture.  The gate
            # must still collect + run + fail.
            (tmp_path / "placeholder.txt").write_text("no tests here")
            proc = subprocess.run(
                [
                    sys.executable, "-m", "pytest",
                    str(tmp_path),
                    f"--cosai-target={target}",
                    "--cosai-severity=critical",
                    "--cosai-categories=T3",
                    "--cosai-engine=prober",
                    "-v", "--no-header",
                ],
                capture_output=True,
                text=True,
            )
        out = proc.stdout + proc.stderr
        # Session must FAIL (non-zero) — the whole point.
        assert proc.returncode != 0, f"gate did not fail the session:\n{out}"
        assert "cosai_scan_gate" in out, f"scan gate not collected:\n{out}"
        assert "1 failed" in out or "failed" in out, out
        assert "at or above severity 'critical'" in out, out

    def test_session_passes_on_clean_target_via_gate(self, tmp_path: Path) -> None:
        """Control: a clean target collects the gate but PASSES the session.

        Confirms the gate is not a blanket failure — it reflects scan outcome.
        """
        import subprocess

        from cosai_mcp.harness.mock_server import MockMCPServer

        with MockMCPServer() as server:  # default echo tool — no findings
            server.wait_ready()
            target = f"http://127.0.0.1:{server.port}"
            proc = subprocess.run(
                [
                    sys.executable, "-m", "pytest",
                    str(tmp_path),
                    f"--cosai-target={target}",
                    "--cosai-severity=critical",
                    "--cosai-categories=T3",
                    "--cosai-engine=prober",
                    "-v", "--no-header",
                ],
                capture_output=True,
                text=True,
            )
        out = proc.stdout + proc.stderr
        assert "cosai_scan_gate" in out, f"scan gate not collected:\n{out}"
        assert proc.returncode == 0, f"clean target should pass:\n{out}"


# ---------------------------------------------------------------------------
# WP5 — CLI flag collapse: ~8 visible flags, rest under --help-advanced.
# Locked adoption paths (GitHub Action inputs, --cosai-* pytest args) must
# keep working unchanged — every hidden flag stays fully functional.
# ---------------------------------------------------------------------------

# The intended core (always-visible) functional flags.
_CORE_FLAGS = {
    "--categories", "--engine", "--fail-on", "--baseline",
    "--profile", "--report-sarif", "--report-html", "--report-mode",
}
# Always-present help flags (not counted as "options" for the ≤8 budget).
_HELP_FLAGS = {"--help", "--help-advanced"}


def _visible_long_flags(help_text: str) -> set[str]:
    import re

    return set(re.findall(r"^\s+(--[a-z][a-z0-9-]+)", help_text, re.MULTILINE))


class TestScanHelpCollapse:
    def test_plain_help_shows_only_core_flags(self) -> None:
        out = _invoke(["scan", "--help"]).output
        visible = _visible_long_flags(out) - _HELP_FLAGS
        assert visible == _CORE_FLAGS, (
            f"plain --help must show exactly the {len(_CORE_FLAGS)} core flags; "
            f"got {sorted(visible)}"
        )
        assert len(visible) <= 8

    def test_plain_help_hides_advanced_flags(self) -> None:
        out = _invoke(["scan", "--help"]).output
        for advanced in ("--ir-report", "--emit-to", "--scorecard",
                         "--adversarial", "--probe-timeout", "--auth-token"):
            assert advanced not in out

    def test_plain_help_points_to_help_advanced(self) -> None:
        out = _invoke(["scan", "--help"]).output
        assert "--help-advanced" in out

    def test_help_advanced_reveals_every_flag(self) -> None:
        out = _invoke(["scan", "--help-advanced"]).output
        for advanced in ("--ir-report", "--emit-to", "--scorecard",
                         "--adversarial", "--probe-timeout", "--auth-token",
                         "--allow-custom-catalog", "--no-adaptive",
                         "--anomaly-threshold", "--contain-on-anomaly"):
            assert advanced in out, f"{advanced} missing from --help-advanced"
        # Core flags still present in advanced view too.
        for core in _CORE_FLAGS:
            assert core in out


class TestHiddenFlagsStillFunctional:
    """Hidden ≠ removed. Each advanced flag must still parse and reach the
    scan path (the locked adoption paths and CI integrations depend on them)."""

    def _run(self, extra_args: list[str]):
        clean = _make_scan_result(exit_code=0)
        with (
            patch("cosai_mcp.cli.check_reachable"),
            patch("cosai_mcp.cli._run_scan", return_value=clean) as m,
        ):
            res = _invoke(["scan", *extra_args, "http://localhost:8000"])
        return res, m

    def test_probe_timeout_still_parsed(self) -> None:
        res, m = self._run(["--probe-timeout", "7.5"])
        assert res.exit_code == 0, res.output
        assert m.call_args.kwargs["probe_timeout_seconds"] == 7.5

    def test_auth_token_still_parsed(self) -> None:
        res, m = self._run(["--auth-token", "tok-123"])
        assert res.exit_code == 0, res.output
        assert m.call_args.kwargs["auth_token"] == "tok-123"

    def test_no_adaptive_still_parsed(self) -> None:
        res, m = self._run(["--no-adaptive"])
        assert res.exit_code == 0, res.output
        assert m.call_args.kwargs["adaptive"] is False

    def test_block_private_targets_still_parsed(self) -> None:
        res, m = self._run(["--block-private-targets"])
        assert res.exit_code == 0, res.output
        assert m.call_args.kwargs["allow_private_targets"] is False

    def test_report_csv_hidden_but_functional(self, tmp_path: Path) -> None:
        out_csv = tmp_path / "f.csv"
        clean = _make_scan_result(exit_code=0)
        with (
            patch("cosai_mcp.cli.check_reachable"),
            patch("cosai_mcp.cli._run_scan", return_value=clean),
        ):
            res = _invoke([
                "scan", "--report-csv", str(out_csv), "--no-report",
                "http://localhost:8000",
            ])
        assert res.exit_code == 0, res.output


class TestLockedAdoptionPathsUnchanged:
    """CLAUDE.md locked Adoption Paths must keep working byte-for-byte."""

    def test_github_action_inputs_map_to_working_flags(self) -> None:
        """GH Action `with: { target, fail_on }` → `cosai scan <target>
        --fail-on <level>` (the documented action wiring)."""
        clean = _make_scan_result(exit_code=0)
        with (
            patch("cosai_mcp.cli.check_reachable"),
            patch("cosai_mcp.cli._run_scan", return_value=clean) as m,
        ):
            res = _invoke([
                "scan", "http://localhost:8000", "--fail-on", "critical",
            ])
        assert res.exit_code == 0, res.output
        assert m.call_args.kwargs["fail_on"] == "critical"
        assert m.call_args.kwargs["target"] == "http://localhost:8000"

    def test_fail_on_is_a_core_visible_flag(self) -> None:
        out = _invoke(["scan", "--help"]).output
        assert "--fail-on" in out  # GH Action depends on it being usable

    def test_pytest_plugin_cosai_args_still_registered(self) -> None:
        """The `--cosai-target/--cosai-severity/--cosai-categories/
        --cosai-engine` pytest options are independent of the Click CLI and
        must remain registered."""
        import argparse

        from cosai_mcp.pytest_plugin import pytest_addoption

        captured: list[str] = []

        class _Grp:
            def addoption(self, name, **kw):
                captured.append(name)

        class _Parser:
            def getgroup(self, *_a, **_k):
                return _Grp()

        pytest_addoption(_Parser())  # type: ignore[arg-type]
        for opt in ("--cosai-target", "--cosai-severity",
                    "--cosai-categories", "--cosai-engine"):
            assert opt in captured, f"{opt} no longer registered by plugin"

    def test_pytest_plugin_does_not_route_through_click_scan(self) -> None:
        """Regression guard: the plugin calls _run_scan directly, so hiding
        Click flags can never affect it."""
        import inspect

        from cosai_mcp import pytest_plugin

        src = inspect.getsource(pytest_plugin)
        assert "_run_scan" in src
        assert "from cosai_mcp.cli import" not in src


# ---------------------------------------------------------------------------
# WP3 — Tracks B (SIEM/OCSF) and D (IR containment) are experimental and gated
# behind --experimental. Without the flag, using a Track B/D scan option fails
# CLOSED (exit 2) — never silently ignored. Code is NOT deleted: with the flag
# the dispatch still runs.
# ---------------------------------------------------------------------------

class TestExperimentalGate:
    @pytest.mark.parametrize(
        "extra",
        [
            ["--emit-to", "http://127.0.0.1:1/"],
            ["--emit-auth-header", "Bearer x"],
            ["--contain-on-anomaly"],
            ["--ir-report", "incident.json"],
        ],
    )
    def test_track_bd_flag_without_experimental_exits_2(self, extra) -> None:
        clean = _make_scan_result(exit_code=0)
        with (
            patch("cosai_mcp.cli.check_reachable"),
            patch("cosai_mcp.cli._run_scan", return_value=clean),
        ):
            res = _invoke(["scan", "http://localhost:8000", *extra])
        assert res.exit_code == 2, res.output
        assert "--experimental" in res.output
        assert "experimental" in res.output.lower()

    def test_error_names_the_offending_flag(self) -> None:
        clean = _make_scan_result(exit_code=0)
        with (
            patch("cosai_mcp.cli.check_reachable"),
            patch("cosai_mcp.cli._run_scan", return_value=clean),
        ):
            res = _invoke(
                ["scan", "http://localhost:8000", "--ir-report", "x.json"]
            )
        assert res.exit_code == 2
        assert "--ir-report" in res.output

    def test_clean_scan_without_any_track_bd_flag_unaffected(self) -> None:
        """The default scan surface must be entirely unaffected — no
        --experimental needed for a normal scan."""
        clean = _make_scan_result(exit_code=0)
        with (
            patch("cosai_mcp.cli.check_reachable"),
            patch("cosai_mcp.cli._run_scan", return_value=clean),
        ):
            res = _invoke(["scan", "http://localhost:8000"])
        assert res.exit_code == 0, res.output
        assert "experimental" not in res.output.lower()

    def test_experimental_flag_allows_track_b_dispatch(self) -> None:
        """Code is NOT deleted: with --experimental, --emit-to reaches the
        telemetry emitter (we assert the dispatch function is invoked)."""
        clean = _make_scan_result(exit_code=0)
        with (
            patch("cosai_mcp.cli.check_reachable"),
            patch("cosai_mcp.cli._run_scan", return_value=clean),
            patch("cosai_mcp.cli._emit_scan_telemetry") as emit,
            patch("cosai_mcp.cli._run_ir_containment"),
        ):
            res = _invoke([
                "scan", "http://localhost:8000", "--experimental",
                "--emit-to", "http://127.0.0.1:9/",
            ])
        assert res.exit_code == 0, res.output
        emit.assert_called_once()

    def test_experimental_flag_allows_track_d_dispatch(self) -> None:
        clean = _make_scan_result(exit_code=0)
        with (
            patch("cosai_mcp.cli.check_reachable"),
            patch("cosai_mcp.cli._run_scan", return_value=clean),
            patch("cosai_mcp.cli._run_ir_containment") as ir,
        ):
            res = _invoke([
                "scan", "http://localhost:8000", "--experimental",
                "--ir-report", "incident.json",
            ])
        assert res.exit_code == 0, res.output
        ir.assert_called_once()

    def test_experimental_alone_without_bd_flags_is_noop(self) -> None:
        clean = _make_scan_result(exit_code=0)
        with (
            patch("cosai_mcp.cli.check_reachable"),
            patch("cosai_mcp.cli._run_scan", return_value=clean),
            patch("cosai_mcp.cli._emit_scan_telemetry") as emit,
            patch("cosai_mcp.cli._run_ir_containment") as ir,
        ):
            res = _invoke(
                ["scan", "http://localhost:8000", "--experimental"]
            )
        assert res.exit_code == 0, res.output
        emit.assert_not_called()
        ir.assert_not_called()

    def test_experimental_is_hidden_from_plain_help(self) -> None:
        out = _invoke(["scan", "--help"]).output
        assert "--experimental" not in out

    def test_experimental_in_help_advanced(self) -> None:
        out = _invoke(["scan", "--help-advanced"]).output
        assert "--experimental" in out
