"""ENT-P0-4 — fleet/multi-target scan with one verdict
(docs/ENTERPRISE_REQUIREMENTS_2026-07-01.md).

"As SEC, I need `cosai scan --targets targets.yaml` with bounded per-host
concurrency, aggregating N servers into one exit code + one merged SARIF +
one roll-up scorecard, so that an org with 40 MCP servers can gate a
release on the fleet, not script 40 invocations and hand-merge results."

Acceptance: a 3-target file yields one aggregated scorecard, a merged SARIF
that renders in GitHub, and an exit code that is the max severity across
targets; one unreachable target degrades to exit 3 for that host without
masking findings on the others.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from cosai_mcp.exceptions import TargetUnreachableError
from cosai_mcp.fleet import (
    FleetResult,
    TargetOutcome,
    _aggregate_exit_code,
    _default_scan_one,
    _sanitize_error,
    build_fleet_scorecard,
    merge_sarif,
    parse_targets_file,
    run_fleet_scan,
)

# ===========================================================================
# parse_targets_file — dependency-free format (CLAUDE.md locks the runtime
# dependency list to httpx/websockets/google-re2/joserfc/keyring/jsonschema/
# cryptography/click; adding pyyaml as a NEW core dep to parse a literal
# "targets.yaml" was not this task's call to make unilaterally, so the
# format is plain text — one target URL per line, '#' comments and blank
# lines ignored).
# ===========================================================================

class TestParseTargetsFile:
    def test_parses_one_url_per_line(self, tmp_path: Path) -> None:
        p = tmp_path / "targets.txt"
        p.write_text("http://host1:8000\nhttp://host2:8000\nhttp://host3:8000\n")
        assert parse_targets_file(p) == [
            "http://host1:8000", "http://host2:8000", "http://host3:8000",
        ]

    def test_ignores_blank_lines_and_comments(self, tmp_path: Path) -> None:
        p = tmp_path / "targets.txt"
        p.write_text(
            "# fleet targets\nhttp://host1:8000\n\n  # another comment\n"
            "http://host2:8000\n   \n"
        )
        assert parse_targets_file(p) == ["http://host1:8000", "http://host2:8000"]

    def test_strips_whitespace_per_line(self, tmp_path: Path) -> None:
        p = tmp_path / "targets.txt"
        p.write_text("  http://host1:8000  \n\thttp://host2:8000\t\n")
        assert parse_targets_file(p) == ["http://host1:8000", "http://host2:8000"]

    def test_empty_file_raises_value_error(self, tmp_path: Path) -> None:
        p = tmp_path / "targets.txt"
        p.write_text("# only comments\n\n")
        with pytest.raises(ValueError, match="no targets"):
            parse_targets_file(p)

    def test_rejects_line_missing_scheme(self, tmp_path: Path) -> None:
        p = tmp_path / "targets.txt"
        p.write_text("host1:8000\n")
        with pytest.raises(ValueError, match="host1:8000"):
            parse_targets_file(p)


# ===========================================================================
# Exit code aggregation — precedence: scanner error (2) > findings (1) >
# unreachable (3) > clean (0). A proven finding on one target must outrank
# "couldn't reach a different target" in the aggregate; a scanner error
# anywhere must dominate everything (matches the single-target locked
# contract: exit 2 is always a failure regardless of --fail-on).
# ===========================================================================

class TestAggregateExitCode:
    def test_all_clean_is_clean(self) -> None:
        assert _aggregate_exit_code([0, 0, 0]) == 0

    def test_one_finding_dominates_clean(self) -> None:
        assert _aggregate_exit_code([0, 1, 0]) == 1

    def test_scanner_error_dominates_findings(self) -> None:
        assert _aggregate_exit_code([1, 2, 1]) == 2

    def test_findings_dominate_unreachable(self) -> None:
        """A real finding on target B must not be masked by target A being
        unreachable — the acceptance criterion's core requirement."""
        assert _aggregate_exit_code([3, 1]) == 1

    def test_unreachable_alone_is_exit_3(self) -> None:
        assert _aggregate_exit_code([0, 3, 0]) == 3

    def test_empty_list_is_clean(self) -> None:
        assert _aggregate_exit_code([]) == 0


# ===========================================================================
# run_fleet_scan — bounded concurrency + per-target failure isolation.
# Uses an injectable scan_fn so concurrency is proven deterministically
# (peak-concurrent-call counter under a lock) rather than via flaky
# wall-clock timing.
# ===========================================================================

class TestRunFleetScanConcurrency:
    def _tracking_scan_fn(self, hold_seconds: float = 0.05):
        """Returns (scan_fn, peak_concurrency_box). scan_fn records how many
        calls are in-flight simultaneously via a lock-guarded counter."""
        state = {"current": 0, "peak": 0}
        lock = threading.Lock()

        def scan_fn(target: str, **_kwargs) -> TargetOutcome:
            with lock:
                state["current"] += 1
                state["peak"] = max(state["peak"], state["current"])
            time.sleep(hold_seconds)
            with lock:
                state["current"] -= 1
            return TargetOutcome(target_url=target, exit_code=0, result=None)

        return scan_fn, state

    def test_concurrency_is_bounded_by_max_concurrency(self) -> None:
        scan_fn, state = self._tracking_scan_fn()
        targets = [f"http://host{i}:8000" for i in range(6)]
        run_fleet_scan(targets, max_concurrency=2, scan_fn=scan_fn)
        assert state["peak"] <= 2

    def test_concurrency_actually_parallelizes_not_serialized(self) -> None:
        """max_concurrency=3 against 3 targets must let more than one run
        at once — otherwise 'bounded concurrency' silently degraded to
        one-at-a-time and the fleet feature provides no speedup."""
        scan_fn, state = self._tracking_scan_fn(hold_seconds=0.1)
        targets = [f"http://host{i}:8000" for i in range(3)]
        run_fleet_scan(targets, max_concurrency=3, scan_fn=scan_fn)
        assert state["peak"] >= 2


class TestRunFleetScanIsolation:
    def test_one_unreachable_target_does_not_mask_others(self) -> None:
        """The exact acceptance criterion: one unreachable target degrades
        to exit 3 for that host without masking findings on the others."""

        def scan_fn(target: str, **_kwargs) -> TargetOutcome:
            if target == "http://down:8000":
                raise TargetUnreachableError(f"Cannot reach {target}")
            if target == "http://vulnerable:8000":
                return TargetOutcome(target_url=target, exit_code=1, result=None)
            return TargetOutcome(target_url=target, exit_code=0, result=None)

        result = run_fleet_scan(
            ["http://down:8000", "http://vulnerable:8000", "http://clean:8000"],
            max_concurrency=3,
            scan_fn=scan_fn,
        )
        by_target = {o.target_url: o for o in result.targets}
        assert by_target["http://down:8000"].exit_code == 3
        assert by_target["http://vulnerable:8000"].exit_code == 1
        assert by_target["http://clean:8000"].exit_code == 0
        # the fleet's aggregate exit code reflects the real finding, not
        # the unreachable host
        assert result.exit_code == 1

    def test_scanner_exception_isolated_to_one_target(self) -> None:
        """An unexpected exception scanning one target must not abort the
        whole fleet run — it degrades that target to exit 2 (scanner
        error) and the others still complete."""

        def scan_fn(target: str, **_kwargs) -> TargetOutcome:
            if target == "http://broken:8000":
                raise RuntimeError("boom")
            return TargetOutcome(target_url=target, exit_code=0, result=None)

        result = run_fleet_scan(
            ["http://broken:8000", "http://clean:8000"],
            max_concurrency=2,
            scan_fn=scan_fn,
        )
        by_target = {o.target_url: o for o in result.targets}
        assert by_target["http://broken:8000"].exit_code == 2
        assert by_target["http://broken:8000"].error is not None
        assert by_target["http://clean:8000"].exit_code == 0
        assert result.exit_code == 2

    def test_result_order_matches_input_order(self) -> None:
        """Output order must be deterministic (input order), not
        completion order — concurrent scans finish in arbitrary order."""

        def scan_fn(target: str, **_kwargs) -> TargetOutcome:
            # reverse-order artificial delay so completion order != input order
            time.sleep(0.03 if target.endswith("0") else 0.0)
            return TargetOutcome(target_url=target, exit_code=0, result=None)

        targets = [f"http://host{i}:8000" for i in range(4)]
        result = run_fleet_scan(targets, max_concurrency=4, scan_fn=scan_fn)
        assert [o.target_url for o in result.targets] == targets


# ===========================================================================
# merge_sarif — combine N single-run SARIF documents into one multi-run
# document GitHub's SARIF viewer can render.
# ===========================================================================

class TestMergeSarif:
    @staticmethod
    def _single_run_sarif(target_url: str, rule_id: str | None = None) -> dict:
        run = {
            "tool": {"driver": {"name": "cosai-mcp", "version": "0.1.0", "rules": []}},
            "results": [],
            "invocations": [{"executionSuccessful": True, "properties": {"targetUrl": target_url}}],
        }
        if rule_id:
            run["tool"]["driver"]["rules"] = [{"id": rule_id, "name": rule_id}]
            run["results"] = [{"ruleId": rule_id, "level": "error", "message": {"text": "x"}}]
        return {"$schema": "https://x", "version": "2.1.0", "runs": [run]}

    def test_merges_n_documents_into_one_with_n_runs(self) -> None:
        docs = [
            self._single_run_sarif("http://host1:8000"),
            self._single_run_sarif("http://host2:8000"),
            self._single_run_sarif("http://host3:8000"),
        ]
        merged = merge_sarif(docs)
        assert merged["version"] == "2.1.0"
        assert len(merged["runs"]) == 3

    def test_preserves_every_target_findings(self) -> None:
        docs = [
            self._single_run_sarif("http://host1:8000", rule_id="T01-001"),
            self._single_run_sarif("http://host2:8000", rule_id="T03-001"),
        ]
        merged = merge_sarif(docs)
        rule_ids = {
            run["results"][0]["ruleId"] for run in merged["runs"] if run["results"]
        }
        assert rule_ids == {"T01-001", "T03-001"}

    def test_merging_empty_list_is_a_value_error(self) -> None:
        with pytest.raises(ValueError):
            merge_sarif([])


# ===========================================================================
# build_fleet_scorecard — one aggregated artifact wrapping N per-target
# signed Scorecards.
# ===========================================================================

class TestBuildFleetScorecard:
    def test_wraps_one_entry_per_target(self) -> None:
        outcomes = (
            TargetOutcome(target_url="http://host1:8000", exit_code=0, result=None),
            TargetOutcome(target_url="http://host2:8000", exit_code=1, result=None),
        )
        fleet_result = FleetResult(targets=outcomes, exit_code=1)
        doc = build_fleet_scorecard(fleet_result)
        assert doc["fleet_exit_code"] == 1
        assert doc["target_count"] == 2
        assert [t["target_url"] for t in doc["targets"]] == [
            "http://host1:8000", "http://host2:8000",
        ]

    def test_unreachable_target_has_no_scorecard_but_is_listed(self) -> None:
        outcomes = (
            TargetOutcome(
                target_url="http://down:8000", exit_code=3, result=None,
                error="Cannot reach down:8000",
            ),
        )
        fleet_result = FleetResult(targets=outcomes, exit_code=3)
        doc = build_fleet_scorecard(fleet_result)
        assert doc["targets"][0]["scorecard"] is None
        assert doc["targets"][0]["error"] == "Cannot reach down:8000"


# ===========================================================================
# _sanitize_error — panel-review finding: TargetOutcome.error is str(exc)
# on exceptions raised while scanning a TARGET SERVER (DNS, TLS, HTTP,
# JSON-RPC parsing) and can embed target-influenced bytes. Every other
# target-influenced string in this codebase is sanitized at ingestion
# (CLAUDE.md "Report Security") before reaching a written artifact; this
# closes the one new artifact (fleet scorecard) that didn't.
# ===========================================================================

class TestSanitizeError:
    def test_strips_control_chars(self) -> None:
        assert "\x1b" not in _sanitize_error("\x1b[31mred\x1b[0m")

    def test_html_escapes(self) -> None:
        result = _sanitize_error("<script>alert(1)</script>")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_caps_length(self) -> None:
        result = _sanitize_error("a" * 10_000)
        assert len(result) <= 4096 + len("…[truncated]")

    def test_ordinary_error_text_survives_readable(self) -> None:
        result = _sanitize_error("Cannot reach 127.0.0.1:1")
        assert "Cannot reach 127.0.0.1:1" in result


class TestDefaultScanOneErrorSanitization:
    def test_unreachable_error_is_sanitized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import cosai_mcp.api as api_module

        def _fake_check_reachable(host: str, port: int) -> None:
            raise TargetUnreachableError(f"Cannot reach {host}:{port} <script>evil</script>")

        monkeypatch.setattr(api_module, "check_reachable", _fake_check_reachable)
        outcome = _default_scan_one("http://evil:8000")
        assert outcome.exit_code == 3
        assert "<script>" not in (outcome.error or "")


# ===========================================================================
# skip_reachability — panel-review finding: the single-target CLI's escape
# hatch for targets whose MCP endpoint doesn't accept a bare TCP connect
# was silently dropped in fleet mode, force-failing every such target as
# UNREACHABLE with no operator recourse.
# ===========================================================================

class TestDefaultScanOneSkipReachability:
    def test_skip_reachability_bypasses_check_reachable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import cosai_mcp.api as api_module

        def _fail_if_called(host: str, port: int) -> None:
            raise AssertionError("check_reachable must not be called when skip_reachability=True")

        monkeypatch.setattr(api_module, "check_reachable", _fail_if_called)

        def _fake_run_scan(target: str, **_kwargs):
            from cosai_mcp.api import ScanResult

            return ScanResult(
                target_url=target, threats=(), probe_results=(), scenario_results=(),
                scan_timestamp="2026-01-01T00:00:00Z", catalog_hash="x", exit_code=0,
            )

        monkeypatch.setattr(api_module, "_run_scan", _fake_run_scan)
        outcome = _default_scan_one("http://localhost:8000", skip_reachability=True)
        assert outcome.exit_code == 0

    def test_reachability_still_checked_by_default(self) -> None:
        """skip_reachability defaults to False — must not silently skip
        the check unless explicitly requested."""
        outcome = _default_scan_one("http://127.0.0.1:1")  # nothing listens
        assert outcome.exit_code == 3


# ===========================================================================
# per_target_timeout — panel-review finding: ThreadPoolExecutor's default
# shutdown(wait=True) blocks until every submitted future completes, so a
# single hung target blocks the ENTIRE fleet run indefinitely, defeating
# the "one bad target doesn't block the others" guarantee at the
# whole-fleet level even though per-target isolation was already correct.
# ===========================================================================

class TestRunFleetScanTimeout:
    def test_hung_target_does_not_block_the_fleet(self) -> None:
        def scan_fn(target: str, **_kwargs) -> TargetOutcome:
            if target == "http://hung:8000":
                time.sleep(30)  # far longer than the test's per_target_timeout
                return TargetOutcome(target_url=target, exit_code=0, result=None)
            return TargetOutcome(target_url=target, exit_code=0, result=None)

        start = time.monotonic()
        result = run_fleet_scan(
            ["http://hung:8000", "http://clean:8000"],
            max_concurrency=2,
            per_target_timeout=0.3,
            scan_fn=scan_fn,
        )
        elapsed = time.monotonic() - start

        assert elapsed < 5.0, f"run_fleet_scan blocked for {elapsed}s on a hung target"
        by_target = {o.target_url: o for o in result.targets}
        assert by_target["http://hung:8000"].exit_code == 2
        assert "timed out" in (by_target["http://hung:8000"].error or "").lower()
        assert by_target["http://clean:8000"].exit_code == 0

    def test_default_timeout_does_not_interfere_with_normal_scans(self) -> None:
        """The 600s default must not fire for ordinary fast scans."""

        def scan_fn(target: str, **_kwargs) -> TargetOutcome:
            return TargetOutcome(target_url=target, exit_code=0, result=None)

        result = run_fleet_scan(
            ["http://a:8000", "http://b:8000"], max_concurrency=2, scan_fn=scan_fn
        )
        assert all(o.exit_code == 0 for o in result.targets)
