"""CoSAI MCP Security v2.0 Security Assurance Profiles — `--assurance-level` verifier.

Covers the control matrix's consistency (every linked ID exists; only
positive-signal probes may prove a control), verdict and level semantics
(fail-closed; evidence never PASS; findings beat evidence; unrun tests block
attestation; MET only when fully scanner-verified), evidence intake hardening,
scorecard embedding + strict verification, and the public entry points
(Scanner.run full-scope gate, CLI flags and reports).
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from cosai_mcp.assurance import (
    CONTROLS,
    CONTROLS_BY_ID,
    AssuranceReport,
    EvidenceItem,
    LevelResult,
    Strength,
    Verdict,
    evaluate_assurance,
    load_evidence,
)
from cosai_mcp.assurance.controls import DIMENSIONS
from cosai_mcp.catalog.loader import CatalogLoader
from cosai_mcp.harness.mock_server import MockMCPServer
from cosai_mcp.harness.result import ProbeResult

CATALOG_ROOT = Path(__file__).parent.parent / "catalog"
_PASSIVE_IDS = {"T03", "T04", "T05", "T06", "T09", "T11"}
_SCENARIO_IDS = {"T2-SC-001", "T2-SC-002", "T6-SC-001", "T7-SC-001", "T7-SC-002"}
_L1_MUSTS = ("TN-02", "TN-03", "TN-07", "IS-01", "IS-02")
# Linked tests that must have RUN for the L1 MUST controls to be attestable.
_L1_LINKED_PASSES = ("T08-003", "T07-001")


def _pr(threat_id: str, passed: bool, *, inconclusive: bool = False,
        error: bool = False, suppressed: bool = False) -> ProbeResult:
    return ProbeResult(
        probe_id=f"{threat_id}-p1", threat_id=threat_id, passed=passed,
        status_code=200, response_body="", error="boom" if error else None,
        assertions=(), duration_seconds=0.0,
        inconclusive_reason="n/a" if inconclusive else None, suppressed=suppressed,
    )


def _passes(*threat_ids: str) -> list[ProbeResult]:
    return [_pr(t, True) for t in threat_ids]


@dataclasses.dataclass(frozen=True)
class _Scenario:
    scenario_id: str
    passed: bool
    status: str = "complete"


def _ev(*control_ids: str) -> dict[str, EvidenceItem]:
    return {c: EvidenceItem(control_id=c, artifact="a.txt", sha256="0" * 64) for c in control_ids}


def _verdict(report: AssuranceReport, control_id: str) -> Verdict:
    return next(c.verdict for c in report.controls if c.control_id == control_id)


def _reason(report: AssuranceReport, control_id: str) -> str:
    return next(c.reason for c in report.controls if c.control_id == control_id)


# ===========================================================================
# Control matrix consistency
# ===========================================================================

class TestControlMatrix:
    def test_ids_unique_and_dimensions_valid(self) -> None:
        ids = [c.control_id for c in CONTROLS]
        assert len(ids) == len(set(ids))
        assert {c.dimension for c in CONTROLS} == set(DIMENSIONS)

    def test_levels_and_blackbox_bounds(self) -> None:
        for c in CONTROLS:
            assert c.levels and set(c.levels) <= {1, 2, 3, 4}, c.control_id
            assert 0 <= c.blackbox_max_level <= max(c.levels), c.control_id
            assert bool(c.blackbox_max_level) == bool(c.verify_with), c.control_id

    def test_every_linked_id_exists(self) -> None:
        """Format coverage: a typo'd link would silently never fail a control."""
        catalog_ids = {t.id for t in CatalogLoader(CATALOG_ROOT).load_all()}
        known = catalog_ids | _PASSIVE_IDS | _SCENARIO_IDS
        for c in CONTROLS:
            assert not (set(c.probe_threats) - known), c.control_id
            assert set(c.verify_with) <= catalog_ids, c.control_id

    def test_exploit_negative_assertion_probes_cannot_verify(self) -> None:
        """Only probes asserting a POSITIVE control signal (specific rejection
        code / status / error=true) may prove a control. 'Did not leak X' passes
        against a tool that ignores its arguments (adversary P1b EXPLOIT 4)."""
        threats = {t.id: t for t in CatalogLoader(CATALOG_ROOT).load_all()}

        def positive(a: Any) -> bool:
            op = a.operator.value
            # A generic `response.error == true` is NOT positive: an auth
            # rejection or rate limit satisfies it (round-2 EXPLOIT 3).
            return (
                (a.target == "response.error_code" and op in ("eq", "error_code_in"))
                or (a.target == "response.status_code" and op == "status_in")
            )

        for c in CONTROLS:
            for tid in c.verify_with:
                for probe in threats[tid].probes:
                    assert probe.assertions and all(positive(a) for a in probe.assertions), \
                        (c.control_id, probe.id)

    def test_level3_token_binding_is_a_hard_must(self) -> None:
        req = CONTROLS_BY_ID["AZ-04"].requirement(3)
        assert req is not None and req.strength is Strength.MUST
        assert CONTROLS_BY_ID["AZ-04"].requirement(2) is None

    def test_regression_sd07_confidentiality_clause_is_must(self) -> None:
        sd07 = CONTROLS_BY_ID["SD-07"].requirement(2)
        is01 = CONTROLS_BY_ID["IS-01"].requirement(1)
        assert sd07 is not None and sd07.strength is Strength.MUST
        assert is01 is not None and is01.strength is Strength.MUST


# ===========================================================================
# Verdict / level semantics
# ===========================================================================

class TestEvaluate:
    def test_level1_must_set(self) -> None:
        report = evaluate_assurance(1, [])
        musts = {c.control_id for c in report.controls if c.strength is Strength.MUST}
        assert musts == set(_L1_MUSTS)

    def test_no_results_is_indeterminate(self) -> None:
        report = evaluate_assurance(1, [])
        assert report.result is LevelResult.INDETERMINATE

    def test_positive_signal_probes_prove_control(self) -> None:
        report = evaluate_assurance(2, _passes("T07-004", "T07-005"))
        assert _verdict(report, "TN-04") is Verdict.PASS

    def test_exploit_partial_linked_probes_not_pass(self) -> None:
        missing = evaluate_assurance(2, _passes("T07-004"))
        assert _verdict(missing, "TN-04") is Verdict.UNVERIFIED
        assert "did not run" in _reason(missing, "TN-04")
        inconclusive = evaluate_assurance(
            2, [*_passes("T07-004"), _pr("T07-005", True, inconclusive=True)])
        assert _verdict(inconclusive, "TN-04") is Verdict.UNVERIFIED
        assert "no conclusive result" in _reason(inconclusive, "TN-04")

    def test_regression_ti06_partial_category_scan_is_not_pass(self) -> None:
        report = evaluate_assurance(3, _passes("T08-004", "T08-005"))
        assert _verdict(report, "TI-06") is Verdict.UNVERIFIED

    def test_exploit_reachability_probe_does_not_prove_binding(self) -> None:
        report = evaluate_assurance(1, _passes("T08-003"))
        assert _verdict(report, "TN-02") is Verdict.UNVERIFIED

    def test_exploit_auth_rejection_does_not_verify_payload_limits(self) -> None:
        """T10 probes accept any error (auth/rate-limit), so they can never PROVE
        payload limits — only disprove them."""
        report = evaluate_assurance(2, _passes("T10-001", "T10-002", "T10-003",
                                               "T10-004", "T10-005"))
        assert _verdict(report, "TN-05") is Verdict.UNVERIFIED

    def test_exploit_verifier_threat_with_one_inconclusive_probe_not_pass(self) -> None:
        p2 = dataclasses.replace(_pr("T07-004", True, inconclusive=True), probe_id="T07-004-p2")
        report = evaluate_assurance(2, [*_passes("T07-004", "T07-005"), p2])
        assert _verdict(report, "TN-04") is Verdict.UNVERIFIED

    def test_exploit_passive_inconclusive_blocks_attestation(self) -> None:
        ti01_linked = ("T06-001", "T06-002", "T11-001")
        results = [*_passes(*ti01_linked), _pr("T11", False, inconclusive=True)]
        report = evaluate_assurance(3, results, [_Scenario("T6-SC-001", passed=True)],
                                    evidence=_ev("TI-01"))
        assert _verdict(report, "TI-01") is Verdict.UNVERIFIED
        assert "T11" in _reason(report, "TI-01")
        absent = evaluate_assurance(3, _passes(*ti01_linked),
                                    [_Scenario("T6-SC-001", passed=True)], evidence=_ev("TI-01"))
        assert _verdict(absent, "TI-01") is Verdict.ATTESTED  # absent passive scan is exempt

    def test_exploit_era_not_applicable_linked_probes_block_attestation(self) -> None:
        report = evaluate_assurance(
            2, [_pr("T07-004", False, inconclusive=True), _pr("T07-005", False, inconclusive=True)],
            evidence=_ev("TN-04"))
        assert _verdict(report, "TN-04") is Verdict.UNVERIFIED
        assert "no conclusive" in _reason(report, "TN-04")

    def test_blackbox_above_max_level_is_unverified(self) -> None:
        report = evaluate_assurance(4, _passes("T07-004", "T07-005"))
        assert _verdict(report, "TN-04") is Verdict.UNVERIFIED
        assert "only up to Level 3" in _reason(report, "TN-04")

    def test_finding_fails_level(self) -> None:
        report = evaluate_assurance(1, [_pr("T08-003", False), *_passes("T07-001")],
                                    evidence=_ev(*_L1_MUSTS))
        assert _verdict(report, "TN-02") is Verdict.FAIL
        assert report.result is LevelResult.NOT_MET

    def test_finding_beats_evidence(self) -> None:
        report = evaluate_assurance(1, [_pr("T08-003", False)], evidence=_ev("TN-02"))
        assert _verdict(report, "TN-02") is Verdict.FAIL

    def test_baseline_suppressed_finding_still_fails(self) -> None:
        report = evaluate_assurance(1, [_pr("T08-003", False, suppressed=True)])
        assert _verdict(report, "TN-02") is Verdict.FAIL

    def test_unrun_linked_tests_block_attestation(self) -> None:
        report = evaluate_assurance(2, [], evidence=_ev("ID-01"))
        assert _verdict(report, "ID-01") is Verdict.UNVERIFIED
        assert "did not run" in _reason(report, "ID-01")

    def test_evidence_is_attested_not_pass(self) -> None:
        report = evaluate_assurance(2, [], evidence=_ev("ID-02"))
        assert _verdict(report, "ID-02") is Verdict.ATTESTED

    def test_exploit_all_attested_not_plain_met(self) -> None:
        report = evaluate_assurance(1, _passes(*_L1_LINKED_PASSES), evidence=_ev(*_L1_MUSTS))
        assert report.result is LevelResult.MET_WITH_ATTESTATION
        assert report.to_dict()["must_counts"]["attested"] == len(_L1_MUSTS)

    def test_failing_stateful_scenario_fails_control(self) -> None:
        report = evaluate_assurance(3, [], [_Scenario("T2-SC-002", passed=False)])
        assert _verdict(report, "AZ-01") is Verdict.FAIL
        assert report.result is LevelResult.NOT_MET

    def test_incomplete_scenario_is_not_evidence(self) -> None:
        report = evaluate_assurance(
            3, [], [_Scenario("T2-SC-002", passed=False, status="scan-incomplete")])
        assert _verdict(report, "AZ-01") is Verdict.UNVERIFIED

    def test_should_failure_does_not_gate(self) -> None:
        report = evaluate_assurance(
            1, [_pr("T02-003", False), *_passes(*_L1_LINKED_PASSES)],
            evidence=_ev(*_L1_MUSTS))
        assert _verdict(report, "AZ-08") is Verdict.FAIL
        assert report.result is LevelResult.MET_WITH_ATTESTATION

    def test_passive_scan_ids_link(self) -> None:
        report = evaluate_assurance(3, [_pr("T03", False)])
        assert _verdict(report, "TI-02") is Verdict.FAIL

    def test_rejects_bad_level(self) -> None:
        with pytest.raises(ValueError):
            evaluate_assurance(5, [])


# ===========================================================================
# Evidence intake
# ===========================================================================

_TARGET = "http://127.0.0.1:9"


def _write_manifest(root: Path, controls: dict[str, Any], *, target: str | None = _TARGET,
                    **top: Any) -> None:
    doc: dict[str, Any] = {"schema_version": "1.0", "controls": controls, **top}
    if target is not None:
        doc["target"] = target
    (root / "evidence.json").write_text(json.dumps(doc))


class TestEvidence:
    def test_valid_manifest_hashes_artifact_and_sanitizes_note(self, tmp_path: Path) -> None:
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "iss.txt").write_bytes(b"proof")
        _write_manifest(tmp_path, {"ID-02": {"artifact": "sub/iss.txt",
                                             "note": "<b>ok</b>\x1b[31m"}})
        manifest = load_evidence(tmp_path)
        assert manifest.target == _TARGET
        assert manifest.items["ID-02"].sha256 == hashlib.sha256(b"proof").hexdigest()
        assert manifest.items["ID-02"].note == "&lt;b&gt;ok&lt;/b&gt;[31m"

    def test_regression_artifact_ansi_escape_stripped_from_reason(self, tmp_path: Path) -> None:
        name = "ev\x1b[2Jspoof.txt"
        (tmp_path / name).write_text("x")
        _write_manifest(tmp_path, {"ID-02": {"artifact": name}})
        item = load_evidence(tmp_path).items["ID-02"]
        assert "\x1b" not in item.artifact
        report = evaluate_assurance(2, [], evidence={"ID-02": item})
        assert "\x1b" not in _reason(report, "ID-02")

    @pytest.mark.parametrize("controls", [
        {"XX-99": {"artifact": "a.txt"}},                       # unknown control
        {"ID-02": {"artifact": "a.txt", "extra": 1}},           # unknown entry key
        {"ID-02": {"artifact": "../outside.txt"}},              # traversal
        {"ID-02": {"artifact": "/etc/passwd"}},                 # absolute
        {"ID-02": {"artifact": "missing.txt"}},                 # missing file
        {"ID-02": {"artifact": "empty.txt"}},                   # empty artifact
        {"ID-02": {"artifact": ""}},                            # empty path
        {"ID-02": "a.txt"},                                     # wrong shape
    ])
    def test_rejects_bad_entries(self, tmp_path: Path, controls: dict[str, Any]) -> None:
        (tmp_path / "a.txt").write_text("x")
        (tmp_path / "empty.txt").write_text("")
        (tmp_path.parent / "outside.txt").write_text("x")
        _write_manifest(tmp_path, controls)
        with pytest.raises((ValueError, FileNotFoundError)):
            load_evidence(tmp_path)

    def test_requires_target(self, tmp_path: Path) -> None:
        _write_manifest(tmp_path, {}, target=None)
        with pytest.raises(ValueError, match="target"):
            load_evidence(tmp_path)

    def test_rejects_unknown_top_level_key(self, tmp_path: Path) -> None:
        _write_manifest(tmp_path, {}, level_override=4)
        with pytest.raises(ValueError):
            load_evidence(tmp_path)

    def test_rejects_symlinked_artifact(self, tmp_path: Path) -> None:
        secret = tmp_path.parent / "secret.txt"
        secret.write_text("s")
        os.symlink(secret, tmp_path / "link.txt")
        _write_manifest(tmp_path, {"ID-02": {"artifact": "link.txt"}})
        with pytest.raises(ValueError, match="symlink"):
            load_evidence(tmp_path)

    def test_rejects_symlinked_evidence_dir(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        real.mkdir()
        _write_manifest(real, {})
        os.symlink(real, tmp_path / "ev")
        with pytest.raises(ValueError, match="symlink"):
            load_evidence(tmp_path / "ev")

    def test_rejects_invalid_json(self, tmp_path: Path) -> None:
        (tmp_path / "evidence.json").write_text("{not json")
        with pytest.raises(ValueError):
            load_evidence(tmp_path)


# ===========================================================================
# Scorecard embedding + strict verification
# ===========================================================================

def _minimal_scan_result(assurance: AssuranceReport | None) -> Any:
    from cosai_mcp.api import ScanResult

    return ScanResult(
        target_url="http://t", threats=(), probe_results=(), scenario_results=(),
        scan_timestamp="2026-09-27T00:00:00+00:00", catalog_hash="h", exit_code=0,
        assurance=assurance,
    )


def _signed_scorecard_file(tmp_path: Path, report: AssuranceReport | None) -> Path:
    from cosai_mcp.scorecard.builder import build_scorecard

    sc = build_scorecard(_minimal_scan_result(report), signed=True)
    path = tmp_path / "sc.json"
    path.write_text(json.dumps(sc.to_dict(), indent=2))
    return path


class TestScorecard:
    def test_assurance_block_signed_and_round_trips(self) -> None:
        from cosai_mcp.scorecard.builder import build_scorecard
        from cosai_mcp.scorecard.models import Scorecard
        from cosai_mcp.scorecard.signing import verify_scorecard

        report = evaluate_assurance(1, _passes(*_L1_LINKED_PASSES), evidence=_ev("IS-02"),
                                    scope={"engine": "all"})
        sc = build_scorecard(_minimal_scan_result(report), signed=True)
        reloaded = Scorecard.from_dict(json.loads(json.dumps(sc.to_dict())))
        assert reloaded.assurance == report
        verify_scorecard(reloaded)

    def test_tampered_assurance_block_fails_verification(self) -> None:
        from cosai_mcp.scorecard.builder import build_scorecard
        from cosai_mcp.scorecard.models import Scorecard
        from cosai_mcp.scorecard.signing import ScorecardVerificationError, verify_scorecard

        sc = build_scorecard(_minimal_scan_result(evaluate_assurance(1, [])), signed=True)
        d = sc.to_dict()
        d["assurance"]["result"] = "met"
        with pytest.raises(ScorecardVerificationError):
            verify_scorecard(Scorecard.from_dict(d))

    def test_scorecard_without_assurance_omits_key(self) -> None:
        from cosai_mcp.scorecard.builder import build_scorecard
        from cosai_mcp.scorecard.models import Scorecard
        from cosai_mcp.scorecard.signing import verify_scorecard

        sc = build_scorecard(_minimal_scan_result(None), signed=True)
        d = sc.to_dict()
        assert "assurance" not in d
        verify_scorecard(Scorecard.from_dict(d))

    def test_verify_and_show_print_assurance(self, tmp_path: Path) -> None:
        from cosai_mcp.cli import main

        path = _signed_scorecard_file(tmp_path, evaluate_assurance(1, []))
        verify = CliRunner().invoke(main, ["scorecard", "verify", str(path)])
        assert verify.exit_code == 0, verify.output
        assert "CoSAI assurance: Level 1 → indeterminate" in verify.output
        show = CliRunner().invoke(main, ["scorecard", "show", str(path)])
        assert "CoSAI assurance: Level 1" in show.output

    def test_regression_scorecard_show_prints_assurance_block(self, tmp_path: Path) -> None:
        from cosai_mcp.cli import main

        report = evaluate_assurance(1, _passes(*_L1_LINKED_PASSES), evidence=_ev(*_L1_MUSTS))
        path = _signed_scorecard_file(tmp_path, report)
        show = CliRunner().invoke(main, ["scorecard", "show", str(path)])
        assert "met_with_attestation" in show.output

    def test_exploit_duplicate_key_scorecard_rejected(self, tmp_path: Path) -> None:
        from cosai_mcp.cli import main

        path = _signed_scorecard_file(tmp_path, evaluate_assurance(1, []))
        text = path.read_text().replace(
            '"result": "indeterminate"', '"result": "met", "result": "indeterminate"', 1)
        path.write_text(text)
        result = CliRunner().invoke(main, ["scorecard", "verify", str(path)])
        assert result.exit_code == 2 and "duplicate" in result.output

    def test_exploit_show_unverified_assurance_claim_sanitized_and_labelled(
        self, tmp_path: Path,
    ) -> None:
        from cosai_mcp.cli import main

        path = _signed_scorecard_file(tmp_path, evaluate_assurance(1, []))
        d = json.loads(path.read_text())
        d["assurance"]["profile_version"] = "v2\x1b[2J forged"
        path.write_text(json.dumps(d))
        show = CliRunner().invoke(main, ["scorecard", "show", str(path)])
        assert "\x1b" not in show.output
        assert "signature NOT verified" in show.output
        d["assurance"] = "x"
        path.write_text(json.dumps(d))
        crashed = CliRunner().invoke(main, ["scorecard", "show", str(path)])
        assert crashed.exit_code == 2 and not isinstance(crashed.exception, TypeError)

    @pytest.mark.parametrize("mutate", [
        lambda d: d["assurance"]["must_counts"].__setitem__("pass", 99),
        lambda d: d["assurance"].__setitem__("verified_by", "auditor"),
        lambda d: d.__setitem__("assurance_override", {"result": "met"}),
    ])
    def test_non_canonical_fields_rejected(self, tmp_path: Path, mutate: Any) -> None:
        from cosai_mcp.cli import main

        path = _signed_scorecard_file(tmp_path, evaluate_assurance(1, []))
        d = json.loads(path.read_text())
        mutate(d)
        path.write_text(json.dumps(d))
        result = CliRunner().invoke(main, ["scorecard", "verify", str(path)])
        assert result.exit_code == 2, result.output


# ===========================================================================
# Entry points — a level claim requires a FULL scan
# ===========================================================================

def _l1_evidence(root: Path, target: str) -> Path:
    root.mkdir(exist_ok=True)
    (root / "art.txt").write_text("attestation")
    _write_manifest(root, {c: {"artifact": "art.txt"} for c in _L1_MUSTS}, target=target)
    return root


def _full_scan(monkeypatch: pytest.MonkeyPatch, evidence: Path | None,
               server: MockMCPServer, base_exit: int = 0) -> Any:
    import cosai_mcp.api as api
    from cosai_mcp import Scanner

    monkeypatch.setattr(api, "_determine_exit_code", lambda *a, **k: base_exit)
    return Scanner(
        f"http://127.0.0.1:{server.port}", allow_private_targets=True,
        probe_timeout_seconds=10.0, assurance_level=1, evidence_dir=evidence,
    ).run()


class TestScannerGate:
    def test_full_scan_gate_indeterminate_then_attested(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        with MockMCPServer() as server:
            server.wait_ready()
            target = f"http://127.0.0.1:{server.port}"
            bare = _full_scan(monkeypatch, None, server)
            attested = _full_scan(monkeypatch, _l1_evidence(tmp_path / "ev", target), server)
            internal = _full_scan(monkeypatch, None, server, base_exit=2)
        assert bare.assurance.result is LevelResult.INDETERMINATE and bare.exit_code == 1
        assert attested.assurance.result is LevelResult.MET_WITH_ATTESTATION
        assert attested.exit_code == 0
        assert attested.assurance.scope["engine"] == "all"
        assert attested.assurance.scope["categories"] is None
        assert attested.assurance.scope["protocol_era"] == "auto"
        assert attested.assurance.scope["auth_token_supplied"] is False
        assert internal.exit_code == 2  # never downgraded

    @pytest.mark.parametrize("kwargs", [
        {"categories": ["T8"]},
        {"engine": "prober"},
    ])
    def test_exploit_category_filter_cannot_yield_met(self, kwargs: dict[str, Any]) -> None:
        from cosai_mcp import Scanner

        with pytest.raises(ValueError, match="full scan|--engine all"):
            Scanner(_TARGET, allow_private_targets=True, assurance_level=1, **kwargs).run()

    def test_exploit_custom_catalog_id_collision_cannot_verify_control(self) -> None:
        from cosai_mcp import Scanner

        with pytest.raises(ValueError, match="allow-custom-catalog"):
            Scanner(_TARGET, allow_private_targets=True, assurance_level=1,
                    allow_custom_catalog=True).run()

    def test_exploit_uppercase_engine_runs_all_engines_under_assurance(self) -> None:
        from cosai_mcp import Scanner

        with MockMCPServer() as server:
            server.wait_ready()
            result = Scanner(f"http://127.0.0.1:{server.port}", allow_private_targets=True,
                             categories=["T8"], engine="PROBER").run()
        assert result.probe_results  # normalised: the prober branch actually ran

    def test_profile_skipping_categories_rejected(self) -> None:
        from cosai_mcp import Scanner
        from cosai_mcp.profiles.builtin import BUILTIN_PROFILES

        profile = next(p for p in BUILTIN_PROFILES.values() if p.skip_categories)
        with pytest.raises(ValueError, match="skips"):
            Scanner(_TARGET, allow_private_targets=True, assurance_level=1,
                    profile=profile).run()

    def test_evidence_for_other_target_rejected_before_probes(self, tmp_path: Path) -> None:
        from cosai_mcp import Scanner

        with MockMCPServer() as server:
            server.wait_ready()
            ev = _l1_evidence(tmp_path / "ev", "https://other.example.com/mcp")
            with pytest.raises(ValueError, match="does not match"):
                Scanner(f"http://127.0.0.1:{server.port}", allow_private_targets=True,
                        assurance_level=1, evidence_dir=ev).run()
            assert server.request_log == []

    def test_evidence_without_level_rejected(self, tmp_path: Path) -> None:
        from cosai_mcp import Scanner

        with pytest.raises(ValueError, match="--evidence requires"):
            Scanner(_TARGET, allow_private_targets=True,
                    evidence_dir=_l1_evidence(tmp_path / "ev", _TARGET)).run()


class TestCli:
    def test_exploit_report_assurance_bound_to_scorecard(self, tmp_path: Path) -> None:
        from cosai_mcp.cli import main

        report_path = tmp_path / "assurance.json"
        sc_path = tmp_path / "sc.json"
        with MockMCPServer() as server:
            server.wait_ready()
            target = f"http://127.0.0.1:{server.port}"
            result = CliRunner().invoke(main, [
                "scan", target, "--allow-private-targets", "--no-report",
                "--assurance-level", "1", "--evidence", str(_l1_evidence(tmp_path / "ev", target)),
                "--report-assurance", str(report_path), "--scorecard", str(sc_path),
            ])
        assert "CoSAI assurance Level 1" in result.output, result.output
        doc = json.loads(report_path.read_text())
        sc = json.loads(sc_path.read_text())
        assert doc["unsigned_copy"] is True
        assert doc["scorecard_signature"] == sc["signature"]
        assert doc["assurance"] == sc["assurance"]
        assert sc["assurance"]["result"] == "met_with_attestation"
        verify = CliRunner().invoke(main, ["scorecard", "verify", str(sc_path)])
        assert verify.exit_code == 0, verify.output

    def test_cli_rejects_out_of_range_level(self) -> None:
        from cosai_mcp.cli import main

        result = CliRunner().invoke(main, ["scan", _TARGET, "--assurance-level", "5"])
        assert result.exit_code == 2

    def test_cli_report_assurance_requires_level(self, tmp_path: Path) -> None:
        from cosai_mcp.cli import main

        with MockMCPServer() as server:
            server.wait_ready()
            result = CliRunner().invoke(main, [
                "scan", f"http://127.0.0.1:{server.port}", "--allow-private-targets",
                "--categories", "T8", "--engine", "prober", "--no-report",
                "--report-assurance", str(tmp_path / "a.json"),
            ])
        assert result.exit_code == 2
        assert "requires --assurance-level" in result.output

    def test_cli_fleet_rejects_assurance_level(self, tmp_path: Path) -> None:
        from cosai_mcp.cli import main

        targets = tmp_path / "fleet.txt"
        targets.write_text(f"{_TARGET}\n")
        result = CliRunner().invoke(main, ["scan", "--targets", str(targets),
                                           "--assurance-level", "2"])
        assert result.exit_code == 2 and "--assurance-level" in result.output
