"""Tests for cosai_mcp.scorecard — models, builder, signing, CLI."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from cosai_mcp.cli import main
from cosai_mcp.scorecard.builder import build_scorecard, _grade_category, _determine_conformance
from cosai_mcp.scorecard.models import (
    CategoryResult,
    ConformanceLevel,
    Grade,
    Scorecard,
)
from cosai_mcp.scorecard.signing import (
    ScorecardVerificationError,
    sign_scorecard,
    verify_scorecard,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_scorecard(
    conformance_level: ConformanceLevel = ConformanceLevel.FULL_CONFORMANCE,
    categories: list[CategoryResult] | None = None,
    signed: bool = False,
) -> Scorecard:
    if categories is None:
        categories = [
            CategoryResult(
                category=f"T{i}",
                grade=Grade.PASS,
                probe_count=2,
                finding_count=0,
                critical_count=0,
                high_count=0,
                coverage_engine="black_box_prober",
            )
            for i in range(1, 13)
        ]
    sc = Scorecard(
        scan_id="test-scan-123",
        target_url="http://target.example.com:8000",
        scan_timestamp="2026-05-15T12:00:00Z",
        catalog_hash="abc123",
        tool_version="0.0.1-test",
        categories=tuple(categories),
        conformance_level=conformance_level,
        public_key="",
        signature="",
    )
    if signed:
        return sign_scorecard(sc)
    return sc


def _make_fail_category(cat: str, critical: int = 1) -> CategoryResult:
    return CategoryResult(
        category=cat,
        grade=Grade.FAIL,
        probe_count=3,
        finding_count=critical,
        critical_count=critical,
        high_count=0,
        coverage_engine="black_box_prober",
    )


# ---------------------------------------------------------------------------
# Grade assignment
# ---------------------------------------------------------------------------

class TestGradeAssignment:
    def test_no_probes_is_not_tested(self) -> None:
        assert _grade_category(0, 0, 0, 0) == Grade.NOT_TESTED

    def test_probes_no_findings_is_pass(self) -> None:
        assert _grade_category(5, 0, 0, 0) == Grade.PASS

    def test_critical_finding_is_fail(self) -> None:
        assert _grade_category(5, 2, 1, 0) == Grade.FAIL

    def test_high_finding_is_fail(self) -> None:
        assert _grade_category(5, 1, 0, 1) == Grade.FAIL

    def test_medium_only_finding_is_warn(self) -> None:
        assert _grade_category(5, 1, 0, 0) == Grade.WARN

    def test_low_only_finding_is_warn(self) -> None:
        assert _grade_category(5, 2, 0, 0) == Grade.WARN


# ---------------------------------------------------------------------------
# Conformance level determination
# ---------------------------------------------------------------------------

class TestConformanceLevels:
    def test_all_pass_is_full_conformance(self) -> None:
        cats = [
            CategoryResult(f"T{i}", Grade.PASS, 2, 0, 0, 0, "prober")
            for i in range(1, 13)
        ]
        assert _determine_conformance(cats) == ConformanceLevel.FULL_CONFORMANCE

    def test_one_fail_no_critical_is_partial(self) -> None:
        cats = [CategoryResult(f"T{i}", Grade.PASS, 2, 0, 0, 0, "prober") for i in range(1, 13)]
        cats[0] = CategoryResult("T1", Grade.FAIL, 2, 1, 0, 1, "prober")  # high, not critical
        assert _determine_conformance(cats) == ConformanceLevel.PARTIAL_CONFORMANCE

    def test_one_fail_with_critical_is_non_conformant(self) -> None:
        cats = [CategoryResult(f"T{i}", Grade.PASS, 2, 0, 0, 0, "prober") for i in range(1, 13)]
        cats[0] = CategoryResult("T1", Grade.FAIL, 2, 1, 1, 0, "prober")  # critical
        assert _determine_conformance(cats) == ConformanceLevel.NON_CONFORMANT

    def test_four_fails_is_non_conformant(self) -> None:
        cats = [CategoryResult(f"T{i}", Grade.PASS, 2, 0, 0, 0, "prober") for i in range(1, 13)]
        for i in range(4):
            cats[i] = CategoryResult(f"T{i+1}", Grade.FAIL, 2, 1, 0, 1, "prober")
        assert _determine_conformance(cats) == ConformanceLevel.NON_CONFORMANT

    def test_excessive_not_tested_is_insufficient(self) -> None:
        cats = [CategoryResult(f"T{i}", Grade.NOT_TESTED, 0, 0, 0, 0, "prober") for i in range(1, 13)]
        assert _determine_conformance(cats) == ConformanceLevel.INSUFFICIENT_COVERAGE

    def test_warn_not_counted_as_fail(self) -> None:
        cats = [CategoryResult(f"T{i}", Grade.PASS, 2, 0, 0, 0, "prober") for i in range(1, 13)]
        cats[0] = CategoryResult("T1", Grade.WARN, 2, 1, 0, 0, "prober")
        # WARN + all others PASS → full conformance (WARN is not FAIL)
        level = _determine_conformance(cats)
        assert level == ConformanceLevel.FULL_CONFORMANCE


# ---------------------------------------------------------------------------
# CategoryResult + Scorecard serialisation
# ---------------------------------------------------------------------------

class TestSerialisation:
    def test_category_result_roundtrip(self) -> None:
        cr = CategoryResult(
            category="T1",
            grade=Grade.FAIL,
            probe_count=3,
            finding_count=2,
            critical_count=1,
            high_count=1,
            coverage_engine="black_box_prober",
        )
        restored = CategoryResult.from_dict(cr.to_dict())
        assert restored.category == "T1"
        assert restored.grade == Grade.FAIL
        assert restored.critical_count == 1

    def test_scorecard_to_dict_json_serializable(self) -> None:
        sc = _make_scorecard()
        json.dumps(sc.to_dict())  # must not raise

    def test_scorecard_roundtrip(self) -> None:
        sc = _make_scorecard()
        restored = Scorecard.from_dict(sc.to_dict())
        assert restored.scan_id == sc.scan_id
        assert restored.conformance_level == sc.conformance_level
        assert len(restored.categories) == len(sc.categories)

    def test_scorecard_has_12_categories(self) -> None:
        sc = _make_scorecard()
        assert len(sc.categories) == 12
        category_names = {c.category for c in sc.categories}
        assert category_names == {f"T{i}" for i in range(1, 13)}


# ---------------------------------------------------------------------------
# Ed25519 signing and verification
# ---------------------------------------------------------------------------

class TestSigning:
    def test_sign_produces_public_key_and_signature(self) -> None:
        sc = _make_scorecard()
        signed = sign_scorecard(sc)
        assert signed.public_key != ""
        assert signed.signature != ""
        assert signed.is_signed

    def test_verify_passes_on_valid_signature(self) -> None:
        sc = _make_scorecard(signed=True)
        verify_scorecard(sc)  # must not raise

    def test_verify_fails_on_tampered_conformance_level(self) -> None:
        sc = _make_scorecard(signed=True)
        tampered = Scorecard.from_dict({
            **sc.to_dict(),
            "conformance_level": ConformanceLevel.FULL_CONFORMANCE.value,  # changed
        })
        # Only fails if the conformance_level was different in the original
        if sc.conformance_level != ConformanceLevel.FULL_CONFORMANCE:
            with pytest.raises(ScorecardVerificationError):
                verify_scorecard(tampered)

    def test_verify_fails_on_tampered_target_url(self) -> None:
        sc = _make_scorecard(signed=True)
        tampered_dict = sc.to_dict()
        tampered_dict["target_url"] = "http://attacker.example.com"
        tampered = Scorecard.from_dict(tampered_dict)
        with pytest.raises(ScorecardVerificationError):
            verify_scorecard(tampered)

    def test_verify_fails_on_tampered_finding_count(self) -> None:
        # Reduce finding count in T1 to make it look clean
        cats = list(_make_scorecard().categories)
        cats[0] = CategoryResult("T1", Grade.FAIL, 3, 2, 1, 0, "prober")
        sc = sign_scorecard(_make_scorecard(categories=cats))
        # Tamper: change finding_count to 0
        d = sc.to_dict()
        d["categories"][0]["finding_count"] = 0
        d["categories"][0]["grade"] = "pass"
        tampered = Scorecard.from_dict(d)
        with pytest.raises(ScorecardVerificationError):
            verify_scorecard(tampered)

    def test_verify_fails_on_unsigned_scorecard(self) -> None:
        sc = _make_scorecard(signed=False)
        with pytest.raises(ScorecardVerificationError, match="unsigned"):
            verify_scorecard(sc)

    def test_regression_trust_anchor_rejects_foreign_key(self) -> None:
        """A scorecard signed by a different key must be rejected when the local key is pinned."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        # Generate a foreign key
        foreign_priv = Ed25519PrivateKey.generate()
        foreign_pub = foreign_priv.public_key().public_bytes_raw()

        # Produce a valid signature under the foreign key
        from cosai_mcp.scorecard.signing import _canonical_bytes, _signable_dict
        sc_base = _make_scorecard()
        payload = _canonical_bytes(_signable_dict(sc_base))
        foreign_sig = foreign_priv.sign(payload)

        forged = Scorecard.from_dict({
            **sc_base.to_dict(),
            "public_key": foreign_pub.hex(),
            "signature": foreign_sig.hex(),
        })

        # Patch trust anchor to return local key (≠ foreign key)
        local_priv = Ed25519PrivateKey.generate()
        local_pub = local_priv.public_key().public_bytes_raw()
        with patch(
            "cosai_mcp.scorecard.signing._get_trusted_public_key_bytes",
            return_value=local_pub,
        ):
            with pytest.raises(ScorecardVerificationError, match="trusted"):
                verify_scorecard(forged)

    def test_regression_h1_fail_closed_when_no_trust_anchor(self) -> None:
        """H-1 sibling: scorecard verify must FAIL CLOSED when neither the
        keyring key nor COSAI_SCORECARD_PUBKEY is available — a fresh-keypair
        forgery must NOT pass.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cosai_mcp.scorecard.signing import _canonical_bytes, _signable_dict

        attacker = Ed25519PrivateKey.generate()
        sc_base = _make_scorecard()
        payload = _canonical_bytes(_signable_dict(sc_base))
        forged = Scorecard.from_dict({
            **sc_base.to_dict(),
            "public_key": attacker.public_key().public_bytes_raw().hex(),
            "signature": attacker.sign(payload).hex(),
        })
        with patch(
            "cosai_mcp.scorecard.signing._get_trusted_public_key_bytes",
            return_value=None,
        ):
            with pytest.raises(ScorecardVerificationError, match="No trust anchor"):
                verify_scorecard(forged)

    def test_regression_l1_malformed_env_pubkey_fails_closed(
        self, monkeypatch
    ) -> None:
        """L-1 sibling: malformed COSAI_SCORECARD_PUBKEY must raise a config
        error, never silently downgrade to fail-open.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cosai_mcp.scorecard.signing import _canonical_bytes, _signable_dict

        monkeypatch.setenv("COSAI_SCORECARD_PUBKEY", "!!!not-base64!!!")
        attacker = Ed25519PrivateKey.generate()
        sc_base = _make_scorecard()
        payload = _canonical_bytes(_signable_dict(sc_base))
        forged = Scorecard.from_dict({
            **sc_base.to_dict(),
            "public_key": attacker.public_key().public_bytes_raw().hex(),
            "signature": attacker.sign(payload).hex(),
        })
        with pytest.raises(ScorecardVerificationError, match="not valid base64"):
            verify_scorecard(forged)

    def test_regression_h1_cli_verify_fails_closed_no_anchor(
        self, tmp_path
    ) -> None:
        """H-1 at the CLI entry point: `cosai scorecard verify` must exit
        non-zero on a fresh-keypair forgery when no trust anchor exists.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cosai_mcp.scorecard.signing import _canonical_bytes, _signable_dict

        attacker = Ed25519PrivateKey.generate()
        sc_base = _make_scorecard()
        payload = _canonical_bytes(_signable_dict(sc_base))
        forged = Scorecard.from_dict({
            **sc_base.to_dict(),
            "public_key": attacker.public_key().public_bytes_raw().hex(),
            "signature": attacker.sign(payload).hex(),
        })
        sc_path = tmp_path / "forged_scorecard.json"
        sc_path.write_text(json.dumps(forged.to_dict()), encoding="utf-8")

        with patch(
            "cosai_mcp.scorecard.signing._get_trusted_public_key_bytes",
            return_value=None,
        ):
            result = CliRunner().invoke(
                main, ["scorecard", "verify", str(sc_path)]
            )
        assert result.exit_code == 1, result.output
        assert "signature valid" not in result.output.lower()

    def test_regression_scorecard_tampered_then_resigned_rejected(self) -> None:
        """Re-signing a tampered scorecard with a different key must be rejected."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cosai_mcp.scorecard.signing import _canonical_bytes, _signable_dict

        # Start with a clean signed scorecard
        sc = _make_scorecard(signed=True)
        trusted_pub = bytes.fromhex(sc.public_key)

        # Tamper + re-sign with foreign key
        foreign_priv = Ed25519PrivateKey.generate()
        foreign_pub = foreign_priv.public_key().public_bytes_raw()
        tampered_dict = sc.to_dict()
        tampered_dict["target_url"] = "http://attacker.example.com"
        tampered_dict["public_key"] = ""
        tampered_dict["signature"] = ""
        tampered_sc = Scorecard.from_dict(tampered_dict)
        payload = _canonical_bytes(_signable_dict(tampered_sc))
        tampered_dict["public_key"] = foreign_pub.hex()
        tampered_dict["signature"] = foreign_priv.sign(payload).hex()
        forged = Scorecard.from_dict(tampered_dict)

        # Verification must reject because foreign_pub ≠ trusted_pub
        with patch(
            "cosai_mcp.scorecard.signing._get_trusted_public_key_bytes",
            return_value=trusted_pub,
        ):
            with pytest.raises(ScorecardVerificationError):
                verify_scorecard(forged)


# ---------------------------------------------------------------------------
# CLI — cosai scorecard verify / show
# ---------------------------------------------------------------------------

class TestScorecardCLI:
    def _write_scorecard(self, path: Path, signed: bool = True) -> Scorecard:
        sc = _make_scorecard(signed=signed)
        path.write_text(json.dumps(sc.to_dict()), encoding="utf-8")
        return sc

    def test_scorecard_verify_exits_0_on_valid(self, tmp_path: Path) -> None:
        p = tmp_path / "scorecard.json"
        self._write_scorecard(p, signed=True)
        runner = CliRunner()
        result = runner.invoke(main, ["scorecard", "verify", str(p)])
        assert result.exit_code == 0, result.output
        assert "[OK]" in result.output

    def test_scorecard_verify_exits_1_on_tampered(self, tmp_path: Path) -> None:
        p = tmp_path / "scorecard.json"
        sc = self._write_scorecard(p, signed=True)
        raw = json.loads(p.read_text())
        raw["target_url"] = "http://attacker.example.com"
        p.write_text(json.dumps(raw), encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["scorecard", "verify", str(p)])
        assert result.exit_code == 1

    def test_scorecard_verify_exits_2_on_invalid_json(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("{not valid", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["scorecard", "verify", str(p)])
        assert result.exit_code == 2

    def test_scorecard_show_prints_all_categories(self, tmp_path: Path) -> None:
        p = tmp_path / "scorecard.json"
        self._write_scorecard(p, signed=True)
        runner = CliRunner()
        result = runner.invoke(main, ["scorecard", "show", str(p)])
        assert result.exit_code == 0, result.output
        for i in range(1, 13):
            assert f"T{i}" in result.output

    def test_scorecard_show_with_verify_exits_0(self, tmp_path: Path) -> None:
        p = tmp_path / "scorecard.json"
        self._write_scorecard(p, signed=True)
        runner = CliRunner()
        result = runner.invoke(main, ["scorecard", "show", str(p), "--verify"])
        assert result.exit_code == 0, result.output


# ---------------------------------------------------------------------------
# CLI — cosai scan --scorecard integration
# ---------------------------------------------------------------------------

class TestScanScorecardWiring:
    def test_scan_scorecard_writes_file(self, tmp_path: Path) -> None:
        """--scorecard must write a valid JSON scorecard after scan."""
        from cosai_mcp.harness.mock_server import MockMCPServer

        sc_file = tmp_path / "scorecard.json"
        with MockMCPServer() as target:
            target.wait_ready()
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "scan",
                    f"http://127.0.0.1:{target.port}",
                    "--no-report",
                    "--report-mode", "ci",
                    "--scorecard", str(sc_file),
                    "--no-sign-scorecard",
                    "--skip-reachability",
                ],
            )
        assert result.exit_code != 3, result.output
        assert sc_file.exists(), "Scorecard file was not created"
        data = json.loads(sc_file.read_text())
        assert "conformance_level" in data
        assert len(data["categories"]) == 12

    def test_scan_scorecard_output_line_printed(self, tmp_path: Path) -> None:
        """Scan must print a 'Scorecard:' line when --scorecard is set."""
        from cosai_mcp.harness.mock_server import MockMCPServer

        sc_file = tmp_path / "scorecard.json"
        with MockMCPServer() as target:
            target.wait_ready()
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "scan",
                    f"http://127.0.0.1:{target.port}",
                    "--no-report",
                    "--report-mode", "ci",
                    "--scorecard", str(sc_file),
                    "--no-sign-scorecard",
                    "--skip-reachability",
                ],
            )
        assert result.exit_code != 3, result.output
        assert "Scorecard" in result.output

    def test_regression_scorecard_error_exits_2(self, tmp_path: Path) -> None:
        """If scorecard cannot be written, scan must exit 2."""
        from cosai_mcp.harness.mock_server import MockMCPServer

        # Use a path inside a non-existent directory to force an OSError
        bad_path = str(tmp_path / "nonexistent_dir" / "scorecard.json")
        with MockMCPServer() as target:
            target.wait_ready()
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "scan",
                    f"http://127.0.0.1:{target.port}",
                    "--no-report",
                    "--report-mode", "ci",
                    "--scorecard", bad_path,
                    "--no-sign-scorecard",
                    "--skip-reachability",
                ],
            )
        assert result.exit_code == 2, result.output
