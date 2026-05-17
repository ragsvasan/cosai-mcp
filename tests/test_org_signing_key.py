"""WP6 — org / shared fleet signing-key model.

Contract:

- ``COSAI_REPORT_SIGNING_KEY`` (base64 raw 32-byte Ed25519 private key) is the
  org/shared key. When set, BOTH report signing and scorecard signing use it
  instead of the per-installation keychain key, so every machine in a fleet
  produces artifacts with the **same public-key fingerprint** → fleet
  scorecards are directly comparable.
- Fail-closed: set-but-invalid raises ``OrgSigningKeyError`` (signing) /
  ``ScorecardVerificationError`` (verification); it never silently downgrades
  to a per-machine key (which would look authentic but be incomparable).
- Fleet round-trip: sign on "machine A" and verify on "machine B" by setting
  ONE env var, with no separate public-key distribution.
"""
from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cosai_mcp.report.sign import (
    OrgSigningKeyError,
    ReportSigner,
    org_signing_key,
    verify_report_signature,
    _pub_fingerprint,
)
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

_ENV = "COSAI_REPORT_SIGNING_KEY"


def _org_key_b64() -> tuple[str, Ed25519PrivateKey]:
    key = Ed25519PrivateKey.generate()
    return base64.b64encode(key.private_bytes_raw()).decode(), key


def _scorecard(signed: bool = False) -> Scorecard:
    cats = [
        CategoryResult(
            category=f"T{i}", grade=Grade.PASS, probe_count=1,
            finding_count=0, critical_count=0, high_count=0,
            coverage_engine="black_box_prober",
        )
        for i in range(1, 13)
    ]
    sc = Scorecard(
        scan_id="wp6-scan", target_url="http://t:8000",
        scan_timestamp="2026-05-17T00:00:00Z", catalog_hash="abc",
        tool_version="test", categories=tuple(cats),
        conformance_level=ConformanceLevel.FULL_CONFORMANCE,
        public_key="", signature="",
    )
    return sign_scorecard(sc) if signed else sc


# ---------------------------------------------------------------------------
# org_signing_key — resolution + fail-closed
# ---------------------------------------------------------------------------

class TestOrgSigningKeyResolution:
    def test_unset_returns_none(self, monkeypatch) -> None:
        monkeypatch.delenv(_ENV, raising=False)
        assert org_signing_key() is None

    def test_empty_returns_none(self, monkeypatch) -> None:
        monkeypatch.setenv(_ENV, "")
        assert org_signing_key() is None

    def test_valid_returns_key(self, monkeypatch) -> None:
        b64, key = _org_key_b64()
        monkeypatch.setenv(_ENV, b64)
        got = org_signing_key()
        assert got is not None
        assert got.private_bytes_raw() == key.private_bytes_raw()

    def test_invalid_base64_raises(self, monkeypatch) -> None:
        monkeypatch.setenv(_ENV, "!!!not base64!!!")
        with pytest.raises(OrgSigningKeyError, match="not valid base64"):
            org_signing_key()

    def test_wrong_length_raises(self, monkeypatch) -> None:
        monkeypatch.setenv(_ENV, base64.b64encode(b"too-short").decode())
        with pytest.raises(OrgSigningKeyError, match="32 bytes"):
            org_signing_key()

    def test_64_byte_key_rejected(self, monkeypatch) -> None:
        # An Ed25519 *keypair* (priv+pub, 64 bytes) is a common mistake.
        monkeypatch.setenv(_ENV, base64.b64encode(b"\x00" * 64).decode())
        with pytest.raises(OrgSigningKeyError, match="32 bytes"):
            org_signing_key()


# ---------------------------------------------------------------------------
# ReportSigner — org key drives fleet comparability
# ---------------------------------------------------------------------------

class TestReportSignerUsesOrgKey:
    def test_org_key_used_when_set(self, monkeypatch) -> None:
        b64, key = _org_key_b64()
        monkeypatch.setenv(_ENV, b64)
        sig = ReportSigner().sign(
            '{"version":"2.1.0"}', "2026-05-17T00:00:00Z", "cat-hash"
        )
        expected_fp = _pub_fingerprint(key.public_key())
        assert sig.public_key_fingerprint == expected_fp

    def test_fleet_two_machines_same_fingerprint(self, monkeypatch) -> None:
        """Two independent ReportSigner() instances (simulating two fleet
        machines) with the SAME org env var yield the SAME fingerprint —
        the property that makes fleet scorecards comparable."""
        b64, _ = _org_key_b64()
        monkeypatch.setenv(_ENV, b64)
        a = ReportSigner().sign("{}", "2026-05-17T00:00:00Z", "h")
        b = ReportSigner().sign("{}", "2026-05-17T00:00:00Z", "h")
        assert a.public_key_fingerprint == b.public_key_fingerprint

    def test_explicit_key_arg_overrides_env(self, monkeypatch) -> None:
        b64, _ = _org_key_b64()
        monkeypatch.setenv(_ENV, b64)
        explicit = Ed25519PrivateKey.generate()
        sig = ReportSigner(private_key=explicit).sign(
            "{}", "2026-05-17T00:00:00Z", "h"
        )
        assert sig.public_key_fingerprint == _pub_fingerprint(
            explicit.public_key()
        )

    def test_org_signed_report_verifies_with_org_fingerprint(
        self, monkeypatch
    ) -> None:
        b64, key = _org_key_b64()
        monkeypatch.setenv(_ENV, b64)
        sarif = '{"version":"2.1.0","runs":[]}'
        sig = ReportSigner().sign(sarif, "2026-05-17T00:00:00Z", "h")
        trusted_fp = _pub_fingerprint(key.public_key())
        assert verify_report_signature(sig, sarif, trusted_fp) is True

    def test_malformed_org_key_raises_not_silent_fallback(
        self, monkeypatch
    ) -> None:
        monkeypatch.setenv(_ENV, "garbage")
        with pytest.raises(OrgSigningKeyError):
            ReportSigner()


# ---------------------------------------------------------------------------
# Scorecard — org key drives fleet round-trip without pubkey distribution
# ---------------------------------------------------------------------------

class TestScorecardUsesOrgKey:
    def test_sign_then_verify_round_trips_with_only_org_env(
        self, monkeypatch
    ) -> None:
        """Sign on 'machine A', verify on 'machine B' — both only share the
        org env var, no COSAI_SCORECARD_PUBKEY, no shared keyring."""
        b64, _ = _org_key_b64()
        monkeypatch.setenv(_ENV, b64)
        monkeypatch.delenv("COSAI_SCORECARD_PUBKEY", raising=False)
        signed = _scorecard(signed=True)
        # verify uses the org key as trust anchor — must not raise.
        verify_scorecard(signed)

    def test_two_fleet_machines_same_scorecard_public_key(
        self, monkeypatch
    ) -> None:
        b64, _ = _org_key_b64()
        monkeypatch.setenv(_ENV, b64)
        a = _scorecard(signed=True)
        b = _scorecard(signed=True)
        assert a.public_key == b.public_key
        assert a.public_key != ""

    def test_tampered_org_signed_scorecard_fails(self, monkeypatch) -> None:
        b64, _ = _org_key_b64()
        monkeypatch.setenv(_ENV, b64)
        monkeypatch.delenv("COSAI_SCORECARD_PUBKEY", raising=False)
        signed = _scorecard(signed=True)
        tampered = Scorecard(
            scan_id=signed.scan_id, target_url="http://evil:9999",
            scan_timestamp=signed.scan_timestamp,
            catalog_hash=signed.catalog_hash, tool_version=signed.tool_version,
            categories=signed.categories,
            conformance_level=signed.conformance_level,
            public_key=signed.public_key, signature=signed.signature,
        )
        with pytest.raises(ScorecardVerificationError):
            verify_scorecard(tampered)

    def test_malformed_org_key_fails_verification_closed(
        self, monkeypatch
    ) -> None:
        """A set-but-broken org key must raise on verify, never silently fall
        back to the per-machine keyring trust anchor."""
        good_b64, _ = _org_key_b64()
        monkeypatch.setenv(_ENV, good_b64)
        signed = _scorecard(signed=True)
        monkeypatch.setenv(_ENV, "!!!broken!!!")
        monkeypatch.delenv("COSAI_SCORECARD_PUBKEY", raising=False)
        with pytest.raises(ScorecardVerificationError, match="base64"):
            verify_scorecard(signed)

    def test_scorecard_pubkey_env_still_takes_precedence(
        self, monkeypatch
    ) -> None:
        """Explicit COSAI_SCORECARD_PUBKEY is the strongest trust anchor and
        must win even when the org signing key is also set."""
        b64, key = _org_key_b64()
        monkeypatch.setenv(_ENV, b64)
        signed = _scorecard(signed=True)
        pub_b64 = base64.b64encode(
            key.public_key().public_bytes_raw()
        ).decode()
        monkeypatch.setenv("COSAI_SCORECARD_PUBKEY", pub_b64)
        verify_scorecard(signed)  # matches → must not raise


# ---------------------------------------------------------------------------
# CLI surfacing — a misconfigured fleet key must be LOUD
# ---------------------------------------------------------------------------

class TestCliSurfacesMisconfiguredOrgKey:
    def test_sarif_report_warns_on_bad_org_key(self, monkeypatch, tmp_path):
        from click.testing import CliRunner

        from cosai_mcp.cli import main
        from cosai_mcp.api import ScanResult

        monkeypatch.setenv(_ENV, "not-valid-base64!!!")
        sarif_out = tmp_path / "r.sarif"

        clean = ScanResult(
            target_url="http://localhost:8000", threats=(),
            probe_results=(), scenario_results=(),
            scan_timestamp="2026-05-17T00:00:00Z", catalog_hash="abc",
            exit_code=0,
        )
        with (
            __import__("unittest.mock", fromlist=["patch"]).patch(
                "cosai_mcp.cli.check_reachable"
            ),
            __import__("unittest.mock", fromlist=["patch"]).patch(
                "cosai_mcp.cli._run_scan", return_value=clean
            ),
        ):
            res = CliRunner().invoke(
                main,
                [
                    "scan", "http://localhost:8000",
                    "--report-sarif", str(sarif_out), "--no-report",
                ],
            )
        # Scan itself still succeeds (signing is best-effort) ...
        assert res.exit_code == 0, res.output
        # ... but the misconfigured fleet key is surfaced loudly.
        assert "Report not signed" in res.output
        # And the SARIF body was still written (signing failure ≠ scan failure)
        assert sarif_out.exists()

    def test_scorecard_fails_closed_on_bad_org_key(
        self, monkeypatch, tmp_path
    ):
        from click.testing import CliRunner

        from cosai_mcp.cli import main
        from cosai_mcp.api import ScanResult

        monkeypatch.setenv(_ENV, "not-valid-base64!!!")
        sc_out = tmp_path / "sc.json"
        clean = ScanResult(
            target_url="http://localhost:8000", threats=(),
            probe_results=(), scenario_results=(),
            scan_timestamp="2026-05-17T00:00:00Z", catalog_hash="abc",
            exit_code=0,
        )
        with (
            __import__("unittest.mock", fromlist=["patch"]).patch(
                "cosai_mcp.cli.check_reachable"
            ),
            __import__("unittest.mock", fromlist=["patch"]).patch(
                "cosai_mcp.cli._run_scan", return_value=clean
            ),
        ):
            res = CliRunner().invoke(
                main,
                [
                    "scan", "http://localhost:8000",
                    "--scorecard", str(sc_out), "--no-report",
                ],
            )
        # An explicitly-requested scorecard must FAIL CLOSED (exit 2) when the
        # fleet key is misconfigured — not silently produce an unsigned one.
        assert res.exit_code == 2, res.output
        assert "scorecard" in res.output.lower()
