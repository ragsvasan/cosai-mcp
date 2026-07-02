"""ENT-P0-1 — `--expected-catalog-hash` pin (docs/ENTERPRISE_REQUIREMENTS_2026-07-01.md).

Security contract under test:

- A release gate must be reproducible: the same catalog on disk hashes
  identically across independent scan runs (determinism — the acceptance
  criterion ENT-P0-1 states explicitly: "two runs ... produce byte-identical
  scorecard catalog_hash").
- When `--expected-catalog-hash` is pinned and the loaded catalog no longer
  matches it, the scan must fail closed BEFORE any probe/network activity
  runs — never silently scan with an unverified ruleset, and never spend a
  round-trip against the target on a catalog that's already known-wrong.
- Consumed inside the `_run_scan` call path (Wiring Check) — the same entry
  point `TestBaselineWiredIntoRunScan` in test_baseline.py uses — not via an
  unwired helper, and reachable from both the CLI and the Python API
  (`Scanner`) surfaces.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from cosai_mcp.api import Scanner, _run_scan

CATALOG_ROOT = Path(__file__).resolve().parents[2] / "catalog"

_STUB_SCAN = {
    "target": "http://127.0.0.1:8000",
    "categories": ["T1"],
    "engine": "prober",
    "allow_custom_catalog": False,
    "probe_timeout_seconds": 5.0,
    "catalog_root": CATALOG_ROOT,
    "allow_private_targets": True,
}


def _scan(expected_catalog_hash):
    with patch(
        "cosai_mcp.api._run_discovery",
        return_value=("ping", ()),
    ), patch(
        "cosai_mcp.harness.runner.ProbeRunner.run_threat", return_value=[]
    ) as mock_run_threat:
        result = _run_scan(**{**_STUB_SCAN, "expected_catalog_hash": expected_catalog_hash})
        return result, mock_run_threat


class TestExpectedCatalogHashWiredIntoRunScan:

    def test_no_expected_hash_scans_normally(self) -> None:
        """Backward compatible: omitting the flag (None, the default) never gates."""
        result, mock_run_threat = _scan(None)
        assert result.catalog_hash
        assert mock_run_threat.called

    def test_matching_expected_hash_scans_normally(self) -> None:
        """Compute the real hash once, then re-scan pinned to it — must proceed
        exactly as an unpinned scan would."""
        seed, _ = _scan(None)
        result, mock_run_threat = _scan(seed.catalog_hash)
        assert result.catalog_hash == seed.catalog_hash
        assert mock_run_threat.called

    def test_mismatched_expected_hash_fails_closed_before_any_probe(self) -> None:
        """A wrong pin must raise (the CLI's existing `except ValueError:
        sys.exit(2)` maps this the same way it already does for a malformed
        baseline) — and must never reach the probe engine, so a rejected
        catalog never spends a round-trip against the target."""
        with patch(
            "cosai_mcp.api._run_discovery", return_value=("ping", ())
        ), patch(
            "cosai_mcp.harness.runner.ProbeRunner.run_threat", return_value=[]
        ) as mock_run_threat:
            with pytest.raises(ValueError, match="[Cc]atalog hash"):
                _run_scan(**{**_STUB_SCAN, "expected_catalog_hash": "0" * 64})
            assert not mock_run_threat.called, (
                "a rejected catalog pin must never reach the probe engine"
            )

    def test_mismatch_message_names_expected_and_actual(self) -> None:
        """The error must be actionable: name BOTH hashes, not just the
        pinned one — otherwise a future edit that drops the actual-hash half
        of the f-string would pass a test that only checks the pinned side."""
        seed, _ = _scan(None)
        wrong = "deadbeef" * 8
        with pytest.raises(ValueError) as exc_info:
            _scan(wrong)
        assert wrong in str(exc_info.value)
        assert seed.catalog_hash in str(exc_info.value)


class TestCatalogHashBindsSecurityRelevantFields:
    """Adversary-pass finding (ENT-P0-1 review): _catalog_hash's own
    docstring promises the hash binds every security-relevant field, but
    Probe.protocol_error_is_expected was omitted from the canonical view.
    That field decides whether a JSON-RPC protocol error scores as a secure
    PASS or is downgraded to INCONCLUSIVE (catalog/models.py) — a tampered
    catalog that flips only this field would pass an
    --expected-catalog-hash pin unnoticed."""

    @staticmethod
    def _threat(protocol_error_is_expected: bool):
        import types

        from cosai_mcp.catalog.models import (
            Assertion,
            Operator,
            Probe,
            Provenance,
            Severity,
            ThreatDefinition,
        )

        probe = Probe(
            id="T99-999-p1",
            transport="http",
            method="tools/call",
            payload=types.MappingProxyType({}),
            assertions=(Assertion(target="response.error", operator=Operator.EQ, value=True),),
            protocol_error_is_expected=protocol_error_is_expected,
        )
        return ThreatDefinition(
            schema_version="1.1",
            id="T99-999",
            category="T99",
            severity=Severity.HIGH,
            cosai_ref="T99",
            owasp_ref="",
            cwe=(),
            probes=(probe,),
            remediation="",
            references=(),
            provenance=Provenance.OFFICIAL,
        )

    def test_protocol_error_is_expected_binds_catalog_hash(self) -> None:
        from cosai_mcp.api import _catalog_hash

        a = self._threat(protocol_error_is_expected=False)
        b = self._threat(protocol_error_is_expected=True)
        assert _catalog_hash([a]) != _catalog_hash([b]), (
            "protocol_error_is_expected must bind the catalog hash — flipping "
            "it changes whether a probe's protocol error is a secure pass or "
            "INCONCLUSIVE, so a catalog differing only in this field must not "
            "hash identically"
        )


class TestCatalogHashDeterminism:
    """ENT-P0-1's acceptance criterion: two independent runs against the same
    catalog on disk must produce a byte-identical scorecard catalog_hash —
    the property an air-gapped, reproducible CI gate depends on."""

    def test_catalog_hash_stable_across_independent_scans(self) -> None:
        first, _ = _scan(None)
        second, _ = _scan(None)
        assert first.catalog_hash == second.catalog_hash
        assert len(first.catalog_hash) == 64  # sha256 hex digest


class TestExpectedCatalogHashScannerAPI:
    """Python API parity — Scanner is the documented public surface
    alongside the CLI (README.md 'Python API' section)."""

    def test_scanner_accepts_expected_catalog_hash_and_wires_to_run_scan(self) -> None:
        with patch(
            "cosai_mcp.api._run_discovery", return_value=("ping", ())
        ), patch(
            "cosai_mcp.harness.runner.ProbeRunner.run_threat", return_value=[]
        ):
            scanner = Scanner(
                "http://127.0.0.1:8000",
                categories=["T1"],
                catalog_root=CATALOG_ROOT,
                allow_private_targets=True,
                expected_catalog_hash="0" * 64,
            )
            with pytest.raises(ValueError, match="[Cc]atalog hash"):
                scanner.run()
