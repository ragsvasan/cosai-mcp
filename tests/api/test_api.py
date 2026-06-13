"""Python API tests — Scanner, ScanResult, scrub_env, COVERAGE_MATRIX."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cosai_mcp.adversarial import AdversarialMode
from cosai_mcp.adversarial.enforcer import UnsafeProbeError
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
    _run_scan,
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

    def test_regression_h2_assertion_change_changes_hash(self) -> None:
        """H-2: a sabotaged assertion (probe suppressed) with an UNCHANGED
        threat id must produce a DIFFERENT catalog_hash. Hashing only ids
        let an attacker swap assertion logic and keep a valid report sig.
        """
        from cosai_mcp.catalog.models import (
            Assertion, Operator, Probe, Provenance, Severity, ThreatDefinition,
        )

        def _mk(assertion_value: str) -> ThreatDefinition:
            probe = Probe(
                id="T03-001-p1",
                transport="http",
                method="tools/call",
                payload=MappingProxyType({"name": "x", "arguments": {}}),
                assertions=(
                    Assertion(
                        target="response.body",
                        operator=Operator.NOT_CONTAINS,
                        value=assertion_value,
                        compiled_pattern=None,
                    ),
                ),
                probe_token=None,
                probe_count=1,
                probe_headers=None,
            )
            return ThreatDefinition(
                schema_version="1.0",
                id="T03-001",  # IDENTICAL id for both variants
                category="T3",
                severity=Severity.CRITICAL,
                cosai_ref="T3",
                owasp_ref="MCP-Top10-A03",
                cwe=("CWE-74",),
                probes=(probe,),
                remediation="Enforce strict JSON schema.",
                references=("https://cosai.org/T3",),
                provenance=Provenance.OFFICIAL,
                mode="read-only",
            )

        clean = _mk("root:")       # detects /etc/passwd disclosure
        sabotaged = _mk("zzzzz")   # assertion can never fire -> finding hidden
        assert _catalog_hash([clean]) != _catalog_hash([sabotaged])

    def test_regression_h2_severity_change_changes_hash(self) -> None:
        """H-2: downgrading a threat's severity (id unchanged) must change
        the hash — severity drives the CI fail-on gate.
        """
        from cosai_mcp.catalog.models import (
            Provenance, Severity, ThreatDefinition,
        )

        def _mk(sev: Severity) -> ThreatDefinition:
            return ThreatDefinition(
                schema_version="1.0",
                id="T01-001",
                category="T1",
                severity=sev,
                cosai_ref="T1",
                owasp_ref="MCP-A1",
                cwe=("CWE-287",),
                probes=(),
                remediation="Fix it.",
                references=(),
                provenance=Provenance.OFFICIAL,
            )

        assert _catalog_hash([_mk(Severity.CRITICAL)]) != _catalog_hash(
            [_mk(Severity.LOW)]
        )

    def test_regression_h2_payload_change_changes_hash(self) -> None:
        """H-2: altering a probe payload (id unchanged) must change the hash."""
        from cosai_mcp.catalog.models import (
            Probe, Provenance, Severity, ThreatDefinition,
        )

        def _mk(arg: str) -> ThreatDefinition:
            probe = Probe(
                id="T04-001-p1",
                transport="http",
                method="tools/call",
                payload=MappingProxyType({"name": "x", "arguments": {"cmd": arg}}),
                assertions=(),
                probe_token=None,
                probe_count=1,
                probe_headers=None,
            )
            return ThreatDefinition(
                schema_version="1.0",
                id="T04-001",
                category="T4",
                severity=Severity.CRITICAL,
                cosai_ref="T4",
                owasp_ref="MCP-A4",
                cwe=("CWE-74",),
                probes=(probe,),
                remediation="x",
                references=(),
                provenance=Provenance.OFFICIAL,
            )

        assert _catalog_hash([_mk("; cat /etc/passwd")]) != _catalog_hash(
            [_mk("harmless")]
        )


# ---------------------------------------------------------------------------
# _determine_exit_code
# ---------------------------------------------------------------------------

class TestDetermineExitCode:
    def _make_probe_result(
        self, *, passed: bool, error: str | None = None,
        inconclusive_reason: str | None = None,
    ):
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
            inconclusive_reason=inconclusive_reason,
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

    def test_inconclusive_is_not_a_finding(self) -> None:
        """Audit COV-06: an INCONCLUSIVE probe (passed=False, inconclusive_reason
        set, error=None) is neither a finding (exit 1) nor a scanner error
        (exit 2).  A scan whose only non-pass is inconclusive exits 0."""
        r = self._make_probe_result(
            passed=False, inconclusive_reason="protocol error -32601 — method not found"
        )
        assert _determine_exit_code([r], [], "critical") == 0

    def test_inconclusive_alongside_real_finding_still_returns_1(self) -> None:
        inc = self._make_probe_result(
            passed=False, inconclusive_reason="boundary rejection"
        )
        finding = self._make_probe_result(passed=False)
        assert _determine_exit_code([inc, finding], [], "critical") == 1


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

    def test_probe_delay_forwarded_to_run_scan(self) -> None:
        """probe_delay_seconds set on Scanner is passed through to _run_scan."""
        mock_result = ScanResult(
            target_url="http://t:8000", threats=(), probe_results=(),
            scenario_results=(), scan_timestamp="t", catalog_hash="h", exit_code=0,
        )
        with patch("cosai_mcp.api._run_scan", return_value=mock_result) as mock_fn:
            Scanner("http://t:8000", probe_delay_seconds=1.5).run()

        assert mock_fn.call_args.kwargs["probe_delay_seconds"] == 1.5

    def test_probe_delay_default_is_zero(self) -> None:
        """Default probe_delay_seconds is 0 — no sleep added without explicit flag."""
        mock_result = ScanResult(
            target_url="http://t:8000", threats=(), probe_results=(),
            scenario_results=(), scan_timestamp="t", catalog_hash="h", exit_code=0,
        )
        with patch("cosai_mcp.api._run_scan", return_value=mock_result) as mock_fn:
            Scanner("http://t:8000").run()

        assert mock_fn.call_args.kwargs["probe_delay_seconds"] == 0.0


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


# ---------------------------------------------------------------------------
# Adversarial scan safety wiring
# ---------------------------------------------------------------------------

def _write_signed_adversarial_catalog(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    threat_id: str = "T03-ADV-001",
    category: str = "T3",
    mode: str = "read-only",
    callback: str | None = None,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    pubkey = private_key.public_key().public_bytes_raw()
    monkeypatch.setenv("COSAI_PUBKEY", base64.b64encode(pubkey).decode())

    payload = {
        "name": "echo",
        "arguments": {"input": "{{canary}}"},
    }
    if callback is not None:
        payload["arguments"]["callback"] = callback

    threat = {
        "schema_version": "1.0",
        "id": threat_id,
        "category": category,
        "severity": "high",
        "cosai_ref": category,
        "owasp_ref": "MCP-Top10-A03",
        "cwe": ["CWE-74"],
        "adversarial": True,
        "mode": mode,
        "description": "Adversarial test fixture",
        "canary_placement": "arguments.input",
        "probes": [
            {
                "id": f"{threat_id}-p1",
                "transport": "http",
                "method": "tools/call",
                "payload": payload,
                "assertions": [
                    {"target": "response.body", "operator": "not_contains", "value": "{{canary}}"}
                ],
            }
        ],
        "remediation": "Do not exfiltrate canaries.",
        "references": ["https://cosai.org/adversarial"],
    }

    adv_dir = root / "official" / "adversarial"
    adv_dir.mkdir(parents=True)
    raw = json.dumps(threat, indent=2).encode()
    json_path = adv_dir / f"{threat_id}.json"
    json_path.write_bytes(raw)
    json_path.with_suffix(".json.sig").write_bytes(
        base64.b64encode(private_key.sign(raw)) + b"\n"
    )


class TestAdversarialScanSafety:
    def test_regression_stateful_adversarial_rejected_by_scan_path(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Stateful adversarial probes must be rejected by _run_scan without the flag."""
        _write_signed_adversarial_catalog(
            tmp_path,
            monkeypatch,
            threat_id="T05-ADV-001",
            category="T5",
            mode="stateful",
        )

        with pytest.raises(UnsafeProbeError, match="stateful"):
            _run_scan(
                target="http://myserver.example.com:8000",
                categories=["T5"],
                engine="prober",
                allow_custom_catalog=False,
                probe_timeout_seconds=1.0,
                catalog_root=tmp_path,
                allow_private_targets=True,
                adversarial_mode=AdversarialMode(
                    enabled=True,
                    ownership_declaration="I own myserver.example.com",
                    allow_stateful=False,
                ),
            )

    def test_regression_external_endpoint_rejected_by_scan_path(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """External URLs in adversarial probe payloads must be rejected by _run_scan."""
        _write_signed_adversarial_catalog(
            tmp_path,
            monkeypatch,
            callback="https://attacker.example/callback",
        )

        with pytest.raises(UnsafeProbeError, match="external URL"):
            _run_scan(
                target="http://myserver.example.com:8000",
                categories=["T3"],
                engine="prober",
                allow_custom_catalog=False,
                probe_timeout_seconds=1.0,
                catalog_root=tmp_path,
                allow_private_targets=True,
                adversarial_mode=AdversarialMode(
                    enabled=True,
                    ownership_declaration="I own myserver.example.com",
                ),
            )

    def test_regression_stateful_adversarial_allowed_with_flag(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The allow-stateful flag should let scan orchestration continue."""
        _write_signed_adversarial_catalog(
            tmp_path,
            monkeypatch,
            threat_id="T05-ADV-001",
            category="T5",
            mode="stateful",
        )

        with patch("cosai_mcp.api._run_discovery", return_value=("echo", ())), \
             patch("cosai_mcp.harness.runner.ProbeRunner.run_threat", return_value=[]):
            result = _run_scan(
                target="http://myserver.example.com:8000",
                categories=["T5"],
                engine="prober",
                allow_custom_catalog=False,
                probe_timeout_seconds=1.0,
                catalog_root=tmp_path,
                allow_private_targets=True,
                adversarial_mode=AdversarialMode(
                    enabled=True,
                    ownership_declaration="I own myserver.example.com",
                    allow_stateful=True,
                ),
            )

        assert result.exit_code == 0
        assert [t.id for t in result.threats] == ["T05-ADV-001"]


# ---------------------------------------------------------------------------
# Regression: T1 probes must strip both auth_token AND auth_header
# ---------------------------------------------------------------------------

class TestT1AuthProbeNoAuthHeader:
    """T1 probes must run without auth so the server can enforce authentication.

    Regression: no_auth_config previously only cleared auth_token but left
    auth_header intact (the pre-formatted "Bearer <tok>" string set by profile).
    The transport uses auth_header in _build_headers() and it takes precedence,
    so T1 probes silently sent valid credentials and never exercised the
    unauthenticated code path.
    """

    def test_regression_no_auth_config_clears_auth_header(self, tmp_path: Path) -> None:
        """_run_scan must build no_auth_config with auth_header=None for T1 probes.

        Integration test: enters _run_scan with a profile that sets auth_header,
        captures the ScanConfig passed to ProbeRunner for T1 threats, and asserts
        both auth_token and auth_header are None.
        """
        from cosai_mcp.config import ScanConfig
        from cosai_mcp.profiles.models import ServerProfile
        import types

        profile = ServerProfile(
            name="test",
            description="test",
            mcp_path="/mcp",
            auth_header_format="Bearer {token}",
            tool_name_map=types.MappingProxyType({}),
            skip_categories=frozenset(),
            notes="",
        )

        captured_configs: list[ScanConfig] = []

        class CapturingProbeRunner:
            def __init__(self, config: ScanConfig, target_url: str) -> None:
                captured_configs.append(config)
                self._config = config
                self._target_url = target_url

            def run_threat(self, threat, variables=None, pass_on_auth_reject=False,
                           discovered_tool=None):
                return []

        with patch("cosai_mcp.api._run_discovery", return_value=("ping", ())), \
             patch("cosai_mcp.api.ProbeRunner", CapturingProbeRunner), \
             patch("cosai_mcp.api.StatefulHarness"):
            # Write a minimal T1 catalog entry
            import json as _json
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            key = Ed25519PrivateKey.generate()
            official = tmp_path / "official"
            official.mkdir()
            threat = {
                "schema_version": "1.0", "id": "T01-001", "category": "T1",
                "severity": "critical", "cosai_ref": "T1", "owasp_ref": "MCP-Top10-A01",
                "cwe": ["CWE-287"],
                "probes": [{"id": "T01-001-p1", "transport": "http",
                            "method": "tools/call",
                            "payload": {"name": "{{tool_name}}", "arguments": {}},
                            "assertions": [{"target": "response.error",
                                            "operator": "eq", "value": True}]}],
                "remediation": "Enforce auth.", "references": [],
            }
            raw = _json.dumps(threat).encode()
            (official / "T01-001.json").write_bytes(raw)
            (official / "T01-001.json.sig").write_bytes(
                base64.b64encode(key.sign(raw)) + b"\n"
            )
            import base64 as _b64
            pub_b64 = _b64.b64encode(key.public_key().public_bytes_raw()).decode()
            with patch.dict(os.environ, {"COSAI_PUBKEY": pub_b64}):
                _run_scan(
                    target="http://localhost:9999",
                    categories=["T1"],
                    engine="prober",
                    allow_custom_catalog=False,
                    probe_timeout_seconds=1.0,
                    catalog_root=tmp_path,
                    allow_private_targets=True,
                    auth_token="tok_abc",
                    profile=profile,
                )

        # The ProbeRunner created for T1 probes (no_auth_config) must have
        # both auth_token and auth_header cleared.
        t1_runner_configs = [c for c in captured_configs if c.auth_token is None]
        assert t1_runner_configs, "No ProbeRunner with auth_token=None — T1 probes may be running with auth"
        for cfg in t1_runner_configs:
            assert cfg.auth_header is None, (
                f"T1 no_auth_config still has auth_header={cfg.auth_header!r}; "
                "unauthenticated probe would silently use valid credentials"
            )


# ---------------------------------------------------------------------------
# _extract_retry_after — rate-limit backoff helper
# ---------------------------------------------------------------------------

class TestExtractRetryAfter:
    """_extract_retry_after must parse retry_after from HTML-escaped -32029 errors."""

    from cosai_mcp.api import _extract_retry_after
    from cosai_mcp.harness.result import make_probe_result

    def _rate_limit_result(self, retry_after: int | None = 60) -> object:
        from cosai_mcp.harness.result import make_probe_result
        # Simulate the exact error string produced by the subprocess runner
        # when Mnemo returns -32029.  make_probe_result HTML-escapes this,
        # turning single-quotes into &#x27; — the regex must survive that.
        data = f"{{'retry_after': {retry_after}}}" if retry_after is not None else "{}"
        raw = f"Subprocess error: Server rejected initialize: {{'code': -32029, 'message': 'Rate limit exceeded', 'data': {data}}}"
        return make_probe_result(
            probe_id="T10-004-p1",
            threat_id="T10",
            passed=False,
            assertions=(),
            error=raw,
        )

    def test_regression_extract_retry_after_html_escaped(self):
        """HTML-escaped error (&#x27; for quotes) must still yield retry_after."""
        from cosai_mcp.api import _extract_retry_after
        result = self._rate_limit_result(retry_after=60)
        assert "&#x27;" in result.error, "precondition: error must be HTML-escaped"
        assert _extract_retry_after([result]) == 60.0

    def test_regression_extract_retry_after_fractional(self):
        """Fractional retry_after (e.g. 30.5) must be returned as float."""
        from cosai_mcp.api import _extract_retry_after
        from cosai_mcp.harness.result import make_probe_result
        raw = "Subprocess error: Server rejected initialize: {'code': -32029, 'data': {'retry_after': 30.5}}"
        result = make_probe_result(probe_id="T10", threat_id="T10", passed=False, assertions=(), error=raw)
        assert _extract_retry_after([result]) == 30.5

    def test_regression_extract_retry_after_no_retry_after_field(self):
        """-32029 with no retry_after key must return None (fall back to probe_delay)."""
        from cosai_mcp.api import _extract_retry_after
        result = self._rate_limit_result(retry_after=None)
        assert _extract_retry_after([result]) is None

    def test_regression_extract_retry_after_unrelated_error(self):
        """Non-rate-limit error must return None."""
        from cosai_mcp.api import _extract_retry_after
        from cosai_mcp.harness.result import make_probe_result
        result = make_probe_result(
            probe_id="T01", threat_id="T01", passed=False, assertions=(),
            error="Connection refused",
        )
        assert _extract_retry_after([result]) is None

    def test_regression_extract_retry_after_first_wins(self):
        """First -32029 result with retry_after is returned; later results ignored."""
        from cosai_mcp.api import _extract_retry_after
        r1 = self._rate_limit_result(retry_after=45)
        r2 = self._rate_limit_result(retry_after=90)
        assert _extract_retry_after([r1, r2]) == 45.0

    def test_regression_extract_retry_after_response_body(self):
        """-32029 in response_body (assertion failure, not subprocess crash) is detected.

        T10-002 hits the rate limiter and the server returns -32029 as a JSON-RPC
        error response — this ends up in result.response_body, not result.error.
        """
        from cosai_mcp.api import _extract_retry_after
        from cosai_mcp.harness.result import make_probe_result
        body = "{'jsonrpc':'2.0','id':1,'error':{'code': -32029,'data':{'retry_after': 60}}}"
        result = make_probe_result(
            probe_id="T10-002-p1",
            threat_id="T10",
            passed=False,
            assertions=(),
            response={"_body": body, "_status_code": 200},
        )
        assert _extract_retry_after([result]) == 60.0


class TestDetermineExitCode:
    """_determine_exit_code exit-code semantics for timeouts and rate-limit errors."""

    def _timeout_result(self) -> object:
        from cosai_mcp.harness.result import make_probe_result
        return make_probe_result(
            probe_id="T02-004-p1", threat_id="T02", passed=False, assertions=(),
            error="Probe timed out after 30.0s",
        )

    def _rate_limit_error_result(self) -> object:
        from cosai_mcp.harness.result import make_probe_result
        return make_probe_result(
            probe_id="T11-001-p1", threat_id="T11", passed=False, assertions=(),
            error="Subprocess error: Server rejected initialize: {'code': -32029, 'message': 'Rate limit exceeded', 'data': {'retry_after': 60}}",
        )

    def _crash_result(self) -> object:
        from cosai_mcp.harness.result import make_probe_result
        return make_probe_result(
            probe_id="T01-001-p1", threat_id="T01", passed=False, assertions=(),
            error="Probe subprocess exited without producing a result",
        )

    def _passing_result(self, probe_id: str = "T02-004-p2", threat_id: str = "T02") -> object:
        from cosai_mcp.harness.result import make_probe_result
        return make_probe_result(
            probe_id=probe_id, threat_id=threat_id, passed=True, assertions=(), error=None,
        )

    def test_regression_timeout_alongside_pass_not_exit_2(self):
        """A timeout probe does not corrupt a scan where another probe passed cleanly."""
        from cosai_mcp.api import _determine_exit_code
        code = _determine_exit_code([self._timeout_result(), self._passing_result()], [], "critical")
        assert code == 0, f"timeout + passing probe should be exit 0, got {code}"

    def test_regression_timeout_sole_probe_is_exit_2(self):
        """A scan where the only probe timed out is scan-incomplete (nothing was verified)."""
        from cosai_mcp.api import _determine_exit_code
        code = _determine_exit_code([self._timeout_result()], [], "critical")
        assert code == 2, f"sole timeout probe should be exit 2 (scan-incomplete), got {code}"

    def test_regression_rate_limit_alongside_pass_not_exit_2(self):
        """-32029 rate-limit error alongside a passing probe is not scan-incomplete."""
        from cosai_mcp.api import _determine_exit_code
        code = _determine_exit_code([self._rate_limit_error_result(), self._passing_result()], [], "critical")
        assert code == 0, f"rate-limit + passing probe should be exit 0, got {code}"

    def test_regression_rate_limit_sole_probe_is_exit_2(self):
        """A scan where the only probe was rate-limited is scan-incomplete (nothing verified)."""
        from cosai_mcp.api import _determine_exit_code
        code = _determine_exit_code([self._rate_limit_error_result()], [], "critical")
        assert code == 2, f"sole rate-limit probe should be exit 2 (scan-incomplete), got {code}"

    def test_regression_crash_still_exit_2(self):
        """A genuine subprocess crash must still trigger exit code 2."""
        from cosai_mcp.api import _determine_exit_code
        code = _determine_exit_code([self._crash_result()], [], "critical")
        assert code == 2, f"subprocess crash must be exit 2, got {code}"
