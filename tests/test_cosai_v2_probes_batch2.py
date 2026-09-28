"""CoSAI MCP Security v2.0 — P1 batch 2: _meta identity spoofing (T01-007),
task-handle enumeration (T07-007), and public cacheScope on tool results
(T05-003).

Catalog probes go through Scanner.run against vulnerable / secure modern /
legacy mocks.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cosai_mcp import Scanner
from cosai_mcp.assurance import EvidenceItem, Verdict, evaluate_assurance
from cosai_mcp.config import ScanConfig
from cosai_mcp.harness.mock_server import MockMCPServer
from cosai_mcp.harness.result import ProbeResult
from cosai_mcp.stateful.harness import _apply_method_overrides
from cosai_mcp.stateful.scenarios import t2_privilege_escalation_chain

CATALOG_ROOT = Path(__file__).parent.parent / "catalog"
_MODERN: dict[str, Any] = {"protocol_era": "modern"}


def _scan(mock_kwargs: dict[str, Any], categories: list[str], **scanner_kwargs: Any) -> list[Any]:
    with MockMCPServer(**mock_kwargs) as server:
        server.wait_ready()
        result = Scanner(
            f"http://127.0.0.1:{server.port}", categories=categories, engine="prober",
            allow_private_targets=True, probe_timeout_seconds=10.0, **scanner_kwargs,
        ).run()
    return list(result.probe_results)


def _by(results: list[Any], threat_id: str) -> list[Any]:
    found = [r for r in results if r.threat_id == threat_id]
    assert found, [r.threat_id for r in results]
    return found


def _finding(r: Any) -> bool:
    return r.passed is False and r.error is None and r.inconclusive_reason is None


# ===========================================================================
# Catalog probes
# ===========================================================================

_AUTHED = {**_MODERN, "modern_requires_auth": True}
_CASES = [
    # threat,   category, vulnerable mock,                                 secure mock
    ("T01-007", "T1", {**_AUTHED, "trust_meta_admin_identity": True}, _AUTHED),
    ("T07-007", "T7", {**_MODERN, "expose_task_enumeration": True}, _MODERN),
    ("T05-003", "T5", {**_MODERN, "tool_cache_scope_public": True}, _MODERN),
]


@pytest.mark.parametrize(("threat_id", "cat", "vulnerable", "secure"), _CASES)
def test_probe_fails_on_vulnerable_server(threat_id: str, cat: str,
                                          vulnerable: dict[str, Any],
                                          secure: dict[str, Any]) -> None:
    results = _by(_scan(vulnerable, [cat], auth_token="tok"), threat_id)
    assert all(_finding(r) for r in results), results


@pytest.mark.parametrize(("threat_id", "cat", "vulnerable", "secure"), _CASES)
def test_probe_passes_on_secure_server(threat_id: str, cat: str,
                                       vulnerable: dict[str, Any],
                                       secure: dict[str, Any]) -> None:
    results = _by(_scan(secure, [cat], auth_token="tok"), threat_id)
    assert all(r.passed is True for r in results), results


@pytest.mark.parametrize(("threat_id", "cat"), [(c[0], c[1]) for c in _CASES])
def test_probe_not_applicable_on_legacy_server(threat_id: str, cat: str) -> None:
    results = _by(_scan({}, [cat]), threat_id)
    assert all(r.inconclusive_reason and "not applicable" in r.inconclusive_reason
               for r in results), results


def test_method_overrides_preserve_every_scenario_field() -> None:
    import dataclasses

    base = dataclasses.replace(t2_privilege_escalation_chain(), loop_budget_check=True)
    remapped = _apply_method_overrides(base, {"admin_delete": "purge"})
    for f in dataclasses.fields(base):
        if f.name != "steps":
            assert getattr(remapped, f.name) == getattr(base, f.name), f.name


# ===========================================================================
# Assurance links — optional disproof
# ===========================================================================

def _pr(threat_id: str, passed: bool, inconclusive: bool = False) -> ProbeResult:
    return ProbeResult(
        probe_id=f"{threat_id}-p1", threat_id=threat_id, passed=passed, status_code=200,
        response_body="", error=None, assertions=(), duration_seconds=0.0,
        inconclusive_reason="n/a" if inconclusive else None,
    )


def _ev(cid: str) -> dict[str, EvidenceItem]:
    return {cid: EvidenceItem(control_id=cid, artifact="a", sha256="0" * 64)}


def _verdict(report: Any, cid: str) -> Verdict:
    return next(c.verdict for c in report.controls if c.control_id == cid)


def test_optional_link_finding_fails_control() -> None:
    assert _verdict(evaluate_assurance(2, [_pr("T01-007", False)]), "SD-02") is Verdict.FAIL
    assert _verdict(evaluate_assurance(3, [_pr("T05-003", False)]), "TI-05") is Verdict.FAIL
    assert _verdict(evaluate_assurance(2, [_pr("T07-007", False),
                                           _pr("T7-SC-001", True), _pr("T7-SC-002", True)]),
                    "SD-01") is Verdict.FAIL


def test_optional_link_not_applicable_does_not_block_attestation() -> None:
    report = evaluate_assurance(2, [_pr("T01-007", False, inconclusive=True)],
                                evidence=_ev("SD-02"))
    assert _verdict(report, "SD-02") is Verdict.ATTESTED


# ===========================================================================
# Adversary batch-2 regressions — T01-007 false-PASS paths and disclosure
# ===========================================================================

def test_exploit_t01_007_public_discover_gated_tools_list() -> None:
    results = _by(_scan({**_AUTHED, "auth_exempt_discover": True,
                         "trust_meta_admin_identity": True}, ["T1"], auth_token="tok"),
                  "T01-007")
    assert all(_finding(r) for r in results), results


def test_exploit_t01_007_dual_era_open_legacy_handshake() -> None:
    results = _by(_scan({"protocol_era": "dual", "modern_requires_auth": True,
                         "trust_meta_admin_identity": True}, ["T1"], auth_token="tok"),
                  "T01-007")
    assert all(_finding(r) for r in results), results


def test_exploit_t01_007_required_args_tool_retry_keeps_meta() -> None:
    from cosai_mcp.catalog.loader import CatalogLoader
    from cosai_mcp.discovery import _tool_dict_to_discovered
    from cosai_mcp.harness.runner import _synthesize_probe

    threat = CatalogLoader(CATALOG_ROOT).load_file(Path("official/T01-007.json"))
    tool = _tool_dict_to_discovered({"name": "book", "description": "d", "inputSchema": {
        "type": "object", "properties": {"when": {"type": "string"}}, "required": ["when"]}})
    assert tool is not None
    synth = _synthesize_probe(threat.probes[0], threat, tool)
    assert synth is not None
    meta = synth.payload["_meta"]
    assert meta["io.modelcontextprotocol/clientInfo"]["name"] == "admin-console"


def test_exploit_optional_probe_skip_disclosed() -> None:
    report = evaluate_assurance(2, [_pr("T01-007", False, inconclusive=True)],
                                evidence=_ev("SD-02"))
    sd02 = next(c for c in report.controls if c.control_id == "SD-02")
    assert sd02.verdict is Verdict.ATTESTED
    assert "T01-007" in sd02.reason and "not conclusively run" in sd02.reason


def test_exploit_legacy_pin_on_modern_target_blocks_sd02() -> None:
    report = evaluate_assurance(2, [_pr("T01-007", False, inconclusive=True)],
                                evidence=_ev("SD-02"),
                                required_optional=frozenset({"T01-007"}))
    assert _verdict(report, "SD-02") is Verdict.UNVERIFIED


# ===========================================================================
# Round-2 regressions
# ===========================================================================

def test_regression_t01_007_legacy_init_auth_not_applicable() -> None:
    results = _by(_scan({"initialize_requires_auth": True}, ["T1"], auth_token="tok"),
                  "T01-007")
    assert all(r.error is None and r.inconclusive_reason
               and "not applicable" in r.inconclusive_reason for r in results), results


def test_regression_t01_007_legacy_session_400_not_scan_error() -> None:
    with MockMCPServer(initialize_requires_auth=True) as server:
        server.wait_ready()
        Scanner(f"http://127.0.0.1:{server.port}", categories=["T1"], engine="prober",
                allow_private_targets=True, probe_timeout_seconds=10.0,
                auth_token="tok").run()
        modern_calls = [r for r in server.request_log if r.get("method") == "tools/call"
                        and "_meta" in (r.get("params") or {})]
    assert modern_calls == []  # no modern-framed call sent to a legacy server


def test_regression_assurance_legacy_pin_modern_target_sd02_not_attested() -> None:
    with pytest.raises(ValueError, match="--protocol-era auto"):
        Scanner("http://127.0.0.1:9", allow_private_targets=True, assurance_level=2,
                protocol_era="legacy").run()


def _evidence_dir(root: Path, target: str, controls: tuple[str, ...]) -> Path:
    root.mkdir(exist_ok=True)
    (root / "a.txt").write_text("x")
    (root / "evidence.json").write_text(json.dumps({
        "schema_version": "1.0", "target": target,
        "controls": {c: {"artifact": "a.txt"} for c in controls}}))
    return root


@pytest.mark.parametrize(("tools", "expected"), [
    ([], Verdict.ATTESTED),                     # no tools: T05-003 not promoted
    (None, Verdict.ATTESTED),                   # tools: T05-003 runs conclusively
])
def test_regression_t05_003_empty_manifest_not_promoted(
    tmp_path: Path, tools: list[Any] | None, expected: Verdict,
) -> None:
    kwargs: dict[str, Any] = dict(_MODERN)
    if tools is not None:
        kwargs["tools"] = tools
    with MockMCPServer(**kwargs) as server:
        server.wait_ready()
        target = f"http://127.0.0.1:{server.port}"
        result = Scanner(target, allow_private_targets=True, probe_timeout_seconds=10.0,
                         assurance_level=3,
                         evidence_dir=_evidence_dir(tmp_path / "ev", target, ("TI-05",))).run()
    ti05 = next(c for c in result.assurance.controls if c.control_id == "TI-05")
    assert ti05.verdict is expected, ti05.reason


# ===========================================================================
# Round-3 regressions
# ===========================================================================

def test_regression_t01_007_forced_modern_unauth_discover_400_still_probes() -> None:
    """Auth refusal of discover with a generic 400 classifies as LEGACY; on a
    target the authenticated scan pinned modern it must not hide T01-007."""
    results = _by(_scan({**_AUTHED, "unauth_http_status": 400,
                         "trust_meta_admin_identity": True}, ["T1"], auth_token="tok"),
                  "T01-007")
    assert all(_finding(r) for r in results), results


@pytest.mark.parametrize(("checked", "expected"), [
    (None, Verdict.UNVERIFIED),   # discovery FAILED → T05-003 stays promoted
    ((), Verdict.ATTESTED),       # server really exposes no tools → not promoted
])
def test_regression_assurance_discovery_failure_keeps_tools_call_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, checked: Any, expected: Verdict,
) -> None:
    import cosai_mcp.api as api
    import cosai_mcp.discovery as discovery

    monkeypatch.setattr(api, "_run_discovery", lambda *a, **k: ("ping", ()))
    monkeypatch.setattr(discovery, "discover_tools_checked", lambda *a, **k: checked)
    tool_not_found = {"jsonrpc": "2.0", "id": 0,
                      "error": {"code": -32602, "message": "Unknown tool: ping"}}
    with MockMCPServer(**_MODERN, tools_call_response=tool_not_found) as server:
        server.wait_ready()
        target = f"http://127.0.0.1:{server.port}"
        result = Scanner(target, allow_private_targets=True, probe_timeout_seconds=10.0,
                         assurance_level=3,
                         evidence_dir=_evidence_dir(tmp_path / "ev", target, ("TI-05",))).run()
    ti05 = next(c for c in result.assurance.controls if c.control_id == "TI-05")
    assert ti05.verdict is expected, ti05.reason


# ===========================================================================
# Round-4 regressions — scan-level era pin needs positive legacy evidence
# ===========================================================================

@pytest.mark.parametrize(("mock_kwargs", "expected"), [
    ({**_AUTHED, "unauth_http_status": 400}, None),   # modern, refuses unauth discover
    ({}, "legacy"),                                   # discover → -32601
    ({"discover_http_status": 400}, "legacy"),        # no -32601, handshake succeeds
])
def test_regression_detect_era_400_is_undetermined(
    mock_kwargs: dict[str, Any], expected: str | None,
) -> None:
    from cosai_mcp.config import ScanConfig
    from cosai_mcp.discovery import detect_protocol_era

    with MockMCPServer(**mock_kwargs) as server:
        server.wait_ready()
        config = ScanConfig(target_host="127.0.0.1", target_port=server.port,
                            allow_private_targets=True, probe_timeout_seconds=5.0)
        assert detect_protocol_era(f"http://127.0.0.1:{server.port}", config) == expected


def test_regression_assurance_unauth_400_discover_keeps_t01_007_promotion(
    tmp_path: Path,
) -> None:
    with MockMCPServer(**_AUTHED, unauth_http_status=400,
                       trust_meta_admin_identity=True) as server:
        server.wait_ready()
        target = f"http://127.0.0.1:{server.port}"
        result = Scanner(target, allow_private_targets=True, probe_timeout_seconds=10.0,
                         assurance_level=2,
                         evidence_dir=_evidence_dir(tmp_path / "ev", target, ("SD-02",))).run()
    t01_007 = [r for r in result.probe_results if r.threat_id == "T01-007"]
    assert t01_007 and all(r.error is None for r in t01_007), t01_007
    sd02 = next(c for c in result.assurance.controls if c.control_id == "SD-02")
    assert sd02.verdict is not Verdict.ATTESTED, sd02.reason



def test_regression_legacy_400_discover_trace_id_401_nonauth_init_failure_not_pass() -> None:
    """Server-controlled discover text ('…a401f…', 'unauthorized') must never let a
    non-auth handshake failure become a synthesized T1 PASS (round-5 FIX 1)."""
    from cosai_mcp.catalog.loader import CatalogLoader
    from cosai_mcp.harness.runner import ProbeRunner

    threat = CatalogLoader(CATALOG_ROOT).load_file(Path("official/T01-001.json"))
    with MockMCPServer(discover_http_status=400,
                       discover_error_message="bad request traceId=a401f9 unauthorized",
                       initialize_http_status=500) as server:
        server.wait_ready()
        config = ScanConfig(target_host="127.0.0.1", target_port=server.port,
                            allow_private_targets=True, probe_timeout_seconds=10.0)
        result = ProbeRunner(config, f"http://127.0.0.1:{server.port}").run_probe(
            threat.probes[0], threat, variables={"tool_name": "echo"},
            pass_on_auth_reject=True)
    assert result.passed is not True, result
