"""CoSAI MCP Security v2.0 — P1a probes for the MCP 2026-07-28 attack surface.

Each catalog probe is exercised through the public entry point (Scanner.run →
_run_scan → ProbeRunner subprocess) against a VULNERABLE mock (must FAIL), a
SECURE modern mock (must PASS), and a LEGACY mock (must be INCONCLUSIVE — the
surface does not exist there).  Also covers schema 1.2 (`requires_protocol_era`)
format coverage, the passive T3 tool-schema hygiene scan, and SARIF/HTML output.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, create_autospec

import pytest
from click.testing import CliRunner

from cosai_mcp import Scanner
from cosai_mcp.catalog.loader import CatalogLoader
from cosai_mcp.catalog.schema import validate_threat_json
from cosai_mcp.config import ScanConfig
from cosai_mcp.exceptions import SchemaValidationError
from cosai_mcp.harness.context import ProbeContext
from cosai_mcp.harness.mock_server import MockMCPServer
from cosai_mcp.harness.runner import _probe_from_dict, _probe_to_dict
from cosai_mcp.protocol import META_CLIENT_INFO, tool_schema_violations
from cosai_mcp.session import MCPSession, SessionStatus
from cosai_mcp.transport.base import Transport

CATALOG_ROOT = Path(__file__).parent.parent / "catalog"


def _scan(mock_kwargs: dict[str, Any], categories: list[str]) -> list[Any]:
    with MockMCPServer(**mock_kwargs) as server:
        server.wait_ready()
        result = Scanner(
            f"http://127.0.0.1:{server.port}",
            categories=categories, engine="prober", allow_private_targets=True,
            probe_timeout_seconds=10.0,
        ).run()
    return list(result.probe_results)


def _by_threat(results: list[Any], threat_id: str) -> list[Any]:
    found = [r for r in results if r.threat_id == threat_id]
    assert found, f"no results for {threat_id}: {[r.threat_id for r in results]}"
    return found


def _is_finding(r: Any) -> bool:
    return r.passed is False and r.error is None and r.inconclusive_reason is None


# ===========================================================================
# Schema 1.2 format coverage
# ===========================================================================

class TestSchema12:
    def _threat(self, **probe_extra: Any) -> dict[str, Any]:
        return {
            "schema_version": "1.2", "id": "T07-099", "category": "T7",
            "severity": "low", "cosai_ref": "T7", "owasp_ref": "x", "cwe": ["CWE-1"],
            "probes": [{"id": "p", "transport": "http", "method": "tools/list",
                        "payload": {}, "assertions": [], **probe_extra}],
            "remediation": "r", "references": [],
        }

    def test_requires_protocol_era_accepted(self) -> None:
        validate_threat_json(self._threat(requires_protocol_era="modern"))
        validate_threat_json(self._threat(requires_protocol_era="legacy"))

    def test_requires_protocol_era_closed_enum(self) -> None:
        with pytest.raises(SchemaValidationError):
            validate_threat_json(self._threat(requires_protocol_era="future"))

    def test_older_schema_versions_still_load(self) -> None:
        threats = CatalogLoader(CATALOG_ROOT).load_all()
        versions = {t.schema_version for t in threats}
        assert {"1.0", "1.2"} <= versions

    def test_field_survives_subprocess_serialization(self) -> None:
        threat = CatalogLoader(CATALOG_ROOT).load_file(Path("official/T07-004.json"))
        probe = threat.probes[0]
        assert _probe_from_dict(_probe_to_dict(probe)).requires_protocol_era == "modern"


# ===========================================================================
# ProbeContext era gate and _meta pass-through
# ===========================================================================

def _ready_session(era: str) -> tuple[MCPSession, Any]:
    transport = create_autospec(Transport, instance=True)
    transport.send = AsyncMock(return_value={"jsonrpc": "2.0", "id": 1, "result": {}})
    session = MCPSession(transport, ScanConfig(target_host="h", target_port=1))
    session.enter_unverified(modern=(era == "modern"))
    assert session.status is SessionStatus.READY
    return session, transport


def test_modern_only_probe_is_inconclusive_on_legacy_session() -> None:
    threat = CatalogLoader(CATALOG_ROOT).load_file(Path("official/T07-005.json"))
    session, transport = _ready_session("legacy")
    result = asyncio.run(
        ProbeContext(session, session._config, "http://h:1").execute_probe(
            threat.probes[0], threat, {}
        )
    )
    assert result.passed is False
    assert result.inconclusive_reason and "not applicable" in result.inconclusive_reason
    transport.send.assert_not_awaited()


def test_tools_call_probe_meta_is_forwarded() -> None:
    from cosai_mcp.catalog.models import Probe

    session, transport = _ready_session("modern")
    probe = Probe(
        id="x", transport="http", method="tools/call",
        payload={"name": "echo", "arguments": {}, "_meta": {META_CLIENT_INFO: {"name": "spoof"}}},
        assertions=(),
    )
    threat = CatalogLoader(CATALOG_ROOT).load_file(Path("official/T07-005.json"))
    asyncio.run(ProbeContext(session, session._config, "http://h:1").execute_probe(
        probe, threat, {}))
    sent = transport.send.await_args.args[1]
    assert sent["_meta"][META_CLIENT_INFO] == {"name": "spoof"}


# ===========================================================================
# New catalog probes via Scanner.run — vulnerable / secure / legacy
# ===========================================================================

_MODERN: dict[str, Any] = {"protocol_era": "modern"}
_CASES = [
    # threat,   vulnerable mock kwargs,                       secure mock kwargs
    ("T07-004", {**_MODERN, "skip_header_validation": True}, _MODERN),
    ("T07-005", {**_MODERN, "accept_unknown_versions": True}, _MODERN),
    ("T07-006", {"protocol_era": "dual"}, _MODERN),
    ("T11-002", {**_MODERN, "advertise_logging": True}, _MODERN),
]


@pytest.mark.parametrize(("threat_id", "vulnerable", "secure"), _CASES)
def test_probe_fails_on_vulnerable_server(
    threat_id: str, vulnerable: dict[str, Any], secure: dict[str, Any],
) -> None:
    results = _by_threat(_scan(vulnerable, [threat_id[:3].replace("0", "", 1)]), threat_id)
    assert all(_is_finding(r) for r in results), results


@pytest.mark.parametrize(("threat_id", "vulnerable", "secure"), _CASES)
def test_probe_passes_on_secure_modern_server(
    threat_id: str, vulnerable: dict[str, Any], secure: dict[str, Any],
) -> None:
    results = _by_threat(_scan(secure, [threat_id[:3].replace("0", "", 1)]), threat_id)
    assert all(r.passed is True for r in results), results


@pytest.mark.parametrize("threat_id", [c[0] for c in _CASES])
def test_probe_not_applicable_on_legacy_server(threat_id: str) -> None:
    results = _by_threat(_scan({}, [threat_id[:3].replace("0", "", 1)]), threat_id)
    assert all(
        r.passed is False and r.inconclusive_reason and "not applicable" in r.inconclusive_reason
        for r in results
    ), results


# ===========================================================================
# Passive T3 tool-schema hygiene
# ===========================================================================

class TestToolSchemaViolations:
    def test_clean_schema(self) -> None:
        assert tool_schema_violations({"type": "object", "properties": {
            "q": {"type": "string", "x-mcp-header": "Q"},
            "o": {"type": "object", "properties": {"t": {"type": ["string", "null"],
                                                        "x-mcp-header": "T"}}},
            "loc": {"$ref": "#/$defs/loc"},
        }, "$defs": {"loc": {"type": "string"}}}) == []

    @pytest.mark.parametrize(("schema", "needle"), [
        ({"properties": {"a": {"$ref": "https://evil.example/s.json"}}}, "external $ref"),
        ({"properties": {"a": {"type": "number", "x-mcp-header": "A"}}}, "type 'number'"),
        ({"properties": {"a": {"type": "string", "x-mcp-header": "bad name"}}}, "HTTP token"),
        ({"properties": {"a": {"type": "string", "x-mcp-header": "D"},
                         "b": {"type": "string", "x-mcp-header": "d"}}}, "duplicate"),
        ({"properties": {"a": {"type": "array", "items": {"type": "string",
                                                          "x-mcp-header": "I"}}}},
         "not reachable"),
        ({"anyOf": [{"properties": {"a": {"type": "string", "x-mcp-header": "C"}}}]},
         "not reachable"),
    ])
    def test_violations(self, schema: dict[str, Any], needle: str) -> None:
        assert any(needle in v for v in tool_schema_violations(schema)), \
            tool_schema_violations(schema)

    def test_depth_and_size_bounds(self) -> None:
        deep: dict[str, Any] = {"type": "string"}
        for _ in range(40):
            deep = {"type": "object", "properties": {"x": deep}}
        assert any("depth" in v for v in tool_schema_violations(deep))
        wide = {"properties": {f"p{i}": {"type": "string"} for i in range(3000)}}
        assert any("subschemas" in v for v in tool_schema_violations(wide))

    def test_hostile_input_does_not_raise(self) -> None:
        assert tool_schema_violations("nope") == []
        assert tool_schema_violations({"properties": {"a": {"x-mcp-header": 5}}})


def test_passive_t3_schema_scan_through_scanner() -> None:
    tools = [
        {"name": "echo", "description": "ok", "inputSchema": {"type": "object"}},
        {"name": "lure", "description": "x", "inputSchema": {"type": "object", "properties": {
            "a": {"$ref": "https://evil.example/<script>.json"},
            "b": {"type": "number", "x-mcp-header": "B"},
        }}},
    ]
    results = _scan({"protocol_era": "modern", "tools": tools}, ["T3"])
    findings = [r for r in results if r.probe_id.startswith("T03-schema-p")]
    assert len(findings) == 1 and _is_finding(findings[0])
    assert "external $ref" in findings[0].response_body
    assert "<script>" not in findings[0].response_body  # escaped at ingestion


def test_passive_t3_schema_scan_clean_marker() -> None:
    results = _scan({"protocol_era": "modern"}, ["T3"])
    assert any(r.probe_id == "T03-schema-clean" and r.passed for r in results)


# ===========================================================================
# Full pipeline: new IDs survive SARIF + HTML
# ===========================================================================

def test_new_probe_findings_survive_sarif_and_html(tmp_path: Path) -> None:
    from cosai_mcp.cli import main

    sarif_path = tmp_path / "out.sarif"
    html_path = tmp_path / "out.html"
    with MockMCPServer(protocol_era="dual", skip_header_validation=True,
                       accept_unknown_versions=True, advertise_logging=True) as server:
        server.wait_ready()
        result = CliRunner().invoke(main, [
            "scan", f"http://127.0.0.1:{server.port}", "--allow-private-targets",
            "--categories", "T7,T11", "--engine", "prober", "--fail-on", "low",
            "--report-sarif", str(sarif_path), "--report-html", str(html_path),
        ])
    assert result.exit_code == 1, result.output
    doc = json.loads(sarif_path.read_text())
    rule_ids = {r["ruleId"] for r in doc["runs"][0]["results"]}
    # Dual-era server: pinned modern → all four v2.0 findings reported.
    assert {"T07-004", "T07-005", "T07-006", "T11-002"} <= rule_ids
    html = html_path.read_text()
    for tid in ("T07-004", "T07-005", "T07-006", "T11-002"):
        assert tid in html


def test_regression_synthesized_retry_keeps_every_probe_field() -> None:
    """Adaptive-synthesis retry must not drop requires_protocol_era (or any field)."""
    import dataclasses

    from cosai_mcp.discovery import _tool_dict_to_discovered
    from cosai_mcp.harness.runner import _synthesize_probe

    threat = CatalogLoader(CATALOG_ROOT).load_file(Path("official/T07-004.json"))
    probe = threat.probes[1]  # tools/call probe
    tool = _tool_dict_to_discovered({"name": "echo", "description": "d", "inputSchema": {
        "type": "object", "properties": {"msg": {"type": "string"}}, "required": ["msg"]}})
    assert tool is not None
    synth = _synthesize_probe(probe, threat, tool)
    assert synth is not None
    assert synth.requires_protocol_era == "modern"
    for f in dataclasses.fields(probe):
        if f.name != "payload":
            assert getattr(synth, f.name) == getattr(probe, f.name), f.name


def test_regression_t3_schema_findings_survive_sarif_and_html(tmp_path: Path) -> None:
    from cosai_mcp.cli import main

    tools = [{"name": "lure", "description": "x", "inputSchema": {
        "type": "object", "properties": {"a": {"$ref": "https://evil.example/s.json"}}}}]
    sarif_path = tmp_path / "t3.sarif"
    html_path = tmp_path / "t3.html"
    with MockMCPServer(protocol_era="modern", tools=tools) as server:
        server.wait_ready()
        CliRunner().invoke(main, [
            "scan", f"http://127.0.0.1:{server.port}", "--allow-private-targets",
            "--categories", "T3", "--engine", "prober",
            "--report-sarif", str(sarif_path), "--report-html", str(html_path),
        ])
    doc = json.loads(sarif_path.read_text())
    assert "T03-100" in {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "external $ref" in html_path.read_text()
