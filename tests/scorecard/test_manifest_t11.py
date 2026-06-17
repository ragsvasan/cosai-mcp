"""Passive T11 supply-chain manifest scan (WG-89 reviewer item 3).

The legacy T11-001 black-box probe (ask for a fictional tool name; treat -32601
as a pass) is vacuous — every conformant server passes it. `_scan_manifest_t11`
adds the real black-box T11 surface an external scanner can decide: discovered
tools vs the operator's approved-tool allowlist (typosquat + unexpected tool).
"""
from __future__ import annotations

import types
import warnings

from cosai_mcp.api import _scan_manifest_t11
from cosai_mcp.discovery import DiscoveredTool


def _tool(name: str) -> DiscoveredTool:
    return DiscoveredTool(
        name=name,
        description="",
        input_schema=types.MappingProxyType({}),
        boolean_params=(),
        string_params=(),
        numeric_params=(),
        required_params=(),
    )


def _tools(*names: str) -> tuple:
    return tuple(_tool(n) for n in names)


class TestScanManifestT11:
    def test_empty_manifest_yields_nothing(self) -> None:
        assert _scan_manifest_t11((), ("a", "b")) == []

    def test_no_allowlist_is_inconclusive_not_clean(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            results = _scan_manifest_t11(_tools("search", "deploy"), None)
        assert len(results) == 1
        r = results[0]
        assert r.threat_id == "T11"
        assert r.passed is False
        assert r.inconclusive_reason is not None
        assert "allowlist" in r.inconclusive_reason.lower()

    def test_no_allowlist_warns(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _scan_manifest_t11(_tools("search"), None)
        assert any("tool-allowlist" in str(w.message) for w in caught)

    def test_all_tools_approved_emits_clean_marker(self) -> None:
        results = _scan_manifest_t11(_tools("search", "deploy"), ("search", "deploy"))
        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].probe_id == "T11-manifest-clean"

    def test_unexpected_tool_is_a_finding(self) -> None:
        results = _scan_manifest_t11(_tools("search", "exfiltrate"), ("search",))
        findings = [r for r in results if not r.passed]
        assert findings
        assert all(r.threat_id == "T11" for r in findings)
        assert any("not on the operator allowlist" in r.response_body for r in findings)

    def test_typosquat_is_a_distinct_finding(self) -> None:
        # 'searh' is Levenshtein-1 from the approved 'search' → typosquat.
        results = _scan_manifest_t11(_tools("searh"), ("search",))
        findings = [r for r in results if not r.passed]
        assert any("typosquat" in r.response_body.lower() for r in findings)
        assert any("within one edit" in r.response_body for r in findings)

    def test_approved_tool_not_flagged(self) -> None:
        results = _scan_manifest_t11(_tools("search"), ("search", "deploy"))
        assert all(r.passed for r in results)

    def test_finding_redacts_no_raw_secret_and_is_escaped(self) -> None:
        # Tool names pass _SAFE_TOOL_NAME_RE; body is HTML-escaped via make_probe_result.
        results = _scan_manifest_t11(_tools("evil_tool"), ("good_tool",))
        assert results[0].response_body  # non-empty, escaped finding text


class TestParseToolAllowlist:
    """The --tool-allowlist CLI value parser."""

    def _parse(self, raw):
        from cosai_mcp.cli import _parse_tool_allowlist
        return _parse_tool_allowlist(raw)

    def test_none_returns_none(self) -> None:
        assert self._parse(None) is None

    def test_blank_returns_none(self) -> None:
        assert self._parse("  ,  ,") is None

    def test_comma_separated_parsed_and_stripped(self) -> None:
        assert self._parse(" search , deploy ") == ("search", "deploy")

    def test_deduplicates_preserving_order(self) -> None:
        assert self._parse("a,b,a,c,b") == ("a", "b", "c")


class TestScanManifestT11Wiring:
    """Prove _scan_manifest_t11 is reached from _run_scan / Scanner with the
    allowlist threaded through — guards the 'field defined but never set' mode."""

    def test_typosquat_flagged_through_scanner(self) -> None:
        from cosai_mcp.api import Scanner
        from cosai_mcp.config import ScanConfig
        from cosai_mcp.harness.mock_server import MockMCPServer

        # Server exposes 'serch' — a Levenshtein-1 typosquat of approved 'search'.
        tools = [{"name": "serch", "description": "x", "inputSchema": {"type": "object"}}]
        with MockMCPServer(tools=tools) as server:
            cfg = ScanConfig(
                target=f"http://127.0.0.1:{server.port}",
                categories=["T11"],
                allow_private_targets=True,
                probe_timeout_seconds=15.0,
                tool_allowlist=("search",),
            )
            result = Scanner(cfg, engine="prober").run()

        t11 = [r for r in result.probe_results if r.threat_id == "T11"]
        assert any(
            not r.passed and "typosquat" in r.response_body.lower() for r in t11
        ), "T11 typosquat must fire via Scanner.run with --tool-allowlist"

    def test_no_allowlist_inconclusive_through_scanner(self) -> None:
        from cosai_mcp.api import Scanner
        from cosai_mcp.config import ScanConfig
        from cosai_mcp.harness.mock_server import MockMCPServer

        tools = [{"name": "search", "description": "x", "inputSchema": {"type": "object"}}]
        with MockMCPServer(tools=tools) as server:
            cfg = ScanConfig(
                target=f"http://127.0.0.1:{server.port}",
                categories=["T11"],
                allow_private_targets=True,
                probe_timeout_seconds=15.0,
            )
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                result = Scanner(cfg, engine="prober").run()

        t11 = [r for r in result.probe_results if r.threat_id == "T11"]
        assert any(
            r.inconclusive_reason and "allowlist" in r.inconclusive_reason.lower()
            for r in t11
        ), "T11 must be INCONCLUSIVE (not clean) without an allowlist"

    def test_regression_t11_inconclusive_is_not_has_findings(self) -> None:
        """An INCONCLUSIVE T11 result (no allowlist) must NOT set has_findings —
        inconclusive != finding, consistent with exit-code/findings semantics."""
        from cosai_mcp.api import Scanner
        from cosai_mcp.config import ScanConfig
        from cosai_mcp.harness.mock_server import MockMCPServer

        tools = [{"name": "search", "description": "x", "inputSchema": {"type": "object"}}]
        # Reject the unlisted-tool call so the legacy T11-001 probe PASSES,
        # isolating the manifest INCONCLUSIVE as the only non-passing T11 result.
        reject = {"jsonrpc": "2.0", "id": 0, "error": {"code": -32601, "message": "Method not found"}}
        with MockMCPServer(tools=tools, tools_call_response=reject) as server:
            cfg = ScanConfig(
                target=f"http://127.0.0.1:{server.port}",
                categories=["T11"],
                allow_private_targets=True,
                probe_timeout_seconds=15.0,
            )
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                result = Scanner(cfg, engine="prober").run()

        # T11 emitted an inconclusive result, but the scan has no real finding.
        assert any(r.inconclusive_reason for r in result.probe_results)
        assert result.has_findings is False
