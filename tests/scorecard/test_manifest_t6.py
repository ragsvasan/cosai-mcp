"""COV-02: real T6 manifest-integrity detection (_scan_manifest_t6).

Replaces the vacuous T06-001/002 black-box probes (which only asserted that
tools/list succeeds, and so passed against a fully shadowed/typosquatted server)
with name-collision + reserved-method-shadow + Levenshtein near-collision
detection over the discovered manifest.
"""
from __future__ import annotations

import types

from cosai_mcp.api import _scan_manifest_t6
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


class TestScanManifestT6:
    def test_empty_manifest_yields_nothing(self) -> None:
        assert _scan_manifest_t6(()) == []

    def test_clean_manifest_emits_single_pass_marker(self) -> None:
        results = _scan_manifest_t6(_tools("get_memory", "save_session", "list_threads"))
        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].threat_id == "T06"
        assert results[0].probe_id == "T06-manifest-clean"

    def test_name_collision_is_a_finding(self) -> None:
        results = _scan_manifest_t6(_tools("get_memory", "get_memory", "save"))
        findings = [r for r in results if not r.passed]
        assert findings, "duplicate tool name must produce a finding"
        assert all(r.threat_id == "T06" for r in findings)
        assert any("collision" in r.response_body.lower() for r in findings)

    def test_reserved_method_shadow_is_a_finding(self) -> None:
        # 'tools_call' is within Levenshtein 1 of the reserved 'tools/call'.
        results = _scan_manifest_t6(_tools("tools_call", "get_memory"))
        findings = [r for r in results if not r.passed]
        assert any("reserved MCP method" in r.response_body for r in findings)

    def test_near_collision_between_tools_is_a_finding(self) -> None:
        # 'get_memory' vs 'get_memorx' differ by one edit → typosquat/shadow.
        results = _scan_manifest_t6(_tools("get_memory", "get_memorx"))
        findings = [r for r in results if not r.passed]
        assert any("single edit" in r.response_body for r in findings)

    def test_shadowed_server_no_longer_vacuously_passes(self) -> None:
        """The exact COV-02 complaint: a typosquatted manifest must FAIL T6, not
        pass. With a collision present, no clean PASS marker is emitted and at
        least one failing T06 result exists."""
        results = _scan_manifest_t6(_tools("delete_user", "delete_user"))
        assert not any(r.probe_id == "T06-manifest-clean" for r in results)
        assert any(not r.passed and r.threat_id == "T06" for r in results)

    def test_pluralised_variants_not_flagged(self) -> None:
        """FIX [1]: benign singular/plural pairs (get_user/get_users) are a
        trailing-'s' difference, not a typosquat — must not fire a finding."""
        results = _scan_manifest_t6(_tools("get_user", "get_users", "list_file", "list_files"))
        assert all(r.passed for r in results)
        assert results[0].probe_id == "T06-manifest-clean"


class TestScanManifestT6Wiring:
    """FIX [2]: prove _scan_manifest_t6 is actually reached from _run_scan with a
    real discovered manifest — guards against the historical 'function exists +
    unit-tested but never wired into the scan path' dead-code failure mode."""

    def test_regression_t6_wiring_run_scan_reserved_method_shadow(self) -> None:
        from pathlib import Path
        from cosai_mcp.api import _run_scan
        from cosai_mcp.harness.mock_server import MockMCPServer

        catalog_root = Path(__file__).parent.parent.parent / "catalog"
        # 'tools_call' is Levenshtein-1 from the reserved method 'tools/call'.
        shadow_tools = [{"name": "tools_call", "description": "x", "inputSchema": {"type": "object"}}]
        with MockMCPServer(tools=shadow_tools) as server:
            server.wait_ready()
            result = _run_scan(
                target=f"http://127.0.0.1:{server.port}",
                categories=["T6"],
                engine="prober",
                allow_custom_catalog=False,
                probe_timeout_seconds=15.0,
                catalog_root=catalog_root,
                allow_private_targets=True,
            )
        t6 = [r for r in result.probe_results if r.threat_id == "T06"]
        assert any(
            not r.passed and "reserved MCP method" in r.response_body for r in t6
        ), "T6 manifest scan must fire via _run_scan on a reserved-method shadow"


class TestScorecardCategorisesManifestResults:
    """The scorecard must place threat_id-only manifest results in the right
    CoSAI category (regression for the _category_from_threat_id fallback)."""

    def test_category_from_threat_id(self) -> None:
        from cosai_mcp.scorecard.builder import _category_from_threat_id
        assert _category_from_threat_id("T06") == "T6"
        assert _category_from_threat_id("T04-manifest-p1") == "T4"
        assert _category_from_threat_id("T09") == "T9"
        assert _category_from_threat_id("nonsense") == "T?"
