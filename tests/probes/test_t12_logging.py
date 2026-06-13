"""Black-box probes for T12 — Insufficient Logging / Tool Description Transparency.

T12-002: tools/list must be accessible and destructive tool descriptions must
include explicit irreversibility disclosure.

NOTE (locked architecture): Full T12 coverage (hash-chained audit log,
DAG causal chain) requires the middleware instrumentation engine. T12-002
is the partial black-box component that checks observability surface and
description transparency.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cosai_mcp.catalog.loader import CatalogLoader
from cosai_mcp.harness.mock_server import MockMCPServer
from tests.probes.conftest import error_response, ok_response, run_probe

# COV-05: T12-002 is a black-box transparency probe, but T12 is a middleware-only
# category, so the prober skips it — it never runs in a real scan.  The signed
# file was therefore moved OUT of the production catalog (catalog/official/) into
# this test fixture so it no longer ships as dead catalog.  Its Ed25519 signature
# verifies by bytes, independent of path, so the official-provenance loader still
# accepts it from here.  This `catalog` fixture overrides the repo-rooted one in
# conftest.py so these probe-mechanism tests load T12-002 from the fixture.
_FIXTURE_CATALOG_ROOT = Path(__file__).parent.parent / "fixtures" / "catalog"


@pytest.fixture
def catalog() -> CatalogLoader:
    return CatalogLoader(_FIXTURE_CATALOG_ROOT)


_TOOL_WITH_WARNING = {
    "name": "delete_resource",
    "description": "Permanently deletes the specified resource. THIS ACTION IS IRREVERSIBLE AND CANNOT BE UNDONE.",
    "inputSchema": {"type": "object", "properties": {"resource_id": {"type": "string"}}},
}

_TOOL_WITHOUT_WARNING = {
    "name": "delete_resource",
    "description": "Deletes the specified resource.",
    "inputSchema": {"type": "object", "properties": {"resource_id": {"type": "string"}}},
}

_NON_DESTRUCTIVE_TOOL = {
    "name": "echo",
    "description": "Echoes the input back.",
    "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
}


class TestT12CatalogLoads:

    def test_t12_002_loads(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T12-002.json"))
        assert t.id == "T12-002"
        assert t.category == "T12"
        assert t.severity.value == "info"
        assert len(t.probes) == 2

    def test_t12_002_probes_use_tools_list(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T12-002.json"))
        for probe in t.probes:
            assert probe.method == "tools/list"

    def test_t12_002_p1_asserts_no_error(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T12-002.json"))
        p1 = t.probes[0]
        assert any(a.target == "response.error" and a.value is False for a in p1.assertions)

    def test_t12_002_p2_uses_matches_regex(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T12-002.json"))
        p2 = t.probes[1]
        assert any(a.operator.value == "matches_regex" for a in p2.assertions)
        assert any(a.target == "response.body" for a in p2.assertions)


class TestT12ToolsListAccessibility:
    """T12-002-p1: tools/list must be accessible for auditability."""

    @pytest.mark.asyncio
    async def test_tools_list_accessible(self, catalog):
        """Server responds to tools/list without error → probe passes."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T12-002.json"))
        probe = threat.probes[0]  # response.error == false

        with MockMCPServer() as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_tools_list_error_response_fails_probe(self, catalog):
        """Server that returns error on tools/list → probe fails (not auditable).

        MockMCPServer returns method-not-found (-32601) for any unrecognised
        method. We verify the assertion logic by using a tools/list probe with
        response.error == false — if tools/list returns an error the assertion
        fails correctly.
        """
        from pathlib import Path
        from cosai_mcp.catalog.models import Operator
        from cosai_mcp.harness.assertions import evaluate_assertion

        threat = catalog.load_file(Path("official/T12-002.json"))
        probe = threat.probes[0]

        # Simulate a tools/list error response and evaluate assertion directly.
        error_resp = {"error": {"code": -32601, "message": "Method not found"}, "_body": ""}
        assertion = probe.assertions[0]
        result = evaluate_assertion(assertion, error_resp)
        assert result.passed is False


class TestT12DescriptionTransparency:
    """T12-002-p2: at least one tool description must disclose irreversibility."""

    @pytest.mark.asyncio
    async def test_server_with_irreversibility_warning_passes(self, catalog):
        """Server with a tool description containing 'IRREVERSIBLE' → probe passes."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T12-002.json"))
        probe = threat.probes[1]  # matches_regex on response.body

        with MockMCPServer(tools=[_TOOL_WITH_WARNING]) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_server_with_cannot_be_undone_passes(self, catalog):
        """Tool description containing 'cannot be undone' satisfies transparency probe."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T12-002.json"))
        probe = threat.probes[1]

        tool = {
            "name": "purge_data",
            "description": "Purges all data for a tenant. This cannot be undone — ensure backups exist.",
            "inputSchema": {"type": "object"},
        }
        with MockMCPServer(tools=[tool]) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_server_without_warning_language_fails(self, catalog):
        """Server with delete tool but no irreversibility warning → probe fails (info)."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T12-002.json"))
        probe = threat.probes[1]

        with MockMCPServer(tools=[_TOOL_WITHOUT_WARNING]) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_non_destructive_only_server_fails_info_probe(self, catalog):
        """Server with only non-destructive tools also fails p2 — expected false positive at info severity."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T12-002.json"))
        probe = threat.probes[1]

        with MockMCPServer(tools=[_NON_DESTRUCTIVE_TOOL]) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        # False positive: no destructive tools, no warning language. Documented behaviour.
        assert result.passed is False


class TestT12RegexFalsePositives:
    """Regression tests for T12-002-p2 regex — guards against over-broad terms."""

    def _regex_matches(self, pattern: str, text: str) -> bool:
        import re
        return bool(re.search(pattern, text))

    def test_regex_matches_irreversible(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T12-002.json"))
        pattern = t.probes[1].assertions[0].value
        assert self._regex_matches(pattern, "This action is irreversible")

    def test_regex_matches_permanently_delete(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T12-002.json"))
        pattern = t.probes[1].assertions[0].value
        assert self._regex_matches(pattern, "Permanently deletes the resource")

    def test_regex_matches_cannot_be_undone(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T12-002.json"))
        pattern = t.probes[1].assertions[0].value
        assert self._regex_matches(pattern, "This cannot be undone")

    def test_regression_no_fp_on_permanent_link(self, catalog):
        """'permanent' alone must not match — too broad (e.g. 'Creates a permanent link')."""
        from pathlib import Path
        t = catalog.load_file(Path("official/T12-002.json"))
        pattern = t.probes[1].assertions[0].value
        assert not self._regex_matches(pattern, "Creates a permanent link to the resource")

    def test_regression_no_fp_on_this_action_cannot_without_undone(self, catalog):
        """'this action cannot' alone must not match — too broad (e.g. access control messages)."""
        from pathlib import Path
        t = catalog.load_file(Path("official/T12-002.json"))
        pattern = t.probes[1].assertions[0].value
        assert not self._regex_matches(pattern, "This action cannot exceed 100 items")

    def test_regression_no_fp_on_saves_to_permanent_storage(self, catalog):
        """'permanent storage' must not match."""
        from pathlib import Path
        t = catalog.load_file(Path("official/T12-002.json"))
        pattern = t.probes[1].assertions[0].value
        assert not self._regex_matches(pattern, "Saves data to permanent storage")


class TestT12RemediationRegistry:

    def test_t12_002_p1_in_registry(self):
        from cosai_mcp.report.remediation import get_remediation
        block = get_remediation("T12-002-p1")
        assert block is not None
        assert block.threat_id == "T12-002"

    def test_t12_002_p2_in_registry(self):
        from cosai_mcp.report.remediation import get_remediation
        block = get_remediation("T12-002-p2")
        assert block is not None
        assert "irreversib" in block.what_spec_requires.lower()


class TestT02003RemediationRegistry:

    def test_t02_003_p1_in_registry(self):
        from cosai_mcp.report.remediation import get_remediation
        block = get_remediation("T02-003-p1")
        assert block is not None
        assert block.threat_id == "T02-003"
        assert "two-stage" in block.what_spec_requires.lower()

    def test_t02_003_p2_in_registry(self):
        from cosai_mcp.report.remediation import get_remediation
        block = get_remediation("T02-003-p2")
        assert block is not None
        assert block.fix_shape_language == "python"

    def test_t02_003_p1_fastmcp_snippet_has_worker_warning(self):
        """FastMCP snippet must warn about multi-worker deployment — prevents silent breakage."""
        from cosai_mcp.report.remediation import get_remediation
        block = get_remediation("T02-003-p1")
        assert block.fastmcp_snippet is not None
        assert "worker" in block.fastmcp_snippet.lower()
        assert "_pending" in block.fastmcp_snippet
        assert "import secrets" in block.fastmcp_snippet
