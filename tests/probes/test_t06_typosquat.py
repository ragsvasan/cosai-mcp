"""Tests for T6-002: typosquat detection via TyposquatDetector and catalog probe."""
from __future__ import annotations

from pathlib import Path

import pytest

from cosai_mcp.middleware.integrity import TyposquatDetector
from tests.probes.conftest import error_response, ok_response, run_probe


CATALOG_ROOT = Path(__file__).parent.parent.parent / "catalog"


# ===========================================================================
# T6-002 catalog loads
# ===========================================================================

class TestT06002CatalogLoads:

    def test_t06_002_catalog_loads(self, catalog):
        t = catalog.load_file(Path("official/T06-002.json"))
        assert t.id == "T06-002"
        assert t.category == "T6"
        assert len(t.probes) >= 1


# ===========================================================================
# T6-002 probe execution against mock server
# ===========================================================================

class TestT06002Probe:

    @pytest.mark.asyncio
    async def test_t06_002_clean_server_passes(self, catalog):
        """Server returns a normal tools/list response → probe passes (response.error=false)."""
        from cosai_mcp.harness.mock_server import MockMCPServer
        t = catalog.load_file(Path("official/T06-002.json"))
        probe = t.probes[0]

        with MockMCPServer() as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_t06_002_initialize_error_prevents_probe(self, catalog):
        """Server rejects initialize → session cannot start → probe raises SessionIncompleteError."""
        from cosai_mcp.harness.mock_server import MockMCPServer
        from cosai_mcp.exceptions import SessionIncompleteError
        t = catalog.load_file(Path("official/T06-002.json"))
        probe = t.probes[0]

        with MockMCPServer(initialize_error="Unauthorized") as server:
            server.wait_ready()
            with pytest.raises(SessionIncompleteError):
                await run_probe(probe, t, server)


# ===========================================================================
# TyposquatDetector integration with tools/list data
# ===========================================================================

class TestTyposquatDetectorIntegration:

    def test_t06_002_typosquat_server_fails(self):
        """Tools/list with a typosquatted name → TyposquatDetector flags it."""
        detector = TyposquatDetector()
        tools = [
            {"name": "anthropic-mcp-tools"},    # legitimate
            {"name": "anthropic_mcp_tools"},    # typosquat — distance 2 (two _ → - substitutions)
        ]
        findings = detector.check_tools(
            tools,
            allowlist=["anthropic-mcp-tools"],
            max_distance=2,
        )
        assert len(findings) == 1
        assert findings[0].tool_name == "anthropic_mcp_tools"

    def test_t06_002_clean_server_passes_typosquat_check(self):
        """Tools/list with only allowlisted names → no findings."""
        detector = TyposquatDetector()
        tools = [{"name": "read_file"}, {"name": "write_file"}]
        findings = detector.check_tools(
            tools,
            allowlist=["read_file", "write_file"],
        )
        assert findings == []

    def test_t06_002_empty_allowlist_no_findings(self):
        detector = TyposquatDetector()
        tools = [{"name": "evil_tool"}]
        findings = detector.check_tools(tools, allowlist=[])
        assert findings == []
