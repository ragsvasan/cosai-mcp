"""Black-box probes for T6 (Integrity/Verification) and T11 (Supply Chain/Lifecycle).

T06-001: Tool listing is available and consistent (shadowing detection prerequisite).
T11-001: Unlisted tool names must be rejected — allowlist enforcement.

NOTE (locked architecture): Full T6 coverage (tool shadowing, manifest verification)
requires the stateful conformance harness, not black-box probes. T06-001 is the
partial black-box component only.
"""
from __future__ import annotations

import pytest

from cosai_mcp.harness.mock_server import MockMCPServer
from tests.probes.conftest import error_response, ok_response, run_probe


class TestT06CatalogLoads:

    def test_t06_001_loads(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T06-001.json"))
        assert t.id == "T06-001"
        assert t.category == "T6"
        assert len(t.probes) == 1
        assert t.probes[0].method == "tools/list"


class TestT11CatalogLoads:

    def test_t11_001_loads(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T11-001.json"))
        assert t.id == "T11-001"
        assert t.category == "T11"
        assert len(t.probes) == 2


class TestT06ToolIntegrity:
    """T06-001: tools/list must succeed and return a consistent manifest."""

    @pytest.mark.asyncio
    async def test_tools_list_returns_manifest(self, catalog):
        """Server responds to tools/list without error → probe passes."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T06-001.json"))
        probe = threat.probes[0]

        with MockMCPServer() as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server, variables={})

        assert result.passed is True
        assert result.error is None

    @pytest.mark.asyncio
    async def test_tools_list_probe_fails_when_server_returns_error(self, catalog):
        """If the server returns an error for tools/list, the probe assertion fails.

        T06-001-p1 asserts response.error == False (tools/list should succeed).
        A server that rejects tools/list makes shadowing undetectable → probe fails.
        """
        from pathlib import Path
        threat = catalog.load_file(Path("official/T06-001.json"))
        probe = threat.probes[0]

        # Provide a custom tools list response that's an error
        # We can't intercept tools/list via tools_call_response (that's only for tools/call),
        # but we can verify the assertion logic: response.error == False means "success expected".
        # Use a no-tools server so tools/list returns an empty list (still a success).
        # The real "error" case is tested by checking probe assertion semantics directly.
        from cosai_mcp.catalog.models import Operator
        assert any(a.target == "response.error" and a.operator == Operator.EQ and a.value is False
                   for a in probe.assertions), "T06-001-p1 must assert response.error == False"

    @pytest.mark.asyncio
    async def test_request_log_shows_tools_list_called(self, catalog):
        """Verify that the probe actually sends tools/list to the server."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T06-001.json"))
        probe = threat.probes[0]

        with MockMCPServer() as server:
            server.wait_ready()
            await run_probe(probe, threat, server, variables={})
            log = server.request_log

        methods = [r.get("method") for r in log]
        assert "tools/list" in methods


class TestT11SupplyChain:
    """T11-001: Server must reject unlisted / unknown tool names.

    NOTE (WG-89 reviewer item 3): T11-001 is a minimal liveness check — it asks
    for a fictional tool name and expects rejection. Every JSON-RPC-conformant
    server passes it, so on its own it does NOT speak to supply-chain integrity.
    The real black-box T11 surface is the operator-allowlist passive scan
    (``cosai_mcp.api._scan_manifest_t11`` + ``--tool-allowlist``): it flags
    unexpected tools and Levenshtein-1 typosquats, and reports INCONCLUSIVE
    (never clean) when no allowlist is supplied. See
    ``tests/scorecard/test_manifest_t11.py``."""

    @pytest.mark.asyncio
    async def test_secure_server_rejects_unlisted_tool(self, catalog):
        """Secure server: rejects __cosai_probe_unlisted_tool__ → probe passes."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T11-001.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32601, "Method not found")) as server:  # noqa: E501
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_vulnerable_server_executes_unlisted_tool(self, catalog):
        """Vulnerable server: executes any tool name including unlisted ones → fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T11-001.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response("result")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_error_code_in_allowlist_check(self, catalog):
        """T11-001-p1 checks error_code_in [-32601, -32602, -32603]."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T11-001.json"))
        probe = threat.probes[0]

        # -32602 (Invalid params) is also an acceptable rejection
        with MockMCPServer(tools_call_response=error_response(-32602, "Tool not in allowlist")) as server:  # noqa: E501
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_path_traversal_tool_name_method_not_found_is_inconclusive(self, catalog):
        """T11-001-p2 asserts only response.error==true with NO error_code guard.
        A -32601 (method not found) for the traversal tool name is
        indistinguishable from a server that simply lacks the tool — it is NOT
        proof a signed allowlist rejected it (adversary EXPLOIT 1 / audit COV-11).
        The honest verdict is INCONCLUSIVE; real typosquat detection is the
        manifest-enumeration engine (Batch 2 / COV-02)."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T11-001.json"))
        probe = threat.probes[1]  # path-traversal tool name probe

        with MockMCPServer(tools_call_response=error_response(-32601, "Invalid tool name")) as server:  # noqa: E501
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False
        assert result.inconclusive_reason is not None

    @pytest.mark.asyncio
    async def test_path_traversal_tool_name_executed_fails(self, catalog):
        """Vulnerable server: executes tool with path-traversal name → probe fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T11-001.json"))
        probe = threat.probes[1]

        with MockMCPServer(tools_call_response=ok_response("file content")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_t11_probes_not_findings_on_allowlist_server(self, catalog):
        """On a strict-allowlist server returning -32601: p1 (which asserts the
        error_code is in an expected protocol set) is a real PASS; p2 (bare
        error-presence, no error_code guard) is INCONCLUSIVE — neither is a
        finding, but only the error_code-guarded probe earns a PASS (COV-11)."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T11-001.json"))

        results = []
        for probe in threat.probes:
            with MockMCPServer(tools_call_response=error_response(-32601, "Not in allowlist")) as server:  # noqa: E501
                server.wait_ready()
                r = await run_probe(probe, threat, server)
                results.append(r)

        p1, p2 = results
        assert p1.passed is True and p1.inconclusive_reason is None
        assert p2.passed is False and p2.inconclusive_reason is not None
