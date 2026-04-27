"""Black-box probes for T1 — Improper Authentication.

Probe semantics:
  result.passed = True  → server rejected unauthenticated access (secure)
  result.passed = False → server allowed unauthenticated access (vulnerability)
"""
from __future__ import annotations

import pytest

from cosai_mcp.harness.mock_server import MockMCPServer
from tests.probes.conftest import error_response, ok_response, run_probe


class TestT01CatalogLoads:
    """Verify the official T01 catalog entries parse and verify correctly."""

    def test_t01_001_loads(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T01-001.json"))
        assert t.id == "T01-001"
        assert t.category == "T1"
        assert len(t.probes) >= 1

    def test_t01_002_loads(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T01-002.json"))
        assert t.id == "T01-002"
        assert len(t.probes) == 2
        # Both probes assert response.error == True
        for probe in t.probes:
            assert any(a.target == "response.error" for a in probe.assertions)


class TestT01UnauthenticatedToolCall:
    """T01-001: tools/call without credentials should be rejected."""

    @pytest.mark.asyncio
    async def test_secure_server_rejects_unauthenticated_call(self, catalog):
        """Secure server: returns error → probe assertions hold → passed=True."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T01-001.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32001, "Unauthorized")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True
        assert result.error is None

    @pytest.mark.asyncio
    async def test_vulnerable_server_allows_unauthenticated_call(self, catalog):
        """Vulnerable server: returns success → probe assertion fails → passed=False."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T01-001.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response("user data")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_probe_captures_error_code(self, catalog):
        """Error code is extractable from the response for reporting."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T01-001.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32001)) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True
        assert result.probe_id == probe.id
        assert result.threat_id == threat.id


class TestT01MultipleProbes:
    """T01-002: Two probes — both must pass for a secure server."""

    @pytest.mark.asyncio
    async def test_secure_server_passes_all_probes(self, catalog):
        """All T01-002 probes pass when server correctly rejects everything."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T01-002.json"))

        results = []
        for probe in threat.probes:
            with MockMCPServer(tools_call_response=error_response(-32001)) as server:
                server.wait_ready()
                r = await run_probe(probe, threat, server)
                results.append(r)

        assert all(r.passed for r in results), [r.assertions for r in results]

    @pytest.mark.asyncio
    async def test_vulnerable_server_fails_admin_probe(self, catalog):
        """Vulnerable server: admin_reset succeeds → probe 2 fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T01-002.json"))
        probe = threat.probes[1]  # admin_reset probe

        with MockMCPServer(tools_call_response=ok_response("reset complete")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_error_code_in_assertion(self, catalog):
        """T01-002-p1 checks error_code_in [-32600, -32603, -32001]."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T01-002.json"))
        probe = threat.probes[0]  # has error_code_in assertion

        # Server returns -32603 (internal error) — still in the allowed set
        with MockMCPServer(tools_call_response=error_response(-32603, "Forbidden")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_wrong_error_code_fails(self, catalog):
        """Error code -32099 is not in [-32600, -32603, -32001] → assertion fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T01-002.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32099, "Custom")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        # response.error == True passes, but error_code_in fails
        assert result.passed is False
