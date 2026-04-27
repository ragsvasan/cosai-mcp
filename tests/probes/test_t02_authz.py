"""Black-box probes for T2 — Missing Access Control / Confused Deputy.

Probe semantics:
  result.passed = True  → server rejected cross-session / privilege-escalation attempt
  result.passed = False → server allowed unauthorised access (vulnerability)
"""
from __future__ import annotations

import pytest

from cosai_mcp.harness.mock_server import MockMCPServer
from tests.probes.conftest import error_response, ok_response, run_probe


class TestT02CatalogLoads:

    def test_t02_001_loads(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T02-001.json"))
        assert t.id == "T02-001"
        assert t.category == "T2"
        assert len(t.probes) == 2
        for probe in t.probes:
            assert any(a.target == "response.error" for a in probe.assertions)


class TestT02ConfusedDeputy:
    """T02-001: Tool call with another user's session_id must be rejected."""

    @pytest.mark.asyncio
    async def test_secure_server_rejects_cross_session_access(self, catalog):
        """Secure server: rejects tool call with foreign session_id → probe passes."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T02-001.json"))
        probe = threat.probes[0]  # session_id injection probe

        with MockMCPServer(tools_call_response=error_response(-32001, "Session mismatch")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_vulnerable_server_processes_foreign_session(self, catalog):
        """Vulnerable server: processes request with foreign session_id → probe fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T02-001.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response("victim data returned")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_secure_server_rejects_privilege_escalation(self, catalog):
        """Secure server: rejects role=admin argument → probe passes."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T02-001.json"))
        probe = threat.probes[1]  # privilege_level=99 probe

        with MockMCPServer(tools_call_response=error_response(-32001, "Privilege escalation denied")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_vulnerable_server_grants_admin_via_argument(self, catalog):
        """Vulnerable server: honours role=admin in argument → privilege escalation → fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T02-001.json"))
        probe = threat.probes[1]

        with MockMCPServer(tools_call_response=ok_response("Admin access granted")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_all_t02_probes_pass_on_secure_server(self, catalog):
        """All T02-001 probes pass on a properly access-controlled server."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T02-001.json"))

        results = []
        for probe in threat.probes:
            with MockMCPServer(tools_call_response=error_response(-32001, "Denied")) as server:
                server.wait_ready()
                r = await run_probe(probe, threat, server)
                results.append(r)

        assert all(r.passed for r in results)
