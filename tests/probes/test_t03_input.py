"""Black-box probes for T3 — Input Validation Failures.

Probe semantics:
  result.passed = True  → server did NOT leak sensitive data (secure)
  result.passed = False → server leaked sensitive data or accepted injection (vulnerable)
"""
from __future__ import annotations

import pytest

from cosai_mcp.harness.mock_server import MockMCPServer
from tests.probes.conftest import error_response, ok_response, run_probe


class TestT03CatalogLoads:

    def test_t03_001_loads(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T03-001.json"))
        assert t.id == "T03-001"
        assert t.category == "T3"
        assert len(t.probes) == 3

    def test_t03_002_loads(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T03-002.json"))
        assert t.id == "T03-002"
        assert len(t.probes) == 2
        # All probes check that body doesn't contain sensitive strings
        for probe in t.probes:
            assert all(a.operator.value == "not_contains" for a in probe.assertions)


class TestT03CommandInjection:
    """T03-001: Server must not execute injected shell commands."""

    @pytest.mark.asyncio
    async def test_secure_server_returns_error_not_shell_output(self, catalog):
        """Secure server: returns error → no shell output → probe passes."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T03-001.json"))
        probe = threat.probes[0]  # "; cat /etc/passwd" probe

        with MockMCPServer(tools_call_response=error_response(-32602, "Invalid argument")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_vulnerable_server_leaks_passwd(self, catalog):
        """Vulnerable server: echoes injected command output → probe fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T03-001.json"))
        probe = threat.probes[0]

        # Simulates a server that runs the command and returns output
        with MockMCPServer(tools_call_response=ok_response("root:x:0:0:root:/root:/bin/bash")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False  # response body contains "root:"

    @pytest.mark.asyncio
    async def test_vulnerable_server_leaks_id_output(self, catalog):
        """Vulnerable server: leaks uid= output from $(id) injection → probe fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T03-001.json"))
        probe = threat.probes[1]  # $(id) probe

        with MockMCPServer(tools_call_response=ok_response("uid=1000(user) gid=1000(user)")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False  # body contains "uid="

    @pytest.mark.asyncio
    async def test_secure_server_sanitizes_id_injection(self, catalog):
        """Secure server: returns generic response without shell output → probe passes."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T03-001.json"))
        probe = threat.probes[1]

        with MockMCPServer(tools_call_response=ok_response("processed")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_all_t03_001_probes_pass_on_secure_server(self, catalog):
        """All 3 T03-001 probes pass when server never leaks sensitive content."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T03-001.json"))

        results = []
        for probe in threat.probes:
            with MockMCPServer(tools_call_response=error_response(-32602, "Rejected")) as server:
                server.wait_ready()
                r = await run_probe(probe, threat, server)
                results.append(r)

        assert all(r.passed for r in results)


class TestT03PathTraversal:
    """T03-002: Server must not expose files outside its sandbox via path traversal."""

    @pytest.mark.asyncio
    async def test_secure_server_blocks_path_traversal(self, catalog):
        """Secure server: rejects traversal payload → probe passes."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T03-002.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32602, "Path not allowed")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_vulnerable_server_leaks_passwd_via_traversal(self, catalog):
        """Vulnerable server: reads and returns /etc/passwd → probe fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T03-002.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response("root:x:0:0:/root:/bin/bash")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_url_encoded_traversal_probe(self, catalog):
        """URL-encoded traversal probe: secure server returns error → passes."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T03-002.json"))
        probe = threat.probes[1]  # %2e%2e%2f encoded probe

        with MockMCPServer(tools_call_response=error_response(-32602)) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_url_encoded_traversal_vulnerable(self, catalog):
        """URL-encoded traversal bypasses naive string check → body leak fails probe."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T03-002.json"))
        probe = threat.probes[1]

        with MockMCPServer(tools_call_response=ok_response("root:x:0:0:/root:/bin/bash")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False
