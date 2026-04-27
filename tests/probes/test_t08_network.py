"""Black-box probes for T8 — Network Binding Failures.

T08-001: SSRF — server must reject internal-address URLs in tool arguments.
T08-002: Unencrypted transport detection (informational — probe passes if server responds).
"""
from __future__ import annotations

import pytest

from cosai_mcp.harness.mock_server import MockMCPServer
from tests.probes.conftest import error_response, ok_response, run_probe


class TestT08CatalogLoads:

    def test_t08_001_loads(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T08-001.json"))
        assert t.id == "T08-001"
        assert t.category == "T8"
        assert len(t.probes) == 2

    def test_t08_002_loads(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T08-002.json"))
        assert t.id == "T08-002"
        assert len(t.probes) == 1
        # T08-002 probe checks that initialize succeeds (transport info probe)
        probe = t.probes[0]
        assert probe.method == "initialize"


class TestT08SSRF:
    """T08-001: Tool arguments with internal URLs must be rejected."""

    @pytest.mark.asyncio
    async def test_secure_server_rejects_metadata_url(self, catalog):
        """Secure server: rejects IMDS URL in tool arg → error → probe passes."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T08-001.json"))
        probe = threat.probes[0]  # 169.254.169.254 probe

        with MockMCPServer(tools_call_response=error_response(-32602, "URL not allowed")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_vulnerable_server_fetches_metadata(self, catalog):
        """Vulnerable server: fetches IMDS and returns content → probe fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T08-001.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response("ami-id\ninstance-id\nhostname")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        # response.error == False → assertion "eq True" fails → probe fails
        assert result.passed is False

    @pytest.mark.asyncio
    async def test_secure_server_rejects_localhost_ssh(self, catalog):
        """Secure server: rejects localhost:22 SSRF → probe passes (error + no SSH banner)."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T08-001.json"))
        probe = threat.probes[1]  # localhost:22 / 10.0.0.1 probe

        with MockMCPServer(tools_call_response=error_response(-32602, "Private address blocked")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_vulnerable_server_leaks_ssh_banner(self, catalog):
        """Vulnerable server: connects to localhost:22 and returns SSH banner → probe fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T08-001.json"))
        probe = threat.probes[1]

        # Body contains SSH banner — the not_contains assertion catches it
        with MockMCPServer(tools_call_response=ok_response("SSH-2.0-OpenSSH_8.9")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False  # body contains "SSH-"

    @pytest.mark.asyncio
    async def test_all_ssrf_probes_pass_on_secure_server(self, catalog):
        """All T08-001 probes pass on a server that rejects private-address URLs."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T08-001.json"))

        results = []
        for probe in threat.probes:
            with MockMCPServer(tools_call_response=error_response(-32602, "Blocked")) as server:
                server.wait_ready()
                r = await run_probe(probe, threat, server)
                results.append(r)

        assert all(r.passed for r in results)


class TestT08UnencryptedTransport:
    """T08-002: Informational — server accepts initialize over current transport."""

    @pytest.mark.asyncio
    async def test_server_responds_to_initialize(self, catalog):
        """T08-002-p1 checks initialize succeeds — finding is logged by reporter, not a pass/fail gate."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T08-002.json"))
        probe = threat.probes[0]

        # MockMCPServer always responds to initialize successfully
        with MockMCPServer() as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server, variables={})

        # response.error == False (initialize succeeded) → assertion passes
        assert result.passed is True
        assert result.error is None

    @pytest.mark.asyncio
    async def test_probe_method_is_initialize(self, catalog):
        """T08-002 probe targets initialize — verifies catalog is correct."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T08-002.json"))
        assert threat.probes[0].method == "initialize"
