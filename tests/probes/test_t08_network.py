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
    async def test_metadata_url_boundary_rejection_is_inconclusive(self, catalog):
        """Audit COV-08: a -32602 validation rejection of the IMDS URL is
        INCONCLUSIVE — it does not prove the tool even fetches URLs (a server
        with no URL-fetching tool returns the same error). Positive evidence the
        tool fetches URLs is added in Batch 7."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T08-001.json"))
        probe = threat.probes[0]  # 169.254.169.254 probe

        with MockMCPServer(tools_call_response=error_response(-32602, "URL not allowed")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False
        assert result.inconclusive_reason is not None

    @pytest.mark.asyncio
    async def test_vulnerable_server_fetches_metadata(self, catalog):
        """Vulnerable server: fetches IMDS and returns content → probe fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T08-001.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response("ami-id\ninstance-id\nhostname")) as server:  # noqa: E501
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        # response.error == False → assertion "eq True" fails → probe fails
        assert result.passed is False

    @pytest.mark.asyncio
    async def test_localhost_ssh_boundary_rejection_is_inconclusive(self, catalog):
        """Audit COV-08: a -32602 rejection of the localhost:22 SSRF payload is
        INCONCLUSIVE (no positive evidence the tool fetches URLs). The genuine
        vulnerable case (SSH banner leaked) is still detected below."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T08-001.json"))
        probe = threat.probes[1]  # localhost:22 / 10.0.0.1 probe

        with MockMCPServer(tools_call_response=error_response(-32602, "Private address blocked")) as server:  # noqa: E501
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False
        assert result.inconclusive_reason is not None

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
    async def test_all_ssrf_probes_inconclusive_on_boundary_rejection(self, catalog):
        """Audit COV-08: when every SSRF payload is rejected at the validation
        boundary (-32602), all probes are INCONCLUSIVE — the scanner cannot
        prove the tool fetches URLs at all, so it must not report a vacuous PASS."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T08-001.json"))

        results = []
        for probe in threat.probes:
            with MockMCPServer(tools_call_response=error_response(-32602, "Blocked")) as server:
                server.wait_ready()
                r = await run_probe(probe, threat, server)
                results.append(r)

        assert all(not r.passed and r.inconclusive_reason is not None for r in results)


class TestT08UnencryptedTransport:
    """T08-002: Informational — server accepts initialize over current transport."""

    @pytest.mark.asyncio
    async def test_server_responds_to_initialize(self, catalog):
        """T08-002-p1 checks initialize succeeds — finding is logged by reporter, not a pass/fail gate."""  # noqa: E501
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
