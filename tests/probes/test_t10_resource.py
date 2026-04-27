"""Black-box probes for T10 — Resource Management Failures.

T10-001: Oversized input — server must reject payloads that exceed size limits.
T10-002: Rate limiting — informational; checks basic liveness under normal load.
"""
from __future__ import annotations

import pytest

from cosai_mcp.harness.mock_server import MockMCPServer
from tests.probes.conftest import error_response, ok_response, run_probe


class TestT10CatalogLoads:

    def test_t10_001_loads(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T10-001.json"))
        assert t.id == "T10-001"
        assert t.category == "T10"
        assert len(t.probes) == 1
        # Probe expects error (server rejects oversized input)
        probe = t.probes[0]
        assert any(a.target == "response.error" for a in probe.assertions)

    def test_t10_002_loads(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T10-002.json"))
        assert t.id == "T10-002"
        assert len(t.probes) == 1


class TestT10OversizedInput:
    """T10-001: Server must reject tool arguments exceeding size limits."""

    @pytest.mark.asyncio
    async def test_secure_server_rejects_oversized_input(self, catalog):
        """Secure server: rejects 100KB argument with error → probe passes."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T10-001.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32600, "Request too large")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True
        assert result.error is None

    @pytest.mark.asyncio
    async def test_vulnerable_server_accepts_oversized_input(self, catalog):
        """Vulnerable server: processes 100KB input and returns success → probe fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T10-001.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response("processed")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_probe_payload_contains_large_input(self, catalog):
        """Verify the probe payload actually contains a large string (100K 'A' chars)."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T10-001.json"))
        probe = threat.probes[0]

        input_val = probe.payload.get("arguments", {}).get("input", "")
        assert len(input_val) == 100000
        assert all(c == "A" for c in input_val)

    @pytest.mark.asyncio
    async def test_413_response_also_passes(self, catalog):
        """HTTP 413 from transport layer still surfaces as JSON-RPC error → probe passes."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T10-001.json"))
        probe = threat.probes[0]

        # Any error response from the server satisfies the assertion
        with MockMCPServer(tools_call_response=error_response(-32700, "Parse error")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True


class TestT10RateLimiting:
    """T10-002: Basic liveness probe — server responds to tool call under normal load."""

    @pytest.mark.asyncio
    async def test_server_responds_to_normal_call(self, catalog):
        """T10-002: Normal call succeeds — server is alive (rate limit probe is informational)."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T10-002.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response("tick-1")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        # Probe asserts response.error == False (liveness check)
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_rate_limited_server_fails_probe(self, catalog):
        """If rate limiter returns error on first call, liveness probe fails (over-aggressive)."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T10-002.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32029, "Rate limit exceeded")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        # response.error == True but assertion expects False → fails
        assert result.passed is False

    @pytest.mark.asyncio
    async def test_duration_recorded(self, catalog):
        """Probe duration is recorded for rate-limit analysis."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T10-002.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response("ok")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.duration_seconds >= 0.0
