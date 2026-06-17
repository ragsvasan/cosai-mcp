"""Black-box probes for T10 — Resource Management Failures.

T10-001: Oversized input — server must reject payloads that exceed size limits.
T10-002: Rate limiting — informational; checks basic liveness under normal load.
T10-005: Per-session call budget — a burst of in-session calls must trip a
         JSON-RPC -32029 budget error (complements T10-004's HTTP 429/503 check).
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

    def test_t10_005_loads(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T10-005.json"))
        assert t.id == "T10-005"
        assert t.category == "T10"
        assert len(t.probes) == 1
        probe = t.probes[0]
        # Burst probe: repeats N times in one session for call-budget detection.
        assert probe.probe_count > 1
        assert probe.method == "tools/call"
        # Asserts the specific JSON-RPC budget error code (not just HTTP status).
        # `eq` is used deliberately over `error_code_in` so a content-layer
        # isError (no error.code) cannot wildcard-satisfy the budget check.
        assert any(
            a.target == "response.error_code"
            and a.operator.value == "eq"
            and a.value == -32029
            for a in probe.assertions
        )


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


class TestT10CallBudget:
    """T10-005: per-session call budget at the JSON-RPC layer.

    A single probe execution asserts ``response.error_code error_code_in
    [-32029]``. In production the probe runs ``probe_count`` times in one
    session (verified separately via the loaded probe_count value); the
    assertion logic itself is verified here per response.
    """

    @pytest.mark.asyncio
    async def test_secure_server_returns_budget_error_passes(self, catalog):
        """Server that returns -32029 (budget exceeded) → probe passes."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T10-005.json"))
        probe = threat.probes[0]

        with MockMCPServer(
            tools_call_response=error_response(-32029, "Per-session call budget exceeded")
        ) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True
        assert result.error is None

    @pytest.mark.asyncio
    async def test_vulnerable_server_no_budget_fails(self, catalog):
        """Server that answers normally (no budget) → no -32029 → probe fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T10-005.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response("processed")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_wrong_error_code_does_not_pass(self, catalog):
        """A non-budget error (e.g. -32000) must NOT satisfy the -32029
        assertion — the probe is specific to the rate-limit code."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T10-005.json"))
        probe = threat.probes[0]

        with MockMCPServer(
            tools_call_response=error_response(-32000, "Internal error")
        ) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_content_layer_iserror_does_not_clear_budget(self, catalog):
        """Security regression: an evasive/broken server that returns an MCP
        content-layer error (result.isError:true, no JSON-RPC error.code) on a
        normal call must NOT satisfy the -32029 budget assertion. Otherwise a
        budget-free server that errors on every call would be falsely cleared as
        having an enforced call budget (false-clean denial-of-wallet). The `eq`
        operator (unlike error_code_in) has no content-layer wildcard, so this
        correctly fails the probe."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T10-005.json"))
        probe = threat.probes[0]

        iserror_response = {
            "jsonrpc": "2.0",
            "id": 0,
            "result": {
                "content": [{"type": "text", "text": "tool errored"}],
                "isError": True,
            },
        }
        with MockMCPServer(tools_call_response=iserror_response) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        # Must be flagged (not passed) — a content-layer error is not proof of
        # a per-session call budget.
        assert result.passed is False

    @pytest.mark.asyncio
    async def test_real_budget_server_trips_within_burst(self, catalog):
        """End-to-end against a server with an actual per-session call_budget:
        running the probe past the budget yields a -32029 response that satisfies
        the assertion. Models the burst behaviour the probe_count loop drives in
        production."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T10-005.json"))
        probe = threat.probes[0]

        # Budget of 0 → the first tools/call is already over budget → -32029.
        with MockMCPServer(call_budget=0) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True
