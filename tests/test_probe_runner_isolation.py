"""Integration tests for ProbeRunner — verifies multiprocessing subprocess path.

Every existing probe test in tests/probes/ uses conftest.run_probe, which
runs probes directly in the parent asyncio process and bypasses ProbeRunner.
These tests go through the ACTUAL ProbeRunner.run_probe() interface to exercise:
  - multiprocessing.Process spawn
  - IPC queue result handoff
  - OS-level timeout + process kill
  - process isolation (subprocess connects to real localhost port)
"""
from __future__ import annotations

import time
import threading
from pathlib import Path

import pytest

from cosai_mcp.catalog.loader import CatalogLoader
from cosai_mcp.config import ScanConfig
from cosai_mcp.harness.mock_server import MockMCPServer
from cosai_mcp.harness.runner import ProbeRunner


CATALOG_ROOT = Path(__file__).parent.parent / "catalog"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(port: int) -> ScanConfig:
    return ScanConfig(
        target_host="127.0.0.1",
        target_port=port,
        allow_private_targets=True,
        probe_timeout_seconds=30.0,
    )


def _load_t03_threat_and_probe():
    """Load T03-001 from the official catalog; return (threat, probe)."""
    loader = CatalogLoader(CATALOG_ROOT)
    threat = loader.load_file(Path("official/T03-001.json"))
    probe = threat.probes[0]
    return threat, probe


def _load_t01_threat_and_probe():
    """Load T01-001 from the official catalog; return (threat, probe)."""
    loader = CatalogLoader(CATALOG_ROOT)
    threat = loader.load_file(Path("official/T01-001.json"))
    probe = threat.probes[0]
    return threat, probe


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestProbeRunnerSubprocessSpawn:
    """ProbeRunner spawns a subprocess that connects to MockMCPServer."""

    def test_probe_runner_spawns_subprocess_and_returns_result(self):
        """
        Start a MockMCPServer configured to return a clean (secure) response,
        run a T03 probe through ProbeRunner, and confirm:
          - a ProbeResult is returned (not None, not an exception)
          - result.error is None (no subprocess crash)
          - probe_id and threat_id are populated correctly
        """
        threat, probe = _load_t03_threat_and_probe()

        # Secure server: returns an error for the injection payload → assertions hold → passed=True
        tools_call_resp = {
            "jsonrpc": "2.0",
            "id": 0,
            "error": {"code": -32602, "message": "Invalid arguments"},
        }

        with MockMCPServer(tools_call_response=tools_call_resp) as server:
            server.wait_ready()
            config = _make_config(server.port)
            target_url = f"http://127.0.0.1:{server.port}"
            runner = ProbeRunner(config, target_url)

            result = runner.run_probe(
                probe,
                threat,
                variables={"tool_name": "echo"},
            )

        assert result is not None
        assert result.error is None, f"unexpected error: {result.error!r}"
        assert result.probe_id == probe.id
        assert result.threat_id == threat.id


class TestProbeRunnerTimeout:
    """ProbeRunner kills the subprocess and returns a timeout result on hang."""

    def test_probe_runner_enforces_timeout(self):
        """
        Configure MockMCPServer to hang forever on tools/call (never respond).
        Call ProbeRunner.run_probe() with timeout_seconds=1.0.
        Assert:
          - result.error contains 'timed out'
          - the call returns within ~5 seconds (not hanging)
        """
        threat, probe = _load_t03_threat_and_probe()

        # A MockMCPServer subclass that blocks forever on tools/call.
        # We use a threading.Event to make the handler hang until the server stops.
        hang_event = threading.Event()

        class _HangingMCPServer(MockMCPServer):
            def handle_rpc(self, request, headers=None):
                method = request.get("method", "")
                if method == "tools/call":
                    # Block until the server is stopped (daemon thread exits when
                    # the process is killed; hang_event is never set in normal flow)
                    hang_event.wait(timeout=60)
                    return {
                        "jsonrpc": "2.0",
                        "id": request.get("id"),
                        "result": {"content": [], "isError": False},
                    }
                # For all other methods, delegate to default behavior
                return super().handle_rpc(request, headers)

        with _HangingMCPServer() as server:
            server.wait_ready()
            config = _make_config(server.port)
            target_url = f"http://127.0.0.1:{server.port}"
            runner = ProbeRunner(config, target_url)

            wall_start = time.monotonic()
            result = runner.run_probe(
                probe,
                threat,
                variables={"tool_name": "echo"},
                timeout_seconds=1.0,
            )
            wall_elapsed = time.monotonic() - wall_start

        # Unblock any hanging thread so the server can stop cleanly
        hang_event.set()

        assert result.error is not None, "expected a timeout error but got None"
        assert "timed out" in result.error.lower(), (
            f"expected 'timed out' in error message, got: {result.error!r}"
        )
        # Should return well within 5 s (timeout=1.0 + 2.0 s grace + margin)
        assert wall_elapsed < 6.0, (
            f"ProbeRunner took {wall_elapsed:.1f}s — possible hang"
        )


class TestProbeRunnerInconclusiveOnUnknownTool:
    """ProbeRunner returns inconclusive_reason when server reports tool-not-found."""

    def test_probe_runner_returns_inconclusive_for_unknown_tool(self):
        """
        Server returns a content-layer error with 'tool not found' message.
        ProbeRunner should detect this as inconclusive and set inconclusive_reason.

        inconclusive_reason is set when the server returns isError=True with a
        schema-mismatch keyword in the content body (see context._SCHEMA_MISMATCH_KEYWORDS).
        A JSON-RPC error does NOT trigger inconclusive — it must be a content-layer error.
        """
        threat, probe = _load_t03_threat_and_probe()

        # Content-layer error with 'tool not found' in the message — triggers
        # _detect_schema_mismatch() in context.py.
        tool_not_found_resp = {
            "jsonrpc": "2.0",
            "id": 0,
            "result": {
                "content": [{"type": "text", "text": "tool not found: nonexistent_tool_xyz"}],
                "isError": True,
            },
        }

        with MockMCPServer(tools_call_response=tool_not_found_resp) as server:
            server.wait_ready()
            config = _make_config(server.port)
            target_url = f"http://127.0.0.1:{server.port}"
            runner = ProbeRunner(config, target_url)

            result = runner.run_probe(
                probe,
                threat,
                variables={"tool_name": "nonexistent_tool_xyz"},
            )

        assert result.inconclusive_reason is not None, (
            "expected inconclusive_reason to be set for tool-not-found response"
        )
