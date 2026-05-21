"""Probe test fixtures — shared helpers for black-box probe tests."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

from cosai_mcp.catalog.loader import CatalogLoader
from cosai_mcp.catalog.models import Probe, ThreatDefinition
from cosai_mcp.config import ScanConfig
from cosai_mcp.harness.context import ProbeContext
from cosai_mcp.harness.mock_server import MockMCPServer
from cosai_mcp.harness.result import ProbeResult
from cosai_mcp.session import MCPSession
from cosai_mcp.transport.streamable_http import StreamableHTTPTransport


CATALOG_ROOT = Path(__file__).parent.parent.parent / "catalog"


@pytest.fixture
def probe_target() -> str:
    url = os.environ.get("MCP_TARGET_URL")
    if not url:
        pytest.skip("MCP_TARGET_URL not set — skipping probe integration test")
    return url


@pytest.fixture
def catalog() -> CatalogLoader:
    return CatalogLoader(CATALOG_ROOT)


async def run_probe(
    probe: Probe,
    threat: ThreatDefinition,
    mock_server: MockMCPServer,
    variables: dict[str, str] | None = None,
    base_headers: dict[str, str] | None = None,
) -> ProbeResult:
    """Execute a probe against a running MockMCPServer and return the result."""
    target_url = f"http://127.0.0.1:{mock_server.port}"
    # Mirror runner.py:245 — merge probe_headers over base_headers so that
    # catalog-level headers (e.g. Authorization, Origin) reach the mock and
    # probe headers always win over any caller-supplied base headers.
    merged: dict[str, str] = dict(base_headers or {})
    if probe.probe_headers:
        merged.update(probe.probe_headers)
    config = ScanConfig(
        target_host="127.0.0.1",
        target_port=mock_server.port,
        allow_private_targets=True,
        probe_timeout_seconds=10.0,
        extra_request_headers=merged or None,
    )
    transport = StreamableHTTPTransport(target_url, config)
    await transport.connect()
    try:
        session = MCPSession(transport, config)
        await session.start()
        ctx = ProbeContext(session, config, target_url)
        return await ctx.execute_probe(probe, threat, variables or {"tool_name": "echo"})
    finally:
        await transport.close()


def error_response(code: int = -32001, message: str = "Unauthorized") -> dict[str, Any]:
    """Build a JSON-RPC error tools/call response for mock server configuration."""
    return {"jsonrpc": "2.0", "id": 0, "error": {"code": code, "message": message}}


def ok_response(text: str = "ok") -> dict[str, Any]:
    """Build a JSON-RPC success tools/call response."""
    return {
        "jsonrpc": "2.0",
        "id": 0,
        "result": {"content": [{"type": "text", "text": text}], "isError": False},
    }
