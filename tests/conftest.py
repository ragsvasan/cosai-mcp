"""Global test fixtures. MCP_TARGET_URL for integration tests against real servers."""
from __future__ import annotations

import os

import pytest


@pytest.fixture
def mcp_target_url() -> str:
    """Target URL for integration tests. Set MCP_TARGET_URL env var to use a real server."""
    return os.environ.get("MCP_TARGET_URL", "http://localhost:8000")


@pytest.fixture
def mcp_target_url_required() -> str:
    """Like mcp_target_url but skips test if not configured."""
    url = os.environ.get("MCP_TARGET_URL")
    if not url:
        pytest.skip("MCP_TARGET_URL not set — skipping integration test")
    return url
