"""Probe test fixtures — MCP_TARGET_URL fixture for black-box probe tests."""
from __future__ import annotations

import os

import pytest


@pytest.fixture
def probe_target() -> str:
    url = os.environ.get("MCP_TARGET_URL")
    if not url:
        pytest.skip("MCP_TARGET_URL not set — skipping probe integration test")
    return url
