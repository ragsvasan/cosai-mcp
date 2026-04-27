"""pytest plugin — --cosai-target, --cosai-severity, --cosai-categories. Phase 8."""
from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--cosai-target", action="store", default=None, help="MCP target URL")
    parser.addoption("--cosai-severity", action="store", default="critical",
                     choices=["critical", "high", "medium", "low"])
    parser.addoption("--cosai-categories", action="store", default="all")


@pytest.fixture
def cosai_target(request: pytest.FixtureRequest) -> str | None:
    return request.config.getoption("--cosai-target")  # type: ignore[no-any-return]
