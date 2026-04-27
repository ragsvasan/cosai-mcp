"""pytest plugin — --cosai-target, --cosai-severity, --cosai-categories fixtures.

Registered as a pytest11 entry point in pyproject.toml so that
``pytest --cosai-target=http://localhost:8000`` works without any explicit
``conftest.py`` changes.
"""
from __future__ import annotations

from typing import Generator

import pytest


# ---------------------------------------------------------------------------
# CLI options
# ---------------------------------------------------------------------------

def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("cosai-mcp", "CoSAI MCP security scanner options")
    group.addoption(
        "--cosai-target",
        action="store",
        default=None,
        metavar="URL",
        help="Base URL of the MCP server to scan (e.g. http://localhost:8000).",
    )
    group.addoption(
        "--cosai-severity",
        action="store",
        default="critical",
        choices=["critical", "high", "medium", "low"],
        help="Minimum severity for a finding to fail a test (default: critical).",
    )
    group.addoption(
        "--cosai-categories",
        action="store",
        default="all",
        metavar="CATEGORIES",
        help="Comma-separated T-categories to run (e.g. T1,T3) or 'all'.",
    )
    group.addoption(
        "--cosai-engine",
        action="store",
        default="all",
        choices=["prober", "stateful", "all"],
        help="Scan engine to use (default: all).",
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def cosai_target(request: pytest.FixtureRequest) -> str | None:
    """URL of the MCP server under test, as supplied via --cosai-target."""
    return request.config.getoption("--cosai-target")  # type: ignore[no-any-return]


@pytest.fixture
def cosai_severity(request: pytest.FixtureRequest) -> str:
    """Minimum severity threshold, as supplied via --cosai-severity."""
    return request.config.getoption("--cosai-severity")  # type: ignore[no-any-return]


@pytest.fixture
def cosai_categories(request: pytest.FixtureRequest) -> list[str] | None:
    """Parsed category list from --cosai-categories, or None for all."""
    raw: str = request.config.getoption("--cosai-categories")
    if not raw or raw.strip().lower() == "all":
        return None
    return [c.strip() for c in raw.split(",") if c.strip()]


@pytest.fixture
def cosai_engine(request: pytest.FixtureRequest) -> str:
    """Engine selection from --cosai-engine."""
    return request.config.getoption("--cosai-engine")  # type: ignore[no-any-return]


@pytest.fixture
def cosai_scan_result(
    cosai_target: str | None,
    cosai_severity: str,
    cosai_categories: list[str] | None,
    cosai_engine: str,
) -> "ScanResult":  # type: ignore[name-defined]
    """Run a full cosai scan against ``cosai_target`` and return the result.

    Skips if ``--cosai-target`` was not provided.  The result is cached for
    the test session (``scope="session"`` is not used here to allow per-test
    override, but callers should use ``cosai_session_scan_result`` for
    session-scoped caching).

    This fixture is useful for asserting on ``ScanResult`` properties::

        def test_no_critical_findings(cosai_scan_result):
            assert not cosai_scan_result.has_findings
    """
    if cosai_target is None:
        pytest.skip("--cosai-target not provided")

    from cosai_mcp.api import CATALOG_ROOT, _run_scan

    return _run_scan(
        target=cosai_target,
        categories=cosai_categories,
        engine=cosai_engine,
        allow_custom_catalog=False,
        probe_timeout_seconds=30.0,
        catalog_root=CATALOG_ROOT,
        fail_on=cosai_severity,
    )


@pytest.fixture(scope="session")
def cosai_session_scan_result(
    request: pytest.FixtureRequest,
) -> Generator["ScanResult", None, None]:  # type: ignore[name-defined]
    """Session-scoped scan — runs once, shared across all tests in the session.

    Use when your test file has many assertions against the same scan:

        @pytest.fixture(scope="session", autouse=True)
        def _scan(cosai_session_scan_result):
            return cosai_session_scan_result
    """
    target: str | None = request.config.getoption("--cosai-target")
    if target is None:
        pytest.skip("--cosai-target not provided")

    categories_raw: str = request.config.getoption("--cosai-categories")
    categories = (
        None
        if not categories_raw or categories_raw.strip().lower() == "all"
        else [c.strip() for c in categories_raw.split(",") if c.strip()]
    )
    engine: str = request.config.getoption("--cosai-engine")
    severity: str = request.config.getoption("--cosai-severity")

    from cosai_mcp.api import CATALOG_ROOT, _run_scan

    yield _run_scan(
        target=target,
        categories=categories,
        engine=engine,
        allow_custom_catalog=False,
        probe_timeout_seconds=30.0,
        catalog_root=CATALOG_ROOT,
        fail_on=severity,
    )
