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


# ---------------------------------------------------------------------------
# Auto-collected scan gate
# ---------------------------------------------------------------------------
#
# Without this, ``pytest --cosai-target=URL`` in a project that has no test
# file consuming ``cosai_scan_result`` collects ZERO tests and exits 0 — a
# silent false-green security gate.  We synthesize one real collected item so
# the scan always runs and fails the session on a finding at/above the
# ``--cosai-severity`` threshold.
#
# The synthetic item is appended in ``pytest_collection_modifyitems`` (after
# normal collection), so it never interferes with a user's own tests and is
# only present when ``--cosai-target`` is supplied.

_SCAN_ITEM_NAME = "cosai_scan_gate"


class CoSAIScanItem(pytest.Item):
    """A real collected pytest item that runs the cosai scan as the test body."""

    def runtest(self) -> None:
        config = self.config
        target: str | None = config.getoption("--cosai-target")
        # Guard: only reachable when target is set (collection only adds us then).
        assert target is not None  # noqa: S101 - invariant, not a user assertion

        categories_raw: str = config.getoption("--cosai-categories")
        categories = (
            None
            if not categories_raw or categories_raw.strip().lower() == "all"
            else [c.strip() for c in categories_raw.split(",") if c.strip()]
        )
        engine: str = config.getoption("--cosai-engine")
        severity: str = config.getoption("--cosai-severity")

        from cosai_mcp.api import (
            CATALOG_ROOT,
            _parse_target,
            _run_scan,
            check_reachable,
        )
        from cosai_mcp.exceptions import TargetUnreachableError

        # Mirror the CLI: a fast TCP reachability probe BEFORE the full scan so
        # an unreachable target fails the session quickly (exit-code-3 path)
        # instead of hanging on per-probe connect timeouts.
        host, port, _ = _parse_target(target)
        try:
            check_reachable(host, port)
        except TargetUnreachableError as exc:
            raise AssertionError(
                f"cosai scan: target {target!r} unreachable (exit code 3) — {exc}"
            ) from exc

        result = _run_scan(
            target=target,
            categories=categories,
            engine=engine,
            allow_custom_catalog=False,
            probe_timeout_seconds=30.0,
            catalog_root=CATALOG_ROOT,
            fail_on=severity,
        )

        # exit_code: 0 clean, 1 finding >= fail_on, 2 scanner error/incomplete,
        # 3 unreachable. Any non-zero code must fail the session — never green.
        if result.exit_code == 0:
            return
        if result.exit_code == 3:
            raise AssertionError(
                f"cosai scan: target {target!r} unreachable (exit code 3)."
            )
        if result.exit_code == 2:
            raise AssertionError(
                "cosai scan incomplete — handshake/manifest failure or scanner "
                "error (exit code 2). Reported as failure, not clean."
            )
        # exit_code == 1: findings at/above the --cosai-severity threshold.
        findings = [
            r for r in result.probe_results
            if not r.passed and not r.suppressed and r.error is None
        ]
        scenario_findings = [
            r for r in result.scenario_results
            if not r.passed and r.status == "complete"
        ]
        n = len(findings) + len(scenario_findings)
        raise AssertionError(
            f"cosai scan found {n} finding(s) at or above severity "
            f"{severity!r} against {target!r} (exit code 1)."
        )

    def repr_failure(self, excinfo: object, **kwargs: object) -> str:  # type: ignore[override]
        # Keep the message terse; the AssertionError text carries the detail.
        return str(getattr(excinfo, "value", excinfo))

    def reportinfo(self) -> tuple[str, int, str]:
        return self.path, 0, f"cosai scan gate [{self.config.getoption('--cosai-target')}]"


def pytest_collection_modifyitems(
    session: pytest.Session,
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    """Append the synthetic scan-gate item when ``--cosai-target`` is set.

    Without ``--cosai-target`` we add nothing, so the plugin/fixtures cleanly
    skip and a bare ``pytest`` run is unaffected.
    """
    if config.getoption("--cosai-target") is None:
        return
    # Avoid double-adding if collection runs more than once.
    if any(getattr(it, "name", None) == _SCAN_ITEM_NAME for it in items):
        return
    item = CoSAIScanItem.from_parent(session, name=_SCAN_ITEM_NAME)
    items.append(item)
