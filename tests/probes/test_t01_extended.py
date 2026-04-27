"""Tests for T01-003 (token replay) and T01-004 (malformed auth) probes."""
from __future__ import annotations

from pathlib import Path

import pytest

from cosai_mcp.harness.mock_server import MockMCPServer
from tests.probes.conftest import error_response, ok_response, run_probe


# ===========================================================================
# T01-003 catalog and probe tests
# ===========================================================================

class TestT01003CatalogLoads:

    def test_t01_003_catalog_loads(self, catalog):
        t = catalog.load_file(Path("official/T01-003.json"))
        assert t.id == "T01-003"
        assert t.category == "T1"
        assert len(t.probes) == 2

    def test_t01_003_probes_assert_error(self, catalog):
        t = catalog.load_file(Path("official/T01-003.json"))
        for probe in t.probes:
            assert any(
                a.target == "response.error" for a in probe.assertions
            )

    def test_regression_t01_003_probes_are_distinct(self, catalog):
        """T01-003 probes must differ in method or assertion value.

        FIX 6: The original two probes were identical (same method, payload, and
        assertion) — the second probe provided zero additional coverage and would
        never catch a vulnerability the first probe missed.
        """
        t = catalog.load_file(Path("official/T01-003.json"))
        p1, p2 = t.probes
        assert (p1.method, p1.assertions) != (p2.method, p2.assertions), (
            "T01-003 probes must not be identical"
        )


class TestT01003Probes:

    @pytest.mark.asyncio
    async def test_t01_003_server_rejects_replay(self, catalog):
        """Secure server rejects replayed token → response.error=true → probe passes."""
        t = catalog.load_file(Path("official/T01-003.json"))
        probe = t.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32001, "Token replayed")) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_t01_003_server_accepts_replay(self, catalog):
        """Vulnerable server accepts replayed token → response.error=false → probe fails."""
        t = catalog.load_file(Path("official/T01-003.json"))
        probe = t.probes[0]

        with MockMCPServer(tools_call_response=ok_response("data")) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is False


# ===========================================================================
# T01-004 catalog and probe tests
# ===========================================================================

class TestT01004CatalogLoads:

    def test_t01_004_catalog_loads(self, catalog):
        t = catalog.load_file(Path("official/T01-004.json"))
        assert t.id == "T01-004"
        assert t.category == "T1"
        assert len(t.probes) == 2

    def test_t01_004_probes_assert_error(self, catalog):
        t = catalog.load_file(Path("official/T01-004.json"))
        for probe in t.probes:
            assert any(
                a.target == "response.error" for a in probe.assertions
            )

    def test_regression_t01_004_probes_are_distinct(self, catalog):
        """T01-004 probes must differ in method or assertion value — see FIX 6."""
        t = catalog.load_file(Path("official/T01-004.json"))
        p1, p2 = t.probes
        assert (p1.method, p1.assertions) != (p2.method, p2.assertions), (
            "T01-004 probes must not be identical"
        )


class TestT01004Probes:

    @pytest.mark.asyncio
    async def test_t01_004_malformed_auth_rejected(self, catalog):
        """Secure server rejects malformed auth → response.error=true → probe passes."""
        t = catalog.load_file(Path("official/T01-004.json"))
        probe = t.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32001, "Bad auth format")) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_t01_004_malformed_auth_accepted_fails(self, catalog):
        """Vulnerable server accepts malformed auth → probe fails."""
        t = catalog.load_file(Path("official/T01-004.json"))
        probe = t.probes[0]

        with MockMCPServer(tools_call_response=ok_response("data")) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is False
