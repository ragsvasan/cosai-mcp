"""Tests for T05 catalog probes: context leakage and credential exfiltration."""
from __future__ import annotations

from pathlib import Path

import pytest

from cosai_mcp.harness.mock_server import MockMCPServer
from tests.probes.conftest import error_response, ok_response, run_probe


# ===========================================================================
# T05-001 catalog loads and probe tests
# ===========================================================================

class TestT05001CatalogLoads:

    def test_t05_001_catalog_loads(self, catalog):
        t = catalog.load_file(Path("official/T05-001.json"))
        assert t.id == "T05-001"
        assert t.category == "T5"
        assert len(t.probes) >= 1

    def test_t05_001_asserts_no_credential_leakage(self, catalog):
        t = catalog.load_file(Path("official/T05-001.json"))
        probe = t.probes[0]
        targets_and_ops = [(a.target, a.operator.value) for a in probe.assertions]
        # Must have at least one not_contains assertion on response body
        assert any(
            t == "response.body" and op == "not_contains"
            for t, op in targets_and_ops
        )


class TestT05001Probes:

    @pytest.mark.asyncio
    async def test_t05_001_secure_server_passes(self, catalog):
        """Server returns clean data → not_contains assertions pass → probe passes."""
        t = catalog.load_file(Path("official/T05-001.json"))
        probe = t.probes[0]

        clean_response = ok_response("The answer is 42. No credentials here.")
        with MockMCPServer(tools_call_response=clean_response) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_t05_001_vulnerable_server_fails(self, catalog):
        """Server leaks API key (sk-) in response body → not_contains assertion fails → probe fails."""
        t = catalog.load_file(Path("official/T05-001.json"))
        probe = t.probes[0]

        leaked_response = ok_response("Your API key is sk-supersecretkey123456789012345")
        with MockMCPServer(tools_call_response=leaked_response) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is False


# ===========================================================================
# T05-002 catalog loads and probe tests
# ===========================================================================

class TestT05002CatalogLoads:

    def test_t05_002_catalog_loads(self, catalog):
        t = catalog.load_file(Path("official/T05-002.json"))
        assert t.id == "T05-002"
        assert t.category == "T5"
        assert len(t.probes) >= 1


class TestT05002Probes:

    @pytest.mark.asyncio
    async def test_t05_002_credential_exfil_rejected(self, catalog):
        """Server returns Bearer token in body → not_contains assertion fails → probe fails."""
        t = catalog.load_file(Path("official/T05-002.json"))
        probe = t.probes[0]

        exfil_response = ok_response("Bearer sk-abcdefghijklmnopqrstuvwxyz12345")
        with MockMCPServer(tools_call_response=exfil_response) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_t05_002_clean_server_passes(self, catalog):
        """Server returns clean response → no bearer token → probe passes."""
        t = catalog.load_file(Path("official/T05-002.json"))
        probe = t.probes[0]

        with MockMCPServer(tools_call_response=ok_response("User data: name=Alice")) as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is True
