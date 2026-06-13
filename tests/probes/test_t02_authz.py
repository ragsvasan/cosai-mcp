"""Black-box probes for T2 — Missing Access Control / Confused Deputy.

Probe semantics:
  result.passed = True  → server rejected cross-session / privilege-escalation attempt
  result.passed = False → server allowed unauthorised access (vulnerability)
"""
from __future__ import annotations

import pytest

from cosai_mcp.harness.mock_server import MockMCPServer
from tests.probes.conftest import error_response, ok_response, run_probe


class TestT02CatalogLoads:

    def test_t02_001_loads(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T02-001.json"))
        assert t.id == "T02-001"
        assert t.category == "T2"
        assert len(t.probes) == 2
        for probe in t.probes:
            assert any(a.target == "response.error" for a in probe.assertions)


class TestT02ConfusedDeputy:
    """T02-001: Tool call with another user's session_id must be rejected."""

    @pytest.mark.asyncio
    async def test_secure_server_rejects_cross_session_access(self, catalog):
        """Secure server: rejects tool call with foreign session_id → probe passes."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T02-001.json"))
        probe = threat.probes[0]  # session_id injection probe

        with MockMCPServer(tools_call_response=error_response(-32001, "Session mismatch")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_vulnerable_server_processes_foreign_session(self, catalog):
        """Vulnerable server: processes request with foreign session_id → probe fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T02-001.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response("victim data returned")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_secure_server_rejects_privilege_escalation(self, catalog):
        """Secure server: rejects role=admin argument → probe passes."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T02-001.json"))
        probe = threat.probes[1]  # privilege_level=99 probe

        with MockMCPServer(tools_call_response=error_response(-32001, "Privilege escalation denied")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_vulnerable_server_grants_admin_via_argument(self, catalog):
        """Vulnerable server: honours role=admin in argument → privilege escalation → fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T02-001.json"))
        probe = threat.probes[1]

        with MockMCPServer(tools_call_response=ok_response("Admin access granted")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_all_t02_probes_pass_on_secure_server(self, catalog):
        """All T02-001 probes pass on a properly access-controlled server."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T02-001.json"))

        results = []
        for probe in threat.probes:
            with MockMCPServer(tools_call_response=error_response(-32001, "Denied")) as server:
                server.wait_ready()
                r = await run_probe(probe, threat, server)
                results.append(r)

        assert all(r.passed for r in results)


class TestT02MethodNotFoundIsInconclusive:
    """Audit COV-06 / §2: T02 access-control probes assert only
    response.error==true.  A -32601 (the assumed privileged tool does not exist)
    must NOT be reported as 'access control enforced' — the honest verdict is
    INCONCLUSIVE.  Mirrors the live mnemo behaviour (admin_delete absent)."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("threat_file", ["official/T02-001.json", "official/T02-003.json"])
    async def test_method_not_found_is_inconclusive_not_pass(self, catalog, threat_file):
        from pathlib import Path
        threat = catalog.load_file(Path(threat_file))
        probe = threat.probes[0]
        with MockMCPServer(tools_call_response=error_response(-32601, "Method not found")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)
        assert result.passed is False
        assert result.inconclusive_reason is not None

    @pytest.mark.asyncio
    async def test_t07_002_method_not_found_is_inconclusive(self, catalog):
        from pathlib import Path
        threat = catalog.load_file(Path("official/T07-002.json"))
        probe = threat.probes[0]
        with MockMCPServer(tools_call_response=error_response(-32601, "Method not found")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)
        assert result.passed is False
        assert result.inconclusive_reason is not None


class TestT02CatalogLoadsT02003:

    def test_t02_003_loads(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T02-003.json"))
        assert t.id == "T02-003"
        assert t.category == "T2"
        assert t.severity.value == "critical"
        assert len(t.probes) == 2
        for probe in t.probes:
            assert any(a.target == "response.error" for a in probe.assertions)
            assert any(a.value is True for a in probe.assertions)

    def test_t02_003_p1_payload_has_destructive_args(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T02-003.json"))
        args = t.probes[0].payload.get("arguments", {})
        assert args.get("action") == "delete"
        assert args.get("force") is True

    def test_t02_003_p1_payload_has_no_confirm_boolean(self, catalog):
        """Probe must NOT include confirm:true — avoids satisfying boolean-gate servers."""
        from pathlib import Path
        t = catalog.load_file(Path("official/T02-003.json"))
        args = t.probes[0].payload.get("arguments", {})
        assert "confirm" not in args

    def test_t02_003_p2_payload_has_destroy_no_dry_run(self, catalog):
        from pathlib import Path
        t = catalog.load_file(Path("official/T02-003.json"))
        args = t.probes[1].payload.get("arguments", {})
        assert args.get("operation") == "destroy"
        assert args.get("dry_run") is False


class TestT02DestructiveOneShotTool:
    """T02-003: destructive one-shot tool execution."""

    @pytest.mark.asyncio
    async def test_secure_server_rejects_delete_action(self, catalog):
        """Server that requires confirmation token rejects one-shot delete → probe passes."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T02-003.json"))
        probe = threat.probes[0]  # action:delete, force:true

        with MockMCPServer(tools_call_response=error_response(-32001, "Confirmation token required")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_vulnerable_server_executes_delete_without_token(self, catalog):
        """Server that executes delete without confirmation → vulnerability → probe fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T02-003.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response("Deleted")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_secure_server_rejects_destroy_no_dry_run(self, catalog):
        """Server that rejects destroy without confirmation token → probe passes."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T02-003.json"))
        probe = threat.probes[1]  # operation:destroy, dry_run:false

        with MockMCPServer(tools_call_response=error_response(-32001, "Confirmation token required for destructive operations")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_vulnerable_server_executes_destroy_without_token(self, catalog):
        """Server that executes destroy without confirmation token → probe fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T02-003.json"))
        probe = threat.probes[1]

        with MockMCPServer(tools_call_response=ok_response("cosai-test-resource destroyed")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_server_accepting_boolean_confirm_is_marked_vulnerable(self, catalog):
        """Server that executes on confirm:true boolean (no token) → one-shot gate → probe fails."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T02-003.json"))
        probe = threat.probes[0]
        # Server that honours any destructive call — simulates a boolean-confirm-only gate
        with MockMCPServer(tools_call_response=ok_response("Deleted (boolean confirm accepted)")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)
        assert result.passed is False, "Boolean confirm gate is not two-stage commit — must be flagged"

    @pytest.mark.asyncio
    async def test_all_t02_003_probes_pass_on_two_stage_server(self, catalog):
        """All T02-003 probes pass when server enforces confirmation token gate."""
        from pathlib import Path
        threat = catalog.load_file(Path("official/T02-003.json"))

        results = []
        for probe in threat.probes:
            with MockMCPServer(tools_call_response=error_response(-32001, "Confirmation token required")) as server:
                server.wait_ready()
                r = await run_probe(probe, threat, server)
                results.append(r)

        assert all(r.passed for r in results)
