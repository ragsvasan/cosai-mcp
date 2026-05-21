"""T07-002 / T07-003: CIBA vs MCP confirmation — OAuth scope enforcement probes.

T07-002 tests that a server does NOT treat `confirmation=true` in tool arguments
as a substitute for a valid OAuth scope.  A vulnerable server accepts the call;
a secure server rejects it with an authorization error.

T07-003 tests that a server DOES honor a valid OAuth scope even when no
`confirmation` flag is present.  A vulnerable server rejects valid-scope calls
because confirmation is absent (inverted authorization model); a secure server
accepts them.

Both probes are derived from IETF draft-klrc-aiagent-auth-01:
  "The agent MUST NOT treat local UI confirmation alone as sufficient
   authorization."
"""
from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio

from tests.probes.conftest import error_response, ok_response, run_probe
from cosai_mcp.catalog.models import Severity
from cosai_mcp.harness.mock_server import MockMCPServer


# ---------------------------------------------------------------------------
# T07-002 catalog loading
# ---------------------------------------------------------------------------

class TestT07002CatalogLoads:
    def test_loads(self, catalog) -> None:
        t = catalog.load_file(Path("official/T07-002.json"))
        assert t.id == "T07-002"
        assert t.category == "T7"
        assert t.severity == Severity.CRITICAL
        assert len(t.probes) == 2

    def test_probe_ids(self, catalog) -> None:
        t = catalog.load_file(Path("official/T07-002.json"))
        ids = [p.id for p in t.probes]
        assert "T07-002-p1" in ids
        assert "T07-002-p2" in ids

    def test_p1_has_probe_headers(self, catalog) -> None:
        t = catalog.load_file(Path("official/T07-002.json"))
        p1 = t.probes[0]
        assert p1.probe_headers is not None
        assert "Authorization" in p1.probe_headers

    def test_p1_assertion_expects_error(self, catalog) -> None:
        t = catalog.load_file(Path("official/T07-002.json"))
        p1 = t.probes[0]
        assert any(
            a.target == "response.error" and a.value is True
            for a in p1.assertions
        )


# ---------------------------------------------------------------------------
# T07-002 probe behaviour
# ---------------------------------------------------------------------------

class TestT07002ConfirmationBypass:
    """Secure server: rejects wrong-scope + confirmation=true (probe passes).
    Vulnerable server: accepts wrong-scope + confirmation=true (probe fails)."""

    @pytest.mark.asyncio
    async def test_secure_server_rejects_confirmation_without_scope(
        self, catalog
    ) -> None:
        """Wrong-scope token + confirmation=true → secure server returns error → PASS."""
        threat = catalog.load_file(Path("official/T07-002.json"))
        probe = threat.probes[0]  # p1: wrong-scope + confirmation=true

        with MockMCPServer(
            scope_guarded_tools={"echo": "tools:write"},
            confirmation_bypasses_scope=False,  # secure
        ) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True
        assert result.error is None
        # Behavioral: assertion evaluated response.error=True from the wire (not a default)
        assert result.assertions[0].actual == "True"
        # Behavioral: server returned the scope-rejection error code
        assert "-32001" in result.response_body

    @pytest.mark.asyncio
    async def test_vulnerable_server_allows_confirmation_bypass(
        self, catalog
    ) -> None:
        """Vulnerable: server accepts because confirmation=true bypasses scope → FAIL."""
        threat = catalog.load_file(Path("official/T07-002.json"))
        probe = threat.probes[0]  # p1: wrong-scope + confirmation=true

        with MockMCPServer(
            scope_guarded_tools={"echo": "tools:write"},
            confirmation_bypasses_scope=True,  # vulnerable: bypass scope on confirmation
        ) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_unauthenticated_with_confirmation_rejected(
        self, catalog
    ) -> None:
        """No Authorization header + confirmation=true → secure server rejects → PASS."""
        threat = catalog.load_file(Path("official/T07-002.json"))
        probe = threat.probes[1]  # p2: no auth + confirmation=true

        with MockMCPServer(
            scope_guarded_tools={"echo": "tools:write"},
            confirmation_bypasses_scope=False,
        ) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True
        # Behavioral: assertion evaluated response.error=True from the wire (not a default)
        assert result.assertions[0].actual == "True"
        # Behavioral: server returned the scope-rejection error code
        assert "-32001" in result.response_body

    @pytest.mark.asyncio
    async def test_valid_scope_without_confirmation_accepted(
        self, catalog
    ) -> None:
        """Sanity: valid-scope token without confirmation is accepted (not T07-002 territory)."""
        threat = catalog.load_file(Path("official/T07-002.json"))
        probe = threat.probes[0]

        # Override probe_headers with valid-scope token to verify mock wiring
        from cosai_mcp.catalog.models import Probe
        import types as _types

        valid_token = (
            "eyJhbGciOiJub25lIn0"
            ".eyJzdWIiOiJ0ZXN0LWFnZW50Iiwic2NvcGUiOiJ0b29sczp3cml0ZSIsImV4cCI6OTk5OTk5OTk5OX0"
            "."
        )
        valid_probe = Probe(
            id=probe.id,
            transport=probe.transport,
            method=probe.method,
            payload=probe.payload,
            assertions=probe.assertions,
            probe_headers=_types.MappingProxyType({"Authorization": f"Bearer {valid_token}"}),
        )

        with MockMCPServer(
            scope_guarded_tools={"echo": "tools:write"},
            confirmation_bypasses_scope=False,
        ) as server:
            server.wait_ready()
            result = await run_probe(valid_probe, threat, server)

        # Valid scope → server accepts → response.error == false → assertion (expects true) fails
        # This confirms the mock correctly allows valid-scope tokens through
        assert result.passed is False  # assertion expects error=True but got False


# ---------------------------------------------------------------------------
# T07-003 catalog loading
# ---------------------------------------------------------------------------

class TestRunProbeHeaderMerge:
    """Regression: run_probe merges base_headers + probe_headers (FIX [3])."""

    @pytest.mark.asyncio
    async def test_probe_headers_merge_over_base_headers(self, catalog) -> None:
        """probe_headers win over base_headers; both reach the mock server."""
        threat = catalog.load_file(Path("official/T07-002.json"))
        probe = threat.probes[0]  # has probe_headers: Authorization (wrong scope)

        with MockMCPServer(
            scope_guarded_tools={"echo": "tools:write"},
            confirmation_bypasses_scope=False,
        ) as server:
            server.wait_ready()
            # Pass a base header alongside the probe; the probe's Authorization wins.
            result = await run_probe(
                probe, threat, server, base_headers={"X-Base": "present"}
            )

        # Scope rejection confirms probe's Authorization header reached the server
        assert result.passed is True
        assert "-32001" in result.response_body
        # X-Base header also reached the mock (visible in last_request_headers)
        assert server._last_request_headers.get("X-Base") == "present"


class TestT07003CatalogLoads:
    def test_loads(self, catalog) -> None:
        t = catalog.load_file(Path("official/T07-003.json"))
        assert t.id == "T07-003"
        assert t.category == "T7"
        assert t.severity == Severity.HIGH
        assert len(t.probes) == 1

    def test_p1_has_probe_headers(self, catalog) -> None:
        t = catalog.load_file(Path("official/T07-003.json"))
        p1 = t.probes[0]
        assert p1.probe_headers is not None
        assert "Authorization" in p1.probe_headers

    def test_p1_assertion_expects_no_error(self, catalog) -> None:
        t = catalog.load_file(Path("official/T07-003.json"))
        p1 = t.probes[0]
        assert any(
            a.target == "response.error" and a.value is False
            for a in p1.assertions
        )


# ---------------------------------------------------------------------------
# T07-003 probe behaviour
# ---------------------------------------------------------------------------

class TestT07003ScopeHonoredWithoutConfirmation:
    """Secure server: accepts valid-scope call with no confirmation (probe passes).
    Vulnerable server: rejects because confirmation is absent (probe fails)."""

    @pytest.mark.asyncio
    async def test_secure_server_accepts_valid_scope_without_confirmation(
        self, catalog
    ) -> None:
        """Valid-scope token + no confirmation → secure server accepts → PASS."""
        threat = catalog.load_file(Path("official/T07-003.json"))
        probe = threat.probes[0]

        with MockMCPServer(
            scope_guarded_tools={"echo": "tools:write"},
            confirmation_gates_access=False,  # secure: scope alone is sufficient
        ) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True
        assert result.error is None

    @pytest.mark.asyncio
    async def test_vulnerable_server_requires_confirmation_as_gate(
        self, catalog
    ) -> None:
        """Vulnerable: server rejects valid-scope call because confirmation=true absent → FAIL."""
        threat = catalog.load_file(Path("official/T07-003.json"))
        probe = threat.probes[0]

        with MockMCPServer(
            scope_guarded_tools={"echo": "tools:write"},
            confirmation_gates_access=True,  # vulnerable: confirmation is the auth gate
        ) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_wrong_scope_still_rejected_without_confirmation(
        self, catalog
    ) -> None:
        """Wrong-scope token without confirmation → secure server still rejects (scope check fires)."""
        threat = catalog.load_file(Path("official/T07-003.json"))
        probe = threat.probes[0]

        # Override probe_headers with wrong-scope token
        from cosai_mcp.catalog.models import Probe
        import types as _types

        wrong_token = (
            "eyJhbGciOiJub25lIn0"
            ".eyJzdWIiOiJ0ZXN0LWFnZW50Iiwic2NvcGUiOiJyZWFkOm90aGVyIiwiZXhwIjo5OTk5OTk5OTk5fQ"
            "."
        )
        wrong_probe = Probe(
            id=probe.id,
            transport=probe.transport,
            method=probe.method,
            payload=probe.payload,
            assertions=probe.assertions,
            probe_headers=_types.MappingProxyType({"Authorization": f"Bearer {wrong_token}"}),
        )

        with MockMCPServer(
            scope_guarded_tools={"echo": "tools:write"},
            confirmation_gates_access=False,
        ) as server:
            server.wait_ready()
            result = await run_probe(wrong_probe, threat, server)

        # Assertion expects error=False (success), but wrong scope → server rejects → assertion fails
        assert result.passed is False
