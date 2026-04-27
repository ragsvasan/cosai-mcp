"""Tests for StatefulHarness — multi-turn MCP conformance engine (T2/T6/T7)."""
from __future__ import annotations

import types as _types

import pytest

from cosai_mcp.config import ScanConfig
from cosai_mcp.harness.mock_server import MockMCPServer
from cosai_mcp.stateful.harness import (
    AssertionFailure,
    Scenario,
    ScenarioStep,
    ScenarioResult,
    StatefulHarness,
    StepAction,
    StepAssertion,
    _evaluate_assertion,
    _resolve_path,
)
from cosai_mcp.stateful.scenarios import (
    t2_confused_deputy,
    t2_privilege_escalation_chain,
    t6_tool_shadowing_mid_session,
    t7_session_token_binding,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _harness() -> StatefulHarness:
    """Return a StatefulHarness configured to talk to localhost."""
    config = ScanConfig(
        target_host="127.0.0.1",
        target_port=0,
        allow_private_targets=True,
        probe_timeout_seconds=5.0,
    )
    return StatefulHarness(config)


def _target(server: MockMCPServer) -> str:
    return f"http://127.0.0.1:{server.port}"


_ADMIN_TOOLS = [
    {"name": "echo", "description": "Echoes input", "inputSchema": {"type": "object"}},
    {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}},
    {"name": "admin_delete", "description": "Admin delete", "inputSchema": {"type": "object"}},
]

_BASIC_TOOLS = [
    {"name": "echo", "description": "Echoes input", "inputSchema": {"type": "object"}},
    {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}},
]

_SHADOW_TOOLS = [
    {"name": "echo", "description": "Shadowed echo v2", "inputSchema": {"type": "object"}},
    {"name": "malicious_tool", "description": "Injected tool", "inputSchema": {"type": "object"}},
]


# ---------------------------------------------------------------------------
# Unit tests — assertion helpers
# ---------------------------------------------------------------------------

class TestResolvePathHelper:

    def test_top_level_key(self):
        assert _resolve_path({"result": {"tools": []}}, "result") == {"tools": []}

    def test_nested_key(self):
        assert _resolve_path({"result": {"tools": [1, 2]}}, "result.tools") == [1, 2]

    def test_missing_key_returns_none(self):
        assert _resolve_path({"result": {}}, "result.missing") is None

    def test_non_dict_mid_path_returns_none(self):
        assert _resolve_path({"a": 42}, "a.b") is None

    def test_error_code_path(self):
        resp = {"error": {"code": -32601, "message": "Method not found"}}
        assert _resolve_path(resp, "error.code") == -32601


class TestEvaluateAssertionHelper:

    def test_eq_passes(self):
        resp = {"result": {"tools": []}}
        assertion = StepAssertion(target="result.tools", operator="eq", expected=[])
        assert _evaluate_assertion(resp, assertion) is None

    def test_eq_fails(self):
        resp = {"result": {"tools": [1]}}
        assertion = StepAssertion(target="result.tools", operator="eq", expected=[])
        failure = _evaluate_assertion(resp, assertion)
        assert failure is not None
        assert failure.operator == "eq"
        assert failure.actual == [1]

    def test_is_not_none_passes(self):
        resp = {"result": {"tools": []}}
        assertion = StepAssertion(target="result", operator="is_not_none")
        assert _evaluate_assertion(resp, assertion) is None

    def test_is_none_on_missing_key_passes(self):
        resp = {"result": {}}
        assertion = StepAssertion(target="error", operator="is_none")
        assert _evaluate_assertion(resp, assertion) is None

    def test_ne_passes_when_different(self):
        resp = {"error": {"code": -32601}}
        assertion = StepAssertion(target="error.code", operator="ne", expected=-32000)
        assert _evaluate_assertion(resp, assertion) is None

    def test_contains_in_list(self):
        resp = {"result": {"names": ["echo", "read_file"]}}
        assertion = StepAssertion(target="result.names", operator="contains", expected="echo")
        assert _evaluate_assertion(resp, assertion) is None

    def test_len_eq_passes(self):
        resp = {"result": {"tools": [1, 2, 3]}}
        assertion = StepAssertion(target="result.tools", operator="len_eq", expected=3)
        assert _evaluate_assertion(resp, assertion) is None

    def test_len_gt_passes(self):
        resp = {"result": {"tools": [1, 2]}}
        assertion = StepAssertion(target="result.tools", operator="len_gt", expected=0)
        assert _evaluate_assertion(resp, assertion) is None

    def test_unknown_operator_fails(self):
        resp = {"result": 1}
        assertion = StepAssertion(target="result", operator="unknown_op")
        failure = _evaluate_assertion(resp, assertion)
        assert failure is not None

    def test_failure_message_populated(self):
        resp = {"error": None}
        assertion = StepAssertion(
            target="error", operator="is_not_none", message="error must be set"
        )
        failure = _evaluate_assertion(resp, assertion)
        assert failure is not None
        assert "error must be set" in failure.message

    def test_regression_not_contains_on_none_is_error(self):
        """not_contains on a missing/None path must fail, not silently pass.

        FIX 5: A security assertion 'response body must not contain <secret>'
        would silently pass if the target path is wrong or missing, producing
        a false-clean result.  Now returns AssertionFailure for non-iterable
        actual values.
        """
        resp = {"result": {}}
        # "error" key is absent → resolves to None → not str/list → failure
        assertion = StepAssertion(
            target="error", operator="not_contains", expected="root:admin"
        )
        failure = _evaluate_assertion(resp, assertion)
        assert failure is not None, (
            "not_contains on missing path must fail, not silently pass"
        )

    def test_regression_empty_assertion_target_is_error(self):
        """Empty assertion target must produce an AssertionFailure, not silently pass.

        FIX 6: An empty target resolves to None and is_not_none always fails,
        but the failure message gives no indication the target is malformed.
        Now returns an explicit failure with a message naming the root cause.
        """
        resp = {"result": "ok"}
        assertion = StepAssertion(target="", operator="is_not_none")
        failure = _evaluate_assertion(resp, assertion)
        assert failure is not None
        assert "empty" in failure.message


# ---------------------------------------------------------------------------
# T2: Privilege escalation chain
# ---------------------------------------------------------------------------

class TestT2PrivilegeEscalation:

    def test_privilege_escalation_blocked_scenario_passes(self):
        """Server that correctly rejects admin_delete → scenario passes (T2 secure)."""
        with MockMCPServer(
            tools=_ADMIN_TOOLS,
            privileged_tools={"admin_delete"},
        ) as server:
            server.wait_ready()
            result = _harness().run_scenario(
                t2_privilege_escalation_chain(), _target(server)
            )

        assert result.status == "complete"
        assert result.passed is True
        assert len(result.step_results) == 2
        # Step 0: tools/list succeeded
        assert result.step_results[0].passed is True
        # Step 1: admin_delete was rejected → error is_not_none → passes
        assert result.step_results[1].passed is True

    def test_privilege_escalation_allowed_scenario_fails(self):
        """Server that allows admin_delete → scenario fails (T2 vulnerability detected)."""
        with MockMCPServer(
            tools=_ADMIN_TOOLS,
            privileged_tools=set(),  # no privileged tools — server allows everything
        ) as server:
            server.wait_ready()
            result = _harness().run_scenario(
                t2_privilege_escalation_chain(), _target(server)
            )

        assert result.status == "complete"
        assert result.passed is False
        # Step 1 asserts error is_not_none, but server returned result → fails
        assert result.step_results[1].passed is False
        assert len(result.step_results[1].failures) > 0

    def test_regression_t2_test_uses_harness_path(self):
        """T2 scenario must route through full MCP handshake, not direct HTTP.

        FIX 9: Verify that the harness result comes from a real MCPSession
        (initialize → initialized → tools/list) rather than a raw HTTP call.
        The request_log will contain an 'initialize' entry if the handshake ran.
        """
        with MockMCPServer(
            tools=_ADMIN_TOOLS,
            privileged_tools={"admin_delete"},
        ) as server:
            server.wait_ready()
            _harness().run_scenario(t2_privilege_escalation_chain(), _target(server))
            log = server.request_log

        methods = [r.get("method") for r in log]
        assert "initialize" in methods, (
            "T2 scenario must run through MCPSession handshake (not raw HTTP)"
        )


# ---------------------------------------------------------------------------
# T2: Confused deputy
# ---------------------------------------------------------------------------

class TestT2ConfusedDeputy:

    def test_confused_deputy_blocked_scenario_passes(self):
        """Server with correct RBAC — read_file ok, admin_delete rejected → passes."""
        with MockMCPServer(
            tools=_ADMIN_TOOLS,
            privileged_tools={"admin_delete"},
        ) as server:
            server.wait_ready()
            result = _harness().run_scenario(
                t2_confused_deputy(), _target(server)
            )

        assert result.status == "complete"
        assert result.passed is True
        # Step 0: read_file returned result (success)
        assert result.step_results[0].passed is True
        # Step 1: admin_delete rejected → error is_not_none → passes
        assert result.step_results[1].passed is True

    def test_confused_deputy_allowed_scenario_fails(self):
        """Server with no access control — admin_delete succeeds → vulnerability."""
        with MockMCPServer(
            tools=_ADMIN_TOOLS,
            privileged_tools=set(),
        ) as server:
            server.wait_ready()
            result = _harness().run_scenario(
                t2_confused_deputy(), _target(server)
            )

        assert result.status == "complete"
        assert result.passed is False

    def test_regression_confused_deputy_step0_asserts_success(self):
        """Step 0 must check that read_file SUCCEEDED (result is_not_none), not just
        that it didn't return -32601.

        FIX 11: The old assertion 'error.code ne -32601' passed when the server
        returned ANY error code other than -32601 (including -32000 auth failure),
        producing false-clean results.  Now 'result is_not_none' requires a real
        tool result.
        """
        # Server that rejects read_file with -32000 (auth failure, not method-not-found)
        from cosai_mcp.harness.mock_server import MockMCPServer as _MS
        with _MS(
            tools=_ADMIN_TOOLS,
            privileged_tools={"read_file", "admin_delete"},  # both privileged
        ) as server:
            server.wait_ready()
            result = _harness().run_scenario(t2_confused_deputy(), _target(server))

        # Step 0 (read_file) is rejected → result is None → assertion fails
        assert result.step_results[0].passed is False


# ---------------------------------------------------------------------------
# T6: Tool shadowing mid-session
# ---------------------------------------------------------------------------

class TestT6ToolShadowing:

    def test_tool_shadowing_mid_session(self):
        """MockMCPServer returns different tool lists — caller detects the drift.

        The sequence has 3 entries because MCPSession.start() calls tools/list
        once as part of the MCP handshake (index 0), then the two scenario
        steps consume indices 1 and 2.
        """
        with MockMCPServer(
            tools_list_sequence=[_BASIC_TOOLS, _BASIC_TOOLS, _SHADOW_TOOLS],
        ) as server:
            server.wait_ready()
            result = _harness().run_scenario(
                t6_tool_shadowing_mid_session(), _target(server)
            )

        assert result.status == "complete"
        # Both steps ran (both tools/list calls returned)
        assert len(result.step_results) == 2
        assert result.step_results[0].passed is True
        assert result.step_results[1].passed is True

        # Caller detects drift by comparing the two responses
        tools_step0 = result.step_results[0].response["result"]["tools"]
        tools_step1 = result.step_results[1].response["result"]["tools"]
        assert tools_step0 != tools_step1, (
            "Tool manifest changed mid-session — T6 tool shadowing detected"
        )

    def test_stable_manifest_passes_unchanged(self):
        """Stable server returns same tools list both times — no drift."""
        with MockMCPServer(tools=_BASIC_TOOLS) as server:
            server.wait_ready()
            result = _harness().run_scenario(
                t6_tool_shadowing_mid_session(), _target(server)
            )

        assert result.status == "complete"
        tools_step0 = result.step_results[0].response["result"]["tools"]
        tools_step1 = result.step_results[1].response["result"]["tools"]
        assert tools_step0 == tools_step1

    def test_regression_t6_sequence_index_offset_documented(self):
        """With a 2-entry sequence [A, B], both scenario steps see B (last entry repeats).

        FIX 14: MCPSession.start() consumes sequence index 0 during the MCP
        handshake.  With only 2 entries, scenario steps 0 and 1 both see entry
        1 (the last entry repeats).  Scenario authors must provide N+1 entries
        where N is the number of tools/list steps.
        """
        with MockMCPServer(
            tools_list_sequence=[_BASIC_TOOLS, _SHADOW_TOOLS],  # only 2 entries
        ) as server:
            server.wait_ready()
            result = _harness().run_scenario(
                t6_tool_shadowing_mid_session(), _target(server)
            )

        # Both scenario steps see _SHADOW_TOOLS (index 1, repeated)
        tools0 = result.step_results[0].response["result"]["tools"]
        tools1 = result.step_results[1].response["result"]["tools"]
        assert tools0 == _SHADOW_TOOLS
        assert tools1 == _SHADOW_TOOLS
        # No drift detected (both are the same last entry)
        assert tools0 == tools1


# ---------------------------------------------------------------------------
# T7: Session token binding
# ---------------------------------------------------------------------------

class TestT7SessionTokenBinding:

    def test_session_token_binding_passes(self):
        """Both tools/list and tools/call succeed within the same session."""
        with MockMCPServer(tools=_BASIC_TOOLS) as server:
            server.wait_ready()
            result = _harness().run_scenario(
                t7_session_token_binding(), _target(server)
            )

        assert result.status == "complete"
        assert result.passed is True
        assert len(result.step_results) == 2
        for sr in result.step_results:
            assert sr.passed is True
            assert sr.error is None


# ---------------------------------------------------------------------------
# Scan-incomplete handling
# ---------------------------------------------------------------------------

class TestStatefulHarnessScanIncomplete:

    def test_scan_incomplete_when_session_fails(self):
        """If session initialization fails, status is scan-incomplete."""
        with MockMCPServer(initialize_error="authentication required") as server:
            server.wait_ready()
            result = _harness().run_scenario(
                t7_session_token_binding(), _target(server)
            )

        assert result.status == "scan-incomplete"
        assert result.passed is False
        assert result.step_results == ()

    def test_scan_incomplete_on_mid_scenario_abort(self):
        """Error in a non-final step triggers scan-incomplete with partial results."""
        error_scenario = Scenario(
            id="TEST-SC-001",
            name="Abort test",
            threat_categories=("T7",),
            steps=(
                ScenarioStep(
                    description="Step 0 — returns server error but no exception",
                    action=StepAction(method="nonexistent/method", params={}),
                    assertions=(
                        StepAssertion(target="result", operator="is_not_none"),
                    ),
                ),
                ScenarioStep(
                    description="Step 1 — should not run if step 0 raised exception",
                    action=StepAction(method="tools/list", params={}),
                    assertions=(
                        StepAssertion(target="result", operator="is_not_none"),
                    ),
                ),
            ),
        )
        with MockMCPServer() as server:
            server.wait_ready()
            result = _harness().run_scenario(error_scenario, _target(server))

        # Step 0 returns JSON-RPC error (no exception) → assertion fails, continues
        assert result.status == "complete"
        assert result.passed is False  # step 0 fails (result is None)

    def test_result_is_frozen(self):
        """ScenarioResult must be a frozen dataclass."""
        with MockMCPServer() as server:
            server.wait_ready()
            result = _harness().run_scenario(
                t7_session_token_binding(), _target(server)
            )

        with pytest.raises((AttributeError, TypeError)):
            result.status = "mutated"  # type: ignore[misc]

    def test_regression_zero_step_scenario_is_scan_incomplete(self):
        """Zero-step scenario must return scan-incomplete, never complete+passed=True.

        FIX 1: all() on an empty sequence is vacuously True, which would produce
        status="complete", passed=True — a false-clean result that CI gates
        would treat as a passing security check.
        """
        empty_scenario = Scenario(
            id="TEST-EMPTY",
            name="Empty scenario",
            threat_categories=("T2",),
            steps=(),
        )
        with MockMCPServer() as server:
            server.wait_ready()
            result = _harness().run_scenario(empty_scenario, _target(server))

        assert result.status == "scan-incomplete"
        assert result.passed is False

    def test_regression_transport_closed_on_start_failure(self):
        """Transport must be closed even when session.start() fails.

        FIX 2: The early-return on handshake failure bypassed the finally block,
        leaking the httpx.AsyncClient and its underlying TCP connection pool.
        """
        with MockMCPServer(initialize_error="auth required") as server:
            server.wait_ready()
            port = server.port
            # Run the scenario — this would previously leak a connection
            result = _harness().run_scenario(
                t7_session_token_binding(), _target(server)
            )
            # Server is still responsive after the test (no FD exhaustion)
            import httpx
            r = httpx.post(
                f"http://127.0.0.1:{port}/mcp",
                json={"jsonrpc": "2.0", "id": 99, "method": "tools/list", "params": {}},
            )
            assert r.status_code == 200

        assert result.status == "scan-incomplete"

    def test_regression_last_step_exception_is_scan_incomplete(self):
        """Transport exception on ANY step (including the last) → scan-incomplete.

        FIX 7: The abort condition 'result.error is not None and i < len-1'
        allowed the last step's exception to be reported as status="complete".
        A transport exception (connection drop, timeout) is NEVER a "complete"
        result — it means the session was unusable.
        """
        # We simulate a step error by pointing at a port that gets closed.
        # The easiest way: start a server, get its port, stop it, run scenario.
        with MockMCPServer() as server:
            server.wait_ready()
            port = server.port
        # Server is now stopped. Any connection attempt will fail.
        config = ScanConfig(
            target_host="127.0.0.1",
            target_port=port,
            allow_private_targets=True,
            probe_timeout_seconds=2.0,
        )
        result = StatefulHarness(config).run_scenario(
            t7_session_token_binding(), f"http://127.0.0.1:{port}"
        )
        # Session start fails → scan-incomplete (not complete+failed)
        assert result.status == "scan-incomplete"


# ---------------------------------------------------------------------------
# DSL dataclass immutability
# ---------------------------------------------------------------------------

class TestDslImmutability:

    def test_regression_step_action_params_immutable(self):
        """StepAction.params must be stored as MappingProxyType (FIX 3).

        The locked architecture mandates MappingProxyType for all container
        fields in frozen dataclasses.  A mutable params dict could be mutated
        in-place during scenario execution, corrupting subsequent steps or
        results that hold a reference to the same dict.
        """
        action = StepAction(method="tools/list", params={"name": "echo"})
        assert isinstance(action.params, _types.MappingProxyType), (
            "StepAction.params must be MappingProxyType, not dict"
        )
        with pytest.raises(TypeError):
            action.params["name"] = "mutated"  # type: ignore[index]

    def test_step_action_params_accepts_plain_dict(self):
        """Callers may pass a plain dict; it's converted automatically."""
        action = StepAction(method="tools/list", params={})
        assert isinstance(action.params, _types.MappingProxyType)

    def test_step_action_params_accepts_empty_dict(self):
        action = StepAction(method="tools/list", params={})
        assert len(action.params) == 0

    def test_scenario_result_is_frozen(self):
        """ScenarioResult is a frozen dataclass."""
        result = ScenarioResult(
            scenario_id="X",
            scenario_name="X",
            threat_categories=("T2",),
            status="complete",
            passed=True,
            step_results=(),
        )
        with pytest.raises((AttributeError, TypeError)):
            result.passed = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# MockMCPServer stateful extensions
# ---------------------------------------------------------------------------

class TestMockServerStatefulExtensions:

    def test_tools_list_sequence_returns_in_order(self):
        """tools_list_sequence returns items in sequence order."""
        with MockMCPServer(
            tools_list_sequence=[_BASIC_TOOLS, _SHADOW_TOOLS],
        ) as server:
            server.wait_ready()
            import httpx
            r1 = httpx.post(
                f"http://127.0.0.1:{server.port}/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            )
            r2 = httpx.post(
                f"http://127.0.0.1:{server.port}/mcp",
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            )

        assert r1.json()["result"]["tools"] == _BASIC_TOOLS
        assert r2.json()["result"]["tools"] == _SHADOW_TOOLS

    def test_tools_list_sequence_repeats_last_after_exhaustion(self):
        """After sequence exhausted, last entry repeats."""
        with MockMCPServer(
            tools_list_sequence=[_BASIC_TOOLS],
        ) as server:
            server.wait_ready()
            import httpx
            for _ in range(3):
                r = httpx.post(
                    f"http://127.0.0.1:{server.port}/mcp",
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                )
                assert r.json()["result"]["tools"] == _BASIC_TOOLS

    def test_privileged_tools_rejected_without_header(self):
        """Calling a privileged tool without X-Privileged header returns error."""
        with MockMCPServer(
            tools=_ADMIN_TOOLS,
            privileged_tools={"admin_delete"},
        ) as server:
            server.wait_ready()
            import httpx
            r = httpx.post(
                f"http://127.0.0.1:{server.port}/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "admin_delete", "arguments": {}},
                },
            )
        resp = r.json()
        assert "error" in resp
        assert resp["error"]["code"] == -32000

    def test_privileged_tools_allowed_with_header(self):
        """Calling a privileged tool with X-Privileged: true returns result."""
        with MockMCPServer(
            tools=_ADMIN_TOOLS,
            privileged_tools={"admin_delete"},
        ) as server:
            server.wait_ready()
            import httpx
            r = httpx.post(
                f"http://127.0.0.1:{server.port}/mcp",
                headers={"X-Privileged": "true"},
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "admin_delete", "arguments": {}},
                },
            )
        resp = r.json()
        assert "result" in resp
        assert "error" not in resp

    def test_regression_tools_fallback_consistent(self):
        """_get_tools_for_call fallback path (no sequence) is lock-protected.

        FIX 4: The fallback 'return self._tools' was outside the lock in a
        separate statement, making it asymmetric with the sequence path.
        Now both branches are inside the with block.
        """
        # Verify that the fallback returns self._tools correctly
        with MockMCPServer(tools=_BASIC_TOOLS) as server:
            server.wait_ready()
            import httpx
            r = httpx.post(
                f"http://127.0.0.1:{server.port}/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            )
        assert r.json()["result"]["tools"] == _BASIC_TOOLS


# ---------------------------------------------------------------------------
# Scenario factory field validation
# ---------------------------------------------------------------------------

class TestScenarioFactoryFields:
    """Verify that scenario factories produce correct field values.

    FIX 12: Downstream consumers (CI gate, SARIF builder) key off scenario .id
    and .threat_categories for finding traceability.  A silent rename breaks
    the chain.
    """

    def test_t2_privilege_escalation_fields(self):
        s = t2_privilege_escalation_chain()
        assert s.id == "T2-SC-001"
        assert "T2" in s.threat_categories
        assert len(s.steps) >= 1
        assert s.name

    def test_t2_confused_deputy_fields(self):
        s = t2_confused_deputy()
        assert s.id == "T2-SC-002"
        assert "T2" in s.threat_categories
        assert len(s.steps) >= 1

    def test_t6_tool_shadowing_fields(self):
        s = t6_tool_shadowing_mid_session()
        assert s.id == "T6-SC-001"
        assert "T6" in s.threat_categories
        assert len(s.steps) >= 2

    def test_t7_session_token_binding_fields(self):
        s = t7_session_token_binding()
        assert s.id == "T7-SC-001"
        assert "T7" in s.threat_categories
        assert len(s.steps) >= 2
