"""Tests for StatefulHarness.method_overrides — remapping built-in scenarios'
placeholder tool names / methods onto a real server's equivalents.

Built-in scenarios use generic placeholder identifiers (``admin_delete``,
``read_file``, ``session/terminate``) that express a vulnerability *pattern*.
Against a real server those placeholders do not exist, so the precondition gate
correctly reports the scenario INCONCLUSIVE.  ``method_overrides`` lets an
operator map each placeholder onto the equivalent identifier on their server so
the scenario actually exercises the security control.

These tests pin both the pure remap helper (unit) and the full harness path
end-to-end against a real MockMCPServer (the gap the WG-89 reviewer flagged: a
mechanism with no test exercising it).
"""
from __future__ import annotations

from cosai_mcp.config import ScanConfig
from cosai_mcp.harness.mock_server import MockMCPServer
from cosai_mcp.stateful.harness import (
    Scenario,
    ScenarioStep,
    StepAction,
    StepAssertion,
    StatefulHarness,
    _apply_method_overrides,
)
from cosai_mcp.stateful.scenarios import t2_privilege_escalation_chain


def _harness(method_overrides: dict[str, str] | None = None) -> StatefulHarness:
    config = ScanConfig(
        target_host="127.0.0.1",
        target_port=0,
        allow_private_targets=True,
        probe_timeout_seconds=5.0,
    )
    return StatefulHarness(config, method_overrides=method_overrides)


def _target(server: MockMCPServer) -> str:
    return f"http://127.0.0.1:{server.port}"


# A real server whose privileged tool is named `purge`, not the scenario's
# `admin_delete` placeholder.  `read_file` also does not exist here.
_REAL_TOOLS = [
    {"name": "echo", "description": "Echoes input", "inputSchema": {"type": "object"}},
    {"name": "purge", "description": "Purge a resource", "inputSchema": {"type": "object"}},
]


# ---------------------------------------------------------------------------
# Unit — pure remap helper
# ---------------------------------------------------------------------------

class TestApplyMethodOverridesHelper:

    def test_empty_mapping_is_identity(self):
        scenario = t2_privilege_escalation_chain()
        assert _apply_method_overrides(scenario, {}) is scenario

    def test_remaps_tool_name_in_params(self):
        scenario = t2_privilege_escalation_chain()
        remapped = _apply_method_overrides(scenario, {"admin_delete": "purge"})
        names = [
            s.action.params.get("name")
            for s in remapped.steps
            if s.action.method == "tools/call"
        ]
        assert "purge" in names
        assert "admin_delete" not in names

    def test_remaps_method(self):
        scenario = Scenario(
            id="X",
            name="x",
            threat_categories=("T7",),
            steps=(
                ScenarioStep(
                    description="terminate",
                    action=StepAction(method="session/terminate", params={}),
                    assertions=(),
                ),
            ),
        )
        remapped = _apply_method_overrides(scenario, {"session/terminate": "session/delete"})
        assert remapped.steps[0].action.method == "session/delete"

    def test_preserves_identity_fields(self):
        scenario = t2_privilege_escalation_chain()
        remapped = _apply_method_overrides(scenario, {"admin_delete": "purge"})
        assert remapped.id == scenario.id
        assert remapped.name == scenario.name
        assert remapped.threat_categories == scenario.threat_categories

    def test_non_string_tool_name_left_untouched(self):
        """A params['name'] that is not a string must not crash the remap."""
        scenario = Scenario(
            id="X",
            name="x",
            threat_categories=("T2",),
            steps=(
                ScenarioStep(
                    description="weird",
                    action=StepAction(method="tools/call", params={"name": 123}),
                    assertions=(),
                ),
            ),
        )
        remapped = _apply_method_overrides(scenario, {"admin_delete": "purge"})
        assert remapped.steps[0].action.params.get("name") == 123

    def test_unmapped_identifiers_pass_through(self):
        scenario = t2_privilege_escalation_chain()
        remapped = _apply_method_overrides(scenario, {"read_file": "cat"})
        # admin_delete had no mapping → preserved verbatim
        names = [
            s.action.params.get("name")
            for s in remapped.steps
            if s.action.method == "tools/call"
        ]
        assert "admin_delete" in names


# ---------------------------------------------------------------------------
# E2E — full harness path against a real MockMCPServer
# ---------------------------------------------------------------------------

class TestMethodOverridesE2E:

    def test_without_override_scenario_is_inconclusive(self):
        """Baseline: placeholder `admin_delete` absent from manifest → INCONCLUSIVE.

        Confirms the gap the override closes — the un-mapped scenario cannot be
        evaluated against this real server and is correctly NOT reported clean.
        """
        with MockMCPServer(tools=_REAL_TOOLS, privileged_tools={"purge"}) as server:
            server.wait_ready()
            result = _harness().run_scenario(
                t2_privilege_escalation_chain(), _target(server)
            )
        assert result.status == "inconclusive"
        assert result.passed is False
        assert "admin_delete" in (result.inconclusive_reason or "")

    def test_override_maps_to_real_privileged_tool_secure_passes(self):
        """With `admin_delete -> purge`, the scenario exercises the real
        privileged tool; an unauthenticated call is rejected → scenario passes."""
        with MockMCPServer(tools=_REAL_TOOLS, privileged_tools={"purge"}) as server:
            server.wait_ready()
            result = _harness({"admin_delete": "purge"}).run_scenario(
                t2_privilege_escalation_chain(), _target(server)
            )
        assert result.status == "complete"
        assert result.passed is True
        # Result still carries the ORIGINAL scenario id (reports stay stable).
        assert result.scenario_id == "T2-SC-001"

    def test_override_maps_to_real_unguarded_tool_vulnerable_fails(self):
        """With the same mapping but `purge` NOT privileged, the unauthenticated
        call succeeds → the scenario fails (real privilege-escalation finding)."""
        with MockMCPServer(tools=_REAL_TOOLS, privileged_tools=set()) as server:
            server.wait_ready()
            result = _harness({"admin_delete": "purge"}).run_scenario(
                t2_privilege_escalation_chain(), _target(server)
            )
        assert result.status == "complete"
        assert result.passed is False

    def test_override_actually_hits_real_tool_name_on_wire(self):
        """The remapped tool name must reach the server — assert the request log
        records a `tools/call` for `purge`, never the placeholder `admin_delete`."""
        with MockMCPServer(tools=_REAL_TOOLS, privileged_tools={"purge"}) as server:
            server.wait_ready()
            _harness({"admin_delete": "purge"}).run_scenario(
                t2_privilege_escalation_chain(), _target(server)
            )
            call_names = [
                req.get("params", {}).get("name")
                for req in server.request_log
                if req.get("method") == "tools/call"
            ]
        assert "purge" in call_names
        assert "admin_delete" not in call_names


class TestMethodOverridesWiringThroughScanner:
    """Defense FIX [1]/[3]: prove stateful_method_overrides reaches the harness via
    the public Scanner.run -> _run_scan chain (not just a directly-constructed
    harness). Guards the 'field defined + consumed but never set by any call path'
    dead-code mode."""

    def test_override_flows_from_scanconfig_through_run_scan(self):
        from cosai_mcp.api import Scanner

        with MockMCPServer(tools=_REAL_TOOLS, privileged_tools={"purge"}) as server:
            server.wait_ready()
            cfg = ScanConfig(
                target=f"http://127.0.0.1:{server.port}",
                categories=["T2"],
                allow_private_targets=True,
                probe_timeout_seconds=10.0,
                stateful_method_overrides={"admin_delete": "purge"},
            )
            result = Scanner(cfg, engine="stateful").run()

        t2 = [r for r in result.scenario_results if r.scenario_id == "T2-SC-001"]
        assert t2, "T2 privilege-escalation scenario must have run"
        # Without the override reaching the harness this would be INCONCLUSIVE
        # (admin_delete absent). complete+passed proves the remap flowed through.
        assert t2[0].status == "complete"
        assert t2[0].passed is True

    def test_no_override_is_inconclusive_through_run_scan(self):
        """Same path without the override → INCONCLUSIVE, confirming the previous
        test's PASS is caused by the override and not by something else."""
        from cosai_mcp.api import Scanner

        with MockMCPServer(tools=_REAL_TOOLS, privileged_tools={"purge"}) as server:
            server.wait_ready()
            cfg = ScanConfig(
                target=f"http://127.0.0.1:{server.port}",
                categories=["T2"],
                allow_private_targets=True,
                probe_timeout_seconds=10.0,
            )
            result = Scanner(cfg, engine="stateful").run()

        t2 = [r for r in result.scenario_results if r.scenario_id == "T2-SC-001"]
        assert t2 and t2[0].status == "inconclusive"
