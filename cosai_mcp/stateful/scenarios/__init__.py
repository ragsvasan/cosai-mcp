"""Built-in scenario factories for T2, T6, and T7 conformance testing.

Each function returns a ``Scenario`` that the ``StatefulHarness`` can run
against a real or mock MCP server.

Threat category coverage:
* T2 — Missing Access Control: privilege escalation, confused deputy
* T6 — Integrity/Verification: tool shadowing detection
* T7 — Session Security: session token binding
"""
from __future__ import annotations

from cosai_mcp.stateful.harness import (
    Scenario,
    ScenarioStep,
    StepAction,
    StepAssertion,
)


def t2_privilege_escalation_chain() -> Scenario:
    """T2: Unauthenticated call to a privileged tool must be rejected.

    A secure server returns an error when ``admin_delete`` is called without
    the required authorization.  Scenario *passes* when the server correctly
    rejects the call (finding = server is secure).  Scenario *fails* when the
    server permits the call (finding = privilege escalation vulnerability).
    """
    return Scenario(
        id="T2-SC-001",
        name="Privilege escalation via direct tool call",
        threat_categories=("T2",),
        description=(
            "Verify that calling a privileged tool (admin_delete) without "
            "the required authorization produces an error response. "
            "A server that permits this call is vulnerable to T2."
        ),
        steps=(
            ScenarioStep(
                description="List tools — baseline manifest",
                action=StepAction(method="tools/list", params={}),
                assertions=(
                    StepAssertion(target="result", operator="is_not_none"),
                ),
            ),
            ScenarioStep(
                description="Call privileged tool without authorization — must fail",
                action=StepAction(
                    method="tools/call",
                    params={"name": "admin_delete", "arguments": {"path": "/etc"}},
                ),
                assertions=(
                    StepAssertion(
                        target="error",
                        operator="is_not_none",
                        message="Privileged tool admin_delete must reject unauthenticated call",
                    ),
                ),
            ),
        ),
    )


def t2_confused_deputy() -> Scenario:
    """T2: Privilege must not carry over from an unprivileged call.

    After calling ``read_file`` (unprivileged), an attempt to call
    ``admin_delete`` (privileged) must still be rejected.  Carrying over
    authority between tool calls is a confused deputy vulnerability.
    """
    return Scenario(
        id="T2-SC-002",
        name="Confused deputy — cross-tool authority abuse",
        threat_categories=("T2",),
        description=(
            "After calling an unprivileged tool (read_file), attempt to "
            "call a privileged tool (admin_delete) in the same session. "
            "The server must not elevate permissions based on prior calls."
        ),
        steps=(
            ScenarioStep(
                description="Call unprivileged tool — read_file must succeed",
                action=StepAction(
                    method="tools/call",
                    params={"name": "read_file", "arguments": {"path": "/tmp/test.txt"}},
                ),
                assertions=(
                    StepAssertion(
                        target="result",
                        operator="is_not_none",
                        message="read_file must return a result (unprivileged call must succeed)",
                    ),
                ),
            ),
            ScenarioStep(
                description="Attempt privileged tool — must still fail",
                action=StepAction(
                    method="tools/call",
                    params={"name": "admin_delete", "arguments": {"path": "/etc"}},
                ),
                assertions=(
                    StepAssertion(
                        target="error",
                        operator="is_not_none",
                        message=(
                            "Privileged tool admin_delete must not be accessible "
                            "after an unprivileged read_file call (confused deputy)"
                        ),
                    ),
                ),
            ),
        ),
    )


def t6_tool_shadowing_mid_session() -> Scenario:
    """T6: Two tools/list calls within one session.

    The scenario itself does not enforce that the two manifests match — that
    comparison is done by the caller (test or scanner) by inspecting
    ``step_results[0].response`` vs ``step_results[1].response``.  This
    scenario simply ensures both calls succeed so the comparison is possible.
    """
    return Scenario(
        id="T6-SC-001",
        name="Tool shadowing — manifest drift detection",
        threat_categories=("T6",),
        description=(
            "Call tools/list twice within the same session.  If the manifest "
            "differs between calls (without re-initialization), this indicates "
            "a T6 tool-shadowing violation.  The caller compares step results."
        ),
        steps=(
            ScenarioStep(
                description="First tools/list — capture baseline manifest",
                action=StepAction(method="tools/list", params={}),
                assertions=(
                    StepAssertion(target="result.tools", operator="is_not_none"),
                ),
            ),
            ScenarioStep(
                description="Second tools/list — for drift comparison",
                action=StepAction(method="tools/list", params={}),
                assertions=(
                    StepAssertion(target="result.tools", operator="is_not_none"),
                ),
            ),
        ),
    )


def t7_session_token_binding() -> Scenario:
    """T7: Verify session token is maintained and usable across calls.

    A minimal two-step scenario: list tools, then call a tool.  Both must
    succeed within the same session, confirming the session binding holds.
    """
    return Scenario(
        id="T7-SC-001",
        name="Session token binding — multi-call session integrity",
        threat_categories=("T7",),
        description=(
            "Execute tools/list then tools/call within a single session. "
            "Both steps must succeed, confirming the session token is "
            "correctly bound across the full call sequence."
        ),
        steps=(
            ScenarioStep(
                description="tools/list — verify session is active",
                action=StepAction(method="tools/list", params={}),
                assertions=(
                    StepAssertion(target="result", operator="is_not_none"),
                ),
            ),
            ScenarioStep(
                description="tools/call echo — verify call succeeds in same session",
                action=StepAction(
                    method="tools/call",
                    params={"name": "echo", "arguments": {"message": "ping"}},
                ),
                assertions=(
                    StepAssertion(
                        target="result",
                        operator="is_not_none",
                        message="tools/call must succeed within active session",
                    ),
                ),
            ),
        ),
    )
