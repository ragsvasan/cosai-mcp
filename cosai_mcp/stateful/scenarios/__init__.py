"""Built-in scenario factories for T2, T6, T7, and T10 conformance testing.

Each function returns a ``Scenario`` that the ``StatefulHarness`` can run
against a real or mock MCP server.

Threat category coverage:
* T2 — Missing Access Control: privilege escalation, confused deputy
* T6 — Integrity/Verification: tool shadowing detection
* T7 — Session Security: session token binding, token revocation
* T10 — Resource Management: recursive/looping tool-chain (denial-of-wallet)
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


def t10_recursive_tool_loop(loop_calls: int = 16) -> Scenario:
    """T10: Recursive / looping tool-chain — denial-of-wallet.

    Simulates an agent caught in a recursive tool-invocation loop: the same
    tool is called ``loop_calls`` times in rapid succession within a single
    session, the way a poisoned tool whose output drives the next call would
    drive an agent in an unbounded cycle.  This is where most production money
    is burned ("denial of wallet"), and — unlike a one-shot black-box probe —
    it can only be exercised across a *stateful* multi-call session.

    A SECURE server enforces a per-session call budget: it exhausts the budget
    partway through the loop and keeps rejecting every subsequent call, so the
    final loop iteration is rejected.  Scenario *passes* (server is bounded).

    A VULNERABLE server answers the entire loop with no budget, so the final
    iteration succeeds.  The harness ``loop_budget_check`` then appends a
    synthetic failing step and the scenario *fails* (denial-of-wallet finding).

    Per-step assertions are intentionally empty: an individual successful tool
    call is not itself a finding (a server is allowed to answer calls).  The
    verdict comes entirely from the harness-level call-budget check, which
    inspects every tools/call result once the loop completes.

    ``loop_calls`` defaults to 16 — large enough that any reasonable per-session
    budget trips before the end, small enough to stay well within probe
    timeouts.  Callers may lower it for fast tests.
    """
    # Defensive floor: the loop check needs at least two calls to be meaningful.
    loop_calls = max(2, loop_calls)
    return Scenario(
        id="T10-SC-001",
        name="Recursive tool-chain loop — per-session call budget",
        threat_categories=("T10",),
        description=(
            "Call the same tool repeatedly within one session to simulate an "
            "agent stuck in a recursive tool-invocation loop. A server that "
            "answers the entire loop without ever applying a per-session call "
            "budget is vulnerable to T10 denial-of-wallet. A secure server "
            "exhausts its call budget and rejects the final iteration."
        ),
        loop_budget_check=True,
        steps=tuple(
            ScenarioStep(
                description=(
                    f"Loop iteration {i + 1}/{loop_calls} — repeated tool call"
                ),
                action=StepAction(
                    method="tools/call",
                    params={
                        "name": "echo",
                        "arguments": {"iteration": str(i)},
                    },
                ),
                # No per-step assertion: an individual answered call is not a
                # finding. The harness call-budget check renders the verdict.
                assertions=(),
            )
            for i in range(loop_calls)
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


def t7_session_revocation() -> Scenario:
    """T7: Session token revocation must be honoured immediately.

    This scenario establishes an active session (tools/list succeeds), then
    sends a revocation notification (DELETE /session or equivalent encoded as
    a JSON-RPC notification), then verifies the next call is rejected.

    The scenario itself only sends the revocation *notification* step — the
    caller (test or scanner) is responsible for verifying the final step
    returns an error.  Because the MCP spec does not define a standard
    revocation method, the revocation step uses a synthetic
    ``session/terminate`` notification.  Real servers under test should map
    this to their own revocation path via the harness ``method_overrides``
    option (planned P8 harness extension).

    Scenario *passes* when the post-revocation call is rejected.
    Scenario *fails* when the post-revocation call succeeds (token still
    valid after explicit revocation — T7 vulnerability).
    """
    return Scenario(
        id="T7-SC-002",
        name="Session token revocation — post-revocation calls must fail",
        threat_categories=("T7",),
        description=(
            "Establish an active session, signal explicit revocation via "
            "session/terminate notification, then call tools/list. "
            "A server that continues to accept the session token after "
            "revocation is vulnerable to T7 (token revocation bypass)."
        ),
        steps=(
            ScenarioStep(
                description="tools/list — confirm session is active before revocation",
                action=StepAction(method="tools/list", params={}),
                assertions=(
                    StepAssertion(
                        target="result",
                        operator="is_not_none",
                        message="Session must be active before revocation test",
                    ),
                ),
            ),
            ScenarioStep(
                description="session/terminate — signal explicit revocation (notification)",
                action=StepAction(
                    method="session/terminate",
                    params={"reason": "explicit_revocation_test"},
                ),
                assertions=(),  # notification — no response expected; transport may return empty
            ),
            ScenarioStep(
                description="tools/list after revocation — must be rejected",
                action=StepAction(method="tools/list", params={}),
                assertions=(
                    StepAssertion(
                        target="error",
                        operator="is_not_none",
                        message=(
                            "Session token must be rejected after explicit revocation. "
                            "A successful tools/list here indicates the server does not "
                            "honour revocation (T7 token revocation bypass)."
                        ),
                    ),
                ),
            ),
        ),
    )
