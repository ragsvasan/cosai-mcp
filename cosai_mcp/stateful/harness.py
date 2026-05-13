"""StatefulHarness — multi-turn MCP session engine for T2/T6/T7 conformance testing.

Unlike black-box probes (which open a fresh connection per probe), the
stateful harness maintains a single MCP session across all scenario steps.
This enables detection of:

* Privilege escalation chains (T2): verify access-control decisions hold
  across successive calls in the same session.
* Tool manifest drift mid-session (T6): detect when tools/list returns a
  different manifest after initialization, indicating tool shadowing.
* Session token binding failures (T7): verify session identity is preserved
  across calls.

The harness is synchronous at the public API; async internals are wrapped
with asyncio.run().  Do NOT call run_scenario() from inside a running event
loop (e.g., pytest-asyncio, Jupyter).  In those contexts call
``await harness._run_async(scenario, target_url)`` directly.

scan-incomplete semantics
-------------------------
``status="scan-incomplete"`` means the scanner could not complete the test,
NOT that the target is secure.  Callers MUST treat scan-incomplete as a
failure signal (CI exit code ≥ 2), never as a clean result.
"""
from __future__ import annotations

import asyncio
import types as _types
from dataclasses import dataclass
from typing import Any, Literal, Mapping


def _levenshtein(a: str, b: str) -> int:
    """Edit distance between two strings (for tool-name suggestion)."""
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]

from cosai_mcp.config import ScanConfig
from cosai_mcp.session import MCPSession
from cosai_mcp.transport.streamable_http import StreamableHTTPTransport


# ---------------------------------------------------------------------------
# DSL dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StepAction:
    """RPC action for a single scenario step.

    ``params`` is stored as an immutable ``MappingProxyType``; callers may
    pass a plain ``dict`` and it will be converted automatically.
    """
    method: str
    params: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not isinstance(self.params, _types.MappingProxyType):
            object.__setattr__(self, "params", _types.MappingProxyType(dict(self.params)))


@dataclass(frozen=True)
class StepAssertion:
    """Assertion evaluated against the step response.

    target:
        Dotted path into the JSON-RPC response dict.
        Examples: ``"result.tools"``, ``"error.code"``, ``"error"``.
        Must not be empty.
    operator:
        One of: eq, ne, contains, not_contains, is_none, is_not_none,
        len_eq, len_gt.
    expected:
        Expected value (unused for is_none / is_not_none).
    message:
        Human-readable description shown on failure.

    ``not_contains`` on a missing/non-iterable path is an assertion failure
    (not a silent pass) — mis-targeting a path is caught rather than silently
    returning false-clean.
    """
    target: str
    operator: str
    expected: Any = None
    message: str = ""


@dataclass(frozen=True)
class ScenarioStep:
    description: str
    action: StepAction
    assertions: tuple[StepAssertion, ...]


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    threat_categories: tuple[str, ...]
    steps: tuple[ScenarioStep, ...]
    description: str = ""


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AssertionFailure:
    target: str
    operator: str
    expected: Any
    actual: Any
    message: str


@dataclass(frozen=True)
class StepResult:
    step_index: int
    description: str
    passed: bool
    response: dict[str, Any] | None
    failures: tuple[AssertionFailure, ...]
    error: str | None = None


@dataclass(frozen=True)
class ScenarioResult:
    """Result of running a Scenario.

    status:
        ``"complete"`` — all steps ran and returned JSON-RPC responses
        (regardless of whether they passed assertions).
        ``"scan-incomplete"`` — session setup failed OR a step raised an
        exception (transport error, timeout, connection drop).

    IMPORTANT: ``scan-incomplete`` must be treated as a FAILURE by callers.
    It is NEVER equivalent to a clean result.  CI gates must map
    ``scan-incomplete`` to a non-zero exit code (see locked exit-code
    semantics in CLAUDE.md).
    """
    scenario_id: str
    scenario_name: str
    threat_categories: tuple[str, ...]
    status: Literal["complete", "scan-incomplete", "inconclusive"]
    passed: bool
    step_results: tuple[StepResult, ...]
    inconclusive_reason: str | None = None


# ---------------------------------------------------------------------------
# Assertion evaluation helpers
# ---------------------------------------------------------------------------

def _resolve_path(response: dict[str, Any], path: str) -> Any:
    """Extract a value from a nested dict using a dotted path.

    Special case: ``"error"`` normalizes across both JSON-RPC protocol errors
    (``{"error": {...}}``) and MCP content-layer errors
    (``{"result": {"isError": true, ...}}``).  Both formats indicate rejection.
    """
    if path == "error":
        # JSON-RPC protocol error
        if response.get("error") is not None:
            return response.get("error")
        # MCP content-layer error
        result = response.get("result", {})
        if isinstance(result, dict) and result.get("isError"):
            return {"isError": True}  # synthetic truthy value — normalises both formats
        return None

    parts = path.split(".")
    current: Any = response
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _evaluate_assertion(
    response: dict[str, Any], assertion: StepAssertion
) -> AssertionFailure | None:
    """Return None if the assertion passes, AssertionFailure otherwise.

    An empty ``target`` is always a failure (defensive against mis-targeting).

    The ``not_contains`` operator returns failure when the resolved value is
    not a str or list — this catches mis-targeted paths rather than silently
    passing with a false-clean result.
    """
    if not assertion.target:
        return AssertionFailure(
            target=assertion.target,
            operator=assertion.operator,
            expected=assertion.expected,
            actual=None,
            message="assertion target must not be empty",
        )

    actual = _resolve_path(response, assertion.target)
    op = assertion.operator
    exp = assertion.expected

    if op == "eq":
        passed = actual == exp
    elif op == "ne":
        passed = actual != exp
    elif op == "contains":
        passed = isinstance(actual, (str, list)) and exp in actual
    elif op == "not_contains":
        if not isinstance(actual, (str, list)):
            # Missing or non-iterable path is an assertion error, not a pass.
            # Returning failure catches mis-targeted paths before they produce
            # false-clean results.
            passed = False
        else:
            passed = exp not in actual
    elif op == "is_none":
        passed = actual is None
    elif op == "is_not_none":
        passed = actual is not None
    elif op == "len_eq":
        passed = hasattr(actual, "__len__") and len(actual) == exp
    elif op == "len_gt":
        passed = hasattr(actual, "__len__") and len(actual) > exp
    else:
        passed = False

    if passed:
        return None
    return AssertionFailure(
        target=assertion.target,
        operator=op,
        expected=exp,
        actual=actual,
        message=assertion.message or f"{assertion.target} {op} {exp!r}: got {actual!r}",
    )


# ---------------------------------------------------------------------------
# StatefulHarness
# ---------------------------------------------------------------------------

class StatefulHarness:
    """Run multi-turn MCP conformance scenarios within a single session.

    Each call to ``run_scenario`` opens a fresh MCP session (initialize →
    initialized → tools/list), executes all steps, then closes the session.

    Transport and session are always closed in a ``finally`` block, even when
    the handshake fails, to prevent connection leaks.

    If the session handshake fails or any step raises an exception, returns
    ``status="scan-incomplete"``.  This must be treated as a failure by
    callers — it is never a clean result.
    """

    def __init__(self, config: ScanConfig) -> None:
        self._config = config

    def run_scenario(self, scenario: Scenario, target_url: str) -> ScenarioResult:
        """Run *scenario* synchronously against *target_url*.

        Must not be called from inside a running event loop.  In async
        contexts use ``await harness._run_async(scenario, target_url)``.

        Returns a ``ScenarioResult`` with ``status="complete"`` when all steps
        executed JSON-RPC responses (regardless of pass/fail), or
        ``status="scan-incomplete"`` when the session could not be established
        or a step raised a transport exception.
        """
        return asyncio.run(self._run_async(scenario, target_url))

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _run_async(
        self, scenario: Scenario, target_url: str
    ) -> ScenarioResult:
        # Zero-step scenario is a misconfigured/adversarially crafted input.
        # Vacuous truth (all() on empty) would produce complete+passed=True,
        # which CI would treat as a passing security check.
        if not scenario.steps:
            return ScenarioResult(
                scenario_id=scenario.id,
                scenario_name=scenario.name,
                threat_categories=scenario.threat_categories,
                status="scan-incomplete",
                passed=False,
                step_results=(),
            )

        transport = StreamableHTTPTransport(target_url, self._config)
        session = MCPSession(transport, self._config, target_url=target_url)

        # The finally block always closes transport+session, even if
        # connect() or start() raises — preventing connection leaks.
        try:
            try:
                await transport.connect()
                await session.start()
            except Exception:
                return ScenarioResult(
                    scenario_id=scenario.id,
                    scenario_name=scenario.name,
                    threat_categories=scenario.threat_categories,
                    status="scan-incomplete",
                    passed=False,
                    step_results=(),
                )

            # Check whether all tools the scenario calls actually exist.
            # Scenarios use generic/fictional tool names (admin_delete, read_file)
            # that may not exist on the target server.  Running them produces
            # "unknown tool" responses that look like findings but are not —
            # the scenario simply can't be evaluated on this server.
            # Check whether all tools the scenario calls actually exist on the
            # target server.  Scenarios use generic placeholder tool names
            # (admin_delete, read_file) that may not exist.  Running them
            # produces "unknown tool" responses that look like findings but
            # are not — mark the scenario INCONCLUSIVE instead.
            available_tools: set[str] = {
                t.get("name", "") for t in session.tool_manifest
            }
            if available_tools:  # non-empty manifest — we can check coverage
                overrides: dict[str, str] = self._config.method_overrides or {}
                required_tools = {
                    overrides.get(
                        step.action.params.get("name", ""),
                        step.action.params.get("name", ""),
                    )
                    for step in scenario.steps
                    if step.action.method == "tools/call"
                    and step.action.params.get("name")
                }
                missing = required_tools - available_tools
                if missing:
                    # Suggest the closest available tool by edit distance for each
                    # missing name so the user knows exactly which override to add.
                    suggestions: list[str] = []
                    for m in sorted(missing):
                        closest = min(available_tools, key=lambda t: _levenshtein(m, t))
                        suggestions.append(
                            f"--method-override {m}={closest}"
                        )
                    suggestion_text = (
                        f" Closest available tools: {'; '.join(suggestions)}."
                        if suggestions
                        else " Configure method_overrides to map them to equivalent tools."
                    )
                    return ScenarioResult(
                        scenario_id=scenario.id,
                        scenario_name=scenario.name,
                        threat_categories=scenario.threat_categories,
                        status="inconclusive",
                        passed=False,
                        step_results=(),
                        inconclusive_reason=(
                            f"Scenario requires tool(s) not present on this server: "
                            f"{', '.join(sorted(missing))}. "
                            f"The scenario tests a generic vulnerability pattern using "
                            f"placeholder tool names.{suggestion_text}"
                        ),
                    )

            step_results: list[StepResult] = []
            for i, step in enumerate(scenario.steps):
                result = await self._run_step(session, i, step)
                step_results.append(result)
                # Any transport exception (error != None) means the session is
                # unusable — report scan-incomplete regardless of step position.
                # JSON-RPC error responses (error is None, but assertions fail)
                # continue to completion so all findings are recorded.
                if result.error is not None:
                    return ScenarioResult(
                        scenario_id=scenario.id,
                        scenario_name=scenario.name,
                        threat_categories=scenario.threat_categories,
                        status="scan-incomplete",
                        passed=False,
                        step_results=tuple(step_results),
                    )

            all_passed = all(r.passed for r in step_results)
            return ScenarioResult(
                scenario_id=scenario.id,
                scenario_name=scenario.name,
                threat_categories=scenario.threat_categories,
                status="complete",
                passed=all_passed,
                step_results=tuple(step_results),
            )
        finally:
            try:
                await session.close()
            except Exception:
                pass

    async def _run_step(
        self, session: MCPSession, index: int, step: ScenarioStep
    ) -> StepResult:
        try:
            # send_raw is used intentionally here (not session.tools_list()) so
            # that the harness issues a live network request for every step,
            # including tools/list.  session.tools_list() returns the cached
            # manifest from initialization; using it for T6 would defeat
            # shadowing detection entirely.
            params = dict(step.action.params)
            if step.action.method == "tools/call" and "name" in params:
                overrides: dict[str, str] = self._config.method_overrides or {}
                params["name"] = overrides.get(params["name"], params["name"])
            response = await session.send_raw(step.action.method, params)
        except Exception as exc:
            return StepResult(
                step_index=index,
                description=step.description,
                passed=False,
                response=None,
                failures=(),
                error=str(exc),
            )

        failures: list[AssertionFailure] = []
        for assertion in step.assertions:
            failure = _evaluate_assertion(response, assertion)
            if failure is not None:
                failures.append(failure)

        return StepResult(
            step_index=index,
            description=step.description,
            passed=len(failures) == 0,
            response=response,
            failures=tuple(failures),
            error=None,
        )
