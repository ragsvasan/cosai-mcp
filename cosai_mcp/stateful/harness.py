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


def _manifest_tool_names(response: dict[str, Any] | None) -> frozenset[str] | None:
    """Extract the set of tool names from a tools/list response, or None if the
    response is not a well-formed tools/list result."""
    if not isinstance(response, dict):
        return None
    result = response.get("result")
    if not isinstance(result, dict):
        return None
    tools = result.get("tools")
    if not isinstance(tools, list):
        return None
    return frozenset(
        str(t.get("name", "")) for t in tools if isinstance(t, dict)
    )


# Standard MCP methods a server is expected to implement.  A protocol-validation
# error on one of these is a real signal; a protocol-validation error on a
# NON-standard method (e.g. the synthetic `session/terminate` revocation step)
# means the server simply does not implement that mechanism.
_STANDARD_MCP_METHODS: frozenset[str] = frozenset({
    "initialize", "notifications/initialized", "tools/list", "tools/call",
    "ping", "resources/list", "resources/read", "resources/templates/list",
    "prompts/list", "prompts/get", "completion/complete", "logging/setLevel",
})

# JSON-RPC codes meaning the server did not accept the method/request at all:
# method not found, invalid params, invalid request, parse error.
_UNSUPPORTED_METHOD_CODES: frozenset[int] = frozenset({-32700, -32600, -32601, -32602})


def _scenario_method_not_found(
    scenario: Scenario,
    step_results: list[StepResult],
) -> str | None:
    """Return a human label for the first NON-standard-method step whose response
    is a JSON-RPC protocol-validation error (-32601/-32602/-32600/-32700), or
    None.  Used to mark a scenario INCONCLUSIVE when it depends on a mechanism the
    server does not implement (e.g. a synthetic `session/terminate` revocation
    method) rather than letting a downstream assertion false-positive against a
    secure server that revokes sessions a different way (audit COV-10).

    Scoped to non-standard methods so a real tools/list or tools/call outcome is
    never suppressed (tool-absence is already handled by the precondition gate).
    """
    for step, sr in zip(scenario.steps, step_results):
        if step.action.method in _STANDARD_MCP_METHODS:
            continue
        resp = sr.response
        if isinstance(resp, dict):
            err = resp.get("error")
            if isinstance(err, dict) and err.get("code") in _UNSUPPORTED_METHOD_CODES:
                return f"{sr.step_index} ('{sr.description}') via method '{step.action.method}'"
    return None


def _detect_manifest_drift(
    scenario: Scenario,
    step_results: list[StepResult],
) -> StepResult | None:
    """Diff the tool-name sets of every successful tools/list step in the
    scenario.  Returns a synthetic FAILING StepResult if any two manifests drift
    (a tool was added, removed, or renamed mid-session — T6 shadowing), or None
    if the manifests are consistent or fewer than two tools/list steps exist.

    Audit COV-03: this is the comparison the scenario docstring said was "left to
    the caller"; nothing performed it, so a shadowed manifest passed silently.
    """
    manifests: list[tuple[int, frozenset[str]]] = []
    for step, result in zip(scenario.steps, step_results):
        if step.action.method != "tools/list":
            continue
        names = _manifest_tool_names(result.response)
        if names is not None:
            manifests.append((result.step_index, names))

    if len(manifests) < 2:
        return None

    baseline_index, baseline = manifests[0]
    for idx, names in manifests[1:]:
        if names != baseline:
            added = sorted(names - baseline)
            removed = sorted(baseline - names)
            detail = (
                f"Tool manifest drifted between tools/list step {baseline_index} "
                f"and step {idx} within the same session (no re-initialization). "
                f"added={added} removed={removed}. This indicates T6 tool "
                f"shadowing — a tool was injected, renamed, or withdrawn mid-session."
            )
            return StepResult(
                step_index=len(step_results),
                description="T6 manifest-drift check",
                passed=False,
                response=None,
                failures=(
                    AssertionFailure(
                        target="manifest.tool_names",
                        operator="eq",
                        expected=sorted(baseline),
                        actual=sorted(names),
                        message=detail,
                    ),
                ),
                error=None,
            )
    return None


def _apply_method_overrides(
    scenario: Scenario,
    overrides: Mapping[str, str],
) -> Scenario:
    """Return a copy of *scenario* with placeholder methods and tool names
    remapped to a real server's equivalents via *overrides*.

    Built-in scenarios use generic placeholder identifiers — fictional tool
    names (``admin_delete``, ``read_file``) and synthetic JSON-RPC methods
    (``session/terminate``) — chosen to express a vulnerability *pattern*, not
    to match any specific server.  Against a real third-party server those
    placeholders do not exist, so every step returns ``-32601`` and the
    scenario is (correctly) reported INCONCLUSIVE.  ``method_overrides`` lets an
    operator map each placeholder to the equivalent identifier on their server
    so the scenario actually exercises the security control.

    The same flat ``{placeholder: real}`` mapping covers both axes because
    methods (``session/terminate``) and tool names (``admin_delete``) live in
    disjoint key spaces:

    * ``step.action.method`` is remapped when present as a key.
    * ``step.action.params["name"]`` (the ``tools/call`` tool name) is remapped
      when present as a key.

    Remapping happens once, up front, so every downstream consumer — the
    tool-existence precondition gate, the unsupported-method gate, and live
    step execution — sees the real identifiers consistently.  An empty mapping
    returns the scenario unchanged (identity).
    """
    if not overrides:
        return scenario

    new_steps: list[ScenarioStep] = []
    for step in scenario.steps:
        action = step.action
        new_method = overrides.get(action.method, action.method)

        params = dict(action.params)
        tool_name = params.get("name")
        if isinstance(tool_name, str) and tool_name in overrides:
            params["name"] = overrides[tool_name]

        new_steps.append(
            ScenarioStep(
                description=step.description,
                # StepAction.__post_init__ re-freezes params into a MappingProxyType.
                action=StepAction(method=new_method, params=params),
                assertions=step.assertions,
            )
        )

    return Scenario(
        id=scenario.id,
        name=scenario.name,
        threat_categories=scenario.threat_categories,
        steps=tuple(new_steps),
        description=scenario.description,
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

    def __init__(
        self,
        config: ScanConfig,
        method_overrides: Mapping[str, str] | None = None,
    ) -> None:
        self._config = config
        # Frozen copy so a caller's later mutation cannot retroactively change
        # which identifiers a scenario remaps to (parity with the frozen DSL).
        self._method_overrides: Mapping[str, str] = _types.MappingProxyType(
            dict(method_overrides) if method_overrides else {}
        )

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

        # Remap placeholder tool names / methods to this server's equivalents
        # before any gate or step runs, so the precondition gate, the
        # unsupported-method gate, and live execution all see real identifiers.
        # Result fields below still carry the ORIGINAL scenario id/name/categories
        # so reports remain stable regardless of operator mapping.
        scenario = _apply_method_overrides(scenario, self._method_overrides)

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
                required_tools = {
                    step.action.params.get("name", "")
                    for step in scenario.steps
                    if step.action.method == "tools/call"
                    and step.action.params.get("name")
                }
                missing = required_tools - available_tools
                if missing:
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
                            f"placeholder tool names. To test this scenario, configure "
                            f"method_overrides to map them to equivalent tools on this server."
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

            # Unsupported-method gate.  Some scenarios depend on a non-standard
            # method the server may not implement (e.g. the session-revocation
            # scenario sends a synthetic ``session/terminate``).  If a step gets a
            # JSON-RPC -32601 (method not found), the security mechanism under
            # test does not exist on this server, so a downstream "must be
            # rejected" assertion would FALSE-POSITIVE against a secure server
            # that simply revokes sessions a different way.  Mark the scenario
            # INCONCLUSIVE instead (operator maps the real method via
            # method_overrides) — mirrors the tool-existence precondition gate
            # above and the prober's -32601 handling (audit COV-10).
            unsupported = _scenario_method_not_found(scenario, step_results)
            if unsupported is not None:
                return ScenarioResult(
                    scenario_id=scenario.id,
                    scenario_name=scenario.name,
                    threat_categories=scenario.threat_categories,
                    status="inconclusive",
                    passed=False,
                    step_results=tuple(step_results),
                    inconclusive_reason=(
                        f"Scenario step {unsupported} returned a JSON-RPC "
                        f"method-not-found/invalid-request error: the server does "
                        f"not implement the non-standard method this scenario "
                        f"depends on. The security property could not be evaluated "
                        f"— configure method_overrides to map it to this server's "
                        f"equivalent. INCONCLUSIVE, not a finding."
                    ),
                )

            # T6 manifest-drift detection (audit COV-03).  A scenario that issues
            # two or more live tools/list calls within one session is testing for
            # tool shadowing: if the second manifest differs from the first
            # WITHOUT a re-initialization, the server injected/renamed/removed a
            # tool mid-session.  Previously this comparison was "left to the
            # caller" and nothing performed it, so a shadowed manifest passed
            # silently.  We now diff the manifests here and append a synthetic
            # failing step when they drift, so the scenario FAILS.
            drift_step = _detect_manifest_drift(scenario, step_results)
            if drift_step is not None:
                step_results.append(drift_step)

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
            response = await session.send_raw(step.action.method, dict(step.action.params))
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
