"""ProbeContext — wraps MCPSession + config + target, executes single probes."""
from __future__ import annotations

import json
import time
import types
from typing import TYPE_CHECKING, Any

from cosai_mcp.catalog.models import Probe, ThreatDefinition
from cosai_mcp.catalog.template import substitute_probe_payload
from cosai_mcp.config import ScanConfig
from cosai_mcp.harness.assertions import evaluate_assertion
from cosai_mcp.harness.result import ProbeResult, make_probe_result
from cosai_mcp.session import MCPSession

if TYPE_CHECKING:
    from cosai_mcp.discovery import DiscoveredTool


# Keywords in MCP content-layer error text that indicate the server rejected
# the probe payload because of argument/schema validation — NOT because of the
# security property being tested.  When found, the probe is INCONCLUSIVE.
_SCHEMA_MISMATCH_KEYWORDS: tuple[str, ...] = (
    "unknown argument",
    "unexpected argument",
    "extra argument",
    "invalid argument",
    "unrecognized argument",
    "required field",
    "required argument",
    "missing field",
    "missing required",
    "field required",
    "does not accept",
    "not accepted",
    "not allowed",
    "not a valid",
    "type error",
    "validation error",
    "validation failed",   # e.g. VitalSync: "Validation failed at clientModel: ..."
    "invalid input",       # e.g. VitalSync: "Invalid input: expected string, received undefined"
    "unrecognized key",    # e.g. VitalSync: "Unrecognized key: \"tick\""
    "schema",
    "unknown tool",
    "tool not found",
    "no such tool",
)


# JSON-RPC protocol error codes that mean the probe NEVER reached the tool's
# security logic: the method/tool did not exist (-32601), the arguments did not
# match the tool schema (-32602), the request was malformed (-32600), or it
# failed to parse (-32700).  When a "reject = secure" probe (assert
# response.error == true) is satisfied ONLY by one of these codes, the PASS is
# vacuous — a server that simply lacks the hardcoded tool name would "pass".
# Such results are INCONCLUSIVE, never PASS and never a finding.
#
# Codes deliberately EXCLUDED: -32603 (internal error), -32000..-32099 (server
# application errors, e.g. -32001 auth/scope rejection, -32029 rate limit).
# Those are genuine security-relevant outcomes the probes are meant to observe.
_PROTOCOL_VALIDATION_CODES: frozenset[int] = frozenset(
    {-32700, -32600, -32601, -32602}
)

# Request-level rejection codes: the server failed to parse (-32700) or rejected
# the request as malformed/too-large (-32600) BEFORE dispatching to a tool.  A
# resource/size/parse limit firing emits one of these.  These are the ONLY codes
# a reject-the-request probe (protocol_error_is_expected) may treat as a "control
# fired" secure signal.  -32601 (method not found) and -32602 (invalid params)
# are deliberately EXCLUDED: a server that simply lacks the probed tool returns
# the identical -32601/-32602, so they can never be proof a limit/allowlist fired
# (adversary EXPLOIT 1) — they always downgrade to INCONCLUSIVE.
_REQUEST_LEVEL_CODES: frozenset[int] = frozenset({-32700, -32600})


def _probe_inspects_error_code(probe: Probe) -> bool:
    """True if any of the probe's assertions explicitly target the JSON-RPC
    error code (response.error_code).  Such a probe is intentionally testing
    protocol-level behaviour (e.g. T01-005 asserts ``error_code == -32601``;
    T11-001 accepts -32601/-32602 via ``error_code_in``) — it must NOT be
    downgraded to inconclusive by the generic protocol-error guard below.
    """
    return any(a.target == "response.error_code" for a in probe.assertions)


def _detect_protocol_error(response: dict[str, Any], probe: Probe) -> str | None:
    """Return an inconclusive reason if the response is a JSON-RPC validation/
    not-found error (``-32601``/``-32602``/``-32600``/``-32700``) and the probe
    does not explicitly assert on the error code.

    A ``-32601`` (method not found) means the probe's assumed privileged tool
    does not exist on this server, so a ``response.error == true`` assertion
    holds for the wrong reason.  Treating that as a PASS is the core vacuous-PASS
    bug (audit COV-06): it reports "access control enforced" against a server
    that never had the tested tool.  Returns None when the probe opts in to
    protocol-level testing (see ``_probe_inspects_error_code``).
    """
    if _probe_inspects_error_code(probe):
        return None
    error = response.get("error")
    if not isinstance(error, dict):
        return None
    code = error.get("code")
    if code not in _PROTOCOL_VALIDATION_CODES:
        return None
    if probe.protocol_error_is_expected and code in _REQUEST_LEVEL_CODES:
        # The probe's security control IS rejection of a malformed/oversized
        # request (T10 size/nesting limits) and the server emitted a REQUEST-
        # LEVEL rejection (-32600/-32700) — the limit fired.  NOT suppressed for
        # -32601/-32602: those are indistinguishable from "tool absent" and can
        # never be proof a control fired (adversary EXPLOIT 1).
        return None
    msg = str(error.get("message", ""))[:200]
    return (
        f"Server returned JSON-RPC protocol error {code} ({msg!r}). The "
        f"probe's assumed method/tool was not found or the arguments did "
        f"not match the tool schema, so the security property could not be "
        f"reached. This test is INCONCLUSIVE: a protocol-level rejection is "
        f"not evidence that the security control under test was enforced."
    )


def _detect_schema_mismatch(response: dict[str, Any]) -> str | None:
    """Return an inconclusive reason string if the response indicates the server
    rejected the probe due to argument/schema validation rather than the
    security property being tested.  Returns None when the response looks like
    a genuine security-relevant outcome.
    """
    # Only relevant when the server returned a content-layer error
    result = response.get("result", {})
    if not isinstance(result, dict):
        return None
    if not result.get("isError"):
        return None

    # Extract text from MCP content array
    content = result.get("content", [])
    text_parts: list[str] = []
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                text_parts.append(item["text"])
    elif isinstance(content, str):
        text_parts.append(content)
    error_text = " ".join(text_parts).lower()

    for kw in _SCHEMA_MISMATCH_KEYWORDS:
        if kw in error_text:
            snippet = " ".join(text_parts)[:200]
            return (
                f"Probe payload did not match the server's tool schema — "
                f"server rejected for: {snippet!r}. "
                f"This test is INCONCLUSIVE: the security property could not be "
                f"verified because the probe arguments were not accepted by the tool."
            )
    return None


def _to_json_safe(obj: Any) -> Any:
    """Recursively convert MappingProxyType/tuple to dict/list for JSON serialisation.

    Catalog payloads are frozen (MappingProxyType + tuple) for immutability.
    The transport layer calls json.dumps, which rejects both types.
    This converts them to plain Python containers before the network hop.
    """
    if isinstance(obj, types.MappingProxyType):
        return {k: _to_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, dict):
        return {k: _to_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (tuple, list)):
        return [_to_json_safe(item) for item in obj]
    return obj


class ProbeContext:
    """Binds an active MCPSession to the harness and executes individual probes.

    One ProbeContext is created per isolated probe run (in the subprocess).
    It is not reused across probes.

    Parameters
    ----------
    session:
        An already-started MCPSession (start() has been called).
    config:
        Scan configuration used when creating the session.
    target_url:
        The base URL of the target MCP server.
    """

    def __init__(
        self,
        session: MCPSession,
        config: ScanConfig,
        target_url: str,
    ) -> None:
        self._session = session
        self._config = config
        self._target_url = target_url

    async def execute_probe(
        self,
        probe: Probe,
        threat: ThreatDefinition,
        variables: dict[str, str] | None = None,
        discovered_tool: DiscoveredTool | None = None,
    ) -> ProbeResult:
        """Execute a single probe and return an immutable ProbeResult.

        Template variables are substituted from ``variables``, with
        ``target_url`` defaulting to the context's target URL.
        All exceptions are caught and surfaced via ProbeResult.error.

        ``discovered_tool`` is passed for context (e.g. logging) but retry
        logic lives in the parent ProbeRunner — synthesis happens before fork.
        """
        vars_: dict[str, str] = dict(variables or {})
        vars_.setdefault("target_url", self._target_url)
        vars_.setdefault("session_id", "")
        vars_.setdefault("tool_name", "")

        # Substitute template variables before sending.
        # _to_json_safe converts MappingProxyType/tuple → dict/list so that
        # template substitution and json.dumps both work on plain containers.
        try:
            payload_dict: dict[str, Any] = _to_json_safe(probe.payload)
            resolved_payload = substitute_probe_payload(payload_dict, vars_)
        except Exception as exc:
            return make_probe_result(
                probe_id=probe.id,
                threat_id=threat.id,
                passed=False,
                assertions=(),
                error=f"Template substitution failed: {exc}",
            )

        probe_override_headers = dict(probe.probe_headers) if probe.probe_headers else None

        start = time.monotonic()
        try:
            response = await self._dispatch(probe.method, resolved_payload, override_headers=probe_override_headers)  # noqa: E501
        except Exception as exc:
            duration = time.monotonic() - start
            return make_probe_result(
                probe_id=probe.id,
                threat_id=threat.id,
                passed=False,
                assertions=(),
                error=f"Transport error: {exc}",
                duration_seconds=duration,
            )

        duration = time.monotonic() - start

        # Populate _body for response.body assertions
        body_parts: list[str] = []
        if "result" in response:
            body_parts.append(json.dumps(response["result"], ensure_ascii=False))
        if "error" in response:
            body_parts.append(json.dumps(response["error"], ensure_ascii=False))
        response = dict(response)
        response["_body"] = " ".join(body_parts)

        assertion_results = tuple(
            evaluate_assertion(a, response) for a in probe.assertions
        )
        passed = all(ar.passed for ar in assertion_results)

        # Detect inconclusive: server rejected the probe payload for schema/
        # argument-validation reasons unrelated to the security property being
        # tested.  This prevents false positives when probe arguments don't
        # match a server's tool schema.  Two layers:
        #   1. content-layer isError text matching validation keywords;
        #   2. JSON-RPC protocol errors (-32601/-32602/-32600/-32700) that mean
        #      the probe never reached the tool's security logic.  This is the
        #      core fix that makes "reject = secure" probes INCONCLUSIVE rather
        #      than vacuously PASS on a method-not-found (audit COV-06).
        inconclusive_reason = (
            _detect_schema_mismatch(response)
            or _detect_protocol_error(response, probe)
        )

        # Corroboration (schema 1.1): a probe whose primary assertions FAIL is
        # only reported as a finding when ALL positive-evidence (corroboration)
        # assertions hold.  Without that evidence the failure is treated as
        # INCONCLUSIVE (uncorroborated) — it suppresses noise (e.g. an
        # incidental "root:" substring, or a non-auth-class error) without ever
        # converting a real finding into a pass.  Corroboration is only
        # consulted when the probe would otherwise be a finding and the
        # response was not already inconclusive for schema reasons.
        if (
            not passed
            and probe.corroboration
            and inconclusive_reason is None
        ):
            corro_results = tuple(
                evaluate_assertion(a, response) for a in probe.corroboration
            )
            if not all(cr.passed for cr in corro_results):
                missing = "; ".join(
                    f"{cr.target} {cr.operator} {cr.expected}"
                    for cr in corro_results
                    if not cr.passed
                )
                inconclusive_reason = (
                    "Primary assertion failed but corroborating positive "
                    f"evidence was absent ({missing}). This test is "
                    "INCONCLUSIVE: a single uncorroborated signal is not "
                    "sufficient to report a finding."
                )

        # An INCONCLUSIVE result is NEITHER a pass NOR a finding: the security
        # property could not be verified.  Forcing passed=False here is what
        # stops a vacuous PASS from counting as a clean verdict downstream
        # (api.py has_clean / scorecard PASS grade).  Without this, a probe
        # whose assertion held only because the payload was rejected at the
        # boundary would be reported as "tested and secure" (audit §2).
        final_passed = passed and inconclusive_reason is None

        return make_probe_result(
            probe_id=probe.id,
            threat_id=threat.id,
            passed=final_passed,
            assertions=assertion_results,
            response=response,
            duration_seconds=duration,
            inconclusive_reason=inconclusive_reason,
        )

    async def _dispatch(
        self,
        method: str,
        payload: dict[str, Any],
        override_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Route a probe's method to the appropriate session call."""
        if method == "tools/call":
            name = str(payload.get("name", ""))
            arguments: dict[str, Any] = payload.get("arguments", {})
            if not isinstance(arguments, dict):
                arguments = {}
            return await self._session.tools_call(name, arguments, override_headers=override_headers)  # noqa: E501
        # Default: send via the public session API — never bypass the session layer
        return await self._session.send_raw(method, payload, override_headers=override_headers)
