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
from cosai_mcp.harness.result import AssertionResult, ProbeResult, make_probe_result
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
            response = await self._dispatch(probe.method, resolved_payload, override_headers=probe_override_headers)
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
        # match a server's tool schema.
        inconclusive_reason = _detect_schema_mismatch(response)

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

        return make_probe_result(
            probe_id=probe.id,
            threat_id=threat.id,
            passed=passed,
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
            return await self._session.tools_call(name, arguments, override_headers=override_headers)
        # Default: send via the public session API — never bypass the session layer
        return await self._session.send_raw(method, payload, override_headers=override_headers)
