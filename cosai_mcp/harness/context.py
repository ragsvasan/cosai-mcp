"""ProbeContext — wraps MCPSession + config + target, executes single probes."""
from __future__ import annotations

import json
import time
from typing import Any

from cosai_mcp.catalog.models import Probe, ThreatDefinition
from cosai_mcp.catalog.template import substitute_probe_payload
from cosai_mcp.config import ScanConfig
from cosai_mcp.harness.assertions import evaluate_assertion
from cosai_mcp.harness.result import AssertionResult, ProbeResult, make_probe_result
from cosai_mcp.session import MCPSession


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
    ) -> ProbeResult:
        """Execute a single probe and return an immutable ProbeResult.

        Template variables are substituted from ``variables``, with
        ``target_url`` defaulting to the context's target URL.
        All exceptions are caught and surfaced via ProbeResult.error.
        """
        vars_: dict[str, str] = dict(variables or {})
        vars_.setdefault("target_url", self._target_url)
        vars_.setdefault("session_id", "")
        vars_.setdefault("tool_name", "")

        # Substitute template variables before sending
        try:
            payload_dict: dict[str, Any] = dict(probe.payload)
            resolved_payload = substitute_probe_payload(payload_dict, vars_)
        except Exception as exc:
            return make_probe_result(
                probe_id=probe.id,
                threat_id=threat.id,
                passed=False,
                assertions=(),
                error=f"Template substitution failed: {exc}",
            )

        start = time.monotonic()
        try:
            response = await self._dispatch(probe.method, resolved_payload)
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

        return make_probe_result(
            probe_id=probe.id,
            threat_id=threat.id,
            passed=passed,
            assertions=assertion_results,
            response=response,
            duration_seconds=duration,
        )

    async def _dispatch(
        self, method: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Route a probe's method to the appropriate session call."""
        if method == "tools/call":
            name = str(payload.get("name", ""))
            arguments: dict[str, Any] = payload.get("arguments", {})
            if not isinstance(arguments, dict):
                arguments = {}
            return await self._session.tools_call(name, arguments)
        # Default: send via the public session API — never bypass the session layer
        return await self._session.send_raw(method, payload)
