"""ProbeRunner — multiprocessing.Process isolation, OS-level timeout per probe.

Architecture (non-negotiable from locked decisions):
- Each probe runs in its own multiprocessing.Process
- No shared memory between probes
- OS-enforced timeout via Process.join(timeout=)
- Results passed back via multiprocessing.Queue as plain dicts
- The subprocess creates its own transport + session (no inherited connections)
"""
from __future__ import annotations

import asyncio
import multiprocessing
import time
import types
from typing import Any

from cosai_mcp.catalog.models import (
    Assertion,
    Operator,
    Probe,
    Provenance,
    Severity,
    ThreatDefinition,
)
from cosai_mcp.config import ScanConfig
from cosai_mcp.harness.context import _to_json_safe
from cosai_mcp.harness.result import ProbeResult, _html_escape, make_probe_result

# ---------------------------------------------------------------------------
# Required keys every subprocess result dict must contain (Finding 1)
# ---------------------------------------------------------------------------

_REQUIRED_RESULT_KEYS: frozenset[str] = frozenset(
    {"probe_id", "threat_id", "passed", "assertions", "duration_seconds"}
)


def _validate_raw_result(raw: Any) -> dict[str, Any]:
    """Validate the raw object received from the subprocess queue.

    A malicious or buggy subprocess could put arbitrary data into the queue.
    This validates the shape before trusting any field.

    Raises
    ------
    ValueError
        If raw is not a dict or is missing required keys.
    """
    if not isinstance(raw, dict):
        raise ValueError(
            f"Queue payload must be a dict, got {type(raw).__name__!r}"
        )
    missing = _REQUIRED_RESULT_KEYS - raw.keys()
    if missing:
        raise ValueError(
            f"Queue payload missing required keys: {sorted(missing)}"
        )
    return raw


# ---------------------------------------------------------------------------
# Serialisation helpers — probes and threats as plain dicts for subprocess IPC
# ---------------------------------------------------------------------------

def _probe_to_dict(probe: Probe) -> dict[str, Any]:
    return {
        "id": probe.id,
        "transport": probe.transport,
        "method": probe.method,
        "payload": _to_json_safe(probe.payload),
        "assertions": [
            {
                "target": a.target,
                "operator": a.operator.value,
                "value": list(a.value) if isinstance(a.value, tuple) else a.value,
            }
            for a in probe.assertions
        ],
    }


def _threat_to_dict(threat: ThreatDefinition) -> dict[str, Any]:
    return {
        "id": threat.id,
        "category": threat.category,
        "severity": threat.severity.value,
        "provenance": threat.provenance.value,  # Finding 13: preserve provenance
    }


def _probe_from_dict(d: dict[str, Any]) -> Probe:
    assertions = tuple(
        Assertion(
            target=a["target"],
            operator=Operator(a["operator"]),
            value=tuple(a["value"]) if isinstance(a["value"], list) else a["value"],
        )
        for a in d["assertions"]
    )
    return Probe(
        id=d["id"],
        transport=d["transport"],
        method=d["method"],
        payload=types.MappingProxyType(d["payload"]),
        assertions=assertions,
    )


def _threat_from_dict(d: dict[str, Any]) -> ThreatDefinition:
    return ThreatDefinition(
        schema_version="1.0",
        id=d["id"],
        category=d["category"],
        severity=Severity(d["severity"]),
        cosai_ref="",
        owasp_ref="",
        cwe=(),
        probes=(),
        remediation="",
        references=(),
        provenance=Provenance(d.get("provenance", Provenance.OFFICIAL.value)),
    )


# ---------------------------------------------------------------------------
# Subprocess entry point (module-level for pickle compatibility)
# ---------------------------------------------------------------------------

# Keywords in SessionIncompleteError messages that indicate the server
# correctly rejected an unauthenticated request.  When running auth-test
# probes (T1) without a token, seeing one of these means auth IS enforced —
# the probe assertion "response.error == True" holds at the transport level.
_AUTH_REJECT_KEYWORDS: tuple[str, ...] = (
    "invalid_token",
    "authentication required",
    "401",
    "403",
    "unauthorized",
)


def _is_auth_rejection(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(kw in msg for kw in _AUTH_REJECT_KEYWORDS)


def _probe_subprocess_entry(
    result_queue: "multiprocessing.Queue[dict[str, Any]]",
    probe_dict: dict[str, Any],
    threat_dict: dict[str, Any],
    config: ScanConfig,
    target_url: str,
    variables: dict[str, str],
    pass_on_auth_reject: bool = False,
) -> None:
    """Entry point for the isolated probe subprocess.

    Creates a fresh transport + session, executes the probe, and puts
    the result dict into result_queue.  All exceptions are caught and
    surfaced as error-result dicts — this function must never raise.

    Parameters
    ----------
    pass_on_auth_reject:
        When *True* (used for T1 / auth-enforcement probes), a session
        rejection due to missing/invalid credentials is treated as a PASS
        rather than a scanner error.  The server correctly enforces auth.
    """
    async def _run() -> dict[str, Any]:
        from cosai_mcp.exceptions import SessionIncompleteError
        from cosai_mcp.harness.context import ProbeContext
        from cosai_mcp.session import MCPSession

        probe = _probe_from_dict(probe_dict)
        threat = _threat_from_dict(threat_dict)

        # Finding 6: dispatch on probe.transport, not hardcoded HTTP
        transport_type = probe_dict.get("transport", "http")
        if transport_type == "http":
            from cosai_mcp.transport.streamable_http import StreamableHTTPTransport
            transport = StreamableHTTPTransport(target_url, config)
        elif transport_type == "stdio":
            from cosai_mcp.transport.stdio import StdioTransport
            # For stdio probes target_url is the executable path
            transport = StdioTransport([target_url], config)
        else:
            raise ValueError(f"Unknown transport type: {transport_type!r}")

        await transport.connect()
        try:
            session = MCPSession(transport, config)
            try:
                await session.start()
            except SessionIncompleteError as exc:
                if pass_on_auth_reject and _is_auth_rejection(exc):
                    # Auth correctly enforced at the MCP handshake level.
                    # Synthesise a PASS result — the probe's goal is to confirm
                    # that unauthenticated access is rejected, and it was.
                    from cosai_mcp.harness.result import AssertionResult
                    assertion = AssertionResult(
                        target="response.error",
                        operator="eq",
                        expected="True",
                        actual="True",
                        passed=True,
                        message="Server correctly rejected unauthenticated initialize",
                    )
                    return make_probe_result(
                        probe_id=probe.id,
                        threat_id=threat.id,
                        passed=True,
                        assertions=(assertion,),
                        error=None,
                        duration_seconds=0.0,
                    ).to_dict()
                raise
            ctx = ProbeContext(session, config, target_url)
            result = await ctx.execute_probe(probe, threat, variables)
            return result.to_dict()
        finally:
            await transport.close()

    try:
        result = asyncio.run(_run())
        result_queue.put(result)
    except Exception as exc:
        result_queue.put({
            "probe_id": probe_dict.get("id", ""),
            "threat_id": threat_dict.get("id", ""),
            "passed": False,
            "status_code": None,
            "response_body": "",
            "error": f"Subprocess error: {exc}",
            "assertions": [],
            "duration_seconds": 0.0,
        })


# ---------------------------------------------------------------------------
# ProbeRunner
# ---------------------------------------------------------------------------

class ProbeRunner:
    """Runs probes against a target MCP server with multiprocessing isolation.

    Each call to ``run_probe`` spawns a fresh ``multiprocessing.Process``.
    The process is killed if it exceeds ``timeout_seconds``.

    Parameters
    ----------
    config:
        Scan configuration (probe_timeout_seconds used as default timeout).
    target_url:
        Base URL of the target MCP server.
    """

    def __init__(self, config: ScanConfig, target_url: str) -> None:
        self._config = config
        self._target_url = target_url

    def run_probe(
        self,
        probe: Probe,
        threat: ThreatDefinition,
        variables: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
        pass_on_auth_reject: bool = False,
    ) -> ProbeResult:
        """Execute a probe in an isolated subprocess and return the result.

        If the subprocess times out, it is killed and a timeout ProbeResult
        is returned (passed=False, error describes the timeout).

        Parameters
        ----------
        pass_on_auth_reject:
            Passed through to the subprocess.  Set *True* for T1 auth-
            enforcement probes so that a server-side auth rejection at
            initialize time is treated as a PASS rather than a scanner error.
        """
        timeout = timeout_seconds if timeout_seconds is not None else self._config.probe_timeout_seconds

        ctx: multiprocessing.context.BaseContext = multiprocessing.get_context("spawn")
        result_queue: multiprocessing.Queue[dict[str, Any]] = ctx.Queue()

        probe_dict = _probe_to_dict(probe)
        threat_dict = _threat_to_dict(threat)

        process = ctx.Process(
            target=_probe_subprocess_entry,
            args=(
                result_queue,
                probe_dict,
                threat_dict,
                self._config,
                self._target_url,
                variables or {},
                pass_on_auth_reject,
            ),
            daemon=True,
        )

        start = time.monotonic()
        process.start()
        process.join(timeout=timeout)
        elapsed = time.monotonic() - start

        if process.is_alive():
            process.kill()
            process.join()
            return make_probe_result(
                probe_id=probe.id,
                threat_id=threat.id,
                passed=False,
                assertions=(),
                error=f"Probe timed out after {timeout:.1f}s",
                duration_seconds=elapsed,
            )

        if result_queue.empty():
            return make_probe_result(
                probe_id=probe.id,
                threat_id=threat.id,
                passed=False,
                assertions=(),
                error="Probe subprocess exited without producing a result",
                duration_seconds=elapsed,
            )

        raw = result_queue.get_nowait()
        try:
            validated = _validate_raw_result(raw)
        except ValueError as exc:
            return make_probe_result(
                probe_id=probe.id,
                threat_id=threat.id,
                passed=False,
                assertions=(),
                error=f"Invalid subprocess result: {exc}",
                duration_seconds=elapsed,
            )
        return _result_from_dict(validated)

    def run_threat(
        self,
        threat: ThreatDefinition,
        variables: dict[str, str] | None = None,
        pass_on_auth_reject: bool = False,
    ) -> list[ProbeResult]:
        """Run all probes for a threat definition and return results."""
        return [
            self.run_probe(probe, threat, variables, pass_on_auth_reject=pass_on_auth_reject)
            for probe in threat.probes
        ]


def _result_from_dict(d: dict[str, Any]) -> ProbeResult:
    """Reconstruct a ProbeResult from its to_dict() output."""
    from cosai_mcp.harness.result import AssertionResult
    assertions = tuple(
        AssertionResult(
            target=a["target"],
            operator=a["operator"],
            expected=a["expected"],
            actual=a["actual"],
            passed=a["passed"],
            message=a["message"],
        )
        for a in d.get("assertions", [])
    )
    # HTML-escape fields that originate from an untrusted subprocess (Finding 11)
    raw_error = d.get("error")
    error = _html_escape(raw_error) if raw_error else None
    raw_inconclusive = d.get("inconclusive_reason")
    inconclusive = _html_escape(raw_inconclusive) if raw_inconclusive else None
    return ProbeResult(
        probe_id=d["probe_id"],
        threat_id=d["threat_id"],
        passed=d["passed"],
        status_code=d.get("status_code"),
        response_body=d.get("response_body", ""),
        error=error,
        assertions=assertions,
        duration_seconds=d.get("duration_seconds", 0.0),
        inconclusive_reason=inconclusive,
    )
