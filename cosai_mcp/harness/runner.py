"""ProbeRunner — multiprocessing.Process isolation, OS-level timeout per probe.

Architecture (non-negotiable from locked decisions):
- Each probe runs in its own multiprocessing.Process
- No shared memory between probes
- OS-enforced timeout via Process.join(timeout=)
- Results passed back via multiprocessing.Queue as plain dicts
- The subprocess creates its own transport + session (no inherited connections)

Adaptive probe synthesis (P10):
- If a probe returns INCONCLUSIVE (schema mismatch) and a DiscoveredTool is
  available, the parent synthesizes a new payload and retries ONCE.
- Synthesis is pure (no I/O) and runs in the parent before the second fork.
- A second INCONCLUSIVE marks synthesis_attempted=True — distinguishes
  "we tried" from "we didn't try".
- --no-adaptive (passed as adaptive=False) disables all synthesis; results
  are identical to pre-P10 behavior.
"""
from __future__ import annotations

import asyncio
import dataclasses
import multiprocessing
import time
import types
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cosai_mcp.discovery import DiscoveredTool

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
    d: dict[str, Any] = {
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
    if probe.probe_token is not None:
        d["probe_token"] = probe.probe_token
    if probe.probe_count != 1:
        d["probe_count"] = probe.probe_count
    if probe.probe_headers is not None:
        d["probe_headers"] = dict(probe.probe_headers)
    return d


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
    raw_headers = d.get("probe_headers")
    return Probe(
        id=d["id"],
        transport=d["transport"],
        method=d["method"],
        payload=types.MappingProxyType(d["payload"]),
        assertions=assertions,
        probe_token=d.get("probe_token"),
        probe_count=d.get("probe_count", 1),
        probe_headers=types.MappingProxyType(raw_headers) if raw_headers else None,
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


def _is_transport_inconclusive(result: "ProbeResult") -> bool:
    """Return True when *result* is inconclusive due to a transport failure
    during the MCP initialize handshake (as opposed to a schema mismatch).

    Transport inconclusives are candidates for retry-with-backoff because the
    server may simply be rate-limiting new sessions; the probe payload itself
    is not at fault.  Schema-mismatch inconclusives are handled separately by
    adaptive synthesis.
    """
    return (
        result.inconclusive_reason is not None
        and "MCP handshake" in (result.inconclusive_reason or "")
    )


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
        import dataclasses
        from cosai_mcp.exceptions import SessionIncompleteError
        from cosai_mcp.harness.context import ProbeContext
        from cosai_mcp.session import MCPSession

        probe = _probe_from_dict(probe_dict)
        threat = _threat_from_dict(threat_dict)

        # Apply probe_token: select the appropriate bearer token for this probe.
        effective_config = config
        if probe.probe_token == "read":
            if not config.read_token:
                # No read-scoped token configured — probe is inconclusive.
                return make_probe_result(
                    probe_id=probe.id,
                    threat_id=threat.id,
                    passed=False,
                    assertions=(),
                    error=None,
                    duration_seconds=0.0,
                    inconclusive_reason=(
                        "probe_token='read' requires --read-token to be configured; "
                        "skipping scope-enforcement probe"
                    ),
                ).to_dict()
            effective_config = dataclasses.replace(
                config,
                auth_token=config.read_token,
                auth_header=None,
            )

        # Apply probe_headers: merge into extra_request_headers for this probe.
        if probe.probe_headers:
            merged = dict(effective_config.extra_request_headers or {})
            merged.update(probe.probe_headers)
            effective_config = dataclasses.replace(
                effective_config,
                extra_request_headers=merged,
            )

        # Finding 6: dispatch on probe.transport, not hardcoded HTTP
        transport_type = probe_dict.get("transport", "http")
        if transport_type == "http":
            from cosai_mcp.transport.streamable_http import StreamableHTTPTransport
            transport = StreamableHTTPTransport(target_url, effective_config)
        elif transport_type == "stdio":
            from cosai_mcp.transport.stdio import StdioTransport
            # For stdio probes target_url is the executable path
            transport = StdioTransport([target_url], effective_config)
        else:
            raise ValueError(f"Unknown transport type: {transport_type!r}")

        await transport.connect()
        try:
            session = MCPSession(transport, effective_config, target_url=target_url)
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
                # Transport failure during initialize — the probe never ran.
                # This is a scanner infrastructure problem, not a security verdict.
                return make_probe_result(
                    probe_id=probe.id,
                    threat_id=threat.id,
                    passed=False,
                    assertions=(),
                    error=str(exc),
                    duration_seconds=0.0,
                    inconclusive_reason=(
                        f"Scanner could not complete MCP handshake ({exc}) — "
                        "security property could not be verified"
                    ),
                ).to_dict()
            ctx = ProbeContext(session, effective_config, target_url)

            # probe_count > 1: repeat the probe N times (rate-limit detection).
            # Return the first result that passes all assertions; fall through
            # to the last result if none pass.
            if probe.probe_count > 1:
                last_result = None
                for _ in range(probe.probe_count):
                    last_result = await ctx.execute_probe(probe, threat, variables)
                    if last_result.passed:
                        return last_result.to_dict()
                return last_result.to_dict()  # type: ignore[union-attr]

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

def _synthesize_probe(
    probe: Probe,
    threat: ThreatDefinition,
    discovered_tool: DiscoveredTool,
) -> Probe | None:
    """Synthesize a new Probe with a schema-aware payload.

    Returns a new Probe with a synthesized payload, or None if synthesis
    is not applicable or fails.  Synthesis is pure — no I/O, no subprocess.

    Returns None when:
    - probe.method is not "tools/call" (synthesis only valid for tools/call)
    - synthesize_probe_payload raises ValueError (template-escape guard)
    - any unexpected exception (logged as None → caller returns synthesis_attempted)
    """
    # Guard: synthesis only produces tools/call-shaped payloads.  Applying
    # synthesis to tools/list, initialize, or other method probes would corrupt
    # the payload and produce misleading results (Sonnet P1).
    if probe.method != "tools/call":
        return None

    # Guard: T2 (confused-deputy / missing access control) probes test security
    # via adversarial parameter NAMES (e.g. session_id, role, privilege_level).
    # Synthesis replaces those names with the tool's real parameters, turning a
    # deliberate confused-deputy probe into a benign functional call that will
    # succeed — producing a false positive.  Disable synthesis for T2 entirely.
    if threat.category.upper() == "T2":
        return None

    from cosai_mcp.synthesis import synthesize_probe_payload, threat_pattern_from_category

    try:
        pattern = threat_pattern_from_category(threat.category)
        catalog_payload_dict = _to_json_safe(probe.payload)
        synth_payload = synthesize_probe_payload(discovered_tool, pattern, catalog_payload_dict)
        return Probe(
            id=probe.id,
            transport=probe.transport,
            method=probe.method,
            payload=synth_payload,
            assertions=probe.assertions,
            probe_token=probe.probe_token,
            probe_count=probe.probe_count,
            probe_headers=probe.probe_headers,
        )
    except ValueError:
        # Expected from template-escape guard or missing adversarial value (P2 fix)
        return None
    except Exception:
        # Unexpected exception — treat as synthesis failure, not scanner crash
        return None


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

    def _run_subprocess_once(
        self,
        probe: Probe,
        threat: ThreatDefinition,
        variables: dict[str, str] | None,
        timeout: float,
        pass_on_auth_reject: bool,
    ) -> ProbeResult:
        """Spawn one isolated subprocess for *probe* and return the result.

        This is the primitive used by ``run_probe`` for both the initial
        attempt and transport-level retries.  It does not perform synthesis or
        backoff — callers are responsible for those layers.
        """
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

    def run_probe(
        self,
        probe: Probe,
        threat: ThreatDefinition,
        variables: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
        pass_on_auth_reject: bool = False,
        discovered_tool: DiscoveredTool | None = None,
    ) -> ProbeResult:
        """Execute a probe in an isolated subprocess and return the result.

        If the subprocess times out, it is killed and a timeout ProbeResult
        is returned (passed=False, error describes the timeout).

        If the result is INCONCLUSIVE due to a transport error during the MCP
        initialize handshake (e.g. rate_limit_exceeded), the probe is retried
        up to ``config.max_probe_retries`` times with exponential backoff
        (``config.retry_backoff_seconds * 2^attempt``).

        If after retries the result is still INCONCLUSIVE due to a schema
        mismatch (server rejected the payload) and ``discovered_tool`` is
        provided, the parent synthesizes an adapted payload and retries once.
        Synthesis is pure (no I/O) and runs before the second fork.  If the
        retry is also INCONCLUSIVE, returns that result with
        ``synthesis_attempted=True``.

        Parameters
        ----------
        pass_on_auth_reject:
            Passed through to the subprocess.  Set *True* for T1 auth-
            enforcement probes so that a server-side auth rejection at
            initialize time is treated as a PASS rather than a scanner error.
        discovered_tool:
            Optional tool schema snapshot from pre-scan discovery.  When
            provided and the first attempt is INCONCLUSIVE, enables one
            adaptive retry with a synthesized payload.
        """
        timeout = timeout_seconds if timeout_seconds is not None else self._config.probe_timeout_seconds
        result = self._run_subprocess_once(probe, threat, variables, timeout, pass_on_auth_reject)

        # --- Transport-level retry with exponential backoff ---
        # When the MCP initialize handshake is rejected (rate limit, transient
        # server error), the probe never ran — no security verdict is possible.
        # Retry up to max_probe_retries times; each attempt doubles the delay.
        # This is distinct from adaptive synthesis: we are not changing the
        # payload, just giving the server time to recover.
        max_retries = self._config.max_probe_retries
        if max_retries > 0 and _is_transport_inconclusive(result):
            for attempt in range(max_retries):
                backoff = self._config.retry_backoff_seconds * (2.0 ** attempt)
                time.sleep(backoff)
                retry = self._run_subprocess_once(
                    probe, threat, variables, timeout, pass_on_auth_reject
                )
                if not _is_transport_inconclusive(retry):
                    result = retry
                    break
            else:
                # All retries exhausted — result stays transport-inconclusive.
                pass

        # --- Adaptive retry (P10) — schema-mismatch inconclusive ---
        # If still INCONCLUSIVE (schema mismatch) and a discovered tool is
        # available, synthesize a schema-aware payload and retry once.
        # Synthesis is pure (no I/O) — runs here in the parent before the fork.
        if (
            result.inconclusive_reason is not None
            and not _is_transport_inconclusive(result)
            and discovered_tool is not None
        ):
            adapted_probe = _synthesize_probe(probe, threat, discovered_tool)
            if adapted_probe is not None:
                # One retry — recursive call WITHOUT discovered_tool to prevent
                # infinite retry loops.
                retry_result = self.run_probe(
                    adapted_probe,
                    threat,
                    variables,
                    timeout_seconds,
                    pass_on_auth_reject,
                    discovered_tool=None,  # no further retries
                )
                # Always set synthesis_attempted=True on the retry result so that
                # PASS and FAIL outcomes are distinguishable from natural first-run
                # results in reports and audit trails (Sonnet P1 fix).
                return dataclasses.replace(retry_result, synthesis_attempted=True)
            # Synthesis failed (ValueError / unexpected error) — fall through
            # and return original result with synthesis_attempted=True to signal
            # that we tried but could not synthesize a valid payload.
            return dataclasses.replace(result, synthesis_attempted=True)

        return result

    def run_threat(
        self,
        threat: ThreatDefinition,
        variables: dict[str, str] | None = None,
        pass_on_auth_reject: bool = False,
        discovered_tool: DiscoveredTool | None = None,
    ) -> list[ProbeResult]:
        """Run all probes for a threat definition and return results."""
        return [
            self.run_probe(
                probe,
                threat,
                variables,
                pass_on_auth_reject=pass_on_auth_reject,
                discovered_tool=discovered_tool,
            )
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
        synthesis_attempted=bool(d.get("synthesis_attempted", False)),
    )
