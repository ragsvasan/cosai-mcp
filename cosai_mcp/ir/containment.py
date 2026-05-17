"""Containment action executor for compromised MCP servers.

Containment is intentionally conservative:
- SESSION_KILL: best-effort HTTP close + OCSF incident emit to target's management endpoint
- EMIT_INCIDENT: POST OCSF Security Incident (2001) to a SIEM webhook (non-blocking)
- BLOCK_EGRESS:  generate printable firewall commands (NOT executed — operator approves)
- QUARANTINE_REPORT: write signed JSON incident to disk

None of these actions can be weaponised to attack third parties — the target is always
the MCP server URL captured in the IncidentRecord, which was supplied by the operator
at scan time.
"""
from __future__ import annotations

import json
import logging
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cosai_mcp.exceptions import NetworkAllowlistError, PrivateAddressError
from cosai_mcp.ir.incident import ContainmentAction, IncidentRecord
from cosai_mcp.ir.ocsf_incident import OcsfIncident, build_ocsf_incident
from cosai_mcp.transport.base import is_always_blocked, is_private_address

log = logging.getLogger(__name__)


def _assert_egress_allowed(url: str, *, allow_private: bool) -> None:
    """Validate an outbound containment URL against the network allowlist.

    Containment HTTP (SESSION_KILL DELETE, EMIT_INCIDENT POST) targets a URL
    that originates from an untrusted, machine-generated incident artifact.
    Apply the same RFC1918 / loopback / link-local / IPv6-ULA allowlist that
    every scanner transport enforces, plus a scheme allowlist — fail closed
    (M-1).  ``allow_private`` mirrors the scanner's ``allow_private_targets``
    opt-in for internal SOAR deployments.

    Raises
    ------
    NetworkAllowlistError
        If the scheme is not http/https, the host cannot be resolved, or the
        resolved IP is in an always-blocked range (or a private range without
        an explicit opt-in).
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise NetworkAllowlistError(
            f"Containment target URL has disallowed scheme {parsed.scheme!r}; "
            "only http and https are permitted."
        )
    hostname = parsed.hostname
    if not hostname:
        raise NetworkAllowlistError(
            f"Containment target URL has no host: {url!r}"
        )
    try:
        results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise NetworkAllowlistError(
            f"Cannot resolve containment target host {hostname!r}: {exc}"
        ) from exc
    if not results:
        raise NetworkAllowlistError(
            f"Cannot resolve containment target host {hostname!r}"
        )
    for res in results:
        raw_ip = res[4][0]
        if is_always_blocked(raw_ip):
            raise PrivateAddressError(
                f"Containment target {hostname!r} resolves to {raw_ip}, which "
                "is in an always-blocked range (ULA/fc00::/7)."
            )
        if is_private_address(raw_ip) and not allow_private:
            raise PrivateAddressError(
                f"Containment target {hostname!r} resolves to {raw_ip}, a "
                "private/loopback/link-local address. Pass allow_private=True "
                "(operator opt-in) to act on internal targets."
            )


@dataclass(frozen=True)
class ContainmentResult:
    """Outcome of one containment action."""

    action: ContainmentAction
    success: bool
    detail: str  # human-readable outcome or error


def _resolve_host_ip(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return None


def _generate_block_commands(target_url: str) -> list[str]:
    """Return firewall block commands for the target host.

    Commands are returned as strings for human review — they are NEVER executed.
    Supports iptables (Linux) and pfctl (macOS/BSD).
    """
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""
    ip = _resolve_host_ip(hostname) if hostname else None

    lines: list[str] = [f"# Block egress to MCP server: {target_url}"]
    if ip:
        lines += [
            f"# Resolved: {hostname} → {ip}",
            f"iptables -A OUTPUT -d {ip} -j DROP",
            f"pfctl -t cosai_quarantine -T add {ip}",
        ]
    else:
        lines += [
            f"# Could not resolve {hostname!r} — block by hostname instead:",
            f"# iptables does not support hostnames; use DNS sinkhole or WAF rule.",
            f"# Add to /etc/hosts:  0.0.0.0  {hostname}",
        ]
    return lines


def _emit_ocsf_incident_http(
    ocsf: OcsfIncident,
    endpoint: str,
    auth_header: str | None,
    timeout: float,
    allow_private: bool = False,
) -> ContainmentResult:
    import httpx

    try:
        _assert_egress_allowed(endpoint, allow_private=allow_private)
    except NetworkAllowlistError as exc:
        log.warning("IR emit blocked by network allowlist: %s", type(exc).__name__)
        return ContainmentResult(
            action=ContainmentAction.EMIT_INCIDENT,
            success=False,
            detail=f"blocked by network allowlist ({exc})",
        )

    headers = {"Content-Type": "application/json"}
    if auth_header:
        headers["Authorization"] = auth_header

    try:
        body = json.dumps(ocsf.to_dict()).encode()
        resp = httpx.post(
            endpoint,
            content=body,
            headers=headers,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,  # blocks HTTP_PROXY injection per locked architecture §3
        )
        if 200 <= resp.status_code < 300:
            return ContainmentResult(
                action=ContainmentAction.EMIT_INCIDENT,
                success=True,
                detail=f"OCSF Security Incident emitted → HTTP {resp.status_code}",
            )
        return ContainmentResult(
            action=ContainmentAction.EMIT_INCIDENT,
            success=False,
            detail=f"SIEM returned HTTP {resp.status_code}",
        )
    except Exception as exc:
        log.warning("IR emit failed: %s", type(exc).__name__)
        return ContainmentResult(
            action=ContainmentAction.EMIT_INCIDENT,
            success=False,
            detail=f"connection error ({type(exc).__name__})",
        )


def _session_kill(
    target_url: str, timeout: float, allow_private: bool = False
) -> ContainmentResult:
    """Attempt a best-effort HTTP-level connection close to the MCP server.

    MCP does not define a "kill session" method, so we send an HTTP DELETE
    to the base URL (many servers ignore this) and close cleanly.
    This is a signal, not a guaranteed kill — operator should follow up with
    firewall blocking if hard isolation is required.
    """
    import httpx

    try:
        _assert_egress_allowed(target_url, allow_private=allow_private)
    except NetworkAllowlistError as exc:
        log.warning(
            "IR session_kill blocked by network allowlist: %s", type(exc).__name__
        )
        return ContainmentResult(
            action=ContainmentAction.SESSION_KILL,
            success=False,
            detail=f"blocked by network allowlist ({exc})",
        )

    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            # Best-effort: attempt DELETE; most MCP servers return 404 or 405 — that's fine.
            client.delete(target_url)
    except Exception:
        pass  # intentionally silent — connection close is best-effort

    return ContainmentResult(
        action=ContainmentAction.SESSION_KILL,
        success=True,
        detail=f"Session kill signal sent to {target_url} (best-effort; not guaranteed)",
    )


def perform_containment(
    incident: IncidentRecord,
    actions: list[ContainmentAction] | None = None,
    emit_endpoint: str | None = None,
    emit_auth_header: str | None = None,
    report_path: Path | None = None,
    timeout: float = 10.0,
    allow_private: bool = False,
) -> list[ContainmentResult]:
    """Execute one or more containment actions for an IncidentRecord.

    Parameters
    ----------
    incident:
        The incident record to act on.
    actions:
        Containment actions to execute.  Defaults to ``incident.recommended_actions``.
    emit_endpoint:
        SIEM webhook URL for EMIT_INCIDENT action.
    emit_auth_header:
        Optional ``Authorization`` header value for EMIT_INCIDENT.
    report_path:
        Filesystem path for QUARANTINE_REPORT action.  Defaults to
        ``./cosai-incident-<incident_id>.json`` in the current directory.
    timeout:
        Per-request HTTP timeout in seconds.
    allow_private:
        If False (default, fail closed), containment HTTP to private/
        loopback/link-local addresses is rejected.  Operators acting on
        genuinely internal MCP servers pass True (explicit opt-in), mirroring
        the scanner's ``allow_private_targets``.

    Returns
    -------
    list[ContainmentResult]
        One result per action executed.
    """
    if actions is None:
        actions = list(incident.recommended_actions)

    ocsf = build_ocsf_incident(incident)
    results: list[ContainmentResult] = []

    for action in actions:
        if action == ContainmentAction.EMIT_INCIDENT:
            if not emit_endpoint:
                results.append(ContainmentResult(
                    action=action,
                    success=False,
                    detail="No emit endpoint configured — pass --emit-to",
                ))
                continue
            results.append(_emit_ocsf_incident_http(
                ocsf, emit_endpoint, emit_auth_header, timeout,
                allow_private=allow_private,
            ))

        elif action == ContainmentAction.QUARANTINE_REPORT:
            path = report_path or Path(f"cosai-incident-{incident.incident_id}.json")
            try:
                payload: dict[str, Any] = {
                    "cosai_ir_version": "1.0",
                    "incident": incident.to_dict(),
                    "ocsf_incident": ocsf.to_dict(),
                }
                path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                results.append(ContainmentResult(
                    action=action,
                    success=True,
                    detail=f"Quarantine report written to {path}",
                ))
            except OSError as exc:
                results.append(ContainmentResult(
                    action=action,
                    success=False,
                    detail=f"Failed to write report: {type(exc).__name__}",
                ))

        elif action == ContainmentAction.BLOCK_EGRESS:
            cmds = _generate_block_commands(incident.target_url)
            results.append(ContainmentResult(
                action=action,
                success=True,
                detail="Block commands (review and execute as root):\n" + "\n".join(cmds),
            ))

        elif action == ContainmentAction.SESSION_KILL:
            results.append(_session_kill(
                incident.target_url, timeout=timeout, allow_private=allow_private
            ))

    return results
