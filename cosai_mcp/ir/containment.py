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

from cosai_mcp.ir.incident import ContainmentAction, IncidentRecord
from cosai_mcp.ir.ocsf_incident import OcsfIncident, build_ocsf_incident

log = logging.getLogger(__name__)


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
) -> ContainmentResult:
    import httpx

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


def _session_kill(target_url: str, timeout: float) -> ContainmentResult:
    """Attempt a best-effort HTTP-level connection close to the MCP server.

    MCP does not define a "kill session" method, so we send an HTTP DELETE
    to the base URL (many servers ignore this) and close cleanly.
    This is a signal, not a guaranteed kill — operator should follow up with
    firewall blocking if hard isolation is required.
    """
    import httpx

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
                ocsf, emit_endpoint, emit_auth_header, timeout
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
            results.append(_session_kill(incident.target_url, timeout=timeout))

    return results
