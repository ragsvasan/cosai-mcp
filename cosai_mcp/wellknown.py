"""RFC 9728 Protected Resource Metadata (PRM) discovery check — CoSAI v2.0 SD-04.

When an MCP server demands authentication (HTTP 401 to an unauthenticated
request), MCP clients discover its authorization server through Protected
Resource Metadata: the ``resource_metadata`` parameter of the
``WWW-Authenticate`` challenge, or the well-known URL derived from the MCP
endpoint (RFC 9728 §3.1). This passive check verifies that metadata exists,
names this server as the resource, and lists HTTPS authorization servers.

Network contract (Mnemo dec_451b2d49f9): every request goes through the
DNS-pinned transport to the scanned target's OWN origin only. A server-supplied
``resource_metadata`` URL on another origin is reported, never fetched.

Probe ids ``T01-prm-5`` / ``T01-prm-6`` are INCONCLUSIVE but record that an
HTTP 401 was observed (the target demands authentication).

Results use the bare category id ``"T01"`` (passive-scan convention, SARIF stub
``T01-100``). Hostile text is capped and HTML-escaped at ingestion.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from cosai_mcp.config import ScanConfig
from cosai_mcp.exceptions import CosaiMCPError
from cosai_mcp.harness.result import ProbeResult, _html_escape

_RESOURCE_METADATA_RE = re.compile(r'resource_metadata\s*=\s*"([^"]{1,2048})"', re.I)
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_MAX_AUTH_SERVERS = 16


def _result(idx: str, *, passed: bool, detail: str,
            inconclusive: str | None = None) -> ProbeResult:
    return ProbeResult(
        probe_id=f"T01-prm-{idx}",
        threat_id="T01",
        passed=passed,
        status_code=None,
        response_body=_html_escape(detail[:2000]),
        error=None,
        assertions=(),
        duration_seconds=0.0,
        inconclusive_reason=_html_escape(inconclusive) if inconclusive else None,
    )


def _canonical(url: str) -> str | None:
    """Normalize a URL for comparison: lowercase scheme/host, drop the default
    port, strip one trailing slash. None if unparseable."""
    try:
        u = httpx.URL(url)
    except (httpx.InvalidURL, ValueError, TypeError):
        return None
    if not u.scheme or not u.host:
        return None
    default = {"http": 80, "https": 443}.get(u.scheme.lower())
    port = "" if u.port in (None, default) else f":{u.port}"
    host = u.host.lower()
    host = f"[{host}]" if ":" in host else host
    path = u.path.rstrip("/")
    return f"{u.scheme.lower()}://{host}{port}{path}"


def _validate_prm(doc: Any, expected_resource: str, target_is_loopback: bool) -> list[str]:
    """RFC 9728 / MCP consistency problems in a PRM document.

    ``expected_resource`` is the identifier the metadata URL was derived from
    (RFC 9728 §3.3): the MCP endpoint, or the origin only for the root
    well-known document.
    """
    problems: list[str] = []
    if not isinstance(doc, dict):
        return ["metadata is not a JSON object"]
    resource = doc.get("resource")
    if not isinstance(resource, str) or not resource:
        problems.append("'resource' is missing")
    elif _canonical(resource) != _canonical(expected_resource):
        problems.append("'resource' does not identify this MCP server "
                        f"({resource[:200]!r} vs {expected_resource!r})")
    servers = doc.get("authorization_servers")
    if not isinstance(servers, list) or not servers:
        problems.append("'authorization_servers' is missing or empty")
        return problems
    if len(servers) > _MAX_AUTH_SERVERS:
        problems.append(f"'authorization_servers' lists {len(servers)} entries "
                        f"(more than {_MAX_AUTH_SERVERS})")
    for srv in servers:
        try:
            parsed = urlparse(srv) if isinstance(srv, str) else None
            host = parsed.hostname if parsed is not None else None
        except ValueError:
            parsed, host = None, None
        if parsed is None or not parsed.netloc or not host:
            problems.append(f"authorization server is not a URL: {str(srv)[:200]!r}")
        elif parsed.scheme != "https" and not (target_is_loopback and host in _LOOPBACK_HOSTS):
            problems.append(f"authorization server is not HTTPS: {str(srv)[:200]!r}")
    return problems


async def _scan_async(target_url: str, config: ScanConfig) -> list[ProbeResult]:
    from cosai_mcp.transport.streamable_http import StreamableHTTPTransport

    noauth = dataclasses.replace(config, auth_token=None, auth_header=None)
    per_request = config.probe_timeout_seconds
    transport = StreamableHTTPTransport(target_url, noauth)
    await transport.connect()
    try:
        endpoint = transport.endpoint
        target_is_loopback = (urlparse(endpoint).hostname or "") in _LOOPBACK_HOSTS
        probe = json.dumps({"jsonrpc": "2.0", "id": "cosai-prm", "method": "tools/list",
                            "params": {}}).encode()
        status, headers, _ = await asyncio.wait_for(
            transport.request_raw("POST", endpoint, content=probe), timeout=per_request)
        if status != 401:
            return [_result("1", passed=False, detail=f"unauthenticated request → HTTP {status}",
                            inconclusive=(
                                "The server did not answer an unauthenticated request with "
                                "HTTP 401, so Protected Resource Metadata discovery does not "
                                "apply. INCONCLUSIVE."))]

        notes: list[str] = []
        parsed = urlparse(endpoint)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        base = f"{origin}/.well-known/oauth-protected-resource"
        path = parsed.path.rstrip("/")
        # (url, expected resource identifier) — RFC 9728 §3.3
        candidates: list[tuple[str, str]] = []
        advertised = _RESOURCE_METADATA_RE.search(headers.get("www-authenticate", ""))
        if advertised:
            try:
                url = urljoin(endpoint, advertised.group(1))
                same = transport.same_origin(url)
            except (ValueError, httpx.InvalidURL):
                return [_result("4", passed=False, detail=(
                    "WWW-Authenticate resource_metadata is malformed: "
                    f"{advertised.group(1)[:200]!r}"))]
            if same:
                candidates.append((url, endpoint))
            else:
                notes.append("WWW-Authenticate resource_metadata points to another origin "
                             f"({url[:200]!r}); reported, not fetched.")
        if path:
            candidates.append((base + path, endpoint))
        candidates.append((base, origin if not path else endpoint))

        # A location that timed out, redirected, or returned an unreadable body
        # is UNDETERMINED: it may hold valid metadata a real client would reach
        # (same-origin redirects are followed by MCP SDKs, and the pinned
        # transport rejects 3xx before the Location is visible). FAIL only when
        # every location gave a definite negative (round-3 FIX 1/2).
        undetermined = False
        for url, expected in candidates:
            try:
                g_status, g_headers, body = await asyncio.wait_for(
                    transport.request_raw("GET", url, headers={"Accept": "application/json"}),
                    timeout=per_request)
            except (TimeoutError, ValueError, httpx.HTTPError, CosaiMCPError):
                undetermined = True
                continue
            if g_status != 200:
                continue
            try:
                doc = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, RecursionError):
                return [_result("2", passed=False, detail=" ".join(
                    [*notes, f"Protected Resource Metadata at {url} is not valid JSON."]))]
            problems = _validate_prm(doc, expected, target_is_loopback)
            if problems:
                return [_result("2", passed=False, detail=" ".join(
                    [*notes, f"Protected Resource Metadata at {url}: " + "; ".join(problems)]))]
            if notes:
                # Clients follow the WWW-Authenticate advertisement first; the
                # advertised (off-origin) document was not fetched, so the
                # metadata clients actually use is unverified (round-2 FIX 6).
                return [_result("6", passed=False, detail=" ".join(
                    [*notes, f"Same-origin metadata at {url} is valid."]), inconclusive=(
                    "The server advertises Protected Resource Metadata on another "
                    "origin, which the scanner does not fetch; the metadata clients use "
                    "could not be verified. INCONCLUSIVE."))]
            return [_result("ok", passed=True, detail=(
                f"Protected Resource Metadata at {url} names this server and "
                "lists HTTPS authorization server(s)."))]

        if undetermined:
            return [_result("5", passed=False, detail=" ".join(notes), inconclusive=(
                "The server requires authentication (HTTP 401), but at least one "
                "metadata location redirected, timed out, or returned an unreadable "
                "response; absence of Protected Resource Metadata could not be "
                "established. INCONCLUSIVE."))]
        return [_result("3", passed=False, detail=" ".join([*notes, (
            "The server requires authentication (HTTP 401) but serves no usable RFC 9728 "
            "Protected Resource Metadata on its own origin: clients cannot discover its "
            "authorization server.")]))]
    finally:
        await transport.close()


def scan_protected_resource_metadata(target_url: str, config: ScanConfig) -> list[ProbeResult]:
    """Run the PRM check; a transport failure before the 401 is observed is
    reported INCONCLUSIVE, never clean."""
    try:
        return asyncio.run(asyncio.wait_for(
            _scan_async(target_url, config), timeout=config.probe_timeout_seconds * 5))
    except Exception as exc:  # noqa: BLE001
        return [_result("1", passed=False, detail="",
                        inconclusive=("Protected Resource Metadata check could not run "
                                      f"({type(exc).__name__}). INCONCLUSIVE."))]
