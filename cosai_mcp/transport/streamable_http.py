"""Streamable HTTP transport — MCP 2025-03-26 primary transport."""
from __future__ import annotations

import asyncio
import json
import secrets
import socket
from typing import Any
from urllib.parse import urlparse

import httpx

from cosai_mcp.config import ScanConfig
from cosai_mcp.exceptions import DNSRebindingError, SuspiciousRedirectError
from cosai_mcp.transport.base import (
    Transport,
    check_dns_rebinding,
    check_redirect,
    resolve_and_pin,
)

# ---------------------------------------------------------------------------
# IP-pinning HTTPX transport
# ---------------------------------------------------------------------------

class _PinnedAsyncTransport(httpx.AsyncBaseTransport):
    """Custom HTTPX transport that enforces the pinned IP on every request.

    Rewrites the request URL host to the pinned IP before forwarding to the
    inner transport, so the kernel never re-resolves the hostname via DNS.
    Also re-resolves to detect mid-session DNS rebinding and surfaces
    redirect responses as SuspiciousRedirectError.
    """

    def __init__(
        self,
        pinned_ip: str,
        config: ScanConfig,
        *,
        inner: httpx.AsyncHTTPTransport | None = None,
    ) -> None:
        self._pinned_ip = pinned_ip
        self._config = config
        self._inner = inner or httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        try:
            results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise DNSRebindingError(f"Failed to resolve {host!r}: {exc}") from exc

        if results:
            # Prefer IPv4 to match the address family used by resolve_and_pin.
            results.sort(key=lambda r: 0 if r[0] == socket.AF_INET else 1)
            actual_ip = results[0][4][0]
            check_dns_rebinding(self._pinned_ip, actual_ip)

        # FIX: substitute the pinned IP into the URL so the inner transport
        # connects to the verified IP rather than re-resolving via kernel DNS.
        # The Host header in request.headers retains the original hostname.
        # sni_hostname preserves the original hostname for TLS SNI so SNI-gated
        # servers (Cloud Run, Cloudflare) don't reject the handshake when the
        # URL host is rewritten to a bare IP address.
        pinned_url = request.url.copy_with(host=self._pinned_ip)
        pinned_request = httpx.Request(
            method=request.method,
            url=pinned_url,
            headers=request.headers,
            stream=request.stream,
            extensions={**request.extensions, "sni_hostname": host.encode()},
        )
        response = await self._inner.handle_async_request(pinned_request)
        check_redirect(response.status_code)
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()


# ---------------------------------------------------------------------------
# StreamableHTTPTransport
# ---------------------------------------------------------------------------

class StreamableHTTPTransport(Transport):
    """MCP 2025-03-26 Streamable HTTP transport.

    Single-endpoint POST semantics.  Response is either:
    * ``application/json`` — direct JSON-RPC response
    * ``text/event-stream`` — SSE stream carrying one or more JSON-RPC messages

    Session affinity is maintained via the optional ``Mcp-Session-Id`` header.
    """

    def __init__(self, base_url: str, config: ScanConfig) -> None:
        self._base_url = base_url.rstrip("/")
        self._config = config
        self._pinned_ip: str | None = None
        self._session_id: str | None = None
        self._client: httpx.AsyncClient | None = None
        self._recv_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=64)

        # Compute the single endpoint URL used for every POST.
        # If base_url already has a non-root path (user passed the full MCP URL),
        # use it as-is.  Otherwise, append mcp_path from config (user passed only
        # the origin and expects us to mount at the configured path).
        _parsed = urlparse(self._base_url)
        _url_path = _parsed.path
        if _url_path and _url_path not in ("/", ""):
            # Full URL supplied — use as-is. Caller is explicit about the path;
            # adding a trailing slash would cause 308s on Next.js/Nginx servers.
            self._endpoint = self._base_url.rstrip("/")
        else:
            _origin = f"{_parsed.scheme}://{_parsed.netloc}"
            # Trailing slash required for Starlette-mounted endpoints:
            # Mount('/mcp') issues a 307 to '/mcp/' without it.
            self._endpoint = _origin + config.mcp_path.rstrip("/") + "/"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _next_id(self) -> str:
        return secrets.token_hex(8)

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        if self._config.auth_header:
            headers["Authorization"] = self._config.auth_header
        elif self._config.auth_token:
            headers["Authorization"] = f"Bearer {self._config.auth_token}"
        if self._config.extra_request_headers:
            headers.update(self._config.extra_request_headers)
        return headers

    def _make_rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
            "params": params,
        }

    # ------------------------------------------------------------------
    # Transport lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Resolve and pin the target IP, then create the httpx client."""
        parsed = urlparse(self._base_url)
        host = parsed.hostname or self._config.target_host
        self._pinned_ip = resolve_and_pin(host, self._config)

        pinned_transport = _PinnedAsyncTransport(self._pinned_ip, self._config)
        self._client = httpx.AsyncClient(
            transport=pinned_transport,
            follow_redirects=False,   # hard-coded, non-overridable
            trust_env=False,          # blocks HTTP_PROXY injection
            timeout=self._config.probe_timeout_seconds,
        )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Core send/recv/send_notification
    # ------------------------------------------------------------------

    async def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """POST a JSON-RPC request; return the parsed response."""
        if self._client is None:
            raise RuntimeError("Transport not connected — call connect() first")

        payload = self._make_rpc(method, params)
        response = await self._client.post(
            self._endpoint,
            content=json.dumps(payload).encode(),
            headers=self._build_headers(),
        )

        check_redirect(response.status_code)

        content_type = response.headers.get("content-type", "")

        if "text/event-stream" in content_type:
            data = await self._consume_sse_response(response)
        else:
            data = response.json()
            if sid := response.headers.get("Mcp-Session-Id"):
                self._session_id = sid
        # Inject HTTP metadata for response.status_code and response.header.* assertions
        if isinstance(data, dict):
            data["_status_code"] = response.status_code
            data["_headers"] = {k.lower(): v for k, v in response.headers.items()}
        return data  # type: ignore[no-any-return]

    async def send_notification(self, notification: dict[str, Any]) -> None:
        """POST a pre-built JSON-RPC notification (no id, fire-and-forget)."""
        if self._client is None:
            return
        try:
            response = await self._client.post(
                self._endpoint,
                content=json.dumps(notification).encode(),
                headers=self._build_headers(),
            )
            check_redirect(response.status_code)
        except Exception:
            pass  # notifications are fire-and-forget

    # Hard caps so a hostile server cannot inflate scan wall-time by holding
    # an SSE stream open or dribbling keepalive bytes forever (M-3).  These
    # are independent of the per-probe multiprocessing OS-kill — that is the
    # outer backstop; this is the in-band defence.
    _SSE_MAX_LINES = 10_000

    async def _consume_sse_response(self, response: httpx.Response) -> dict[str, Any]:
        """Return the first complete JSON-RPC SSE event as a dict.

        Returns as soon as the first ``data:`` event is parsed — the whole
        stream is *not* drained.  An explicit read deadline (the configured
        probe timeout) bounds how long a slow/trickling server can stall this
        coroutine, and a hard line cap bounds memory/CPU.  A hostile target
        can therefore no longer hold a process slot for the full probe
        timeout per probe by never closing the stream.
        """
        deadline = self._config.probe_timeout_seconds

        async def _read_first() -> dict[str, Any]:
            event_data: str | None = None
            line_count = 0
            async for line in response.aiter_lines():
                line_count += 1
                if line_count > self._SSE_MAX_LINES:
                    raise TimeoutError(
                        "SSE stream exceeded line cap without a complete "
                        "JSON-RPC message — treating hostile/oversized stream "
                        "as a failed probe."
                    )
                line = line.strip()
                if line.startswith("data:"):
                    event_data = line[len("data:"):].strip()
                elif line == "" and event_data is not None:
                    parsed: dict[str, Any] = json.loads(event_data)
                    return parsed
            raise TimeoutError(
                "SSE stream ended without a complete JSON-RPC message."
            )

        return await asyncio.wait_for(_read_first(), timeout=deadline)

    async def recv(self) -> dict[str, Any]:
        """Return the next queued server-sent message."""
        return await self._recv_queue.get()
