"""Streamable HTTP transport — MCP 2025-03-26 primary transport."""
from __future__ import annotations

import asyncio
import json
import secrets
import socket
from typing import Any
from urllib.parse import urlparse

import httpcore
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

class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Routes TCP connections to the pinned IP while preserving the original
    hostname for TLS SNI.

    Replacing the URL host with the raw IP (the previous approach) causes TLS
    handshake failures on servers that use SNI-based virtual hosting (e.g. GCP
    Cloud Run / Google Frontend) because the server sees an IP address in the
    SNI extension instead of the expected hostname.  This backend keeps the
    hostname in the SNI extension while routing the TCP socket to the
    pre-resolved IP, preventing mid-session DNS rebinding without breaking TLS.
    """

    def __init__(self, pinned_ip: str) -> None:
        self._pinned_ip = pinned_ip
        self._default = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        # Connect the TCP socket to the pinned IP; httpcore passes `host` as
        # server_hostname to start_tls(), so TLS SNI stays correct.
        return await self._default.connect_tcp(
            self._pinned_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_domain_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        raise NotImplementedError("Unix domain sockets are not used by the scanner")

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


class _PinnedAsyncTransport(httpx.AsyncBaseTransport):
    """Custom HTTPX transport that enforces the pinned IP on every request.

    Uses _PinnedNetworkBackend to route TCP connections to the pre-resolved IP
    without replacing the URL host, so TLS SNI contains the original hostname.
    Also re-resolves on every request to detect mid-session DNS rebinding and
    surfaces redirect responses as SuspiciousRedirectError.
    """

    def __init__(
        self,
        pinned_ip: str,
        config: ScanConfig,
        *,
        inner: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._pinned_ip = pinned_ip
        self._config = config
        if inner is not None:
            self._inner = inner
        else:
            # httpx.AsyncHTTPTransport doesn't expose network_backend in
            # httpx 0.28.x, but its internal _pool is an
            # httpcore.AsyncConnectionPool that does accept network_backend.
            # We create the transport normally, then replace _pool with one
            # backed by _PinnedNetworkBackend so TCP sockets route to the
            # pinned IP without touching the URL or TLS SNI.
            import ssl as _ssl
            t = httpx.AsyncHTTPTransport()
            t._pool = httpcore.AsyncConnectionPool(
                ssl_context=_ssl.create_default_context(),
                network_backend=_PinnedNetworkBackend(pinned_ip),
            )
            self._inner = t

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

        # Pass the original request unchanged — the pinned network backend
        # handles IP routing at the TCP layer, leaving URL and SNI intact.
        response = await self._inner.handle_async_request(request)
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

    async def _consume_sse_response(self, response: httpx.Response) -> dict[str, Any]:
        """Drain an SSE stream and return the first data event as a dict."""
        event_data: str | None = None
        async for line in response.aiter_lines():
            line = line.strip()
            if line.startswith("data:"):
                event_data = line[len("data:"):].strip()
            elif line == "" and event_data is not None:
                parsed: dict[str, Any] = json.loads(event_data)
                try:
                    self._recv_queue.put_nowait(parsed)
                except asyncio.QueueFull:
                    pass
                event_data = None

        return await self._recv_queue.get()

    async def recv(self) -> dict[str, Any]:
        """Return the next queued server-sent message."""
        return await self._recv_queue.get()
