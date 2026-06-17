"""Legacy SSE transport — MCP 2024-11-05 backward compat.

Two-endpoint design:
* POST  /message  — client-to-server JSON-RPC requests
* GET   /sse      — server-to-client SSE stream (responses + server-initiated msgs)
"""
from __future__ import annotations

import asyncio
import json
import secrets
from typing import Any
from urllib.parse import urlparse

import httpx

from cosai_mcp.config import ScanConfig
from cosai_mcp.transport.base import (
    Transport,
    check_redirect,
    resolve_and_pin,
)
from cosai_mcp.transport.streamable_http import _PinnedAsyncTransport

_SSE_CLOSED_SENTINEL = object()


class LegacySSETransport(Transport):
    """MCP 2024-11-05 HTTP+SSE transport.

    Client sends requests via POST /message; server replies via an SSE stream
    on GET /sse.  Per-request futures are used for response correlation so the
    shared queue never needs to be scanned for matching IDs.
    """

    # Defensive cap on the background SSE listener so a hostile server cannot
    # drive unbounded CPU/memory by trickling lines forever.  The send() path
    # is independently bounded by asyncio.wait_for on the response future, so
    # this is belt-and-suspenders (M-3 sibling).
    _SSE_MAX_LINES = 100_000

    def __init__(self, base_url: str, config: ScanConfig) -> None:
        self._base_url = base_url.rstrip("/")
        self._config = config
        self._pinned_ip: str | None = None
        self._client: httpx.AsyncClient | None = None
        # Per-request future map: request_id → Future[response_dict]
        self._pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
        # Unsolicited server→client messages (no matching pending request)
        self._recv_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=64)
        self._sse_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _next_id(self) -> str:
        return secrets.token_hex(8)

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
        """Resolve and pin IP, create HTTP client, start SSE listener."""
        parsed = urlparse(self._base_url)
        host: str = parsed.hostname or self._config.target_host or ""
        self._pinned_ip = resolve_and_pin(host, self._config)

        pinned_transport = _PinnedAsyncTransport(self._pinned_ip, self._config)
        self._client = httpx.AsyncClient(
            transport=pinned_transport,
            follow_redirects=False,
            trust_env=False,
            timeout=self._config.probe_timeout_seconds,
        )

        self._sse_task = asyncio.create_task(self._sse_listener())

    async def _sse_listener(self) -> None:
        """Background task that drains the GET /sse stream.

        Responses matching a pending request ID resolve the associated Future.
        Unsolicited messages go into _recv_queue.  The sentinel is always
        placed in the finally block so callers never hang.
        """
        assert self._client is not None
        url = f"{self._base_url}/sse"
        try:
            async with self._client.stream("GET", url) as response:
                check_redirect(response.status_code)
                event_data: str | None = None
                line_count = 0
                async for line in response.aiter_lines():
                    line_count += 1
                    if line_count > self._SSE_MAX_LINES:
                        # Hostile/oversized stream — stop draining; pending
                        # futures are already independently time-bounded by
                        # the send() wait_for (M-3 sibling hardening).
                        break
                    line = line.strip()
                    if line.startswith("data:"):
                        event_data = line[len("data:"):].strip()
                    elif line == "" and event_data is not None:
                        try:
                            msg: dict[str, Any] = json.loads(event_data)
                            self._dispatch(msg)
                        except json.JSONDecodeError:
                            pass
                        event_data = None
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001, S110
            pass
        finally:
            # Cancel all pending futures — the SSE stream is gone
            for fut in list(self._pending.values()):
                if not fut.done():
                    fut.set_exception(RuntimeError("SSE stream closed before response received"))
            self._pending.clear()
            # Signal recv() callers
            try:
                self._recv_queue.put_nowait({"_sse_closed": True})
            except asyncio.QueueFull:
                pass

    def _dispatch(self, msg: dict[str, Any]) -> None:
        """Route a received SSE message to a pending Future or the recv queue."""
        msg_id = msg.get("id")
        if msg_id is not None and str(msg_id) in self._pending:
            fut = self._pending.pop(str(msg_id))
            if not fut.done():
                fut.set_result(msg)
        else:
            try:
                self._recv_queue.put_nowait(msg)
            except asyncio.QueueFull:
                pass  # drop if queue is full — backpressure

    async def close(self) -> None:
        if self._sse_task is not None:
            self._sse_task.cancel()
            try:
                await self._sse_task
            except asyncio.CancelledError:
                pass
            self._sse_task = None

        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Core send/recv/send_notification
    # ------------------------------------------------------------------

    async def send(
        self,
        method: str,
        params: dict[str, Any],
        override_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """POST JSON-RPC to /message; wait for the matching response via the SSE Future."""
        if self._client is None:
            raise RuntimeError("Transport not connected — call connect() first")

        payload = self._make_rpc(method, params)
        request_id = str(payload["id"])
        url = f"{self._base_url}/message"

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if override_headers:
            headers.update(override_headers)

        # Register the future BEFORE posting so _sse_listener can never miss it
        loop = asyncio.get_event_loop()
        fut: asyncio.Future[dict[str, Any]] = loop.create_future()
        self._pending[request_id] = fut

        try:
            post_response = await self._client.post(
                url,
                content=json.dumps(payload).encode(),
                headers=headers,
            )
            check_redirect(post_response.status_code)

            # Some implementations return the response inline (not via SSE)
            if post_response.status_code == 200:
                ct = post_response.headers.get("content-type", "")
                if "application/json" in ct:
                    self._pending.pop(request_id, None)
                    return post_response.json()  # type: ignore[no-any-return]

            return await asyncio.wait_for(fut, timeout=self._config.probe_timeout_seconds)
        except Exception:
            self._pending.pop(request_id, None)
            raise

    async def send_notification(self, notification: dict[str, Any]) -> None:
        """POST a pre-built JSON-RPC notification (no id, fire-and-forget)."""
        if self._client is None:
            return
        url = f"{self._base_url}/message"
        try:
            post_response = await self._client.post(
                url,
                content=json.dumps(notification).encode(),
                headers={"Content-Type": "application/json"},
            )
            check_redirect(post_response.status_code)
        except Exception:  # noqa: BLE001, S110
            pass  # fire-and-forget

    async def recv(self) -> dict[str, Any]:
        """Return the next server-initiated message from the SSE stream."""
        msg = await self._recv_queue.get()
        if msg.get("_sse_closed"):
            raise RuntimeError("SSE stream closed")
        return msg
