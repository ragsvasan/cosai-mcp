"""MCPSession — dual-era MCP lifecycle (2026-07-28 stateless + legacy handshake)."""
from __future__ import annotations

import enum
import warnings
from dataclasses import dataclass
from typing import Any

from cosai_mcp.config import ScanConfig
from cosai_mcp.exceptions import SessionIncompleteError
from cosai_mcp.protocol import (
    LEGACY_VERSIONS,
    META_SERVER_INFO,
    MODERN_PROTOCOL_VERSION,
    EraDetection,
    ProtocolEra,
    build_request_meta,
    classify_discover_response,
    with_request_meta,
    x_mcp_param_headers,
)
from cosai_mcp.transport.base import Transport

# ---------------------------------------------------------------------------
# Client identity — scanner declares only what it implements
# ---------------------------------------------------------------------------
CLIENT_INFO: dict[str, str] = {"name": "cosai-mcp-scanner", "version": "0.1.0"}
CLIENT_CAPABILITIES: dict[str, Any] = {}  # scanner implements nothing server should call back

_LEGACY_HANDSHAKE_METHODS: frozenset[str] = frozenset(
    {"initialize", "notifications/initialized", "initialized"}
)

# Legacy (initialize-negotiated) versions we understand; anything else gets a
# warning but does not abort.
SUPPORTED_VERSIONS: frozenset[str] = LEGACY_VERSIONS

# JSON-RPC error code for unhandled methods
_METHOD_NOT_FOUND = -32601


class SessionStatus(enum.Enum):
    INCOMPLETE = "INCOMPLETE"
    READY = "READY"
    CLOSED = "CLOSED"


@dataclass
class SessionInfo:
    protocol_version: str
    server_info: dict[str, Any]
    tool_manifest: list[dict[str, Any]]
    transport_type: str
    protocol_era: str = ProtocolEra.LEGACY.value


class MCPSession:
    """Manages the full MCP session lifecycle over any Transport.

    Two eras, selected by ``config.protocol_era`` (default ``auto``):

    Modern (2026-07-28, stateless):
      1. ``server/discover`` carrying per-request ``_meta``
      2. ``tools/list`` (with ``_meta``) and cache the manifest
      3. every later request carries ``_meta`` (+ HTTP request-metadata headers)

    Legacy (2025-11-25 and earlier):
      1. send ``initialize`` request
      2. receive and validate ``initialize`` response
      3. send ``initialized`` notification (no id — true JSON-RPC notification)
      4. call ``tools/list`` and cache the manifest

    ``auto`` probes modern first and falls back to legacy when the server is
    not recognisably modern (spec dual-era client rules).  Either way, failure
    of ``tools/list`` or of the chosen handshake → ``SessionIncompleteError``
    (reported ``scan-incomplete``, never ``clean``).
    """

    def __init__(self, transport: Transport, config: ScanConfig, target_url: str = "") -> None:
        self._transport = transport
        self._config = config
        self._target_url = target_url
        self._status = SessionStatus.INCOMPLETE
        self._protocol_version: str = ""
        self._server_info: dict[str, Any] = {}
        self._tool_manifest: list[dict[str, Any]] = []
        self._transport_type: str = type(transport).__name__
        self._era: ProtocolEra = ProtocolEra.LEGACY
        # True when server/discover was rejected with HTTP 401/403.  In the
        # stateless 2026-07-28 era that gates nothing by itself — see
        # enter_unverified() and the runner's auth-reject handling.
        self.discover_auth_rejected: bool = False
        self._request_meta: dict[str, Any] = build_request_meta(CLIENT_INFO, CLIENT_CAPABILITIES)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def tool_manifest(self) -> list[dict[str, Any]]:
        return self._tool_manifest

    @property
    def server_protocol_version(self) -> str:
        return self._protocol_version

    @property
    def status(self) -> SessionStatus:
        return self._status

    @property
    def protocol_era(self) -> ProtocolEra:
        """Era actually in use (``modern`` or ``legacy``) once ``start()`` succeeds."""
        return self._era

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> SessionInfo:
        """Run the era-appropriate MCP handshake and return session info.

        Raises
        ------
        SessionIncompleteError
            If the handshake or ``tools/list`` fails.
        """
        requested = ProtocolEra(self._config.protocol_era)
        if requested is not ProtocolEra.LEGACY:
            detection, response = await self._probe_modern()
            self.discover_auth_rejected = response.get("_status_code") in (401, 403)
            if detection is EraDetection.MODERN:
                return await self._start_modern(response)
            if requested is ProtocolEra.MODERN or detection in (
                EraDetection.MODERN_INCOMPATIBLE,
                EraDetection.MODERN_ERROR,
            ):
                # A recognisably modern server that we cannot speak to must not
                # be silently retried over the legacy handshake (downgrade path).
                raise SessionIncompleteError(
                    f"server/discover did not establish a {MODERN_PROTOCOL_VERSION} "
                    f"session ({detection.value}): {_summarize(response)}"
                )
            # LEGACY / UNDETERMINED under auto → dual-era fallback.
            self._transport.set_protocol_version(None)
            if detection is EraDetection.UNDETERMINED:
                try:
                    return await self._start_legacy()
                except SessionIncompleteError as exc:
                    # Keep the modern rejection (e.g. HTTP 401) visible so the
                    # runner's auth-rejection match still sees it when a
                    # modern-only server also rejects the legacy handshake.
                    raise SessionIncompleteError(
                        f"{exc} [server/discover: {_summarize(response)}]"
                    ) from exc
        return await self._start_legacy()

    async def detect_era(self) -> EraDetection:
        """Classify the server's era with one ``server/discover`` round-trip.

        Does not change session state beyond the transport's header mode.
        Used by the scan orchestrator to pin ``protocol_era`` once per scan.
        """
        detection, _ = await self._probe_modern()
        self._transport.set_protocol_version(None)
        return detection

    def enter_unverified(self, *, modern: bool) -> None:
        """Mark the session READY without a handshake, in modern or legacy framing.

        2026-07-28 is stateless: there is no handshake that authorizes later
        requests, so a server rejecting ``server/discover`` proves nothing about
        whether it enforces auth on ``tools/call``.  The runner uses this to
        send an unauthenticated probe's *actual* request, in both wire
        framings, and judge the real responses.  The manifest is empty.
        """
        if modern:
            self._transport.set_protocol_version(MODERN_PROTOCOL_VERSION)
            self._era = ProtocolEra.MODERN
            self._protocol_version = MODERN_PROTOCOL_VERSION
        else:
            self._transport.set_protocol_version(None)
            self._era = ProtocolEra.LEGACY
        self._tool_manifest = []
        self._status = SessionStatus.READY

    async def _probe_modern(self) -> tuple[EraDetection, dict[str, Any]]:
        """Send ``server/discover`` as a modern request and classify the reply."""
        self._transport.set_protocol_version(MODERN_PROTOCOL_VERSION)
        try:
            response = await self._transport.send(
                "server/discover", with_request_meta({}, self._request_meta)
            )
        except Exception as exc:  # noqa: BLE001 — era unknown; legacy path reports it
            return EraDetection.UNDETERMINED, {"exception": f"{type(exc).__name__}: {exc}"}
        return classify_discover_response(response), response

    async def _start_modern(self, discover_response: dict[str, Any]) -> SessionInfo:
        result = discover_response.get("result", {})
        meta = result.get("_meta") if isinstance(result.get("_meta"), dict) else {}
        server_info = meta.get(META_SERVER_INFO) if isinstance(meta, dict) else None
        self._server_info = server_info if isinstance(server_info, dict) else {}
        self._protocol_version = MODERN_PROTOCOL_VERSION
        self._era = ProtocolEra.MODERN

        try:
            tools_response = await self._transport.send(
                "tools/list", with_request_meta({}, self._request_meta)
            )
        except Exception as exc:
            raise SessionIncompleteError(f"tools/list failed: {exc}") from exc
        if "error" in tools_response:
            raise SessionIncompleteError(
                f"Server returned error on tools/list: {tools_response['error']}"
            )
        tools_result = tools_response.get("result", {})
        result_type = tools_result.get("resultType", "complete")
        if result_type != "complete":
            raise SessionIncompleteError(
                f"tools/list returned non-complete resultType {result_type!r}"
            )
        self._tool_manifest = tools_result.get("tools", [])
        self._status = SessionStatus.READY

        return SessionInfo(
            protocol_version=self._protocol_version,
            server_info=self._server_info,
            tool_manifest=self._tool_manifest,
            transport_type=self._transport_type,
            protocol_era=ProtocolEra.MODERN.value,
        )

    async def _start_legacy(self) -> SessionInfo:
        """initialize → initialized → tools/list (pre-2026-07-28 lifecycle)."""
        self._era = ProtocolEra.LEGACY
        # Step 1 + 2: initialize request/response
        try:
            init_response = await self._transport.send(
                "initialize",
                {
                    "protocolVersion": "2025-03-26",
                    "clientInfo": CLIENT_INFO,
                    "capabilities": CLIENT_CAPABILITIES,
                },
            )
        except Exception as exc:
            raise SessionIncompleteError(
                f"initialize request failed: {exc}"
            ) from exc

        if "error" in init_response:
            raise SessionIncompleteError(
                f"Server rejected initialize: {init_response['error']}"
            )

        result = init_response.get("result", {})
        if not result:
            raise SessionIncompleteError(
                "initialize response missing 'result' field"
            )

        self._protocol_version = result.get("protocolVersion", "")
        self._server_info = result.get("serverInfo", {})

        # Validate negotiated version — warn but continue for forward-compat
        if self._protocol_version not in SUPPORTED_VERSIONS:
            warnings.warn(
                f"MCP server negotiated unsupported protocol version "
                f"{self._protocol_version!r}. "
                f"Supported: {sorted(SUPPORTED_VERSIONS)}. "
                "Proceeding — behavior may be incorrect.",
                stacklevel=2,
            )

        if self._protocol_version == "2024-11-05":
            self._transport_type = "LegacySSETransport"
            if self._target_url:
                # Server requires the 2024-11-05 HTTP+SSE transport — switch now.
                # Close the streamable-HTTP connection used for the initial probe,
                # create a LegacySSETransport, connect it, and re-run the handshake
                # so all subsequent sends go over the correct transport.
                from cosai_mcp.transport.legacy_sse import LegacySSETransport
                await self._transport.close()
                legacy = LegacySSETransport(self._target_url, self._config)
                await legacy.connect()
                self._transport = legacy
                # Re-run initialize on the new transport; extract result fields again.
                try:
                    reinit_response = await self._transport.send(
                        "initialize",
                        {
                            "protocolVersion": "2025-03-26",
                            "clientInfo": CLIENT_INFO,
                            "capabilities": CLIENT_CAPABILITIES,
                        },
                    )
                except Exception as exc:
                    raise SessionIncompleteError(
                        f"initialize on LegacySSETransport failed: {exc}"
                    ) from exc
                if "error" in reinit_response:
                    raise SessionIncompleteError(
                        f"Server rejected initialize on LegacySSETransport: {reinit_response['error']}"  # noqa: E501
                    )
                reinit_result = reinit_response.get("result", {})
                self._protocol_version = reinit_result.get("protocolVersion", self._protocol_version)  # noqa: E501
                self._server_info = reinit_result.get("serverInfo", self._server_info)

        # Step 3: initialized notification — must have no 'id' (JSON-RPC 2.0 notification)
        try:
            await self._send_notification("initialized", {})
        except Exception as exc:
            raise SessionIncompleteError(
                f"initialized notification failed: {exc}"
            ) from exc

        # Step 4: tools/list — required by the locked lifecycle; failure → INCOMPLETE
        try:
            tools_response = await self._transport.send("tools/list", {})
        except Exception as exc:
            raise SessionIncompleteError(
                f"tools/list failed: {exc}"
            ) from exc
        if "error" in tools_response:
            raise SessionIncompleteError(
                f"Server returned error on tools/list: {tools_response['error']}"
            )
        tools_result = tools_response.get("result", {})
        self._tool_manifest = tools_result.get("tools", [])

        # Step 5: session is now READY
        self._status = SessionStatus.READY

        return SessionInfo(
            protocol_version=self._protocol_version,
            server_info=self._server_info,
            tool_manifest=self._tool_manifest,
            transport_type=self._transport_type,
        )

    async def tools_call(
        self,
        name: str,
        arguments: dict[str, Any],
        override_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Invoke a tool on the connected MCP server.

        Raises
        ------
        SessionIncompleteError
            If called before a successful ``start()``.
        """
        self._require_ready()
        return await self.send_raw(
            "tools/call",
            {"name": name, "arguments": arguments},
            override_headers=override_headers,
        )

    async def tools_list(self) -> list[dict[str, Any]]:
        """Return the cached tool manifest (no additional network call)."""
        self._require_ready()
        return self._tool_manifest

    async def send_raw(
        self,
        method: str,
        payload: dict[str, Any],
        override_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send an arbitrary JSON-RPC request to the server.

        Used by ProbeContext for non-standard methods not covered by
        typed helpers (e.g. tools_call). Accessing the transport directly
        from outside the session is a layering violation — this method is
        the correct public API.

        In a modern session the protocol ``_meta`` fields are merged into
        *payload* (probe-supplied ``_meta`` keys win) and, for ``tools/call``,
        ``x-mcp-header``-annotated arguments are mirrored into ``Mcp-Param-*``
        headers.  Probe ``override_headers`` are applied last.

        Raises
        ------
        SessionIncompleteError
            If called before a successful start().
        """
        self._require_ready()
        if self._era is ProtocolEra.MODERN and method in _LEGACY_HANDSHAKE_METHODS:
            # A catalog probe exercising the legacy handshake must send a true
            # legacy request (no _meta, no modern headers), not a hybrid —
            # otherwise a dual-era server's open legacy path goes untested.
            self._transport.set_protocol_version(None)
            try:
                return await self._transport.send(
                    method, payload, override_headers=override_headers
                )
            finally:
                self._transport.set_protocol_version(MODERN_PROTOCOL_VERSION)
        if self._era is ProtocolEra.MODERN:
            headers: dict[str, str] = {}
            if method == "tools/call":
                headers = self._param_headers(payload)
            if override_headers:
                headers.update(override_headers)
            return await self._transport.send(
                method,
                with_request_meta(payload, self._request_meta),
                override_headers=headers or None,
            )
        return await self._transport.send(method, payload, override_headers=override_headers)

    def _param_headers(self, payload: dict[str, Any]) -> dict[str, str]:
        name = payload.get("name")
        for tool in self._tool_manifest:
            if isinstance(tool, dict) and tool.get("name") == name:
                return x_mcp_param_headers(tool.get("inputSchema"), payload.get("arguments"))
        return {}

    async def close(self) -> None:
        self._status = SessionStatus.CLOSED
        await self._transport.close()

    # ------------------------------------------------------------------
    # Server→client request handling
    # ------------------------------------------------------------------

    async def handle_server_request(self, message: dict[str, Any]) -> dict[str, Any]:
        """Return a JSON-RPC -32601 Method Not Found for any server→client request.

        The scanner declares no capabilities, so all server-initiated method
        calls are unsupported by design.
        """
        request_id = message.get("id")
        method = message.get("method", "<unknown>")
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": _METHOD_NOT_FOUND,
                "message": f"Method not found: {method!r}",
            },
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_ready(self) -> None:
        if self._status != SessionStatus.READY:
            raise SessionIncompleteError(
                f"Session is not READY (status={self._status.value}). "
                "Call start() and wait for it to complete before issuing requests."
            )

    async def _send_notification(self, method: str, params: dict[str, Any]) -> None:
        """Send a JSON-RPC notification: pre-built dict without 'id', fire-and-forget."""
        notification: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            # Intentionally no 'id' field — this is a notification, not a request
        }
        try:
            await self._transport.send_notification(notification)
        except Exception:  # noqa: BLE001, S110
            pass  # notifications: fire-and-forget; errors are non-fatal


def _summarize(response: dict[str, Any]) -> str:
    """Short, bounded description of a discover response for error messages.

    Includes the HTTP status and JSON-RPC error so the runner's auth-rejection
    keyword match (``401``/``403``/``unauthorized``) still fires in modern mode.
    """
    parts: list[str] = []
    if (status := response.get("_status_code")) is not None:
        parts.append(f"HTTP {status}")
    if "error" in response:
        parts.append(f"error={response['error']!r}")
    if "exception" in response:
        parts.append(str(response["exception"]))
    if "result" in response and not parts:
        result = response["result"]
        versions = result.get("supportedVersions") if isinstance(result, dict) else None
        parts.append(f"supportedVersions={versions!r}")
    return ("; ".join(parts) or "empty response")[:500]
