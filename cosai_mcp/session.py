"""MCPSession — initialize/initialized handshake, tools/list, full lifecycle."""
from __future__ import annotations

import enum
import warnings
from dataclasses import dataclass
from typing import Any

from cosai_mcp.config import ScanConfig
from cosai_mcp.exceptions import SessionIncompleteError
from cosai_mcp.transport.base import Transport

# ---------------------------------------------------------------------------
# Client identity — scanner declares only what it implements
# ---------------------------------------------------------------------------
CLIENT_INFO: dict[str, str] = {"name": "cosai-mcp-scanner", "version": "0.1.0"}
CLIENT_CAPABILITIES: dict[str, Any] = {}  # scanner implements nothing server should call back

# Versions we understand; anything else gets a warning but does not abort
SUPPORTED_VERSIONS: frozenset[str] = frozenset({"2025-03-26", "2024-11-05"})

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


class MCPSession:
    """Manages the full MCP session lifecycle over any Transport.

    Sequence enforced before probes can run:
      1. send ``initialize`` request
      2. receive and validate ``initialize`` response
      3. send ``initialized`` notification (no id — true JSON-RPC notification)
      4. call ``tools/list`` and cache the manifest (failure is non-fatal)
      5. allow ``tools/call`` and other probe methods
    """

    def __init__(self, transport: Transport, config: ScanConfig) -> None:
        self._transport = transport
        self._config = config
        self._status = SessionStatus.INCOMPLETE
        self._protocol_version: str = ""
        self._server_info: dict[str, Any] = {}
        self._tool_manifest: list[dict[str, Any]] = []
        self._transport_type: str = type(transport).__name__

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

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> SessionInfo:
        """Run the full MCP handshake and return session info.

        Raises
        ------
        SessionIncompleteError
            If the initialize request/response step fails.
        """
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

        # Step 3: initialized notification — must have no 'id' (JSON-RPC 2.0 notification)
        try:
            await self._send_notification("initialized", {})
        except Exception as exc:
            raise SessionIncompleteError(
                f"initialized notification failed: {exc}"
            ) from exc

        # Step 4: tools/list — non-fatal; some servers omit it
        try:
            tools_response = await self._transport.send("tools/list", {})
            if "error" in tools_response:
                self._tool_manifest = []
            else:
                tools_result = tools_response.get("result", {})
                self._tool_manifest = tools_result.get("tools", [])
        except Exception:
            self._tool_manifest = []

        # Step 5: session is now READY
        self._status = SessionStatus.READY

        return SessionInfo(
            protocol_version=self._protocol_version,
            server_info=self._server_info,
            tool_manifest=self._tool_manifest,
            transport_type=self._transport_type,
        )

    async def tools_call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Invoke a tool on the connected MCP server.

        Raises
        ------
        SessionIncompleteError
            If called before a successful ``start()``.
        """
        self._require_ready()
        return await self._transport.send(
            "tools/call",
            {"name": name, "arguments": arguments},
        )

    async def tools_list(self) -> list[dict[str, Any]]:
        """Return the cached tool manifest (no additional network call)."""
        self._require_ready()
        return self._tool_manifest

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
        except Exception:
            pass  # notifications: fire-and-forget; errors are non-fatal
