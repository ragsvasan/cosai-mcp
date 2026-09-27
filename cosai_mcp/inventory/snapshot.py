"""ToolInventory: capture a point-in-time manifest from a live MCP server.

``capture()`` runs the MCP handshake through the scanner's pinned dual-era
session — 2026-07-28 ``server/discover`` → tools/list, falling back to legacy
initialize → initialized → tools/list
and returns a frozen ``ToolInventory``.  The inventory can be serialised to JSON,
signed, and compared across runs to detect drift.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

# Strip ASCII control characters (0x00–0x1F and 0x7F) from tool descriptions
# before storing them.  MCP servers are untrusted; a malicious server can embed
# terminal escape sequences (ANSI CSI codes etc.) in tool descriptions that
# would be replayed into the operator's terminal on `cosai inventory diff`.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


def _strip_controls(s: str) -> str:
    return _CONTROL_CHAR_RE.sub("", s)


@dataclass(frozen=True)
class ToolRecord:
    """One tool entry from a tools/list response."""

    name: str
    description: str
    input_schema: str  # canonical JSON string (sorted keys) for stable hashing

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ToolRecord:
        schema = raw.get("inputSchema") or raw.get("input_schema") or {}
        return cls(
            name=str(raw.get("name", "")),
            description=_strip_controls(str(raw.get("description", ""))),
            input_schema=json.dumps(schema, sort_keys=True, separators=(",", ":")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": json.loads(self.input_schema),
        }


@dataclass(frozen=True)
class ToolInventory:
    """Point-in-time snapshot of an MCP server's tool manifest.

    ``content_hash`` is a SHA-256 digest of the canonical JSON representation
    of all tools (sorted by name, sorted keys).  Signing the inventory commits
    to both the tool list and the capture timestamp.
    """

    target: str
    captured_at: str  # ISO-8601 UTC
    protocol_version: str
    server_name: str
    server_version: str
    tools: tuple[ToolRecord, ...]
    content_hash: str  # hex SHA-256 of canonical tool JSON

    @classmethod
    def build(
        cls,
        target: str,
        protocol_version: str,
        server_name: str,
        server_version: str,
        raw_tools: list[dict[str, Any]],
    ) -> ToolInventory:
        tools = tuple(
            sorted(
                (ToolRecord.from_dict(t) for t in raw_tools),
                key=lambda r: r.name,
            )
        )
        canonical = json.dumps(
            [t.to_dict() for t in tools],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        content_hash = hashlib.sha256(canonical).hexdigest()
        return cls(
            target=target,
            captured_at=datetime.now(UTC).isoformat(),
            protocol_version=protocol_version,
            server_name=server_name,
            server_version=server_version,
            tools=tools,
            content_hash=content_hash,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "captured_at": self.captured_at,
            "protocol_version": self.protocol_version,
            "server_name": self.server_name,
            "server_version": self.server_version,
            "tools": [t.to_dict() for t in self.tools],
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolInventory:
        tools = tuple(ToolRecord.from_dict(t) for t in data.get("tools", []))
        return cls(
            target=str(data["target"]),
            captured_at=str(data["captured_at"]),
            protocol_version=str(data.get("protocol_version", "")),
            server_name=str(data.get("server_name", "")),
            server_version=str(data.get("server_version", "")),
            tools=tools,
            content_hash=str(data["content_hash"]),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, text: str) -> ToolInventory:
        return cls.from_dict(json.loads(text))


def capture(
    target_url: str,
    timeout: float = 10.0,
    allow_private_targets: bool = False,
) -> ToolInventory:
    """Connect to ``target_url``, run MCP handshake, return a ToolInventory.

    Sends:
        1. POST server/discover (MCP 2026-07-28); if not modern, POST initialize
           + initialized (legacy)
        2. POST tools/list

    Parameters
    ----------
    target_url:
        MCP server URL.  The hostname is resolved and validated against the
        network allowlist (RFC1918, loopback, link-local, IPv6 ULA blocked)
        before any connection is opened — matching the locked CLAUDE.md §3
        probe isolation contract.
    allow_private_targets:
        Set to True to allow scanning MCP servers on private/internal networks.

    Raises
    ------
    PrivateAddressError
        If the target resolves to a private/blocked address and
        ``allow_private_targets`` is False.
    RuntimeError
        If the handshake fails or tools/list returns an error.
    """
    from urllib.parse import urlparse

    from cosai_mcp.config import ScanConfig
    from cosai_mcp.transport.base import resolve_and_pin

    url = target_url.rstrip("/")
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if not hostname:
        raise RuntimeError(f"Cannot parse hostname from target URL: {target_url!r}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # Validate the target against the network allowlist (locked contract §3).
    resolve_and_pin(
        hostname,
        ScanConfig(
            target_host=hostname,
            target_port=port,
            allow_private_targets=allow_private_targets,
        ),
    )

    # Both eras run through the scanner's pinned StreamableHTTPTransport +
    # MCPSession (auto era): DNS pinned at connect, no redirects, SSE-aware,
    # server/discover first with legacy initialize fallback.  No raw httpx
    # client, so no path can be forced onto an unpinned connection.
    protocol_version, server_info, raw_tools = _capture_session(
        url, hostname, port, allow_private_targets, timeout
    )
    return ToolInventory.build(
        target=target_url,
        protocol_version=protocol_version,
        server_name=server_info.get("name", ""),
        server_version=server_info.get("version", ""),
        raw_tools=raw_tools,
    )


def _run_sync(coro_factory: Any) -> Any:
    """Run a coroutine to completion from sync code, even inside a running loop.

    ``capture()`` is a synchronous public API; callers inside an event loop
    (async services, Jupyter) must keep working, so the coroutine runs on a
    worker thread with its own loop when one is already running.
    """
    import asyncio
    import concurrent.futures

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro_factory())
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro_factory()).result()


def _capture_session(
    url: str, host: str, port: int, allow_private_targets: bool, timeout: float,
) -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
    """Capture (protocol_version, server_info, tools) via a dual-era session.

    Raises RuntimeError on handshake/tools-list failure (``"initialize
    failed: …"`` for the legacy path, as before) or when the total deadline
    is exceeded.
    """
    import asyncio

    from cosai_mcp.config import ScanConfig
    from cosai_mcp.exceptions import SessionIncompleteError
    from cosai_mcp.protocol import ProtocolEra
    from cosai_mcp.session import MCPSession
    from cosai_mcp.transport.streamable_http import StreamableHTTPTransport

    config = ScanConfig(
        target_host=host,
        target_port=port,
        allow_private_targets=allow_private_targets,
        probe_timeout_seconds=timeout,
        mcp_path="",  # POST to the URL exactly as given
    )

    async def _run() -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
        transport = StreamableHTTPTransport(url, config)
        await transport.connect()
        session = MCPSession(transport, config, target_url=url)
        try:
            info = await session.start()
        except SessionIncompleteError as exc:
            prefix = (
                "modern capture failed"
                if session.protocol_era is ProtocolEra.MODERN
                else "initialize failed"
            )
            raise RuntimeError(f"{prefix}: {exc}") from exc
        finally:
            await session.close()
        manifest = info.tool_manifest if isinstance(info.tool_manifest, list) else []
        tools = [t for t in manifest if isinstance(t, dict)]
        server_info = info.server_info if isinstance(info.server_info, dict) else {}
        return info.protocol_version, server_info, tools

    async def _bounded() -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
        return await asyncio.wait_for(_run(), timeout=timeout * 4)

    try:
        result: tuple[str, dict[str, Any], list[dict[str, Any]]] = _run_sync(_bounded)
    except TimeoutError as exc:
        raise RuntimeError("inventory capture exceeded its deadline") from exc
    return result
