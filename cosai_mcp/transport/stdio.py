"""stdio transport for local MCP server processes.

Security constraints (non-negotiable):
* asyncio.create_subprocess_exec — shell=False is structural (no subprocess.Popen)
* Fixed argv — no template substitution
* close_fds=True
* start_new_session=True
* Filtered env: only PATH, LANG (HOME removed — prevents ~/.profile attacks)
* stdout/stderr size-capped at 10 MB; output_truncated=True when exceeded
* Per-line length cap: 64 KB, silent truncation
* Control characters stripped (keep \\n, \\r, \\t)
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import warnings
from typing import Any

from cosai_mcp.config import ScanConfig
from cosai_mcp.exceptions import OutputTruncatedWarning
from cosai_mcp.transport.base import Transport

# ---------------------------------------------------------------------------
# Safety constants
# ---------------------------------------------------------------------------
_MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10 MB
_MAX_LINE_BYTES = 64 * 1024           # 64 KB
_SAFE_ENV_KEYS = frozenset({"PATH", "LANG"})  # HOME excluded — prevents ~/.profile attacks


def _safe_env() -> dict[str, str]:
    """Return a minimal filtered environment — only PATH and LANG, never HOME."""
    env: dict[str, str] = {}
    for key in _SAFE_ENV_KEYS:
        val = os.environ.get(key)
        if val is not None:
            env[key] = val
    return env


def _strip_control_chars(text: str) -> str:
    """Remove control characters, keeping \\n, \\r, \\t."""
    return "".join(
        ch for ch in text if ch in ("\n", "\r", "\t") or (ord(ch) >= 0x20 and ord(ch) != 0x7F)
    )


def _truncate_line(line: str) -> str:
    """Silently truncate a line to _MAX_LINE_BYTES encoded length."""
    encoded = line.encode("utf-8")
    if len(encoded) > _MAX_LINE_BYTES:
        encoded = encoded[:_MAX_LINE_BYTES]
        return encoded.decode("utf-8", errors="replace")
    return line


# ---------------------------------------------------------------------------
# StdioTransport
# ---------------------------------------------------------------------------

class StdioTransport(Transport):
    """MCP transport that communicates with a local process via stdin/stdout.

    Uses asyncio.create_subprocess_exec so asyncio.wait_for can actually cancel
    blocking reads — unlike subprocess.Popen + run_in_executor where CancelledError
    does not interrupt a blocking readline().

    Parameters
    ----------
    command:
        Fixed argv list, e.g. ``["python", "my_mcp_server.py"]``.
        No shell expansion or template substitution is performed.
    config:
        Scan configuration (timeout used for I/O waits).
    """

    def __init__(self, command: list[str], config: ScanConfig) -> None:
        if not command:
            raise ValueError("command must be a non-empty list")
        self._command = list(command)  # defensive copy
        self._config = config
        self._process: asyncio.subprocess.Process | None = None
        self.output_truncated: bool = False
        self._total_bytes_read: int = 0

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

    async def _read_line_async(self) -> str:
        """Read one line from the child process stdout with size enforcement."""
        assert self._process is not None
        assert self._process.stdout is not None

        try:
            raw = await self._process.stdout.readline()
        except Exception:
            return ""

        if not raw:
            return ""

        self._total_bytes_read += len(raw)
        if self._total_bytes_read > _MAX_OUTPUT_BYTES:
            if not self.output_truncated:
                self.output_truncated = True
                warnings.warn(
                    "Subprocess output exceeded 10 MB cap — truncating",
                    OutputTruncatedWarning,
                    stacklevel=2,
                )
            return ""

        line = raw.decode("utf-8", errors="replace")
        line = _truncate_line(line)
        line = _strip_control_chars(line)
        return line.rstrip("\n")

    # ------------------------------------------------------------------
    # Transport lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Spawn the child MCP server process using asyncio subprocess."""
        self._process = await asyncio.create_subprocess_exec(
            *self._command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_safe_env(),
            close_fds=True,
            start_new_session=True,
        )

    async def close(self) -> None:
        if self._process is not None:
            try:
                if self._process.stdin:
                    self._process.stdin.close()
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    self._process.kill()
                except ProcessLookupError:
                    pass
            finally:
                self._process = None

    # ------------------------------------------------------------------
    # Core send/recv/send_notification
    # ------------------------------------------------------------------

    async def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Write a JSON-RPC request to stdin; read the response from stdout."""
        if self._process is None:
            raise RuntimeError("Transport not connected — call connect() first")

        payload = self._make_rpc(method, params)
        data = json.dumps(payload).encode("utf-8") + b"\n"

        assert self._process.stdin is not None
        self._process.stdin.write(data)
        await self._process.stdin.drain()

        line = await asyncio.wait_for(
            self._read_line_async(),
            timeout=self._config.probe_timeout_seconds,
        )

        if not line:
            return {}
        return json.loads(line)  # type: ignore[no-any-return]

    async def send_notification(self, notification: dict[str, Any]) -> None:
        """Write a pre-built JSON-RPC notification to stdin (fire-and-forget)."""
        if self._process is None or self._process.stdin is None:
            return
        data = json.dumps(notification).encode("utf-8") + b"\n"
        try:
            self._process.stdin.write(data)
            await self._process.stdin.drain()
        except Exception:
            pass  # fire-and-forget

    async def recv(self) -> dict[str, Any]:
        """Read the next unsolicited line from stdout."""
        line = await asyncio.wait_for(
            self._read_line_async(),
            timeout=self._config.probe_timeout_seconds,
        )
        if not line:
            return {}
        return json.loads(line)  # type: ignore[no-any-return]

    async def read_stderr(self) -> str:
        """Read all stderr output from the child process (for diagnostics)."""
        if self._process is None or self._process.stderr is None:
            return ""

        buf = bytearray()
        while True:
            try:
                chunk = await self._process.stderr.read(4096)
            except Exception:
                break
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) >= _MAX_OUTPUT_BYTES:
                self.output_truncated = True
                warnings.warn(
                    "Subprocess stderr exceeded 10 MB cap — truncating",
                    OutputTruncatedWarning,
                    stacklevel=2,
                )
                break

        raw = bytes(buf).decode("utf-8", errors="replace")
        return _strip_control_chars(raw)
