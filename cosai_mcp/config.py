"""ScanConfig — top-level configuration dataclass for the cosai-mcp scanner."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    """Configuration passed to transports and sessions.

    Attributes
    ----------
    target_host:
        Hostname or IP of the MCP server being scanned.
    target_port:
        TCP port of the MCP server.
    allow_private_targets:
        When *True* the network allowlist permits RFC-1918, loopback, and
        link-local addresses.  Use only for scanning internal / development
        servers.  Defaults to *False*.
    probe_timeout_seconds:
        Per-probe wall-clock timeout.  Defaults to 30 s.
    auth_token:
        Optional Bearer token sent in every request's Authorization header.
        Use to scan servers that require authentication for the MCP handshake
        itself (e.g. Mnemo).  Leave *None* for unauthenticated scans.
    mcp_path:
        URL path of the MCP endpoint, including leading slash.  Defaults to
        ``"/mcp"`` — override when the server mounts MCP at a custom path.
    """

    target_host: str
    target_port: int
    allow_private_targets: bool = False
    probe_timeout_seconds: float = 30.0
    auth_token: str | None = None
    mcp_path: str = "/mcp"
    auth_header: str | None = None
    """Pre-formatted Authorization header value (e.g. ``"Bearer tok123"``).
    When set, overrides the default ``"Bearer {auth_token}"`` construction in
    the transport.  Set by profile's ``auth_header_format`` + ``--auth-token``.
    """
