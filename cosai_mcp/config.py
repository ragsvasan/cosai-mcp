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
    """

    target_host: str
    target_port: int
    allow_private_targets: bool = False
    probe_timeout_seconds: float = 30.0
