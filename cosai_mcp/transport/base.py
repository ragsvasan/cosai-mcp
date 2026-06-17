"""Transport ABC — all transports implement this interface.

Also exports the shared network-allowlist helpers used by HTTP transports.
"""
from __future__ import annotations

import ipaddress
import socket
from abc import ABC, abstractmethod
from typing import Any

from cosai_mcp.config import ScanConfig
from cosai_mcp.exceptions import DNSRebindingError, PrivateAddressError, SuspiciousRedirectError

# ---------------------------------------------------------------------------
# Private-address CIDR blocks that are blocked by default
# ---------------------------------------------------------------------------
_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
_LINK_LOCAL = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]
_LOOPBACK = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]
_ULA = [
    ipaddress.ip_network("fc00::/7"),
]

_ALWAYS_BLOCKED: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = _ULA
_PRIVATE_BLOCKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = (
    _RFC1918 + _LINK_LOCAL + _LOOPBACK
)


def _parse_ip(addr: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    return ipaddress.ip_address(addr)


def is_private_address(ip: str) -> bool:
    """Return *True* if *ip* falls in an RFC-1918/loopback/link-local block."""
    parsed = _parse_ip(ip)
    return any(parsed in net for net in _PRIVATE_BLOCKS)


def is_always_blocked(ip: str) -> bool:
    """Return *True* if *ip* is in a block that can never be targeted (ULA)."""
    parsed = _parse_ip(ip)
    return any(parsed in net for net in _ALWAYS_BLOCKED)


def resolve_and_pin(hostname: str, config: ScanConfig) -> str:
    """Resolve *hostname* → IP and validate against the network allowlist.

    Returns the pinned IP string.

    Raises
    ------
    PrivateAddressError
        If the resolved IP is private and *allow_private_targets* is False,
        or if it falls in an always-blocked range.
    """
    # getaddrinfo returns a list of (family, type, proto, canonname, sockaddr)
    results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    if not results:
        raise PrivateAddressError(f"Cannot resolve hostname: {hostname!r}")

    # Prefer IPv4 (AF_INET) over IPv6 — on macOS, localhost resolves to ::1
    # first, but many development servers only bind on 127.0.0.1 (IPv4).
    results.sort(key=lambda r: 0 if r[0] == socket.AF_INET else 1)
    raw_ip: str = str(results[0][4][0])

    if is_always_blocked(raw_ip):
        raise PrivateAddressError(
            f"Target IP {raw_ip} falls in an always-blocked range (ULA/fc00::/7)"
        )

    if is_private_address(raw_ip) and not config.allow_private_targets:
        raise PrivateAddressError(
            f"Target IP {raw_ip} is a private/loopback/link-local address. "
            "Pass --allow-private-targets on the CLI (or allow_private_targets=True "
            "via the Python API) to reach internal/loopback MCP servers."
        )

    return raw_ip


def check_redirect(status_code: int) -> None:
    """Raise *SuspiciousRedirectError* for any 3xx response."""
    if 300 <= status_code < 400:
        raise SuspiciousRedirectError(
            f"Received redirect response ({status_code}). "
            "cosai-mcp never follows redirects — this is flagged as suspicious."
        )


def check_dns_rebinding(expected_ip: str, actual_ip: str) -> None:
    """Raise *DNSRebindingError* if *actual_ip* differs from the pinned *expected_ip*."""
    if expected_ip != actual_ip:
        raise DNSRebindingError(
            f"DNS rebinding detected: pinned IP={expected_ip!r}, "
            f"but connection resolved to {actual_ip!r}"
        )


# ---------------------------------------------------------------------------
# Transport ABC
# ---------------------------------------------------------------------------

class Transport(ABC):
    """Abstract base for all MCP transports."""

    @abstractmethod
    async def connect(self) -> None:
        """Establish the transport connection."""

    @abstractmethod
    async def send(
        self, method: str, params: dict[str, Any], override_headers: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """Send a JSON-RPC request and return the response dict."""

    @abstractmethod
    async def send_notification(self, notification: dict[str, Any]) -> None:
        """Send a JSON-RPC notification (pre-built dict without 'id', no response expected)."""

    @abstractmethod
    async def recv(self) -> dict[str, Any]:
        """Receive the next server-sent message."""

    @abstractmethod
    async def close(self) -> None:
        """Tear down the transport connection."""

    async def __aenter__(self) -> Transport:
        await self.connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()
