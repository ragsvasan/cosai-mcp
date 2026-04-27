"""T8: Bind address validation, shadow server detection."""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass


@dataclass(frozen=True)
class BindCheckResult:
    host: str
    port: int
    is_loopback_only: bool
    resolved_ips: tuple  # tuple[str, ...]
    error: str | None = None


class BindAddressValidator:
    """Check whether a host resolves exclusively to loopback addresses.

    Used by T8-003 to detect servers that bind to 0.0.0.0 instead of loopback,
    which exposes the MCP endpoint to the local network.
    """

    def is_loopback_only(self, host: str) -> bool:
        """Return True if ALL resolved IPs for *host* are in the loopback range.

        Returns False if the host cannot be resolved or resolves to no addresses.
        """
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return False
        ips = [info[4][0] for info in infos]
        if not ips:
            return False
        return all(self._is_loopback_ip(ip) for ip in ips)

    def check_bind_address(
        self,
        host: str,
        port: int,
        timeout: float = 2.0,
    ) -> BindCheckResult:
        """Resolve *host* and classify whether the bind address is loopback-only.

        Does NOT attempt a TCP connection — classification is based on resolved IPs.
        A server bound to `0.0.0.0` accepts connections on all interfaces, which is
        treated as non-loopback (exposed).
        """
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            return BindCheckResult(
                host=host,
                port=port,
                is_loopback_only=False,
                resolved_ips=(),
                error=str(exc),
            )

        ips = tuple(info[4][0] for info in infos)
        loopback_only = bool(ips) and all(self._is_loopback_ip(ip) for ip in ips)
        return BindCheckResult(
            host=host,
            port=port,
            is_loopback_only=loopback_only,
            resolved_ips=ips,
        )

    @staticmethod
    def _is_loopback_ip(ip_str: str) -> bool:
        try:
            return ipaddress.ip_address(ip_str).is_loopback
        except ValueError:
            return False
