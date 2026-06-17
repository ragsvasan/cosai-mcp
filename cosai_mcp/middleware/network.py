"""T8: Operator-supplied bind-config validation and transport TLS inspection.

Scope (WG-89 item 12 — honest framing): this module validates a bind
configuration the OPERATOR supplies (the host:port they tell the scanner the
server is bound to) and inspects the TLS posture of the transport the scanner
actually connects to. It does NOT perform active shadow-server discovery —
i.e. it does not enumerate local network interfaces, port-scan the host, or
hunt for rogue MCP servers listening on other addresses. Active interface
enumeration is an adversarial-scanning capability that is intentionally
out of scope for this non-adversarial conformance scanner; treat the verdict
as "is the address the operator gave us loopback-only?", not "is this host free
of any exposed MCP server?".
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass


@dataclass(frozen=True)
class BindCheckResult:
    host: str
    port: int
    is_loopback_only: bool
    resolved_ips: tuple  # tuple[str, ...]
    error: str | None = None


class BindAddressValidator:
    """Validate an OPERATOR-SUPPLIED bind address (host:port) for T8 exposure.

    Given the host:port the operator declares the MCP server is bound to, this
    classifies whether that address resolves exclusively to loopback. It is used
    by T8-003 to flag servers the operator has bound to 0.0.0.0 (or a routable
    address) instead of loopback, which exposes the MCP endpoint to the local
    network.

    Out of scope (by design — see the module docstring): this performs NO active
    discovery. It does not enumerate interfaces, port-scan, or look for shadow
    servers on other addresses. It only answers a question about the single
    address the operator provided. For TLS posture of the connected transport,
    see :class:`TransportSecurityInspector`.
    """

    def is_loopback_only(self, host: str) -> bool:
        """Return True if ALL resolved IPs for *host* are in the loopback range.

        Returns False if the host cannot be resolved or resolves to no addresses.
        """
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return False
        ips = [str(info[4][0]) for info in infos]
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

        ips = tuple(str(info[4][0]) for info in infos)
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


# ---------------------------------------------------------------------------
# Transport TLS inspection (WG-89 item 12, optional)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TLSInspectionResult:
    host: str
    port: int
    tls: bool                       # did a TLS handshake complete?
    protocol: str | None = None     # e.g. "TLSv1.3"
    cipher: str | None = None       # negotiated cipher suite name
    subject_cn: str | None = None
    san: tuple = ()                 # tuple[str, ...] of dNSName / iPAddress SANs
    not_after: str | None = None    # certificate notAfter (as served)
    mtls_required: bool | None = None  # True if server demanded a client cert
    error: str | None = None


class TransportSecurityInspector:
    """Best-effort TLS posture inspection of the transport the scanner connects to.

    This is an *operator-facing* diagnostic, not active discovery: it connects to
    the single host:port under test and reports the negotiated protocol/cipher,
    the served certificate's subject CN, Subject Alternative Names, expiry, and
    whether the server demanded a client certificate (mTLS). It never scans other
    addresses. All network operations are guarded; any failure is surfaced via
    ``TLSInspectionResult.error`` rather than raised.
    """

    @staticmethod
    def summarize_certificate(
        cert: dict | None,
        cipher: tuple | None = None,
        protocol: str | None = None,
    ) -> dict:
        """Extract a stable summary from a peer cert dict (``ssl.getpeercert()``).

        Pure function — no network. Returns subject CN, SANs (dNSName/iPAddress),
        notAfter, and the negotiated cipher/protocol when provided.
        """
        subject_cn: str | None = None
        san: list[str] = []
        not_after: str | None = None
        if cert:
            for rdn in cert.get("subject", ()):  # tuple of ((key, value), ...)
                for key, value in rdn:
                    if key == "commonName":
                        subject_cn = value
            for typ, value in cert.get("subjectAltName", ()):
                san.append(f"{typ}:{value}")
            not_after = cert.get("notAfter")
        # cipher() returns (name, protocol_version, secret_bits)
        cipher_name = cipher[0] if cipher else None
        proto = protocol or (cipher[1] if cipher and len(cipher) > 1 else None)
        return {
            "subject_cn": subject_cn,
            "san": tuple(san),
            "not_after": not_after,
            "cipher": cipher_name,
            "protocol": proto,
        }

    def inspect(
        self,
        host: str,
        port: int,
        timeout: float = 3.0,
        server_hostname: str | None = None,
    ) -> TLSInspectionResult:
        """Connect to host:port over TLS and report its posture (best-effort).

        Verification is intentionally disabled (``CERT_NONE``) so we can inspect
        self-signed / misconfigured endpoints and still read the served cert; the
        goal is observation, not trust establishment. A handshake failure that
        names a required client certificate is reported as ``mtls_required=True``.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=server_hostname or host) as tls:
                    cert = tls.getpeercert()
                    summary = self.summarize_certificate(
                        cert, tls.cipher(), tls.version()
                    )
                    return TLSInspectionResult(
                        host=host,
                        port=port,
                        tls=True,
                        protocol=summary["protocol"],
                        cipher=summary["cipher"],
                        subject_cn=summary["subject_cn"],
                        san=summary["san"],
                        not_after=summary["not_after"],
                        mtls_required=False,
                    )
        except ssl.SSLError as exc:
            msg = str(exc)
            mtls = "certificate required" in msg.lower() or "peer did not return" in msg.lower()
            return TLSInspectionResult(
                host=host, port=port, tls=False, mtls_required=mtls or None, error=msg,
            )
        except (TimeoutError, OSError) as exc:
            return TLSInspectionResult(
                host=host, port=port, tls=False, error=str(exc),
            )
