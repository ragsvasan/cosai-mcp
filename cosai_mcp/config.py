"""ScanConfig — top-level configuration dataclass for the cosai-mcp scanner."""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class ScanConfig:
    """Configuration passed to transports and sessions.

    Two construction forms are supported:

    1. **Public / documented form** — pass a full ``target`` URL (plus optional
       ``categories`` / ``fail_on``).  ``target_host`` and ``target_port`` are
       derived automatically::

           ScanConfig(target="http://localhost:8000", categories=["T1"], fail_on="high")

    2. **Internal form** — pass ``target_host`` and ``target_port`` directly.
       Used by the scan orchestrator and transports.

    Attributes
    ----------
    target:
        Full target URL (e.g. ``"http://localhost:8000"``).  When provided,
        ``target_host``/``target_port`` are parsed from it.  This is the
        documented public input.
    categories:
        Optional list of CoSAI threat categories to scan (e.g. ``["T1","T4"]``).
        ``None`` scans all categories.  Consumed by the Scanner, not transports.
    fail_on:
        Severity threshold at or above which the scan is considered failing
        (e.g. ``"high"``, ``"critical"``).  Consumed by the Scanner, not transports.
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

    target_host: str | None = None
    target_port: int | None = None
    target: str | None = None
    categories: list[str] | None = None
    fail_on: str = "critical"
    allow_private_targets: bool = False
    probe_timeout_seconds: float = 30.0
    auth_token: str | None = None
    mcp_path: str = "/mcp"
    auth_header: str | None = None
    """Pre-formatted Authorization header value (e.g. ``"Bearer tok123"``).
    When set, overrides the default ``"Bearer {auth_token}"`` construction in
    the transport.  Set by profile's ``auth_header_format`` + ``--auth-token``.
    """
    probe_delay_seconds: float = 0.0
    """Seconds to sleep between probes.  Use to avoid triggering server-side
    rate limiters when scanning servers that enforce per-session call budgets."""
    read_token: str | None = None
    """Bearer token with read-only scope.  Used by probes with ``probe_token: "read"``
    to verify that limited-scope tokens are rejected by write-capable tools."""
    extra_request_headers: dict[str, str] | None = None
    """Extra HTTP headers added to every request in this config context.
    Used by probe_headers to inject headers like Origin for CORS testing."""
    pii_strict: bool = False
    """When *True*, the T5 passive secret/PII manifest scan additionally applies
    the broad-PII strict tier (SSN, IBAN, US phone, Luhn-corroborated PAN) on top
    of the always-on anchored-credential tier.  Default *False* keeps the scan
    fast and low-false-positive.  Set by the ``--pii-strict`` CLI flag."""
    stateful_method_overrides: dict[str, str] | None = None
    """Operator-supplied ``{placeholder: real}`` map applied by the stateful
    harness.  Built-in scenarios use generic placeholder tool names
    (``admin_delete``, ``read_file``) and synthetic methods (``session/terminate``)
    that do not exist on a real server; without a mapping every such scenario is
    reported INCONCLUSIVE.  This map remaps each placeholder to the equivalent
    identifier on the target so the scenario actually exercises the control.
    ``None`` (the default) leaves scenarios unchanged."""

    def __post_init__(self) -> None:
        # Documented public form: derive host/port from the full target URL.
        if self.target is not None:
            parsed = urlparse(self.target)
            if not parsed.scheme or not parsed.hostname:
                raise ValueError(
                    f"Invalid target URL — must include scheme and host: {self.target!r}"
                )
            derived_host = parsed.hostname
            derived_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            # `target` only fills host/port when they are otherwise unset; an
            # explicitly-passed target_host/target_port is left untouched (no
            # mismatch validation — the documented public input is `target` alone).
            if self.target_host is None:
                self.target_host = derived_host
            if self.target_port is None:
                self.target_port = derived_port

        # Internal form requires host + port to be set one way or another.
        if self.target_host is None or self.target_port is None:
            raise ValueError(
                "ScanConfig requires either `target` (a full URL) or both "
                "`target_host` and `target_port`."
            )
