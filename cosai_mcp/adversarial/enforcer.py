"""Dual opt-in guard and probe safety checks for adversarial mode.

Adversarial probes are disabled by default and require two explicit flags:
  --adversarial          : enables adversarial probe loading
  --i-own-this-target    : string that must contain the target hostname verbatim

Both must be present. The ownership declaration is checked at runtime, not just
at CLI parse time, so the API surface is equally protected.
"""
from __future__ import annotations

import ipaddress
import re
import urllib.parse


class UnsafeProbeError(Exception):
    """Raised when a probe would violate adversarial safety invariants."""


# Minimum hostname length for adversarial mode (rejects generic single-word hostnames
# like "api", "mcp", "localhost" that are too ambiguous for ownership assertion)
_MIN_HOSTNAME_LEN = 4

# RFC1918, loopback, link-local, and unspecified addresses that must never appear
# in probe payload URLs regardless of whether they match the target.
_ALWAYS_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("0.0.0.0/32"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _is_blocked_address(host: str) -> bool:
    """Return True if host is a loopback, link-local, or unspecified address."""
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _ALWAYS_BLOCKED_NETWORKS)
    except ValueError:
        return False


def validate_dual_optin(
    adversarial: bool,
    ownership_declaration: str | None,
    target_url: str,
) -> None:
    """Enforce dual opt-in for adversarial mode.

    Raises
    ------
    ValueError
        If ``adversarial`` is True but ``ownership_declaration`` is absent,
        does not contain the target hostname as a word-boundary match, or the
        target hostname is too short (< 4 chars) to be unambiguous.
    """
    if not adversarial:
        return

    if not ownership_declaration:
        raise ValueError(
            "Adversarial mode requires --i-own-this-target=<hostname>. "
            "The declaration must contain the target hostname verbatim."
        )

    try:
        parsed = urllib.parse.urlparse(target_url)
        hostname = parsed.hostname or ""
    except Exception:
        hostname = ""

    if not hostname:
        raise ValueError(
            f"Cannot extract hostname from target URL {target_url!r}. "
            "Adversarial mode requires a valid http/https URL."
        )

    if len(hostname) < _MIN_HOSTNAME_LEN:
        raise ValueError(
            f"Target hostname {hostname!r} is too short (< {_MIN_HOSTNAME_LEN} chars) "
            "to be unambiguous in an ownership declaration. "
            "Use a fully-qualified domain name or IP address."
        )

    # Word-boundary match: hostname must appear as a complete token, not a substring
    # of another word. This prevents "I own localhost" matching "localhost.evil.com".
    pattern = r"(?<![A-Za-z0-9._-])" + re.escape(hostname.lower()) + r"(?![A-Za-z0-9._-])"
    if not re.search(pattern, ownership_declaration.lower()):
        raise ValueError(
            f"Ownership declaration {ownership_declaration!r} does not contain "
            f"target hostname {hostname!r} as a complete word. "
            "The --i-own-this-target string must include the exact target hostname "
            "surrounded by non-hostname characters (spaces, punctuation)."
        )


def check_no_external_endpoints(
    probe_dict: dict,
    target_url: str,
    allow_stateful: bool = False,
) -> None:
    """Verify a probe definition does not reference external hosts.

    Adversarial probes must be in-band — canary observation happens through the
    normal response, never via an external callback URL.

    Also rejects stateful-mode probes unless ``allow_stateful`` is set.

    Raises
    ------
    UnsafeProbeError
        If any string value in the probe looks like an external URL, or if the
        probe is stateful and ``allow_stateful`` is False.
    """
    try:
        target_parsed = urllib.parse.urlparse(target_url)
        target_host = (target_parsed.hostname or "").lower()
    except Exception:
        target_host = ""

    mode = probe_dict.get("mode", "read-only")
    if mode == "stateful" and not allow_stateful:
        probe_id = probe_dict.get("id", "<unknown>")
        raise UnsafeProbeError(
            f"Adversarial probe {probe_id!r} has mode='stateful' but "
            "--allow-stateful-adversarial was not set. "
            "Stateful adversarial probes modify server state — pass the flag to enable."
        )

    _check_dict_for_external_urls(probe_dict, target_host)


def _check_dict_for_external_urls(obj: object, target_host: str) -> None:
    """Recursively walk a probe structure and reject external URL strings."""
    if isinstance(obj, str):
        _reject_if_external_url(obj, target_host)
    elif isinstance(obj, dict):
        for v in obj.values():
            _check_dict_for_external_urls(v, target_host)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _check_dict_for_external_urls(item, target_host)


def _reject_if_external_url(s: str, target_host: str) -> None:
    """Raise UnsafeProbeError if *s* is an http/https URL pointing to an unsafe host.

    Blocks:
    - Any loopback/link-local/unspecified IP address (127.x, ::1, 0.0.0.0, 169.254.x)
      regardless of whether it matches the target — prevents probes from calling
      internal paths on the same machine that aren't the MCP endpoint.
    - Any external hostname that does not match the target.
    """
    lower = s.lower().strip()
    if not (lower.startswith("http://") or lower.startswith("https://")):
        return
    try:
        parsed = urllib.parse.urlparse(s)
        host = (parsed.hostname or "").lower()
    except Exception:
        return
    if not host:
        return

    # Always-blocked: loopback, link-local, unspecified
    if _is_blocked_address(host):
        raise UnsafeProbeError(
            f"Adversarial probe contains URL with blocked address {host!r}. "
            "Loopback, link-local, and unspecified addresses are never permitted "
            "in probe payload URLs."
        )

    # External host check: must match target
    if host != target_host:
        raise UnsafeProbeError(
            f"Adversarial probe contains external URL pointing to {host!r} "
            f"(target is {target_host!r}). "
            "Adversarial probes must be in-band — no external callback endpoints."
        )
