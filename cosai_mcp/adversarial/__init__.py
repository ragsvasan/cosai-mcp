"""Adversarial probe mode for cosai-mcp.

Adversarial probes test for vulnerabilities that require active exploitation
attempts — prompt injection, session token replay, cross-session data leakage.
They use canary-only payloads: scanner-generated strings that prove code path
reachability without extracting real server data.

Safety invariants (non-negotiable):
- Dual opt-in: ``--adversarial`` + ``--i-own-this-target=<hostname>``
- No external endpoints: all canary observation is in-band
- Stateful probes gated by ``--allow-stateful-adversarial``
- Canary values redacted in the public-facing adversarial HTML report
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .canary import Canary, generate_canary, detect_canary
from .enforcer import (
    UnsafeProbeError,
    validate_dual_optin,
    check_no_external_endpoints,
)


@dataclass(frozen=True)
class AdversarialMode:
    """Runtime configuration for an adversarial scan session.

    Attributes
    ----------
    enabled:
        True only when ``--adversarial`` was explicitly passed.
    ownership_declaration:
        The string passed to ``--i-own-this-target``. Must contain the target
        hostname verbatim. None if adversarial mode is disabled.
    allow_stateful:
        Whether stateful adversarial probes are permitted. Defaults to False.
        Requires ``--allow-stateful-adversarial``.
    scan_id:
        The parent scan's UUID, used to generate per-probe canary tokens.
    """
    enabled: bool = False
    ownership_declaration: str | None = None
    allow_stateful: bool = False
    scan_id: str = ""

    def validate(self, target_url: str) -> None:
        """Raise ValueError if the dual opt-in invariant is not satisfied."""
        validate_dual_optin(
            adversarial=self.enabled,
            ownership_declaration=self.ownership_declaration,
            target_url=target_url,
        )

    def make_canary(self, threat_id: str) -> Canary:
        """Generate a fresh canary for one adversarial probe execution."""
        return generate_canary(threat_id=threat_id, scan_id=self.scan_id)


__all__ = [
    "AdversarialMode",
    "Canary",
    "UnsafeProbeError",
    "generate_canary",
    "detect_canary",
    "validate_dual_optin",
    "check_no_external_endpoints",
]
