"""Canary generation and detection for adversarial probes.

A canary is a per-scan, per-probe unique string that proves a code path was
reached without extracting any real server-side data. Canary values:

- Are scanner-generated and ephemeral (not reusable across scans).
- Never exfiltrate to external endpoints — all observation is in-band.
- Are redacted in the adversarial HTML report ("WHAT WE SENT" → [CANARY REDACTED]).
- Use CSPRNG (secrets module) for the token component.
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class Canary:
    """Immutable canary value for one probe execution.

    Attributes
    ----------
    value:
        The canary string, e.g. ``"COSAI_PROBE_T03_c5e25cf_a3f2b1e0"``.
    threat_id:
        CoSAI threat ID this canary was generated for.
    scan_id_prefix:
        First 8 chars of the scan ID (for traceability).
    """
    value: str
    threat_id: str
    scan_id_prefix: str

    def redacted(self) -> str:
        """Return a display-safe placeholder for report rendering."""
        return "[CANARY REDACTED]"


_CANARY_PREFIX = "COSAI_PROBE"
# Matches: COSAI_PROBE_{THREAT_ID}_{8-CHAR-UPPER-PREFIX}_{HEX-TOKEN}
# THREAT_ID may contain hyphens (e.g. T03-ADV-001). Token is 8+ hex chars.
_CANARY_PATTERN = re.compile(r"COSAI_PROBE_[A-Z][A-Z0-9-]*_[0-9A-F]{8}_[0-9a-f]+")


def generate_canary(threat_id: str, scan_id: str) -> Canary:
    """Generate a unique canary for one probe in one scan.

    Format: ``COSAI_PROBE_{threat_id}_{scan_id[:8]}_{token_hex(8)}``
    Example: ``COSAI_PROBE_T03-ADV-001_C5E25CF1_a3f2b1e0c4d5e6f7``

    The token component uses :mod:`secrets` (CSPRNG) — 64-bit entropy per
    NIST SP 800-131A. Never use ``random``.
    """
    safe_id = threat_id.upper()
    prefix = scan_id[:8].upper() if scan_id else "00000000"
    token = secrets.token_hex(8)  # 64-bit entropy
    value = f"{_CANARY_PREFIX}_{safe_id}_{prefix}_{token}"
    return Canary(value=value, threat_id=threat_id, scan_id_prefix=prefix)


def detect_canary(response_body: str, canary: Canary) -> bool:
    """Return True if the canary value appears in *response_body*.

    The check is exact-string, not regex — the canary value is a scanner-owned
    literal, so we control both ends and don't need pattern flexibility.
    """
    if not response_body:
        return False
    return canary.value in response_body
