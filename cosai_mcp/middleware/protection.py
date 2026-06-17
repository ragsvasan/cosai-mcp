"""T5: Context leak prevention, PII scrubbing (RE2 only, stdlib re fallback for dev).

WG-89 reviewer item 3 — a real secret-pattern set, not just ``sk-``/``Bearer``.

Two tiers, split for speed and false-positive control:

* **Default (always on)** — high-confidence, anchored credential & context-leak
  patterns. Every one has a literal anchor (``AKIA``, ``ghp_``, ``AIza`` …) so the
  false-positive rate is near zero and matching stays cheap.
* **Strict (``pii_strict=True``, opt-in via ``--pii-strict``)** — broader PII with
  higher false-positive potential: SSN, IBAN, US phone, and PAN. PAN is
  **corroborated by the Luhn checksum** (primary regex narrows candidates; Luhn
  confirms) to keep the FP rate low, mirroring the catalog's primary+corroboration
  mechanism. Off by default to keep the common scan fast.
"""
from __future__ import annotations

import warnings
from dataclasses import dataclass
from typing import Callable

try:
    import re2 as _re
    _RE2_AVAILABLE = True
    _ReError = _re.error
except ImportError:
    import re as _re  # type: ignore[no-redef]
    _RE2_AVAILABLE = False
    _ReError = _re.error  # type: ignore[assignment]
    warnings.warn(
        "google-re2 not available; falling back to stdlib re. "
        "Production deployments must use google-re2 (no backtracking guarantee).",
        RuntimeWarning,
        stacklevel=1,
    )

# ---------------------------------------------------------------------------
# Pattern tiers — RE2-safe (no backreferences, bounded repetition only)
# ---------------------------------------------------------------------------

# Default tier: anchored credentials + context-leak signals. Low FP, always on.
_DEFAULT_PATTERNS: list[tuple[str, str]] = [
    ("email",            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    # --- credentials / tokens (anchored) ---
    ("jwt",              r"eyJ[A-Za-z0-9_\-]{2,}\.eyJ[A-Za-z0-9_\-]{2,}\.[A-Za-z0-9_\-]*"),
    ("api_key_sk",       r"\bsk-[A-Za-z0-9]{20,}\b"),
    ("github_pat",       r"\bgh[posu]_[A-Za-z0-9]{36}\b"),       # ghp_/gho_/ghs_/ghu_
    ("gitlab_pat",       r"\bglpat-[A-Za-z0-9_\-]{20}\b"),
    ("aws_access_key",   r"\bAKIA[0-9A-Z]{16}\b"),
    ("google_api_key",   r"\bAIza[A-Za-z0-9_\-]{35}\b"),
    ("gcp_service_account", r'"type"\s*:\s*"service_account"'),  # GCP SA JSON marker
    ("azure_sas",        r"[?&]sig=[A-Za-z0-9%/+]{20,}"),        # Azure SAS signature param
    # --- context leakage (T5 is context leakage too, not only credentials) ---
    ("internal_hostname",
     r"\b[a-z0-9][a-z0-9\-]*\.(?:internal|local|corp|intranet|svc\.cluster\.local)\b"),
    ("stack_trace", r"Traceback \(most recent call last\)|(?m)^\s+at [\w.$<>/]+\("),
]

# Strict tier: broad PII, opt-in only. PAN additionally Luhn-corroborated below.
_STRICT_PATTERNS: list[tuple[str, str]] = [
    ("ssn",      r"\b\d{3}-\d{2}-\d{4}\b"),
    ("us_phone", r"\b(?:\+1[.\-\s]?)?\(?\d{3}\)?[.\-\s]?\d{3}[.\-\s]?\d{4}\b"),
    ("iban",     r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    ("pan",      r"\b(?:\d[ \-]?){13,19}\b"),
]

# Session-ID-like tokens: prefixed by sess or session, dash or underscore separated
_SESSION_PATTERN_STR = r"\bsess(?:ion)?[-_][A-Za-z0-9_\-]{3,}\b"

# Unambiguous secrets/credentials — never legitimately present in a tool manifest.
# The passive T5 manifest scan reports only these (+ strict PII when enabled) so it
# does not false-positive on example emails / doc hostnames in tool descriptions.
CREDENTIAL_TYPES: frozenset[str] = frozenset({
    "jwt", "api_key_sk", "github_pat", "gitlab_pat", "aws_access_key",
    "google_api_key", "gcp_service_account", "azure_sas",
})

# Broad-PII types gated behind pii_strict.
STRICT_PII_TYPES: frozenset[str] = frozenset({"ssn", "us_phone", "iban", "pan"})

# pii_types whose regex match is only a *candidate* — a corroborating validator
# must also pass for the match to be reported. Keeps the broad PAN regex honest.
_CORROBORATORS: dict[str, Callable[[str], bool]] = {}


def _luhn_valid(candidate: str) -> bool:
    """Return True if the digits of *candidate* satisfy the Luhn checksum.

    Strips spaces/dashes first. Requires 13–19 digits (PAN length range).
    Pure, allocation-light, no backtracking — safe as a corroboration step.
    """
    digits = [int(c) for c in candidate if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


_CORROBORATORS["pan"] = _luhn_valid


@dataclass(frozen=True)
class RedactedMatch:
    pii_type: str
    start: int
    end: int


@dataclass(frozen=True)
class ScrubResult:
    text: str
    redacted_count: int
    findings: tuple  # tuple[RedactedMatch, ...]


@dataclass(frozen=True)
class LeakFinding:
    current_session_id: str
    found_session_id: str
    offset: int


@dataclass(frozen=True)
class LeakCheckResult:
    leaked: bool
    findings: tuple  # tuple[LeakFinding, ...]


class PIIScrubber:
    """Scrub PII and secrets from text using RE2 patterns (no backtracking).

    Parameters
    ----------
    pii_strict:
        When *True*, additionally match the broad-PII strict tier (SSN, IBAN,
        US phone, Luhn-corroborated PAN). Default *False* keeps the scan to the
        anchored, low-false-positive credential/context-leak tier.
    """

    def __init__(self, pii_strict: bool = False) -> None:
        self._pii_strict = pii_strict
        patterns = list(_DEFAULT_PATTERNS)
        if pii_strict:
            patterns += _STRICT_PATTERNS
        self._compiled: list[tuple[str, object]] = []
        for name, pattern in patterns:
            try:
                self._compiled.append((name, _re.compile(pattern)))
            except _ReError as exc:
                raise RuntimeError(
                    f"RE2 rejected built-in pattern {name!r}: {exc}"
                ) from exc

    @property
    def pii_strict(self) -> bool:
        return self._pii_strict

    def scrub(self, text: str) -> ScrubResult:
        """Replace PII/secret occurrences with [REDACTED:<type>] tokens.

        Non-overlapping greedy selection: longest match wins on overlap.
        Corroborated types (e.g. PAN → Luhn) are dropped when the validator
        fails, so a 16-digit non-card number is left untouched.
        """
        all_matches: list[tuple[int, int, str]] = []
        for pii_type, pattern in self._compiled:
            corroborate = _CORROBORATORS.get(pii_type)
            for m in pattern.finditer(text):  # type: ignore[union-attr]
                if corroborate is not None and not corroborate(m.group(0)):
                    continue  # candidate failed corroboration (e.g. Luhn) — skip
                all_matches.append((m.start(), m.end(), pii_type))

        if not all_matches:
            return ScrubResult(text=text, redacted_count=0, findings=())

        # Sort by start position, then longest match first
        all_matches.sort(key=lambda x: (x[0], -(x[1] - x[0])))

        # Non-overlapping greedy selection
        selected: list[tuple[int, int, str]] = []
        cursor = 0
        for start, end, pii_type in all_matches:
            if start >= cursor:
                selected.append((start, end, pii_type))
                cursor = end

        # Build redacted string
        parts: list[str] = []
        prev = 0
        findings: list[RedactedMatch] = []
        for start, end, pii_type in selected:
            parts.append(text[prev:start])
            parts.append(f"[REDACTED:{pii_type}]")
            findings.append(RedactedMatch(pii_type=pii_type, start=start, end=end))
            prev = end
        parts.append(text[prev:])

        return ScrubResult(
            text="".join(parts),
            redacted_count=len(selected),
            findings=tuple(findings),
        )


class ContextLeakChecker:
    """Detect cross-session context bleed (foreign session ID in a response)."""

    def __init__(self) -> None:
        try:
            self._pattern = _re.compile(_SESSION_PATTERN_STR)
        except _ReError as exc:
            raise RuntimeError(
                f"RE2 rejected session-ID pattern: {exc}"
            ) from exc

    def check(self, current_session_id: str, content: str) -> LeakCheckResult:
        """Scan *content* for session-ID-like tokens that belong to a different session."""
        findings: list[LeakFinding] = []
        for m in self._pattern.finditer(content):  # type: ignore[union-attr]
            found = m.group(0)
            if found != current_session_id:
                findings.append(LeakFinding(
                    current_session_id=current_session_id,
                    found_session_id=found,
                    offset=m.start(),
                ))
        return LeakCheckResult(leaked=bool(findings), findings=tuple(findings))
