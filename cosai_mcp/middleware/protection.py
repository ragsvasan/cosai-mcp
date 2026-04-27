"""T5: Context leak prevention, PII scrubbing (RE2 only, stdlib re fallback for dev)."""
from __future__ import annotations

import warnings
from dataclasses import dataclass

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

# (pii_type, pattern_string) — RE2-safe patterns only (no backtracking)
_PII_PATTERNS: list[tuple[str, str]] = [
    ("ssn",         r"\b\d{3}-\d{2}-\d{4}\b"),
    ("credit_card", r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
    ("email",       r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    ("us_phone",    r"\b(?:\+1[.\-\s]?)?\(?\d{3}\)?[.\-\s]?\d{3}[.\-\s]?\d{4}\b"),
    ("jwt",         r"eyJ[A-Za-z0-9_\-]{2,}\.[A-Za-z0-9_\-]{2,}\.[A-Za-z0-9_\-]*"),
    ("api_key_sk",  r"\bsk-[A-Za-z0-9]{20,}\b"),
    ("github_pat",  r"\bghp_[A-Za-z0-9]{36}\b"),
    # hex_api_key (r"\b[0-9a-f]{40}\b") removed: indistinguishable from git SHA-1
    # hashes without surrounding context — produces high false-positive rate on
    # commit logs and repo metadata that appear in MCP tool output.
]

# Session-ID-like tokens: prefixed by sess or session, dash or underscore separated
_SESSION_PATTERN_STR = r"\bsess(?:ion)?[-_][A-Za-z0-9_\-]{3,}\b"


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
    """Scrub PII and secrets from text using RE2 patterns (no backtracking)."""

    def __init__(self) -> None:
        self._compiled: list[tuple[str, object]] = []
        for name, pattern in _PII_PATTERNS:
            try:
                self._compiled.append((name, _re.compile(pattern)))
            except _ReError as exc:
                raise RuntimeError(
                    f"RE2 rejected built-in pattern {name!r}: {exc}"
                ) from exc

    def scrub(self, text: str) -> ScrubResult:
        """Replace PII occurrences with [REDACTED:<type>] tokens.

        Non-overlapping greedy selection: longest match wins on overlap.
        """
        all_matches: list[tuple[int, int, str]] = []
        for pii_type, pattern in self._compiled:
            for m in pattern.finditer(text):  # type: ignore[union-attr]
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
