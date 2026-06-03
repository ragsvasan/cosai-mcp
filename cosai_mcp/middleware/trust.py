"""T9: Trust boundary enforcement — LLM output is untrusted, sanitize before re-feed.

The core problem:
  When an MCP tool returns LLM-generated content (e.g. a summarisation tool,
  a code-generation tool, or an agent-to-agent call), that content must be
  treated as UNTRUSTED before it is:
    - Passed back as input to another tool call
    - Injected into a system prompt or user turn
    - Used as shell/SQL/template arguments

  Overreliance on LLM judgment without this sanitization is CoSAI T9.

This module provides:
  - LLMOutputSanitizer   — strips control characters, caps length, flags injection
  - TrustBoundaryChecker — validates content is safe to re-feed into a pipeline

Usage::

    sanitizer = LLMOutputSanitizer()
    clean = sanitizer.sanitize(llm_output)
    if clean.flagged:
        # reject or quarantine; do not pass clean.text back into LLM context
"""
from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from cosai_mcp.middleware.boundary import ResponseBoundaryGuard, ScanResult


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_SAFE_LENGTH = 32_768           # chars; anything longer needs explicit override
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")  # excludes \t \n \r
_NULL_BYTE_RE    = re.compile(r"\x00")

# Unicode categories that are almost always attacker-controlled obfuscation
_DANGEROUS_UNICODE_CATEGORIES = frozenset({"Cf", "Cs", "Co", "Cn"})  # format, surrogate, private, unassigned


@dataclass(frozen=True)
class SanitizedOutput:
    """Result of sanitizing a single piece of LLM-generated content."""
    text: str           # cleaned text (HTML-escaped, control chars stripped)
    flagged: bool       # True if injection patterns or dangerous chars found
    truncated: bool     # True if text was capped at _MAX_SAFE_LENGTH
    findings: tuple     # tuple[str, ...] — human-readable issues found


# ---------------------------------------------------------------------------
# LLM Output Sanitizer
# ---------------------------------------------------------------------------

class LLMOutputSanitizer:
    """Sanitize LLM-generated text before it re-enters the MCP pipeline.

    Performs four steps in order:
      1. Length cap — prevents memory exhaustion from runaway generation
      2. Control character stripping — removes C0/C1 control chars (null bytes,
         escape sequences, backspace etc.) that can hijack terminal output or
         confuse downstream parsers
      3. Dangerous Unicode scrubbing — removes format/private-use/unassigned
         codepoints used for invisible text injection
      4. Injection pattern scan — delegates to ResponseBoundaryGuard
    """

    def __init__(self, max_length: int = _MAX_SAFE_LENGTH) -> None:
        self._max_length = max_length
        self._guard = ResponseBoundaryGuard()

    def sanitize(self, text: str) -> SanitizedOutput:
        """Sanitize ``text`` and return a SanitizedOutput.

        The returned ``text`` field is safe to display; the ``flagged`` field
        indicates whether the content should be quarantined rather than re-fed.
        """
        findings: list[str] = []
        truncated = False

        # Step 1: length cap
        if len(text) > self._max_length:
            text = text[:self._max_length]
            truncated = True
            findings.append(f"Content truncated from original length to {self._max_length} chars")

        # Step 2: null byte removal (always dangerous — terminates C strings, bypasses filters)
        if _NULL_BYTE_RE.search(text):
            text = _NULL_BYTE_RE.sub("", text)
            findings.append("Null bytes removed")

        # Step 3: control character stripping (keep \t, \n, \r)
        if _CONTROL_CHAR_RE.search(text):
            text = _CONTROL_CHAR_RE.sub("", text)
            findings.append("Control characters stripped")

        # Step 4: dangerous Unicode category scrubbing
        cleaned_chars: list[str] = []
        found_dangerous = False
        for ch in text:
            cat = unicodedata.category(ch)
            if cat in _DANGEROUS_UNICODE_CATEGORIES:
                found_dangerous = True
            else:
                cleaned_chars.append(ch)
        if found_dangerous:
            text = "".join(cleaned_chars)
            findings.append("Dangerous Unicode codepoints (format/private-use/unassigned) removed")

        # Step 5: injection pattern scan (content-level — not character-level)
        scan = self._guard.check(text)
        if scan.flagged:
            for f in scan.findings:
                findings.append(f"Injection pattern detected at {f.location!r}: {f.excerpt[:80]}")

        # HTML-escape the cleaned text before storing (store-safe per OWASP)
        safe_text = html.escape(text, quote=True)

        return SanitizedOutput(
            text=safe_text,
            flagged=scan.flagged or bool(findings),
            truncated=truncated,
            findings=tuple(findings),
        )


# ---------------------------------------------------------------------------
# Trust Boundary Checker
# ---------------------------------------------------------------------------

class TrustBoundaryChecker:
    """Validates that content is safe to use as a tool argument or system input.

    This is the decision layer on top of LLMOutputSanitizer — it applies the
    sanitizer and then enforces a policy: flagged content MUST NOT proceed.

    Usage::

        checker = TrustBoundaryChecker()
        safe_text = checker.require_safe(llm_output, context="tool_arg:file_path")
        # raises TrustBoundaryViolation if flagged
    """

    def __init__(self, max_length: int = _MAX_SAFE_LENGTH) -> None:
        self._sanitizer = LLMOutputSanitizer(max_length=max_length)

    def check(self, text: str) -> SanitizedOutput:
        """Sanitize and return result without raising."""
        return self._sanitizer.sanitize(text)

    def require_safe(self, text: str, context: str = "") -> str:
        """Sanitize and return clean text, or raise TrustBoundaryViolation.

        Parameters
        ----------
        text:
            LLM-generated content to validate.
        context:
            Human-readable label for error messages (e.g. ``"tool_arg:url"``).

        Returns
        -------
        str
            The HTML-escaped, sanitized text — safe to log and display.

        Raises
        ------
        TrustBoundaryViolation
            If the content contains injection patterns or dangerous characters.
        """
        result = self._sanitizer.sanitize(text)
        if result.flagged:
            summary = "; ".join(result.findings[:3])
            raise TrustBoundaryViolation(
                f"LLM output rejected at trust boundary"
                + (f" [{context}]" if context else "")
                + f": {summary}"
            )
        return result.text


class TrustBoundaryViolation(Exception):
    """Raised when LLM output fails trust boundary checks.

    Callers must catch this and quarantine or discard the content — never
    silently swallow it and use the original unsanitized text.
    """
