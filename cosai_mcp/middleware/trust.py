"""T9: Trust boundary enforcement — LLM output is untrusted, sanitize before re-feed.

SVRTrustGate (Structural Verification Receipt):
  Sits after ResponseBoundaryGuard in check_response().  If an MCP server
  attaches a Signed Verification Receipt to its tool outputs, this gate
  verifies the receipt before the output is allowed to continue downstream.

  Four checks in order:
    1. Structure     — required fields present
    2. Ed25519 sig   — receipt was signed by the expected key (skipped when
                       no public key is configured)
    3. Input hash    — SHA-256 of tool_output matches receipt.input_hash
    4. Verdict       — receipt.verdict.safe_to_rely is True

  All four must pass.  Failed gates log to audit (never raise) — callers decide
  whether to quarantine or reject flagged responses.

  Usage::

      gate = SVRTrustGate(public_key_hex="deadbeef...")
      result = gate.verify_before_chain(receipt_dict, tool_output_text)
      if not result.verified:
          # quarantine or reject

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

import base64
import hashlib
import html
import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

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


# ---------------------------------------------------------------------------
# SVR Trust Gate — Structural Verification Receipt
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SVRGateResult:
    """Outcome of SVR receipt verification before downstream chaining."""
    verified: bool          # True only if ALL four checks pass
    receipt_id: str | None  # from receipt["receipt_id"]; None if absent/missing
    verdict_safe: bool | None  # receipt.verdict.safe_to_rely; None if unreadable
    structure_ok: bool
    signature_ok: bool      # True when sig verified; True when no pubkey (not checked)
    hash_match: bool
    issues: tuple[str, ...]  # human-readable failure reasons, HTML-escaped


_SVR_REQUIRED_FIELDS = frozenset({"receipt_id", "input_hash", "verdict", "signature"})


class SVRTrustGate:
    """Verify a Structural Verification Receipt before chaining tool output.

    The gate enforces the T9 invariant: "verify before chain continues."
    All four checks must pass for ``result.verified`` to be True.

    Parameters
    ----------
    public_key_hex:
        Hex-encoded raw 32-byte Ed25519 public key used to verify the
        receipt's signature.  When ``None``, signature verification is
        skipped (structure, hash, and verdict checks still run).
    """

    def __init__(self, public_key_hex: str | None = None) -> None:
        self._pubkey: Ed25519PublicKey | None = None
        if public_key_hex:
            raw = bytes.fromhex(public_key_hex)
            self._pubkey = Ed25519PublicKey.from_public_bytes(raw)

    def verify_before_chain(
        self,
        receipt: dict[str, Any] | None,
        tool_output: str,
    ) -> SVRGateResult:
        """Verify ``receipt`` against ``tool_output`` before downstream chaining.

        Parameters
        ----------
        receipt:
            Parsed receipt dict attached to the tool response.  May be
            ``None`` or empty — both are treated as "receipt absent" failures.
        tool_output:
            The raw text content of the tool call response.  The gate
            computes ``sha256:`` + hex-digest and compares it to
            ``receipt["input_hash"]``.
        """
        if not receipt:
            return SVRGateResult(
                verified=False, receipt_id=None, verdict_safe=None,
                structure_ok=False, signature_ok=False, hash_match=False,
                issues=("receipt absent or empty",),
            )

        issues: list[str] = []

        # 1. Structure check
        missing = _SVR_REQUIRED_FIELDS - set(receipt.keys())
        if missing:
            for f in sorted(missing):
                issues.append(html.escape(f"missing field: {f!r}", quote=True))
            return SVRGateResult(
                verified=False,
                receipt_id=receipt.get("receipt_id"),
                verdict_safe=None,
                structure_ok=False,
                signature_ok=False,
                hash_match=False,
                issues=tuple(issues),
            )

        receipt_id: str | None = receipt.get("receipt_id")
        structure_ok = True

        # 2. Ed25519 signature verification
        signature_ok = True  # default: "not checked" when no pubkey
        if self._pubkey is not None:
            try:
                sig_bytes = base64.b64decode(receipt["signature"])
                payload = {k: v for k, v in receipt.items() if k != "signature"}
                canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
                self._pubkey.verify(sig_bytes, canonical.encode())
            except (InvalidSignature, Exception) as exc:
                signature_ok = False
                issues.append(html.escape(f"signature invalid: {exc}", quote=True))

        # 3. Input hash match — sha256 of the tool output bytes
        expected = "sha256:" + hashlib.sha256(tool_output.encode()).hexdigest()
        actual = receipt.get("input_hash", "")
        hash_match = actual == expected
        if not hash_match:
            issues.append(
                html.escape(
                    f"input_hash mismatch: receipt has {actual!r}, "
                    f"expected {expected!r}",
                    quote=True,
                )
            )

        # 4. Verdict — safe_to_rely must be True
        verdict = receipt.get("verdict")
        verdict_safe: bool | None = (
            verdict.get("safe_to_rely", False) if isinstance(verdict, dict) else False
        )
        if not verdict_safe:
            issues.append(html.escape(f"verdict safe_to_rely={verdict_safe!r}", quote=True))

        verified = structure_ok and signature_ok and hash_match and bool(verdict_safe)
        return SVRGateResult(
            verified=verified,
            receipt_id=receipt_id,
            verdict_safe=verdict_safe,
            structure_ok=structure_ok,
            signature_ok=signature_ok,
            hash_match=hash_match,
            issues=tuple(issues),
        )
