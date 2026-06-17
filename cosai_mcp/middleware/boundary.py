"""T4: Data/control boundary enforcement and indirect prompt injection detection.

The core problem (locked architecture finding):
  Black-box probing cannot detect T4. The scanner must be IN the call path.
  This module provides two guards that wrap the MCP response pipeline:

  1. ToolPoisoningDetector  — scans tool definitions (name/description/schema)
     for patterns that attempt to hijack the LLM's instruction following.

  2. ResponseBoundaryGuard  — scans tool call responses for indirect prompt
     injection: attacker-controlled content (e.g. a web page fetched by a
     tool) that contains LLM control directives.

Usage (server-side instrumentation or proxy)::

    detector = ToolPoisoningDetector()
    findings = detector.scan(tools_list_response["result"]["tools"])

    guard = ResponseBoundaryGuard()
    result = guard.check(tool_call_response_body)
    if result.flagged:
        # reject / redact / alert
"""
from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Injection pattern library — RE2-compatible (no backreferences/lookbehind)
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an|the)\s+\w+", re.IGNORECASE),
    re.compile(r"new\s+system\s+prompt\s*:", re.IGNORECASE),
    re.compile(r"<\s*system\s*>", re.IGNORECASE),
    re.compile(r"\[system\]", re.IGNORECASE),
    re.compile(r"act\s+as\s+(a|an|the)\s+\w+\s+(without|with\s+no)\s+restrictions?", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"DAN\s+mode", re.IGNORECASE),
    re.compile(r"developer\s+mode\s+(enabled|on|activated)", re.IGNORECASE),
    re.compile(r"bypass\s+(your\s+)?(safety|content|ethical)\s+(filters?|guidelines?|restrictions?)", re.IGNORECASE),  # noqa: E501
    re.compile(r"reveal\s+(your\s+)?(system|initial|original)\s+prompt", re.IGNORECASE),
    re.compile(r"print\s+(your\s+)?(system|initial|original)\s+prompt", re.IGNORECASE),
    re.compile(r"repeat\s+(your\s+)?(system|initial|original)\s+prompt", re.IGNORECASE),
    re.compile(r"exfiltrate", re.IGNORECASE),
    re.compile(r"always\s+(first\s+)?call\s+(the\s+)?\w+\s+tool", re.IGNORECASE),
    re.compile(r"before\s+(anything|every(thing)?)\s+(else\s+)?(you\s+)?(must\s+)?call", re.IGNORECASE),  # noqa: E501
]

# Non-English phrasings of "ignore previous instructions" and friends. Attackers
# localise the injection to slip past English-only keyword filters. Appended to
# _INJECTION_PATTERNS *before* _TOOL_DESCRIPTION_PATTERNS is derived so both the
# response guard and the tool-description scan inherit them.
_INJECTION_PATTERNS += [
    # Spanish
    re.compile(r"ignora\s+(todas\s+)?(las\s+)?instrucciones\s+(previas|anteriores)", re.IGNORECASE),
    # French
    re.compile(r"ignore[rz]?\s+(toutes\s+)?les\s+instructions\s+(précédentes|precedentes)", re.IGNORECASE),  # noqa: E501
    # German
    re.compile(r"ignoriere\s+(alle\s+)?(vorherigen|vorigen)\s+anweisungen", re.IGNORECASE),
    # Portuguese / Italian
    re.compile(r"ignor[ae]\s+(todas\s+)?as\s+instruções\s+anteriores", re.IGNORECASE),
    # Chinese (simplified/traditional): 忽略/无视 (之前|先前|上述) (的)? (指令|指示|提示)
    re.compile(r"(忽略|無視|无视)[^\n]{0,8}(之前|先前|上述|以上)[^\n]{0,6}(指令|指示|提示)"),
]

# Tool-description specific: also catches HTML comment hiding and LLM instruction tokens
_TOOL_DESCRIPTION_PATTERNS: list[re.Pattern[str]] = _INJECTION_PATTERNS + [
    re.compile(r"<!--.{0,300}-->", re.DOTALL),
    re.compile(r"\[\s*INST\s*\]", re.IGNORECASE),
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"\[/?INST\]", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Normalization pre-pass (WG-89 item 10)
# ---------------------------------------------------------------------------
#
# Keyword-literal English matching is trivially evaded: zero-width characters
# split a keyword, Unicode Tag characters smuggle invisible ASCII, RTL overrides
# reorder text, Cyrillic/Greek homoglyphs impersonate Latin letters, leetspeak
# swaps digits for letters, and base64/hex hides the payload entirely. We
# therefore fold the text through several normalizations BEFORE the regex pass
# and match against every resulting variant. Folding only ever ADDS detections;
# the original text is always scanned too, so nothing is lost.

# Invisible / formatting characters stripped before matching: zero-width space,
# ZWNJ, ZWJ, word-joiner, BOM, soft hyphen, and the bidi controls (incl. the
# RTL override U+202E used to visually reverse text).
_INVISIBLE_CHARS: dict[int, None] = dict.fromkeys(
    [
        0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD,  # zero-width / joiners / BOM / soft-hyphen
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E,          # LRE RLE PDF LRO RLO
        0x2066, 0x2067, 0x2068, 0x2069,                  # LRI RLI FSI PDI
    ],
    None,
)

# Common Cyrillic/Greek homoglyphs → Latin look-alike. Folded so that e.g.
# Cyrillic "іgnоrе" (mixed-script) collapses onto ASCII "ignore".
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ո": "n", "м": "m", "т": "t",
    "к": "k", "в": "b", "н": "h", "А": "A", "Е": "E", "О": "O", "Р": "P",
    "С": "C", "Х": "X", "У": "Y", "В": "B", "Н": "H", "К": "K", "М": "M", "Т": "T",
    # Greek
    "ο": "o", "ρ": "p", "α": "a", "ε": "e", "ι": "i", "ν": "v", "τ": "t",
    "Ο": "O", "Ρ": "P", "Α": "A", "Ε": "E", "Τ": "T", "Ι": "I",
}
_HOMOGLYPH_TABLE = {ord(k): v for k, v in _HOMOGLYPHS.items()}

# Leetspeak fold: digits/symbols → the Latin letter they impersonate. Applied as
# an EXTRA variant (never replaces the original), so "1gn0r3 pr3v10us" folds to
# "ignore previous" while ordinary text containing digits is still scanned raw.
_LEET_TABLE = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "@": "a", "$": "s", "8": "b", "+": "t", "|": "i",
})

_B64_FRAGMENT_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_FRAGMENT_RE = re.compile(r"[0-9a-fA-F]{16,}")


def _decode_tag_chars(text: str) -> str:
    """Reveal ASCII smuggled via Unicode Tag characters (U+E0000–U+E007F).

    Tag characters are invisible but map 1:1 onto ASCII (cp − 0xE0000). They are
    the modern "ASCII smuggling" vector for hiding instructions inside otherwise
    innocuous text. Language-tag / cancel tags are dropped.
    """
    out: list[str] = []
    changed = False
    for ch in text:
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F:
            changed = True
            ascii_cp = cp - 0xE0000
            if 0x20 <= ascii_cp <= 0x7E:
                out.append(chr(ascii_cp))
            # else: language tag (U+E0001) / cancel (U+E007F) → drop
        else:
            out.append(ch)
    return "".join(out) if changed else text


def _normalize_unicode(text: str) -> str:
    """NFKC-normalize, strip invisible/bidi characters, and fold homoglyphs."""
    norm = unicodedata.normalize("NFKC", text)
    norm = norm.translate(_INVISIBLE_CHARS)
    return norm.translate(_HOMOGLYPH_TABLE)


def _decode_encoded_fragments(text: str) -> list[str]:
    """Best-effort decode of base64/hex substrings to printable text.

    Returns decoded strings that are predominantly printable, so an injection
    hidden as base64/hex inside a description or response is revealed to the
    regex pass. Non-decodable or binary fragments are ignored.
    """
    out: list[str] = []

    def _mostly_printable(s: str) -> bool:
        return bool(s) and sum(c.isprintable() or c.isspace() for c in s) >= 0.8 * len(s)

    for frag in _B64_FRAGMENT_RE.findall(text):
        candidate = frag.rstrip("=")
        std = candidate.replace("-", "+").replace("_", "/")
        for variant in {candidate, std}:
            try:
                pad = (4 - len(variant) % 4) % 4
                decoded = base64.b64decode(variant + "=" * pad).decode("utf-8", "ignore")
            except (ValueError, binascii.Error):
                continue
            if _mostly_printable(decoded):
                out.append(decoded)

    for frag in _HEX_FRAGMENT_RE.findall(text):
        if len(frag) % 2 != 0:
            continue
        try:
            decoded = bytes.fromhex(frag).decode("utf-8", "ignore")
        except ValueError:
            continue
        if _mostly_printable(decoded):
            out.append(decoded)

    return out


def _detection_variants(text: str) -> list[str]:
    """Return the original text plus every normalized/decoded variant to scan.

    Order is stable and deduplicated; the original is always first so its match
    offsets are preferred for excerpting.
    """
    variants: list[str] = []
    seen: set[str] = set()

    def _add(s: str) -> None:
        if s and s not in seen:
            seen.add(s)
            variants.append(s)

    _add(text)
    tag_decoded = _decode_tag_chars(text)
    _add(tag_decoded)
    for base in (text, tag_decoded):
        folded = _normalize_unicode(base)
        _add(folded)
        _add(folded.translate(_LEET_TABLE))
    for fragment in _decode_encoded_fragments(tag_decoded):
        _add(fragment)
    return variants


@dataclass(frozen=True)
class InjectionFinding:
    """A single detected injection pattern."""
    location: str    # e.g. "tool:echo:description", "response_body"
    pattern: str     # the regex pattern string that matched
    excerpt: str     # up to 120 chars of surrounding context, HTML-escaped
    severity: str    # "critical" | "high"


@dataclass
class ScanResult:
    """Outcome of a boundary scan — mutable accumulator, not frozen."""
    flagged: bool = False
    findings: list[InjectionFinding] = field(default_factory=list)

    def add(self, finding: InjectionFinding) -> None:
        self.findings.append(finding)
        self.flagged = True


def _excerpt(text: str, match: re.Match[str], window: int = 60) -> str:
    start = max(0, match.start() - window)
    end = min(len(text), match.end() + window)
    return html.escape(text[start:end], quote=True)


# ---------------------------------------------------------------------------
# Tool Poisoning Detector
# ---------------------------------------------------------------------------

class ToolPoisoningDetector:
    """Scans a tools/list manifest for prompt injection hidden in tool metadata.

    Attackers embed LLM control directives in tool names, descriptions, or
    parameter schema descriptions so that when the LLM reads the manifest it
    executes attacker instructions.
    """

    def scan(self, tools: list[dict[str, Any]]) -> ScanResult:
        """Scan a list of tool dicts from a tools/list response.

        Parameters
        ----------
        tools:
            The ``result["tools"]`` list from a JSON-RPC tools/list response.
        """
        result = ScanResult()
        for tool in tools:
            name = str(tool.get("name", ""))
            self._check(name, f"tool:{name}:name", _INJECTION_PATTERNS, result, "critical")

            description = str(tool.get("description", ""))
            self._check(description, f"tool:{name}:description", _TOOL_DESCRIPTION_PATTERNS, result, "critical")  # noqa: E501

            schema = tool.get("inputSchema", {})
            if isinstance(schema, dict):
                self._scan_schema(schema, f"tool:{name}:schema", result)

        return result

    def _check(
        self,
        text: str,
        location: str,
        patterns: list[re.Pattern[str]],
        result: ScanResult,
        severity: str,
    ) -> None:
        variants = _detection_variants(text)
        for pattern in patterns:
            for variant in variants:
                m = pattern.search(variant)
                if m:
                    result.add(InjectionFinding(
                        location=location,
                        pattern=pattern.pattern,
                        excerpt=_excerpt(variant, m),
                        severity=severity,
                    ))
                    break  # one finding per pattern is enough; avoid variant dupes

    def _scan_schema(self, schema: dict[str, Any], location: str, result: ScanResult) -> None:
        desc = str(schema.get("description", ""))
        if desc:
            self._check(desc, location + ":description", _TOOL_DESCRIPTION_PATTERNS, result, "critical")  # noqa: E501
        for prop_name, prop_def in schema.get("properties", {}).items():
            if isinstance(prop_def, dict):
                self._scan_schema(prop_def, f"{location}.{prop_name}", result)


# ---------------------------------------------------------------------------
# Response Boundary Guard
# ---------------------------------------------------------------------------

class ResponseBoundaryGuard:
    """Scans tool call response bodies for indirect prompt injection.

    The response body is attacker-controlled — it may be content fetched from
    an external URL, user-supplied documents, or database rows. Any injection
    pattern embedded there can hijack a downstream LLM.
    """

    def check(self, body: str) -> ScanResult:
        """Scan a response body for prompt injection patterns.

        Parameters
        ----------
        body:
            Plain-text content of a tool call response.
        """
        result = ScanResult()
        variants = _detection_variants(body)
        for pattern in _INJECTION_PATTERNS:
            for variant in variants:
                m = pattern.search(variant)
                if m:
                    result.add(InjectionFinding(
                        location="response_body",
                        pattern=pattern.pattern,
                        excerpt=_excerpt(variant, m),
                        severity="high",
                    ))
                    break  # one finding per pattern; evasion variants collapse here
        return result
