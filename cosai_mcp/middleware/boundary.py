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

import html
import re
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
    re.compile(r"bypass\s+(your\s+)?(safety|content|ethical)\s+(filters?|guidelines?|restrictions?)", re.IGNORECASE),
    re.compile(r"reveal\s+(your\s+)?(system|initial|original)\s+prompt", re.IGNORECASE),
    re.compile(r"print\s+(your\s+)?(system|initial|original)\s+prompt", re.IGNORECASE),
    re.compile(r"repeat\s+(your\s+)?(system|initial|original)\s+prompt", re.IGNORECASE),
    re.compile(r"exfiltrate", re.IGNORECASE),
    re.compile(r"always\s+(first\s+)?call\s+(the\s+)?\w+\s+tool", re.IGNORECASE),
    re.compile(r"before\s+(anything|every(thing)?)\s+(else\s+)?(you\s+)?(must\s+)?call", re.IGNORECASE),
]

# Tool-description specific: also catches HTML comment hiding and LLM instruction tokens
_TOOL_DESCRIPTION_PATTERNS: list[re.Pattern[str]] = _INJECTION_PATTERNS + [
    re.compile(r"<!--.{0,300}-->", re.DOTALL),
    re.compile(r"\[\s*INST\s*\]", re.IGNORECASE),
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"\[/?INST\]", re.IGNORECASE),
]


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
            self._check(description, f"tool:{name}:description", _TOOL_DESCRIPTION_PATTERNS, result, "critical")

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
        for pattern in patterns:
            m = pattern.search(text)
            if m:
                result.add(InjectionFinding(
                    location=location,
                    pattern=pattern.pattern,
                    excerpt=_excerpt(text, m),
                    severity=severity,
                ))

    def _scan_schema(self, schema: dict[str, Any], location: str, result: ScanResult) -> None:
        desc = str(schema.get("description", ""))
        if desc:
            self._check(desc, location + ":description", _TOOL_DESCRIPTION_PATTERNS, result, "critical")
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
        for pattern in _INJECTION_PATTERNS:
            m = pattern.search(body)
            if m:
                result.add(InjectionFinding(
                    location="response_body",
                    pattern=pattern.pattern,
                    excerpt=_excerpt(body, m),
                    severity="high",
                ))
        return result
