"""T6: Typosquat detection, manifest baseline checking, tool shadowing detection."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TyposquatFinding:
    tool_name: str
    closest_match: str
    distance: int
    severity: str  # "high" (distance ≤ 1) | "medium" (distance == 2)


@dataclass(frozen=True)
class ManifestDrift:
    """Tools added or removed between baseline and current tools/list response."""
    added: tuple    # tuple[str, ...] — tool names added since baseline
    removed: tuple  # tuple[str, ...] — tool names removed since baseline


def levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings.

    O(m*n) time, O(n) space. Safe for tool names (short strings; no RE2 needed).
    """
    if a == b:
        return 0
    m, n = len(a), len(b)
    if not a:
        return n
    if not b:
        return m

    prev = list(range(n + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * n
        for j, cb in enumerate(b, 1):
            curr[j] = min(
                prev[j] + 1,                           # deletion
                curr[j - 1] + 1,                       # insertion
                prev[j - 1] + (0 if ca == cb else 1),  # substitution
            )
        prev = curr
    return prev[n]


class TyposquatDetector:
    """Detect tool names within edit-distance 2 of an allowlisted trusted name.

    Only active when an allowlist is configured (empty allowlist → no findings).
    Exact matches are never flagged.
    """

    def check_tools(
        self,
        tools: list[dict[str, Any]],
        allowlist: list[str],
        max_distance: int = 2,
    ) -> list[TyposquatFinding]:
        """Return findings for tools whose names are suspiciously close to allowlisted names.

        A tool whose name IS in the allowlist is an exact match — not flagged.
        A tool with Levenshtein distance ≤ max_distance to any allowlisted name is flagged.
        """
        if not allowlist:
            return []

        findings: list[TyposquatFinding] = []
        for tool in tools:
            tool_name = tool.get("name", "")
            if tool_name in allowlist:
                continue  # exact match — allowed

            best_dist = max_distance + 1
            best_match = ""
            for allowed in allowlist:
                d = levenshtein(tool_name, allowed)
                if d <= max_distance and d < best_dist:
                    best_dist = d
                    best_match = allowed

            if best_match:
                severity = "high" if best_dist <= 1 else "medium"
                findings.append(TyposquatFinding(
                    tool_name=tool_name,
                    closest_match=best_match,
                    distance=best_dist,
                    severity=severity,
                ))

        return findings


class ManifestBaselineChecker:
    """Store a tools/list baseline hash and detect drift on re-fetch.

    Used to detect mid-session tool injection or shadowing (T6).
    """

    def __init__(self) -> None:
        self._baseline: frozenset[str] | None = None
        self._baseline_hash: str | None = None

    def store_baseline(self, tools: list[dict[str, Any]]) -> None:
        """Capture the initial tools/list response as the trusted baseline."""
        names = frozenset(t.get("name", "") for t in tools)
        self._baseline = names
        canonical = json.dumps(sorted(names))
        self._baseline_hash = hashlib.sha256(canonical.encode()).hexdigest()

    def check_drift(self, tools: list[dict[str, Any]]) -> ManifestDrift | None:
        """Compare *tools* against baseline.

        Returns a ManifestDrift if the set of tool names has changed, else None.
        Raises RuntimeError if no baseline has been stored yet.
        """
        if self._baseline is None:
            raise RuntimeError(
                "No baseline stored. Call store_baseline() before check_drift()."
            )
        current = frozenset(t.get("name", "") for t in tools)
        added = current - self._baseline
        removed = self._baseline - current
        if added or removed:
            return ManifestDrift(
                added=tuple(sorted(added)),
                removed=tuple(sorted(removed)),
            )
        return None

    @property
    def baseline_hash(self) -> str | None:
        return self._baseline_hash
