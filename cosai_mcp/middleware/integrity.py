"""T6: Typosquat detection, manifest baseline checking, tool shadowing detection."""
from __future__ import annotations

import hashlib
import json
import sys
import warnings
from dataclasses import dataclass
from typing import Any

# Small reference allowlist of well-known MCP tool names drawn from the widely
# deployed reference servers (filesystem, git, github, fetch, memory, sqlite,
# time, …). When the operator supplies no allowlist, the detector falls back to
# this set so it does not silently return nothing (the "false green" WG-89 item
# 11 flagged). It is intentionally small and conservative — it exists to catch
# squats of household-name tools, not to be an exhaustive registry.
WELL_KNOWN_MCP_TOOLS: frozenset[str] = frozenset({
    "read_file", "read_text_file", "read_media_file", "write_file", "edit_file",
    "list_directory", "create_directory", "directory_tree", "move_file",
    "search_files", "get_file_info", "list_allowed_directories",
    "fetch", "search", "search_repositories", "create_issue", "create_pull_request",
    "get_file_contents", "list_commits", "create_or_update_file",
    "read_query", "write_query", "create_table", "list_tables", "describe_table",
    "get_current_time", "convert_time", "sequentialthinking",
})

# Standard MCP JSON-RPC method names a tool name must never shadow (T6). A tool
# whose name equals or is one edit away from one of these can intercept or
# impersonate a protocol method. Kept in sync conceptually with the reserved
# set used by the passive manifest scan in cosai_mcp.api.
STANDARD_MCP_METHODS: frozenset[str] = frozenset({
    "initialize", "ping", "tools/list", "tools/call",
    "resources/list", "resources/read", "resources/templates/list",
    "resources/subscribe", "resources/unsubscribe",
    "prompts/list", "prompts/get", "completion/complete",
    "logging/setlevel", "roots/list", "sampling/createmessage",
    "notifications/initialized", "notifications/cancelled",
})

# Cyrillic/Greek homoglyphs → Latin look-alike. Tool names are folded through
# this map before edit-distance comparison so a mixed-script squat such as
# Cyrillic "rеad_file" (е = U+0435) collapses onto ASCII "read_file".
_HOMOGLYPHS: dict[int, str] = {
    ord(k): v for k, v in {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
        "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ո": "n", "м": "m", "т": "t",
        "к": "k", "в": "b", "н": "h", "г": "r",
        # Greek
        "ο": "o", "ρ": "p", "α": "a", "ε": "e", "ι": "i", "ν": "v", "τ": "t",
    }.items()
}


def fold_homoglyphs(name: str) -> str:
    """Fold common Cyrillic/Greek homoglyphs in *name* to their Latin look-alike."""
    return name.translate(_HOMOGLYPHS)


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
    """Detect tool names within edit-distance 2 of a trusted name.

    Two trust anchors are checked (homoglyph-folded before comparison):

    1. The operator-supplied ``allowlist``. When it is empty, the detector no
       longer returns nothing silently (the WG-89 item-11 "false green"): it
       emits a stderr warning and, unless ``use_reference_allowlist=False``,
       falls back to :data:`WELL_KNOWN_MCP_TOOLS` so squats of household-name
       tools are still caught.
    2. The reserved MCP method names — see :meth:`check_shadowing`.

    Exact matches against the active allowlist are never flagged.
    """

    def check_tools(
        self,
        tools: list[dict[str, Any]],
        allowlist: list[str],
        max_distance: int = 2,
        use_reference_allowlist: bool = True,
    ) -> list[TyposquatFinding]:
        """Return findings for tools whose names are suspiciously close to allowlisted names.

        A tool whose name IS in the active allowlist is an exact match — not
        flagged. A tool whose homoglyph-folded name is within Levenshtein
        ``max_distance`` of any allowlisted name is flagged.
        """
        active = list(allowlist) if allowlist else []
        if not active:
            if use_reference_allowlist:
                print(
                    "cosai-mcp [T6]: no --tool-allowlist supplied; falling back to the "
                    f"built-in reference allowlist ({len(WELL_KNOWN_MCP_TOOLS)} well-known "
                    "MCP tool names). Pass an explicit allowlist for your server's tools "
                    "to detect squats of your own tool names.",
                    file=sys.stderr,
                )
                active = sorted(WELL_KNOWN_MCP_TOOLS)
            else:
                warnings.warn(
                    "TyposquatDetector called with an empty allowlist and "
                    "use_reference_allowlist=False — no typosquat detection will run.",
                    stacklevel=2,
                )
                return []

        allow_set = set(active)
        findings: list[TyposquatFinding] = []
        for tool in tools:
            tool_name = tool.get("name", "")
            if tool_name in allow_set:
                continue  # exact match — allowed

            folded_name = fold_homoglyphs(tool_name)
            best_dist = max_distance + 1
            best_match = ""
            for allowed in active:
                d = levenshtein(folded_name, fold_homoglyphs(allowed))
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

    def check_shadowing(
        self,
        tools: list[dict[str, Any]],
        max_distance: int = 1,
    ) -> list[TyposquatFinding]:
        """Return findings for tool names that shadow a standard MCP method.

        A tool whose homoglyph-folded, lower-cased name equals (distance 0) or is
        within ``max_distance`` edits of a reserved MCP method name can intercept
        or impersonate that protocol method (T6 shadowing). Reported as
        TyposquatFinding with ``closest_match`` set to the shadowed method.
        """
        findings: list[TyposquatFinding] = []
        for tool in tools:
            name = tool.get("name", "")
            folded = fold_homoglyphs(name).lower()
            best_dist = max_distance + 1
            best_match = ""
            for method in STANDARD_MCP_METHODS:
                d = levenshtein(folded, method)
                if d <= max_distance and d < best_dist:
                    best_dist = d
                    best_match = method
            if best_match:
                findings.append(TyposquatFinding(
                    tool_name=name,
                    closest_match=best_match,
                    distance=best_dist,
                    severity="high",
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
