"""Tests for T6 middleware: TyposquatDetector, ManifestBaselineChecker, levenshtein."""
from __future__ import annotations

import pytest

from cosai_mcp.middleware.integrity import (
    ManifestBaselineChecker,
    ManifestDrift,
    TyposquatDetector,
    TyposquatFinding,
    levenshtein,
)


# ===========================================================================
# levenshtein distance
# ===========================================================================

class TestLevenshtein:

    def test_levenshtein_exact_match(self):
        assert levenshtein("abc", "abc") == 0

    def test_levenshtein_empty_strings(self):
        assert levenshtein("", "") == 0

    def test_levenshtein_one_empty(self):
        assert levenshtein("abc", "") == 3
        assert levenshtein("", "abc") == 3

    def test_levenshtein_one_char(self):
        # "anthropic-mcp-tool" vs "anthropic-mcp-tools" — one insertion
        assert levenshtein("anthropic-mcp-tool", "anthropic-mcp-tools") == 1

    def test_levenshtein_two_chars(self):
        # "anthropic_mcp_tools" vs "anthropic-mcp-tools": two substitutions (_ → -)
        assert levenshtein("anthropic_mcp_tools", "anthropic-mcp-tools") == 2

    def test_levenshtein_substitution(self):
        assert levenshtein("kitten", "sitten") == 1

    def test_levenshtein_deletion(self):
        assert levenshtein("kitten", "itten") == 1

    def test_levenshtein_insertion(self):
        assert levenshtein("itten", "kitten") == 1

    def test_levenshtein_above_threshold_not_close(self):
        # "read_file" vs "anthropic-mcp-tools" — distance >> 2
        d = levenshtein("read_file", "anthropic-mcp-tools")
        assert d > 5

    def test_levenshtein_symmetric(self):
        assert levenshtein("abc", "xyz") == levenshtein("xyz", "abc")

    def test_levenshtein_full_replacement(self):
        assert levenshtein("abc", "xyz") == 3


# ===========================================================================
# TyposquatDetector
# ===========================================================================

class TestTyposquatDetector:

    def _tool(self, name: str) -> dict:
        return {"name": name}

    def test_typosquat_detector_flags_close_name(self):
        detector = TyposquatDetector()
        # "anthropic_mcp_tools" differs from "anthropic-mcp-tools" by 2 substitutions (_ → -)
        tools = [self._tool("anthropic_mcp_tools")]
        findings = detector.check_tools(tools, allowlist=["anthropic-mcp-tools"])
        assert len(findings) == 1
        assert findings[0].tool_name == "anthropic_mcp_tools"
        assert findings[0].closest_match == "anthropic-mcp-tools"
        assert findings[0].distance <= 2

    def test_typosquat_detector_passes_exact_name(self):
        detector = TyposquatDetector()
        tools = [self._tool("anthropic-mcp-tools")]
        findings = detector.check_tools(tools, allowlist=["anthropic-mcp-tools"])
        assert findings == []

    def test_typosquat_detector_empty_allowlist(self):
        detector = TyposquatDetector()
        tools = [self._tool("evil_tool")]
        findings = detector.check_tools(tools, allowlist=[])
        assert findings == []

    def test_typosquat_detector_distance_above_threshold_not_flagged(self):
        detector = TyposquatDetector()
        tools = [self._tool("totally_different_name")]
        findings = detector.check_tools(tools, allowlist=["anthropic-mcp-tools"])
        assert findings == []

    def test_typosquat_severity_high_for_distance_1(self):
        detector = TyposquatDetector()
        tools = [self._tool("anthropic-mcp-tool")]  # distance 1 from "anthropic-mcp-tools"
        findings = detector.check_tools(tools, allowlist=["anthropic-mcp-tools"])
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].distance == 1

    def test_typosquat_severity_medium_for_distance_2(self):
        detector = TyposquatDetector()
        # "anthropic_mcp_tools" is distance 2 from "anthropic-mcp-tools" (2× _ → -)
        tools = [self._tool("anthropic_mcp_tools")]
        findings = detector.check_tools(
            tools, allowlist=["anthropic-mcp-tools"], max_distance=2
        )
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert findings[0].distance == 2

    def test_typosquat_multiple_tools_one_flagged(self):
        detector = TyposquatDetector()
        tools = [
            self._tool("read_file"),
            self._tool("write_file"),
            self._tool("anthropic_mcp_tools"),  # suspicious — distance 2 from "anthropic-mcp-tools"
        ]
        findings = detector.check_tools(tools, allowlist=["anthropic-mcp-tools", "read_file"])
        assert len(findings) == 1
        assert findings[0].tool_name == "anthropic_mcp_tools"

    def test_typosquat_finding_is_frozen(self):
        finding = TyposquatFinding(
            tool_name="x", closest_match="y", distance=1, severity="high"
        )
        with pytest.raises((AttributeError, TypeError)):
            finding.tool_name = "mutated"  # type: ignore[misc]

    def test_typosquat_custom_max_distance_0(self):
        """max_distance=0 means only exact matches are allowed — nothing is flagged."""
        detector = TyposquatDetector()
        tools = [self._tool("anthropic-mcp-tool")]
        findings = detector.check_tools(
            tools, allowlist=["anthropic-mcp-tools"], max_distance=0
        )
        # distance 1 > 0, so not flagged at max_distance=0
        assert findings == []


# ===========================================================================
# ManifestBaselineChecker
# ===========================================================================

class TestManifestBaselineChecker:

    def _tool(self, name: str) -> dict:
        return {"name": name}

    def test_manifest_baseline_detects_new_tool(self):
        checker = ManifestBaselineChecker()
        checker.store_baseline([self._tool("read"), self._tool("write")])
        drift = checker.check_drift([self._tool("read"), self._tool("write"), self._tool("evil")])
        assert drift is not None
        assert "evil" in drift.added

    def test_manifest_baseline_same_manifest_passes(self):
        checker = ManifestBaselineChecker()
        tools = [self._tool("read"), self._tool("write")]
        checker.store_baseline(tools)
        drift = checker.check_drift(tools)
        assert drift is None

    def test_manifest_baseline_detects_removed_tool(self):
        checker = ManifestBaselineChecker()
        checker.store_baseline([self._tool("read"), self._tool("write")])
        drift = checker.check_drift([self._tool("read")])
        assert drift is not None
        assert "write" in drift.removed

    def test_manifest_baseline_hash_is_deterministic(self):
        checker1 = ManifestBaselineChecker()
        checker2 = ManifestBaselineChecker()
        tools = [self._tool("a"), self._tool("b")]
        checker1.store_baseline(tools)
        checker2.store_baseline(tools)
        assert checker1.baseline_hash == checker2.baseline_hash

    def test_manifest_baseline_hash_changes_with_tools(self):
        checker = ManifestBaselineChecker()
        checker.store_baseline([self._tool("a")])
        h1 = checker.baseline_hash
        checker.store_baseline([self._tool("b")])
        h2 = checker.baseline_hash
        assert h1 != h2

    def test_manifest_baseline_no_baseline_raises(self):
        checker = ManifestBaselineChecker()
        with pytest.raises(RuntimeError):
            checker.check_drift([self._tool("read")])

    def test_manifest_drift_is_frozen(self):
        drift = ManifestDrift(added=("evil",), removed=())
        with pytest.raises((AttributeError, TypeError)):
            drift.added = ("mutated",)  # type: ignore[misc]

    def test_manifest_empty_tools_list(self):
        checker = ManifestBaselineChecker()
        checker.store_baseline([])
        drift = checker.check_drift([])
        assert drift is None

    def test_manifest_from_empty_to_one_tool(self):
        checker = ManifestBaselineChecker()
        checker.store_baseline([])
        drift = checker.check_drift([self._tool("new_tool")])
        assert drift is not None
        assert "new_tool" in drift.added
