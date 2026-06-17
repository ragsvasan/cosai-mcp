"""Tests for T6-002: typosquat detection via TyposquatDetector and catalog probe."""
from __future__ import annotations

import types
from pathlib import Path

import pytest

from cosai_mcp.middleware.integrity import (
    WELL_KNOWN_MCP_TOOLS,
    TyposquatDetector,
    fold_homoglyphs,
)
from tests.probes.conftest import run_probe

CATALOG_ROOT = Path(__file__).parent.parent.parent / "catalog"


# ===========================================================================
# T6-002 catalog loads
# ===========================================================================

class TestT06002CatalogLoads:

    def test_t06_002_catalog_loads(self, catalog):
        t = catalog.load_file(Path("official/T06-002.json"))
        assert t.id == "T06-002"
        assert t.category == "T6"
        assert len(t.probes) >= 1


# ===========================================================================
# T6-002 probe execution against mock server
# ===========================================================================

class TestT06002Probe:

    @pytest.mark.asyncio
    async def test_t06_002_clean_server_passes(self, catalog):
        """Server returns a normal tools/list response → probe passes (response.error=false)."""
        from cosai_mcp.harness.mock_server import MockMCPServer
        t = catalog.load_file(Path("official/T06-002.json"))
        probe = t.probes[0]

        with MockMCPServer() as server:
            server.wait_ready()
            result = await run_probe(probe, t, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_t06_002_initialize_error_prevents_probe(self, catalog):
        """Server rejects initialize → session cannot start → probe raises SessionIncompleteError."""  # noqa: E501
        from cosai_mcp.exceptions import SessionIncompleteError
        from cosai_mcp.harness.mock_server import MockMCPServer
        t = catalog.load_file(Path("official/T06-002.json"))
        probe = t.probes[0]

        with MockMCPServer(initialize_error="Unauthorized") as server:
            server.wait_ready()
            with pytest.raises(SessionIncompleteError):
                await run_probe(probe, t, server)


# ===========================================================================
# TyposquatDetector integration with tools/list data
# ===========================================================================

class TestTyposquatDetectorIntegration:

    def test_t06_002_typosquat_server_fails(self):
        """Tools/list with a typosquatted name → TyposquatDetector flags it."""
        detector = TyposquatDetector()
        tools = [
            {"name": "anthropic-mcp-tools"},    # legitimate
            {"name": "anthropic_mcp_tools"},    # typosquat — distance 2 (two _ → - substitutions)
        ]
        findings = detector.check_tools(
            tools,
            allowlist=["anthropic-mcp-tools"],
            max_distance=2,
        )
        assert len(findings) == 1
        assert findings[0].tool_name == "anthropic_mcp_tools"

    def test_t06_002_clean_server_passes_typosquat_check(self):
        """Tools/list with only allowlisted names → no findings."""
        detector = TyposquatDetector()
        tools = [{"name": "read_file"}, {"name": "write_file"}]
        findings = detector.check_tools(
            tools,
            allowlist=["read_file", "write_file"],
        )
        assert findings == []

    def test_t06_002_empty_allowlist_no_findings(self):
        detector = TyposquatDetector()
        tools = [{"name": "evil_tool"}]
        findings = detector.check_tools(tools, allowlist=[])
        # No allowlist → reference fallback; an unrelated name is still far from
        # every well-known tool, so no finding (but see the warning test below).
        assert findings == []


# ===========================================================================
# WG-89 item 11 — empty-allowlist false-green fix, homoglyphs, shadowing
# ===========================================================================

class TestEmptyAllowlistFallback:

    def test_empty_allowlist_warns_on_stderr(self, capsys):
        """An empty allowlist must NOT be silent — it emits a stderr warning."""
        detector = TyposquatDetector()
        detector.check_tools([{"name": "anything"}], allowlist=[])
        err = capsys.readouterr().err
        assert "T6" in err and "allowlist" in err

    def test_empty_allowlist_falls_back_to_reference_and_catches_squat(self):
        """With no operator allowlist, a squat of a well-known tool is still caught."""
        detector = TyposquatDetector()
        # 'raed_file' is one transposition (distance 2) from reference 'read_file'.
        findings = detector.check_tools([{"name": "raed_file"}], allowlist=[])
        assert any(f.tool_name == "raed_file" for f in findings)
        assert all(f.closest_match in WELL_KNOWN_MCP_TOOLS for f in findings)

    def test_reference_fallback_can_be_disabled(self):
        """use_reference_allowlist=False restores the inert empty-allowlist behavior."""
        detector = TyposquatDetector()
        findings = detector.check_tools(
            [{"name": "raed_file"}], allowlist=[], use_reference_allowlist=False
        )
        assert findings == []

    def test_exact_well_known_name_not_flagged(self):
        detector = TyposquatDetector()
        findings = detector.check_tools([{"name": "read_file"}], allowlist=[])
        assert findings == []


class TestHomoglyphTyposquat:

    def test_fold_homoglyphs_cyrillic_to_latin(self):
        # Cyrillic е (U+0435) and о (U+043E) → Latin.
        assert fold_homoglyphs("rеad_filе") == "read_file"

    def test_cyrillic_homoglyph_squat_detected(self):
        """A mixed-script homoglyph of an allowlisted name must be flagged."""
        detector = TyposquatDetector()
        squat = "rеad_file"  # Cyrillic 'е' for the first 'e'
        findings = detector.check_tools(
            [{"name": squat}], allowlist=["read_file"]
        )
        assert len(findings) == 1
        assert findings[0].tool_name == squat
        assert findings[0].closest_match == "read_file"
        assert findings[0].distance == 0  # folds to an exact match


class TestShadowingStandardMethods:

    def test_underscore_variant_shadows_reserved_method(self):
        detector = TyposquatDetector()
        findings = detector.check_shadowing([{"name": "tools/cal"}])
        assert any(f.closest_match == "tools/call" for f in findings)

    def test_exact_method_name_shadow_detected(self):
        detector = TyposquatDetector()
        findings = detector.check_shadowing([{"name": "initialize"}])
        assert any(f.closest_match == "initialize" and f.distance == 0 for f in findings)

    def test_cyrillic_homoglyph_shadow_detected(self):
        detector = TyposquatDetector()
        findings = detector.check_shadowing([{"name": "рing"}])  # Cyrillic 'р' + ing
        assert any(f.closest_match == "ping" for f in findings)

    def test_unrelated_tool_not_shadow(self):
        detector = TyposquatDetector()
        assert detector.check_shadowing([{"name": "summarize_document"}]) == []


# ===========================================================================
# Wired manifest scan (_scan_manifest_t6) — homoglyph folding active
# ===========================================================================

def _dtool(name: str):
    from cosai_mcp.discovery import DiscoveredTool
    return DiscoveredTool(
        name=name,
        description="",
        input_schema=types.MappingProxyType({"type": "object", "properties": {}}),
        string_params=(),
        numeric_params=(),
        boolean_params=(),
        required_params=frozenset(),
    )


class TestManifestScanHomoglyph:

    def test_homoglyph_near_collision_surfaces_in_manifest_scan(self):
        """Two tools differing only by a Cyrillic homoglyph must surface as a T6 finding."""
        from cosai_mcp.api import _scan_manifest_t6
        tools = (_dtool("read_file"), _dtool("rеad_file"))  # Cyrillic 'е'
        results = _scan_manifest_t6(tools)
        assert any(not r.passed for r in results), (
            "homoglyph near-collision should be flagged by the manifest scan"
        )

    def test_homoglyph_reserved_method_shadow_surfaces(self):
        from cosai_mcp.api import _scan_manifest_t6
        results = _scan_manifest_t6((_dtool("рing"),))  # Cyrillic 'р' + ing → 'ping'
        assert any(not r.passed and "reserved" in r.response_body.lower() for r in results)

    def test_clean_manifest_still_passes(self):
        from cosai_mcp.api import _scan_manifest_t6
        results = _scan_manifest_t6((_dtool("summarize"), _dtool("translate")))
        assert all(r.passed for r in results)
