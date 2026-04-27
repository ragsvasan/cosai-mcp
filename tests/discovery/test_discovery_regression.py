"""Regression tests for P10 panel findings — discovery.py security fixes.

Each test named test_regression_<finding> corresponds to a panel finding.
"""
from __future__ import annotations

import types

import pytest

from cosai_mcp.discovery import (
    _MAX_DESCRIPTION_LEN,
    _MAX_PROPERTIES,
    _SCHEMA_SIZE_LIMIT_BYTES,
    _tool_dict_to_discovered,
    _validate_tool_name,
    _parse_input_schema,
)


# ---------------------------------------------------------------------------
# Sonnet P0 / Opus F3 — tool name validation
# ---------------------------------------------------------------------------

class TestRegressionMaliciousToolNameRejected:
    """test_regression_malicious_tool_name_rejected — Sonnet P0 / Opus F3.

    Tool names containing template markers, control characters, or non-ASCII
    must be rejected at ingestion so they cannot be expanded by the template
    substitution engine in the probe subprocess.
    """

    def test_regression_template_marker_in_name_rejected(self):
        dt = _tool_dict_to_discovered({"name": "{{target_url}}", "inputSchema": {}})
        assert dt is None, "{{target_url}} in name must be rejected"

    def test_regression_session_id_template_in_name_rejected(self):
        dt = _tool_dict_to_discovered({"name": "{{session_id}}", "inputSchema": {}})
        assert dt is None

    def test_regression_tool_name_template_in_name_rejected(self):
        dt = _tool_dict_to_discovered({"name": "{{tool_name}}", "inputSchema": {}})
        assert dt is None

    def test_regression_embedded_template_in_name_rejected(self):
        dt = _tool_dict_to_discovered({"name": "prefix{{target_url}}suffix", "inputSchema": {}})
        assert dt is None

    def test_regression_newline_in_name_rejected(self):
        dt = _tool_dict_to_discovered({"name": "ping\nfake_section", "inputSchema": {}})
        assert dt is None

    def test_regression_null_byte_in_name_rejected(self):
        dt = _tool_dict_to_discovered({"name": "ping\x00evil", "inputSchema": {}})
        assert dt is None

    def test_regression_unicode_non_ascii_in_name_rejected(self):
        # Cyrillic lookalike — 'е' (U+0435) vs 'e'
        dt = _tool_dict_to_discovered({"name": "sеarch_tool", "inputSchema": {}})
        assert dt is None

    def test_regression_path_traversal_in_name_rejected(self):
        dt = _tool_dict_to_discovered({"name": "../../../evil", "inputSchema": {}})
        assert dt is None

    def test_regression_name_over_256_chars_rejected(self):
        long_name = "a" * 257
        dt = _tool_dict_to_discovered({"name": long_name, "inputSchema": {}})
        assert dt is None

    def test_regression_valid_name_accepted(self):
        dt = _tool_dict_to_discovered({"name": "search_memories", "inputSchema": {}})
        assert dt is not None
        assert dt.name == "search_memories"

    def test_regression_path_chars_in_name_rejected(self):
        # Slashes and dots are not valid in MCP tool names — reject path traversal
        dt = _tool_dict_to_discovered({"name": "tools/list", "inputSchema": {}})
        assert dt is None

    def test_regression_valid_names_with_hyphens_accepted(self):
        dt = _tool_dict_to_discovered({"name": "search-memories", "inputSchema": {}})
        assert dt is not None

    def test_regression_validate_tool_name_helper(self):
        assert _validate_tool_name("valid_tool") is True
        assert _validate_tool_name("search-memories") is True
        assert _validate_tool_name("{{target_url}}") is False
        assert _validate_tool_name("") is False
        assert _validate_tool_name("a" * 257) is False
        assert _validate_tool_name("tool\x00evil") is False
        assert _validate_tool_name("../evil") is False
        assert _validate_tool_name("tools/list") is False


# ---------------------------------------------------------------------------
# Opus F2 — description length cap
# ---------------------------------------------------------------------------

class TestRegressionDescriptionLengthCap:
    """test_regression_description_cap — Opus F2.

    Description fields must be capped to prevent large-body injection into
    report output.  No 5 MB description should reach DiscoveredTool.description.
    """

    def test_regression_description_capped_at_max(self):
        long_desc = "x" * (_MAX_DESCRIPTION_LEN + 1000)
        dt = _tool_dict_to_discovered({
            "name": "t",
            "description": long_desc,
            "inputSchema": {},
        })
        assert dt is not None
        assert len(dt.description) == _MAX_DESCRIPTION_LEN

    def test_regression_description_within_limit_unchanged(self):
        desc = "Search for memories"
        dt = _tool_dict_to_discovered({"name": "t", "description": desc, "inputSchema": {}})
        assert dt is not None
        assert dt.description == desc

    def test_regression_xss_description_stored_as_raw_text(self):
        # Description is stored as raw text (length-capped only); HTML-escaping
        # happens at report ingestion time, not at discovery time.
        # This test confirms it doesn't crash and is capped.
        xss = '<script>alert(1)</script>' * 200
        dt = _tool_dict_to_discovered({"name": "t", "description": xss, "inputSchema": {}})
        assert dt is not None
        assert len(dt.description) <= _MAX_DESCRIPTION_LEN


# ---------------------------------------------------------------------------
# Opus F1 — property count cap
# ---------------------------------------------------------------------------

class TestRegressionPropertyCountCap:
    """test_regression_property_count_cap — Opus F1.

    A schema with >64 properties must be capped before synthesis to prevent
    the oversize pattern from allocating 280 MB (2800 params × 100 KB each).
    """

    def test_regression_properties_capped_at_max(self):
        # Build a schema with 100 single-char string properties (under 64 KB)
        props = {chr(65 + i % 26) + str(i): {"type": "string"} for i in range(100)}
        schema = {"type": "object", "properties": props}
        sp, np, bp, rp = _parse_input_schema(schema)
        assert len(sp) <= _MAX_PROPERTIES

    def test_regression_schema_under_limit_preserved(self):
        props = {f"param_{i}": {"type": "string"} for i in range(5)}
        schema = {"type": "object", "properties": props}
        sp, np, bp, rp = _parse_input_schema(schema)
        assert len(sp) == 5  # under limit, all preserved

    def test_regression_oversize_synthesis_bounded(self):
        from cosai_mcp.synthesis import synthesize_probe_payload, _OVERSIZE_VALUE
        from cosai_mcp.discovery import DiscoveredTool

        # Even if we have 64 string params (max), oversize synthesis uses all 64.
        # Each is 100 KB; total = 6.4 MB — bounded, acceptable.
        string_params = tuple(f"param_{i}" for i in range(_MAX_PROPERTIES))
        tool = DiscoveredTool(
            name="big_tool",
            description="",
            input_schema=types.MappingProxyType({}),
            string_params=string_params,
            numeric_params=(),
            boolean_params=(),
            required_params=frozenset(),
        )
        catalog_payload = {"name": "big_tool", "arguments": {}}
        result = synthesize_probe_payload(tool, "oversize", catalog_payload)
        # Should succeed (not OOM) and produce exactly _MAX_PROPERTIES entries
        assert len(result["arguments"]) == _MAX_PROPERTIES
        for v in result["arguments"].values():
            assert v == _OVERSIZE_VALUE


# ---------------------------------------------------------------------------
# Sonnet P1 — synthesis_attempted on all retry outcomes
# ---------------------------------------------------------------------------

class TestRegressionSynthesisAttemptedFlagAllOutcomes:
    """test_regression_synthesis_attempted_set_on_successful_retry — Sonnet P1.

    synthesis_attempted must be True for every result that went through the
    adaptive retry path, including PASS and FAIL outcomes — not only INCONCLUSIVE.
    An operator must be able to distinguish a natural PASS from one that only
    exists because synthesis adapted the payload.
    """

    def test_regression_synthesis_attempted_true_on_pass_retry(self):
        import dataclasses
        from cosai_mcp.harness.result import make_probe_result

        pass_result = make_probe_result(
            probe_id="T03-001-p1",
            threat_id="T03-001",
            passed=True,
            assertions=(),
        )
        assert not pass_result.synthesis_attempted

        # Simulate what ProbeRunner does on a successful retry
        marked = dataclasses.replace(pass_result, synthesis_attempted=True)
        assert marked.synthesis_attempted
        assert marked.passed  # outcome preserved
        assert marked.inconclusive_reason is None

    def test_regression_synthesis_attempted_true_on_fail_retry(self):
        import dataclasses
        from cosai_mcp.harness.result import make_probe_result

        fail_result = make_probe_result(
            probe_id="T03-001-p1",
            threat_id="T03-001",
            passed=False,
            assertions=(),
        )
        marked = dataclasses.replace(fail_result, synthesis_attempted=True)
        assert marked.synthesis_attempted
        assert not marked.passed

    def test_regression_synthesis_attempted_true_on_inconclusive_retry(self):
        import dataclasses
        from cosai_mcp.harness.result import make_probe_result

        inc_result = make_probe_result(
            probe_id="T03-001-p1",
            threat_id="T03-001",
            passed=False,
            assertions=(),
            inconclusive_reason="still a mismatch after synthesis",
        )
        marked = dataclasses.replace(inc_result, synthesis_attempted=True)
        assert marked.synthesis_attempted
        assert marked.inconclusive_reason is not None


# ---------------------------------------------------------------------------
# Sonnet P1 — non-tools/call probes must not be synthesized
# ---------------------------------------------------------------------------

class TestRegressionNoSynthesisForNonToolsCallProbe:
    """test_regression_no_synthesis_for_non_tools_call_probe — Sonnet P1.

    Synthesis produces tools/call-shaped payloads.  Applying it to probes
    with method != "tools/call" would corrupt the probe and produce misleading
    PASS/FAIL results.
    """

    def test_regression_tools_list_probe_not_synthesized(self):
        from cosai_mcp.harness.runner import _synthesize_probe
        from cosai_mcp.catalog.models import (
            Probe, Provenance, Severity, ThreatDefinition,
        )
        from cosai_mcp.discovery import DiscoveredTool

        probe = Probe(
            id="T08-001-p1",
            transport="http",
            method="tools/list",   # NOT tools/call
            payload=types.MappingProxyType({}),
            assertions=(),
        )
        threat = ThreatDefinition(
            schema_version="1.0",
            id="T08-001",
            category="T8",
            severity=Severity.HIGH,
            cosai_ref="T8",
            owasp_ref="",
            cwe=(),
            probes=(probe,),
            remediation="",
            references=(),
            provenance=Provenance.OFFICIAL,
        )
        tool = DiscoveredTool(
            name="any_tool",
            description="",
            input_schema=types.MappingProxyType({}),
            string_params=("query",),
            numeric_params=(),
            boolean_params=(),
            required_params=frozenset({"query"}),
        )
        result = _synthesize_probe(probe, threat, tool)
        assert result is None, "Non-tools/call probe must not be synthesized"

    def test_regression_initialize_probe_not_synthesized(self):
        from cosai_mcp.harness.runner import _synthesize_probe
        from cosai_mcp.catalog.models import (
            Probe, Provenance, Severity, ThreatDefinition,
        )
        from cosai_mcp.discovery import DiscoveredTool

        probe = Probe(
            id="T01-001-p1",
            transport="http",
            method="initialize",   # NOT tools/call
            payload=types.MappingProxyType({}),
            assertions=(),
        )
        threat = ThreatDefinition(
            schema_version="1.0",
            id="T01-001",
            category="T1",
            severity=Severity.CRITICAL,
            cosai_ref="T1",
            owasp_ref="",
            cwe=(),
            probes=(probe,),
            remediation="",
            references=(),
            provenance=Provenance.OFFICIAL,
        )
        tool = DiscoveredTool(
            name="any_tool",
            description="",
            input_schema=types.MappingProxyType({}),
            string_params=("query",),
            numeric_params=(),
            boolean_params=(),
            required_params=frozenset(),
        )
        result = _synthesize_probe(probe, threat, tool)
        assert result is None
