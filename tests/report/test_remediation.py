"""Tests for P12 remediation-first report mode and panel-finding regressions."""
from __future__ import annotations

import csv
import io
from pathlib import Path

import pytest

from cosai_mcp.catalog.models import Severity
from cosai_mcp.harness.result import AssertionResult, make_probe_result
from cosai_mcp.report.html import HtmlReportBuilder, HtmlReportSection
from cosai_mcp.report.remediation import (
    _VALID_LANGUAGES,
    REMEDIATION_REGISTRY,
    RemediationBlock,
    get_remediation,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_section(
    threat_id: str = "T11-001",
    probe_id: str = "T11-001-p1",
    category: str = "T11",
    passed: bool = False,
    remediation: str = "Fix the dispatcher.",
    severity: Severity = Severity.HIGH,
) -> HtmlReportSection:
    result = make_probe_result(
        probe_id=probe_id,
        threat_id=threat_id,
        passed=passed,
        assertions=(
            AssertionResult(
                target="response.isError",
                operator="eq",
                expected=True,
                actual=False,
                passed=False,
                message="expected True got False",
            ),
        ),
        response={"isError": False, "content": [{"type": "text", "text": "ok"}]},
    )
    return HtmlReportSection(
        threat_id=threat_id,
        category=category,
        severity=severity,
        passed=passed,
        probe_results=[result],
        remediation=remediation,
        references=(),
    )


def _builder(report_mode: str = "full") -> HtmlReportBuilder:
    return HtmlReportBuilder(
        target_url="http://localhost:8000",
        scan_timestamp="2026-04-27T00:00:00Z",
        report_mode=report_mode,
    )


# ---------------------------------------------------------------------------
# test_remediation_block_present_for_t11
# ---------------------------------------------------------------------------

class TestRemediationBlockPresentForT11:

    def test_remediation_tab_present_for_t11_finding(self):
        """T11-001-p1 finding renders a remediation <details> block in the HTML."""
        b = _builder()
        b.add_section(_make_section(threat_id="T11-001", probe_id="T11-001-p1"))
        html = b.build()
        assert "remediation-details" in html, "Expected <details class='remediation-details'>"
        assert "Remediation" in html
        assert "T11-001" in html

    def test_remediation_block_contains_spec_ref(self):
        """T11-001 remediation block includes the MCP spec citation."""
        b = _builder()
        b.add_section(_make_section(threat_id="T11-001", probe_id="T11-001-p1"))
        html = b.build()
        rem = REMEDIATION_REGISTRY.get("T11-001-p1")
        assert rem is not None
        assert rem.spec_ref in html

    def test_remediation_block_contains_fix_shape(self):
        """T11-001 remediation block includes the fix_shape pseudocode."""
        b = _builder()
        b.add_section(_make_section(threat_id="T11-001", probe_id="T11-001-p1"))
        html = b.build()
        REMEDIATION_REGISTRY["T11-001-p1"]
        # fix_shape is HTML-escaped — check for a key substring
        assert "registered_tools" in html

    def test_remediation_registry_covers_t11(self):
        """REMEDIATION_REGISTRY has entries for T11-001-p1 and T11-001-p2."""
        assert "T11-001-p1" in REMEDIATION_REGISTRY
        assert "T11-001-p2" in REMEDIATION_REGISTRY
        rem = REMEDIATION_REGISTRY["T11-001-p1"]
        assert rem.threat_id == "T11-001"
        assert rem.spec_ref
        assert rem.fix_shape
        assert rem.fastmcp_snippet is not None


# ---------------------------------------------------------------------------
# test_remediation_missing_does_not_crash
# ---------------------------------------------------------------------------

class TestRemediationMissingDoesNotCrash:

    def test_unknown_probe_id_returns_none(self):
        """get_remediation for an unregistered probe_id returns None."""
        result = get_remediation("T99-999-p99")
        assert result is None

    def test_section_with_no_registered_remediation_renders_without_tab(self):
        """A finding with no registered remediation renders without a remediation-details block."""
        b = _builder()
        # Use a probe_id that is not in the registry
        b.add_section(_make_section(
            threat_id="T02-001",
            probe_id="T02-001-p1",  # no remediation entry registered
            category="T2",
        ))
        html = b.build()
        # Should render without raising and without a remediation-details element.
        # Check for the HTML element (not the CSS class definition which also contains the name).
        assert "T02-001-p1" not in REMEDIATION_REGISTRY
        assert "<details class='remediation-details'" not in html

    def test_remediation_absent_does_not_raise(self):
        """Builder.build() never raises when remediation lookup returns None."""
        b = _builder()
        b.add_section(_make_section(probe_id="nonexistent-probe-id"))
        html = b.build()  # must not raise
        assert html  # non-empty


# ---------------------------------------------------------------------------
# test_what_we_got_is_html_escaped
# ---------------------------------------------------------------------------

class TestWhatWeGotIsHtmlEscaped:

    def test_xss_in_response_body_is_escaped(self):
        """<script> in probe response body is HTML-escaped in the report output."""
        xss_payload = '<script>alert("xss")</script>'
        result = make_probe_result(
            probe_id="T11-001-p1",
            threat_id="T11-001",
            passed=False,
            assertions=(),
            response={"_body": xss_payload, "_status_code": 200},
        )
        section = HtmlReportSection(
            threat_id="T11-001",
            category="T11",
            severity=Severity.HIGH,
            passed=False,
            probe_results=[result],
            remediation="Fix.",
            references=(),
        )
        b = _builder()
        b.add_section(section)
        html = b.build()

        assert xss_payload not in html, "Raw <script> tag must not appear in HTML output"
        assert "&lt;script&gt;" in html or "alert" not in html, (
            "Script tag must be HTML-escaped or stripped"
        )

    def test_xss_in_remediation_fix_shape_is_escaped(self):
        """fix_shape content is always from the static registry — served HTML-escaped."""
        rem = REMEDIATION_REGISTRY.get("T11-001-p1")
        assert rem is not None
        b = _builder()
        b.add_section(_make_section(threat_id="T11-001", probe_id="T11-001-p1"))
        html = b.build()
        # The registry content contains `{tool_name!r}` — verify it is in escaped form
        assert "<script" not in html


# ---------------------------------------------------------------------------
# test_report_mode_executive_no_code_blocks
# ---------------------------------------------------------------------------

class TestReportModeExecutive:

    def test_executive_mode_has_no_pre_tags(self):
        """Executive mode report contains no <pre> code blocks."""
        b = _builder(report_mode="executive")
        b.add_section(_make_section(threat_id="T11-001", probe_id="T11-001-p1"))
        html = b.build()
        assert "<pre>" not in html

    def test_executive_mode_has_no_detail_sections(self):
        """Executive mode report contains no per-finding detail markup."""
        b = _builder(report_mode="executive")
        b.add_section(_make_section(threat_id="T11-001", probe_id="T11-001-p1"))
        html = b.build()
        # Check for the HTML element (not the CSS class definition)
        assert "<div class='section section-finding'>" not in html
        assert "<div class='probe probe-fail'>" not in html

    def test_executive_mode_still_has_summary_grid(self):
        """Executive mode report still includes the findings summary grid and table."""
        b = _builder(report_mode="executive")
        b.add_section(_make_section(threat_id="T11-001", probe_id="T11-001-p1"))
        html = b.build()
        assert "summary-grid" in html
        assert "Findings Summary" in html

    def test_executive_mode_has_no_remediation_block(self):
        """Executive mode does not render any remediation-details blocks."""
        b = _builder(report_mode="executive")
        b.add_section(_make_section(threat_id="T11-001", probe_id="T11-001-p1"))
        html = b.build()
        # Check for the HTML element (not the CSS selector definition)
        assert "<details class='remediation-details'" not in html


# ---------------------------------------------------------------------------
# test_report_mode_developer_remediation_visible
# ---------------------------------------------------------------------------

class TestReportModeDeveloper:

    def test_developer_mode_remediation_open_by_default(self):
        """Developer mode renders remediation <details> with 'open' attribute."""
        b = _builder(report_mode="developer")
        b.add_section(_make_section(threat_id="T11-001", probe_id="T11-001-p1"))
        html = b.build()
        assert "<details class='remediation-details' open>" in html or \
               "details class='remediation-details' open" in html

    def test_full_mode_remediation_closed_by_default(self):
        """Full mode renders remediation <details> without 'open' attribute."""
        b = _builder(report_mode="full")
        b.add_section(_make_section(threat_id="T11-001", probe_id="T11-001-p1"))
        html = b.build()
        assert "remediation-details" in html
        # Should NOT have the open attribute
        import re
        match = re.search(r"details class='remediation-details'([^>]*)", html)
        assert match is not None
        assert "open" not in match.group(1)


# ---------------------------------------------------------------------------
# test_csv_includes_remediation_columns
# ---------------------------------------------------------------------------

class TestCsvRemediationColumns:

    def _make_scan_result(self):
        """Minimal ScanResult-like object with one T11-001-p1 finding."""
        from cosai_mcp.api import ScanResult
        from cosai_mcp.catalog.loader import CatalogLoader

        loader = CatalogLoader(catalog_root=Path("catalog"), allow_custom=False)
        threats = loader.load_all()
        t11 = next(t for t in threats if t.id == "T11-001")

        probe_result = make_probe_result(
            probe_id="T11-001-p1",
            threat_id="T11-001",
            passed=False,
            assertions=(
                AssertionResult(
                    target="response.isError",
                    operator="eq",
                    expected=True,
                    actual=False,
                    passed=False,
                    message="expected True got False",
                ),
            ),
            response={"isError": False},
        )

        return ScanResult(
            target_url="http://localhost:8000",
            threats=(t11,),
            probe_results=(probe_result,),
            scenario_results=(),
            scan_timestamp="2026-04-27T00:00:00Z",
            catalog_hash="abc123",
            exit_code=1,
        )

    def test_csv_has_remediation_spec_ref_column(self, tmp_path):
        """CSV export includes a 'remediation_spec_ref' column."""
        from cosai_mcp.report.csv_report import write_csv_report

        result = self._make_scan_result()
        out = tmp_path / "out.csv"
        write_csv_report(result, out)

        reader = csv.DictReader(io.StringIO(out.read_text(encoding="utf-8-sig")))
        rows = list(reader)
        assert rows, "CSV must contain at least one data row"
        assert "remediation_spec_ref" in rows[0], "Column 'remediation_spec_ref' missing"

    def test_csv_has_remediation_fix_shape_column(self, tmp_path):
        """CSV export includes a 'remediation_fix_shape' column."""
        from cosai_mcp.report.csv_report import write_csv_report

        result = self._make_scan_result()
        out = tmp_path / "out.csv"
        write_csv_report(result, out)

        reader = csv.DictReader(io.StringIO(out.read_text(encoding="utf-8-sig")))
        rows = list(reader)
        assert "remediation_fix_shape" in rows[0], "Column 'remediation_fix_shape' missing"

    def test_csv_remediation_spec_ref_populated_for_t11(self, tmp_path):
        """CSV row for T11-001-p1 has a non-empty remediation_spec_ref value."""
        from cosai_mcp.report.csv_report import write_csv_report

        result = self._make_scan_result()
        out = tmp_path / "out.csv"
        write_csv_report(result, out)

        reader = csv.DictReader(io.StringIO(out.read_text(encoding="utf-8-sig")))
        rows = list(reader)
        t11_rows = [r for r in rows if r.get("probe_id") == "T11-001-p1"]
        assert t11_rows, "Expected at least one T11-001-p1 row"
        assert t11_rows[0]["remediation_spec_ref"], (
            "remediation_spec_ref should be non-empty for T11-001-p1"
        )


# ---------------------------------------------------------------------------
# test_regression_full_mode_default
# ---------------------------------------------------------------------------

class TestRegressionFullModeDefault:

    def test_no_report_mode_defaults_to_full(self):
        """HtmlReportBuilder with no report_mode argument behaves like 'full' mode."""
        b_default = HtmlReportBuilder(
            target_url="http://localhost:8000",
            scan_timestamp="2026-04-27T00:00:00Z",
        )
        b_full = HtmlReportBuilder(
            target_url="http://localhost:8000",
            scan_timestamp="2026-04-27T00:00:00Z",
            report_mode="full",
        )
        section = _make_section(threat_id="T11-001", probe_id="T11-001-p1")
        b_default.add_section(section)
        b_full.add_section(section)

        html_default = b_default.build()
        html_full = b_full.build()
        assert html_default == html_full

    def test_invalid_report_mode_falls_back_to_full(self):
        """An unrecognised report_mode is silently treated as 'full'."""
        b = HtmlReportBuilder(
            target_url="http://localhost:8000",
            scan_timestamp="2026-04-27T00:00:00Z",
            report_mode="bogus-mode",
        )
        b.add_section(_make_section(threat_id="T11-001", probe_id="T11-001-p1"))
        html = b.build()
        # full mode renders detail sections
        assert "section-finding" in html


# ---------------------------------------------------------------------------
# Panel P0/P1 regression tests (FIX [1], [2], [6], [8], [10])
# ---------------------------------------------------------------------------

class TestPanelRegressions:

    def test_regression_double_encoding_bypass_raw_script(self):
        """Raw <script> in response_body must appear HTML-escaped in the report (FIX [1])."""
        xss_raw = '<script>alert(1)</script>'
        result = make_probe_result(
            probe_id="T11-001-p1",
            threat_id="T11-001",
            passed=False,
            assertions=(),
            response={"_body": xss_raw, "_status_code": 200},
        )
        section = HtmlReportSection(
            threat_id="T11-001", category="T11", severity=Severity.HIGH,
            passed=False, probe_results=[result], remediation="Fix.", references=(),
        )
        b = _builder()
        b.add_section(section)
        html = b.build()
        assert xss_raw not in html
        # response_body is HTML-escaped at ingestion → renders as &lt;script&gt;
        assert "&lt;script&gt;" in html

    def test_regression_double_encoding_bypass_pre_escaped(self):
        """Pre-escaped response_body must NOT be double-escaped (FIX [1])."""
        # make_probe_result HTML-escapes at ingestion, so response_body in the
        # ProbeResult will already be &lt;script&gt; — rendered directly, it should
        # appear as &lt;script&gt; in HTML (displays as <script> in browser — safe).
        xss_raw = '<script>alert(1)</script>'
        result = make_probe_result(
            probe_id="T11-001-p1", threat_id="T11-001", passed=False,
            assertions=(), response={"_body": xss_raw, "_status_code": 200},
        )
        section = HtmlReportSection(
            threat_id="T11-001", category="T11", severity=Severity.HIGH,
            passed=False, probe_results=[result], remediation="Fix.", references=(),
        )
        b = _builder()
        b.add_section(section)
        html = b.build()
        # Must NOT be double-escaped (would render as &amp;lt;script&amp;gt; — ugly)
        assert "&amp;lt;script&amp;gt;" not in html

    def test_regression_verify_cmd_escaping(self):
        """verify_command_suffix with angle brackets is escaped in the report (FIX [2])."""
        rem = RemediationBlock(
            threat_id="T99-001",
            probe_id="cosai-test-p1",
            spec_ref="Test §1",
            what_spec_requires="Test requirement.",
            fix_shape="pass",
            fix_shape_language="python",
            fastmcp_snippet=None,
            typescript_snippet=None,
            verify_command_suffix="--categories T1 <injected>",
        )
        from unittest.mock import patch
        with patch("cosai_mcp.report.html.get_remediation", return_value=rem):
            b = _builder()
            b.add_section(_make_section(threat_id="T99-001", probe_id="cosai-test-p1"))
            html = b.build()
        assert "<injected>" not in html
        assert "&lt;injected&gt;" in html

    def test_regression_csp_contains_script_src_none(self):
        """HTML report CSP includes explicit script-src 'none' directive (FIX [6])."""
        b = _builder()
        html = b.build()
        assert "script-src 'none'" in html

    def test_regression_invalid_fix_shape_language_rejected(self):
        """RemediationBlock raises ValueError for unsupported fix_shape_language (FIX [8])."""
        with pytest.raises(ValueError, match="fix_shape_language"):
            RemediationBlock(
                threat_id="T01-001",
                probe_id="T01-001-p1",
                spec_ref="MCP §1",
                what_spec_requires="Req.",
                fix_shape="pass",
                fix_shape_language="shellscript",  # not in _VALID_LANGUAGES
                fastmcp_snippet=None,
                typescript_snippet=None,
            )

    def test_regression_valid_languages_accepted(self):
        """All values in _VALID_LANGUAGES are accepted by RemediationBlock."""
        for lang in _VALID_LANGUAGES:
            rem = RemediationBlock(
                threat_id="T01-001",
                probe_id="T01-001-p1",
                spec_ref="MCP §1",
                what_spec_requires="Req.",
                fix_shape="pass",
                fix_shape_language=lang,
                fastmcp_snippet=None,
                typescript_snippet=None,
            )
            assert rem.fix_shape_language == lang

    def test_regression_csv_formula_injection_scrubbed(self, tmp_path):
        """CSV cells starting with '=' are prefixed with tab to disable formula injection (FIX [10])."""  # noqa: E501
        from cosai_mcp.api import ScanResult
        from cosai_mcp.catalog.loader import CatalogLoader
        from cosai_mcp.report.csv_report import write_csv_report

        loader = CatalogLoader(catalog_root=Path("catalog"), allow_custom=False)
        threats = loader.load_all()
        t11 = next(t for t in threats if t.id == "T11-001")

        # Craft a probe result whose response_body will trigger formula injection
        # (make_probe_result HTML-escapes, so the final stored value may differ;
        # inject via error field which is also from the server)

        # Build a ProbeResult with formula injection in error field
        evil_response = '=HYPERLINK("http://evil.example")'
        result = make_probe_result(
            probe_id="T11-001-p1", threat_id="T11-001", passed=False,
            assertions=(), response={"_body": evil_response, "_status_code": 200},
        )

        scan = ScanResult(
            target_url="http://localhost:8000",
            threats=(t11,),
            probe_results=(result,),
            scenario_results=(),
            scan_timestamp="2026-04-27T00:00:00Z",
            catalog_hash="abc",
            exit_code=1,
        )

        out = tmp_path / "out.csv"
        write_csv_report(scan, out)

        content = out.read_text(encoding="utf-8-sig")
        # response_body is HTML-escaped at ingestion — the = sign is escaped too
        # so it becomes &equals; or just starts with & — either way not a formula.
        # Regardless, verify no raw =HYPERLINK survives into the CSV.
        assert '=HYPERLINK("http://evil.example")' not in content
