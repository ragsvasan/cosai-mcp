"""Tests for HTML report builder — CSP, reference rendering, escaping."""
from __future__ import annotations

import pytest

from cosai_mcp.catalog.models import Severity
from cosai_mcp.harness.result import make_probe_result, AssertionResult
from cosai_mcp.report.html import HtmlReportBuilder, HtmlReportSection, _safe_url


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _section(
    threat_id: str = "T01-001",
    passed: bool = False,
    references: tuple = (),
    remediation: str = "Fix it.",
) -> HtmlReportSection:
    result = make_probe_result(
        probe_id=threat_id,
        threat_id="T01",
        passed=passed,
        assertions=(),
        response={"_body": "body", "_status_code": 200},
    )
    return HtmlReportSection(
        threat_id=threat_id,
        category="T1",
        severity=Severity.HIGH,
        passed=passed,
        probe_results=[result],
        remediation=remediation,
        references=references,
    )


def _builder() -> HtmlReportBuilder:
    return HtmlReportBuilder(
        target_url="http://localhost:8000",
        scan_timestamp="2026-04-27T00:00:00Z",
    )


# ---------------------------------------------------------------------------
# CSP header
# ---------------------------------------------------------------------------

class TestHtmlCSP:

    def test_html_csp_default_src_none(self):
        """HTML report must include CSP meta tag with default-src 'none'."""
        b = _builder()
        html = b.build()
        assert "Content-Security-Policy" in html
        assert "default-src 'none'" in html

    def test_html_csp_covers_scripts(self):
        """CSP includes both default-src 'none' and explicit script-src 'none'."""
        b = _builder()
        report = b.build()
        assert "default-src 'none'" in report
        # Explicit script-src 'none' is included for scanner compliance checklists
        assert "script-src 'none'" in report

    def test_html_meta_charset_utf8(self):
        b = _builder()
        report = b.build()
        assert "charset=" in report.lower() and "utf-8" in report.lower()


# ---------------------------------------------------------------------------
# Reference rendering
# ---------------------------------------------------------------------------

class TestHtmlReferences:

    def test_html_references_text_only_for_javascript_scheme(self):
        """javascript: URI must be rendered as plain text, never as a clickable link."""
        b = _builder()
        b.add_section(_section(references=("javascript:alert(1)",)))
        html = b.build()
        # Must not appear as href
        assert 'href="javascript:' not in html
        assert "href='javascript:" not in html
        # The URI text itself should appear (escaped) as plain text
        assert "javascript:alert" in html or "javascript:alert(1)" in html

    def test_html_references_valid_url_rendered_as_link(self):
        """https:// URL must be rendered as <a> with rel=noopener noreferrer."""
        b = _builder()
        b.add_section(_section(references=("https://cosai.org/T1",)))
        html = b.build()
        assert 'href="https://cosai.org/T1"' in html
        assert 'rel="noopener noreferrer"' in html

    def test_html_references_http_url_rendered_as_link(self):
        b = _builder()
        b.add_section(_section(references=("http://example.com",)))
        html = b.build()
        assert 'href="http://example.com"' in html
        assert 'rel="noopener noreferrer"' in html

    def test_html_references_data_uri_rendered_as_text(self):
        """data: URI must be rendered as plain text."""
        b = _builder()
        b.add_section(_section(references=("data:text/html,<script>alert(1)</script>",)))
        html = b.build()
        assert "href=\"data:" not in html

    def test_html_references_empty(self):
        b = _builder()
        b.add_section(_section(references=()))
        html = b.build()  # must not raise

    def test_safe_url_accepts_https(self):
        assert _safe_url("https://example.com") == "https://example.com"

    def test_safe_url_accepts_http(self):
        assert _safe_url("http://example.com") == "http://example.com"

    def test_safe_url_rejects_javascript(self):
        assert _safe_url("javascript:alert(1)") is None

    def test_safe_url_rejects_data(self):
        assert _safe_url("data:text/html,x") is None

    def test_safe_url_rejects_ftp(self):
        assert _safe_url("ftp://example.com") is None


# ---------------------------------------------------------------------------
# HTML escaping
# ---------------------------------------------------------------------------

class TestHtmlEscaping:

    def test_xss_in_target_url_escaped(self):
        """XSS in target_url must be HTML-escaped."""
        b = HtmlReportBuilder(
            target_url='"><script>alert(1)</script>',
            scan_timestamp="2026-04-27T00:00:00Z",
        )
        html = b.build()
        assert "<script>" not in html

    def test_xss_in_remediation_escaped(self):
        b = _builder()
        b.add_section(_section(remediation='<script>alert(1)</script>'))
        html = b.build()
        assert "<script>" not in html

    def test_xss_in_threat_id_escaped(self):
        b = _builder()
        b.add_section(_section(threat_id='<img src=x onerror=alert(1)>'))
        html = b.build()
        assert "<img" not in html

    def test_response_body_already_escaped_no_double_escape(self):
        """response_body is pre-escaped at ingestion — must appear correctly in report."""
        result = make_probe_result(
            probe_id="T01-001",
            threat_id="T01",
            passed=False,
            assertions=(),
            response={"_body": "<b>bold</b>", "_status_code": 200},
        )
        section = HtmlReportSection(
            threat_id="T01-001",
            category="T1",
            severity=Severity.LOW,
            passed=False,
            probe_results=[result],
            remediation="",
            references=(),
        )
        b = _builder()
        b.add_section(section)
        html = b.build()
        # response_body was escaped to &lt;b&gt; at ingestion — should appear as-is
        assert "&lt;b&gt;" in html
        # raw <b> must not appear (would be double-rendered)
        assert "<b>bold</b>" not in html


# ---------------------------------------------------------------------------
# Report structure
# ---------------------------------------------------------------------------

class TestHtmlStructure:

    def test_html_has_doctype(self):
        b = _builder()
        html = b.build()
        assert html.startswith("<!DOCTYPE html>")

    def test_html_has_title(self):
        b = _builder()
        html = b.build()
        assert "<title>" in html

    def test_html_includes_target_url(self):
        b = _builder()
        html = b.build()
        assert "localhost:8000" in html

    def test_html_section_shows_threat_id(self):
        b = _builder()
        b.add_section(_section(threat_id="T04-002"))
        html = b.build()
        assert "T04-002" in html

    def test_html_pass_fail_status_shown(self):
        b = _builder()
        b.add_section(_section(passed=False))
        b.add_section(_section(threat_id="T02-001", passed=True))
        html = b.build()
        assert "FAIL" in html
        assert "PASS" in html


# ---------------------------------------------------------------------------
# Regression tests for panel P1/P2 findings
# ---------------------------------------------------------------------------

class TestHtmlRegressions:

    def test_regression_response_body_direct_construction_xss(self):
        """ProbeResult constructed directly (not via make_probe_result) must be safe.

        FIX 5: _render_probe_result relied solely on ingestion-time HTML-escape
        with no render-time defence-in-depth. Direct construction bypasses
        make_probe_result. Now: unescape + re-escape at render time.
        """
        from cosai_mcp.harness.result import ProbeResult, AssertionResult
        result = ProbeResult(
            probe_id="T01-001",
            threat_id="T01",
            passed=False,
            status_code=200,
            response_body="<script>alert(1)</script>",  # NOT pre-escaped
            error=None,
            assertions=(),
            duration_seconds=0.0,
        )
        section = HtmlReportSection(
            threat_id="T01-001",
            category="T1",
            severity=Severity.HIGH,
            passed=False,
            probe_results=[result],
            remediation="",
            references=(),
        )
        b = _builder()
        b.add_section(section)
        report = b.build()
        # Raw <script> must not appear — only HTML-escaped &lt;script&gt;
        assert "<script>" not in report
        assert "&lt;script&gt;" in report

    def test_regression_csp_no_style_src_self(self):
        """CSP must not allow style-src 'self' — prevents external stylesheet loading.

        FIX 6: style-src 'self' was removed; inline CSS uses 'unsafe-inline'.
        'unsafe-inline' allows the embedded <style> block without permitting
        any same-origin stylesheet files an attacker could place alongside the report.
        """
        b = _builder()
        report = b.build()
        assert "style-src 'self'" not in report


# ---------------------------------------------------------------------------
# Regression: all-inconclusive sections must show INCONCLUSIVE, not PASS
# ---------------------------------------------------------------------------

def _inconclusive_section(threat_id: str = "T05-001") -> HtmlReportSection:
    """Section where every probe is inconclusive (transport error during initialize)."""
    result = make_probe_result(
        probe_id=f"{threat_id}-p1",
        threat_id=threat_id,
        passed=False,
        assertions=(),
        error="Server rejected initialize: rate_limit_exceeded",
        inconclusive_reason=(
            "Scanner could not complete MCP handshake "
            "(Server rejected initialize: rate_limit_exceeded) — "
            "security property could not be verified"
        ),
    )
    return HtmlReportSection(
        threat_id=threat_id,
        category="T5",
        severity=Severity.HIGH,
        passed=False,
        probe_results=[result],
        remediation="Apply credential scrubbing.",
        references=(),
    )


def _all_inconclusive_passed_section(threat_id: str = "T02-001") -> HtmlReportSection:
    """Section where every probe has passed=True but inconclusive_reason set
    (schema mismatch — assertion technically passed but security not verified)."""
    result = make_probe_result(
        probe_id=f"{threat_id}-p1",
        threat_id=threat_id,
        passed=True,
        assertions=(),
        inconclusive_reason=(
            "Probe payload did not match the server's tool schema — "
            "security property could not be verified"
        ),
    )
    return HtmlReportSection(
        threat_id=threat_id,
        category="T2",
        severity=Severity.HIGH,
        passed=True,
        probe_results=[result],
        remediation="",
        references=(),
    )


class TestHtmlInconclusiveSections:

    def test_regression_all_inconclusive_section_shows_inconclusive_header(self):
        """A section where all probes are inconclusive must show INCONCLUSIVE badge,
        not PASS. Regression for: transport errors reported as PASS with buried notes.
        """
        b = _builder()
        b.add_section(_inconclusive_section())
        report = b.build()
        assert "INCONCLUSIVE" in report
        assert "st-inconclusive" in report

    def test_regression_all_inconclusive_section_not_in_pass_group(self):
        """All-inconclusive section must appear under 'Inconclusive' group heading,
        not under 'Passed — No Vulnerabilities Detected'.
        """
        b = _builder()
        b.add_section(_inconclusive_section())
        report = b.build()
        assert "Inconclusive — Security Property Not Verified" in report
        assert "Passed — No Vulnerabilities Detected" not in report

    def test_regression_all_inconclusive_not_counted_as_passed_threat(self):
        """All-inconclusive sections must not increment the 'Categories passed' stat."""
        b = _builder()
        b.add_section(_inconclusive_section("T05-001"))
        b.add_section(_section(threat_id="T01-001", passed=True))  # genuine pass
        report = b.build()
        # '1' Categories passed, not '2'
        assert "num-pass'>1<" in report.replace(" ", "").replace("\n", "")

    def test_regression_schema_mismatch_inconclusive_shows_inconclusive_not_pass(self):
        """A section where probes passed=True but all have inconclusive_reason set
        (schema mismatch) must show INCONCLUSIVE header, not PASS.
        Regression for: T02/T03 categories incorrectly showing PASS when probe
        arguments were rejected by the server's JSON schema, not security logic.
        """
        b = _builder()
        b.add_section(_all_inconclusive_passed_section())
        report = b.build()
        assert "INCONCLUSIVE" in report
        assert "st-inconclusive" in report
        # Must NOT use section-pass div class (CSS definition always present, so
        # check the rendered div attribute, not any substring occurrence)
        assert "class='section section-pass'" not in report
