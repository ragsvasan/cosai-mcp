"""Tests for the adversarial HTML report builder."""
from __future__ import annotations

import pytest

from cosai_mcp.adversarial.canary import generate_canary
from cosai_mcp.catalog.models import Severity
from cosai_mcp.report.adversarial_html import AdversarialFinding, AdversarialHtmlReport


def _report(findings=()) -> AdversarialHtmlReport:
    r = AdversarialHtmlReport(
        target_url="http://target.example.com",
        scan_timestamp="2026-04-27T00:00:00Z",
        scan_id="abc12345-1234-1234-1234-abcdef012345",
        ownership_declaration="I own target.example.com",
    )
    for f in findings:
        r.add_finding(f)
    return r


def _finding(**kwargs) -> AdversarialFinding:
    defaults = dict(
        probe_id="T03-ADV-001-p1",
        threat_id="T03-ADV-001",
        category="T3",
        severity=Severity.CRITICAL,
        passed=False,
        canary_detected=False,
        payload_sent="some payload",
        response_body="some response",
        error=None,
        canary=None,
    )
    defaults.update(kwargs)
    return AdversarialFinding(**defaults)


class TestAdversarialHtmlSafety:

    def test_has_doctype(self):
        html = _report().build()
        assert html.startswith("<!DOCTYPE html>")

    def test_noindex_meta(self):
        """Report must include noindex meta tag."""
        html = _report().build()
        assert "noindex" in html

    def test_no_referrer_meta(self):
        """Report must include no-referrer meta tag."""
        html = _report().build()
        assert "no-referrer" in html

    def test_csp_frame_ancestors_none(self):
        """CSP must include frame-ancestors 'none' (HTML-escaped in meta content attr)."""
        html = _report().build()
        # Quotes are HTML-escaped in the meta content attribute value
        assert "frame-ancestors" in html and "none" in html
        assert "frame-ancestors &#x27;none&#x27;" in html

    def test_csp_default_src_none(self):
        html = _report().build()
        assert "default-src &#x27;none&#x27;" in html

    def test_csp_script_src_none(self):
        html = _report().build()
        assert "script-src &#x27;none&#x27;" in html

    def test_red_banner_present(self):
        """Report must include the RESTRICTED banner."""
        html = _report().build()
        assert "RESTRICTED" in html

    def test_target_url_escaped(self):
        """XSS in target_url must be HTML-escaped."""
        r = AdversarialHtmlReport(
            target_url='"><script>alert(1)</script>',
            scan_timestamp="2026-04-27T00:00:00Z",
            scan_id="abc",
            ownership_declaration="I own localhost",
        )
        html = r.build()
        assert "<script>" not in html

    def test_canary_redacted_in_payload(self):
        """Canary value must appear as [CANARY REDACTED] in the rendered payload."""
        c = generate_canary("T03-ADV-001", "abc12345")
        f = _finding(
            payload_sent=f"some probe with {c.value} embedded",
            canary=c,
        )
        html = _report(findings=[f]).build()
        assert c.value not in html
        assert "[CANARY REDACTED]" in html

    def test_canary_not_in_response_section(self):
        """Response body containing a canary value must still be HTML-escaped (not redacted)."""
        c = generate_canary("T03-ADV-001", "abc12345")
        f = _finding(
            payload_sent="probe",
            response_body=f"echo {c.value}",
            canary=c,
        )
        html = _report(findings=[f]).build()
        # Canary in response shows as-is (we want to surface that it was reflected)
        assert c.value in html

    def test_ownership_declaration_shown(self):
        html = _report().build()
        assert "I own target.example.com" in html

    def test_no_findings_message(self):
        html = _report(findings=[]).build()
        assert "No adversarial findings recorded" in html

    def test_canary_hit_badge_shown(self):
        f = _finding(canary_detected=True)
        html = _report(findings=[f]).build()
        assert "CANARY HIT" in html

    def test_finding_probe_id_shown(self):
        f = _finding(probe_id="T03-ADV-001-p1")
        html = _report(findings=[f]).build()
        assert "T03-ADV-001-p1" in html

    def test_regression_response_body_pre_escaped_xss(self):
        """Directly-constructed AdversarialFinding with raw XSS in response_body must be safe.

        FIX [5]: response_body must be HTML-escaped at ingestion. The renderer uses
        unescape + re-escape (defense-in-depth), so raw <script> tags must never appear
        in the rendered HTML regardless of whether the caller escaped at ingestion.
        """
        f = _finding(response_body="<script>alert(1)</script>")
        html = _report(findings=[f]).build()
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_regression_response_body_already_escaped_no_double_escape(self):
        """Pre-escaped response_body must appear correctly (no double-escape of &amp;).

        FIX [5]: If caller correctly escapes at ingestion, the render-time unescape+re-escape
        must produce the same single-escaped output.
        """
        import html as _html
        raw = "<b>bold</b>"
        escaped = _html.escape(raw, quote=True)
        f = _finding(response_body=escaped)
        output = _report(findings=[f]).build()
        # Must appear as HTML-escaped (no raw <b>)
        assert "<b>bold</b>" not in output
        assert "&lt;b&gt;" in output

    def test_regression_redact_canary_none_returns_payload_unchanged(self):
        """_redact_canary with canary=None must return the payload unchanged.

        FIX [9]: Documents the no-canary fallback behavior. When canary=None,
        no string replacement occurs.
        """
        from cosai_mcp.report.adversarial_html import AdversarialHtmlReport
        result = AdversarialHtmlReport._redact_canary("probe payload text", None)
        assert result == "probe payload text"
