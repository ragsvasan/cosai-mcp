"""HTML report builder with strict CSP (default-src 'none')."""
from __future__ import annotations

import html as _html_stdlib
from dataclasses import dataclass
from typing import Any

from cosai_mcp.catalog.models import Severity
from cosai_mcp.harness.result import ProbeResult

# style-src 'self' removed — no stylesheets are used; it would allow an
# attacker with write access to the report directory to load a local CSS file.
_CSP = "default-src 'none'"

# Allowed URL schemes for references — anything else is rendered as plain text.
_SAFE_URL_SCHEMES = ("https://", "http://")


def _safe_url(ref: str) -> str | None:
    """Return ref if it has a safe scheme, else None (render as plain text)."""
    stripped = ref.strip()
    for scheme in _SAFE_URL_SCHEMES:
        if stripped.lower().startswith(scheme):
            return stripped
    return None


def _h(text: object) -> str:
    """HTML-escape a value for attribute or text content use."""
    return _html_stdlib.escape(str(text), quote=True)


@dataclass
class HtmlReportSection:
    threat_id: str
    category: str
    severity: Severity
    passed: bool
    probe_results: list[ProbeResult]
    remediation: str
    references: tuple  # tuple[str, ...]


class HtmlReportBuilder:
    """Build an HTML security report from probe results.

    Security invariants:
    - All dynamic content is html.escape()-d before insertion.
    - ProbeResult fields (response_body, error) are pre-escaped at ingestion;
      this builder treats them as already-safe text (no double-escaping needed).
    - References are rendered as clickable <a> only when scheme ∈ {http, https}.
      All other URIs (javascript:, data:, etc.) are rendered as plain text.
    - CSP meta tag disables all active content: default-src 'none'.
    """

    def __init__(self, target_url: str, scan_timestamp: str) -> None:
        self._target_url = target_url
        self._scan_timestamp = scan_timestamp
        self._sections: list[HtmlReportSection] = []

    def add_section(self, section: HtmlReportSection) -> None:
        self._sections.append(section)

    def build(self) -> str:
        """Return the complete HTML report as a string."""
        sections_html = "\n".join(self._render_section(s) for s in self._sections)
        total = len(self._sections)
        passed = sum(1 for s in self._sections if s.passed)
        failed = total - passed

        return (
            "<!DOCTYPE html>\n"
            "<html lang=\"en\">\n"
            "<head>\n"
            "<meta charset=\"UTF-8\">\n"
            f"<meta http-equiv=\"Content-Security-Policy\" content=\"{_CSP}\">\n"
            "<title>CoSAI MCP Security Report</title>\n"
            "</head>\n"
            "<body>\n"
            f"<h1>CoSAI MCP Security Report</h1>\n"
            f"<p>Target: {_h(self._target_url)}</p>\n"
            f"<p>Scan time: {_h(self._scan_timestamp)}</p>\n"
            f"<p>Results: {failed} finding(s), {passed} passed, {total} total</p>\n"
            f"{sections_html}\n"
            "</body>\n"
            "</html>\n"
        )

    def _render_section(self, section: HtmlReportSection) -> str:
        status = "PASS" if section.passed else "FAIL"
        results_html = "\n".join(
            self._render_probe_result(r) for r in section.probe_results
        )
        refs_html = self._render_references(section.references)

        return (
            f"<section>\n"
            f"<h2>{_h(section.threat_id)} ({_h(section.category)}) — "
            f"{_h(section.severity.value.upper())} — {_h(status)}</h2>\n"
            f"{results_html}\n"
            f"<p><strong>Remediation:</strong> {_h(section.remediation)}</p>\n"
            f"<p><strong>References:</strong></p>\n"
            f"<ul>{refs_html}</ul>\n"
            f"</section>\n"
        )

    def _render_probe_result(self, result: ProbeResult) -> str:
        status = "PASS" if result.passed else "FAIL"
        # response_body is HTML-escaped at ingestion (make_probe_result).
        # Defence-in-depth: unescape then re-escape so the output is correct
        # even if a ProbeResult is constructed directly without make_probe_result.
        raw_body = _html_stdlib.unescape(result.response_body) if result.response_body else ""
        body_display = _h(raw_body) if raw_body else "(empty)"
        error_html = (
            f"<p>Error: {_h(_html_stdlib.unescape(result.error))}</p>"
            if result.error else ""
        )
        return (
            f"<div>\n"
            f"<h3>Probe {_h(result.probe_id)}: {_h(status)}</h3>\n"
            f"{error_html}"
            f"<pre>{body_display}</pre>\n"
            f"</div>\n"
        )

    def _render_references(self, references: tuple) -> str:
        items: list[str] = []
        for ref in references:
            safe = _safe_url(str(ref))
            if safe is not None:
                # Safe URL — render as link with rel="noopener noreferrer"
                items.append(
                    f"<li><a href=\"{_h(safe)}\" "
                    f"rel=\"noopener noreferrer\">{_h(safe)}</a></li>"
                )
            else:
                # Unsafe scheme (javascript:, data:, etc.) — render as plain text
                items.append(f"<li>{_h(str(ref))}</li>")
        return "\n".join(items)
