"""Adversarial-mode HTML report builder.

Differences from the standard HtmlReportBuilder:
- Red warning banner at top (visually distinct from normal reports)
- X-Robots-Tag / noindex meta tag (prevent search engine indexing of probe data)
- frame-ancestors 'none' in CSP (extra clickjacking protection)
- "WHAT WE SENT" section redacts canary values to [CANARY REDACTED]
- Report is self-contained — no external resources

This report is NOT suitable for executive distribution. It contains probe
payloads and canary strings that are sensitive to the target environment.
"""
from __future__ import annotations

import html
from dataclasses import dataclass, field
from typing import Sequence

from ..adversarial.canary import Canary
from ..catalog.models import Severity


def _h(s: object) -> str:
    return html.escape(str(s), quote=True)


def _unescape(s: str) -> str:
    """Reverse html.escape so we can re-escape at render time (defense-in-depth).

    response_body is HTML-escaped at ingestion (constructor). At render time we
    unescape then re-escape to guard against directly-constructed AdversarialFinding
    objects that bypass the ingestion path.
    """
    return html.unescape(s)


@dataclass
class AdversarialFinding:
    """One adversarial probe result for the report.

    ``response_body`` MUST be HTML-escaped before construction (escape at ingestion,
    not at render time — per CLAUDE.md architecture). Use ``html.escape(s, quote=True)``.
    """
    probe_id: str
    threat_id: str
    category: str
    severity: Severity
    passed: bool
    canary_detected: bool
    payload_sent: str
    response_body: str  # must be HTML-escaped at ingestion
    error: str | None
    canary: Canary | None = None
    notes: str = ""


class AdversarialHtmlReport:
    """Builder for the adversarial-mode HTML report."""

    _CSP = (
        "default-src 'none'; "
        "script-src 'none'; "
        "style-src 'unsafe-inline'; "
        "font-src 'none'; "
        "img-src 'none'; "
        "connect-src 'none'; "
        "frame-ancestors 'none'"
    )

    def __init__(
        self,
        target_url: str,
        scan_timestamp: str,
        scan_id: str,
        ownership_declaration: str,
    ) -> None:
        self._target_url = target_url
        self._scan_timestamp = scan_timestamp
        self._scan_id = scan_id
        self._ownership_declaration = ownership_declaration
        self._findings: list[AdversarialFinding] = []

    def add_finding(self, finding: AdversarialFinding) -> None:
        self._findings.append(finding)

    def build(self) -> str:
        findings_html = "\n".join(
            self._render_finding(f) for f in self._findings
        )
        if not self._findings:
            findings_html = "<p class='no-findings'>No adversarial findings recorded.</p>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="{_h(self._CSP)}">
<meta name="robots" content="noindex, nofollow, noarchive">
<meta name="referrer" content="no-referrer">
<title>CoSAI Adversarial Probe Report — {_h(self._target_url)}</title>
<style>
  body {{
    font-family: monospace;
    background: #0a0a0a;
    color: #e0e0e0;
    margin: 0;
    padding: 0;
  }}
  .banner {{
    background: #8b0000;
    color: #fff;
    padding: 1rem 2rem;
    border-bottom: 3px solid #ff0000;
    font-size: 1.1rem;
    font-weight: bold;
  }}
  .banner .subtitle {{
    font-size: 0.85rem;
    font-weight: normal;
    margin-top: 0.25rem;
    color: #ffcccc;
  }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 1.5rem; }}
  .meta-table {{ border-collapse: collapse; margin-bottom: 1.5rem; width: 100%; }}
  .meta-table td {{ padding: 0.3rem 0.8rem; border: 1px solid #333; }}
  .meta-table td:first-child {{ color: #aaa; width: 180px; }}
  .finding {{
    border: 1px solid #444;
    border-radius: 4px;
    margin-bottom: 1.2rem;
    overflow: hidden;
  }}
  .finding.fail {{ border-color: #8b0000; }}
  .finding.pass {{ border-color: #006400; }}
  .finding.canary-hit {{ border-color: #ff4500; border-width: 2px; }}
  .finding-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.5rem 0.8rem;
    background: #111;
    border-bottom: 1px solid #333;
  }}
  .badge {{
    padding: 0.2rem 0.5rem;
    border-radius: 3px;
    font-size: 0.8rem;
    font-weight: bold;
  }}
  .badge.fail {{ background: #8b0000; color: #fff; }}
  .badge.pass {{ background: #006400; color: #fff; }}
  .badge.canary {{ background: #ff4500; color: #fff; }}
  .badge.inconclusive {{ background: #555; color: #ddd; }}
  .finding-body {{ padding: 0.8rem; }}
  .section-label {{ color: #888; font-size: 0.8rem; margin: 0.6rem 0 0.2rem; }}
  pre {{
    background: #111;
    border: 1px solid #333;
    border-radius: 3px;
    padding: 0.5rem;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    margin: 0;
    font-size: 0.8rem;
    color: #c0c0c0;
  }}
  pre.redacted {{ color: #666; font-style: italic; }}
  .no-findings {{ color: #666; padding: 1rem; }}
  h1 {{ color: #ff6666; margin: 0; font-size: 1.2rem; }}
  h2 {{ color: #cc4444; border-bottom: 1px solid #333; padding-bottom: 0.3rem; }}
</style>
</head>
<body>
<div class="banner">
  ⚠ CoSAI Adversarial Probe Report — RESTRICTED
  <div class="subtitle">
    This report contains active probe payloads and canary strings.
    Do not distribute outside the authorized testing team.
    Not indexed by search engines. Canary values are redacted.
  </div>
</div>
<div class="container">
  <h1>Adversarial Scan Results</h1>
  <table class="meta-table">
    <tr><td>Target</td><td>{_h(self._target_url)}</td></tr>
    <tr><td>Scan ID</td><td>{_h(self._scan_id)}</td></tr>
    <tr><td>Timestamp</td><td>{_h(self._scan_timestamp)}</td></tr>
    <tr><td>Ownership Declaration</td><td>{_h(self._ownership_declaration)}</td></tr>
    <tr><td>Total Probes</td><td>{len(self._findings)}</td></tr>
    <tr><td>Canary Hits</td><td>{sum(1 for f in self._findings if f.canary_detected)}</td></tr>
  </table>
  <h2>Findings</h2>
  {findings_html}
</div>
</body>
</html>"""

    def _render_finding(self, f: AdversarialFinding) -> str:
        status_class = "pass" if f.passed else "fail"
        if f.canary_detected:
            status_class = "canary-hit"

        badges = []
        if f.canary_detected:
            badges.append("<span class='badge canary'>CANARY HIT</span>")
        elif f.passed:
            badges.append("<span class='badge pass'>PASS</span>")
        else:
            badges.append("<span class='badge fail'>FAIL</span>")

        if f.severity == Severity.CRITICAL:
            badges.append("<span class='badge fail'>CRITICAL</span>")
        elif f.severity == Severity.HIGH:
            badges.append("<span class='badge fail'>HIGH</span>")

        badges_html = " ".join(badges)

        payload_display = self._redact_canary(f.payload_sent, f.canary)
        # Unescape + re-escape: defense-in-depth against directly-constructed findings
        # that bypass the ingestion-time escape contract.
        response_display = _h(_unescape(f.response_body)[:2000]) if f.response_body else "<em>(empty)</em>"
        error_display = f"<p class='section-label'>Error</p><pre>{_h(f.error)}</pre>" if f.error else ""
        notes_display = f"<p class='section-label'>Notes</p><p>{_h(f.notes)}</p>" if f.notes else ""

        return f"""<div class="finding {status_class}">
  <div class="finding-header">
    <strong>{_h(f.probe_id)}</strong>
    <span>Category: {_h(f.category)} | Severity: {_h(f.severity.value.upper())}</span>
    <span>{badges_html}</span>
  </div>
  <div class="finding-body">
    <p class="section-label">WHAT WE SENT (canary redacted)</p>
    <pre class="redacted">{_h(payload_display)}</pre>
    <p class="section-label">Response</p>
    <pre>{response_display}</pre>
    {error_display}
    {notes_display}
  </div>
</div>"""

    @staticmethod
    def _redact_canary(payload: str, canary: Canary | None) -> str:
        """Replace canary value with [CANARY REDACTED] in the payload display."""
        if canary is None:
            return payload
        return payload.replace(canary.value, canary.redacted())
