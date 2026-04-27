"""HTML report builder — self-contained, no external resources, strict CSP.

Uses Mnemo's design system tokens (dark theme, teal accent, Inter font).
"""
from __future__ import annotations

import html as _html_stdlib
from dataclasses import dataclass
from typing import Any

from cosai_mcp.catalog.models import Severity
from cosai_mcp.harness.result import ProbeResult

_CSP = "default-src 'none'; style-src 'unsafe-inline'; font-src 'none'"
_SAFE_URL_SCHEMES = ("https://", "http://")

_CATEGORY_NAMES: dict[str, str] = {
    "T1":  "Improper Authentication",
    "T2":  "Missing Access Control",
    "T3":  "Input Validation Failures",
    "T4":  "Data/Control Boundary",
    "T5":  "Inadequate Data Protection",
    "T6":  "Integrity / Verification Failures",
    "T7":  "Session Security Failures",
    "T8":  "Network Binding Failures",
    "T9":  "Trust Boundary Failures",
    "T10": "Resource Management",
    "T11": "Supply Chain / Lifecycle",
    "T12": "Insufficient Logging",
}

_SEVERITY_COLOR: dict[str, str] = {
    "critical": "#DC2626",
    "high":     "#F59E0B",
    "medium":   "#0B7285",
    "low":      "#10B981",
    "info":     "#7A8599",
}

_CSS = """
:root {
  --mn-bg: #0F1521;
  --mn-surface: #1A2332;
  --mn-surface-2: #20293A;
  --mn-surface-3: #283345;
  --mn-teal: #0B7285;
  --mn-teal-hover: #065A6E;
  --mn-teal-08: rgba(11,114,133,0.08);
  --mn-teal-16: rgba(11,114,133,0.16);
  --mn-teal-25: rgba(11,114,133,0.25);
  --mn-text: #F5F0E8;
  --mn-text-2: #C8C8C0;
  --mn-text-3: #7A8599;
  --mn-border: rgba(255,255,255,0.07);
  --mn-border-md: rgba(255,255,255,0.12);
  --mn-border-strong: rgba(255,255,255,0.20);
  --mn-ok: #10B981;
  --mn-ok-bg: rgba(16,185,129,0.12);
  --mn-warn: #F59E0B;
  --mn-warn-bg: rgba(245,158,11,0.12);
  --mn-error: #DC2626;
  --mn-error-bg: rgba(220,38,38,0.12);
  --mn-shadow: 0 2px 8px rgba(0,0,0,0.30);
  --mn-shadow-md: 0 8px 24px rgba(0,0,0,0.35);
  --mn-r-md: 6px;
  --mn-r-lg: 8px;
  --mn-r-xl: 12px;
}
* { box-sizing: border-box; }
body {
  font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont,
               'Segoe UI', Helvetica, Arial, sans-serif;
  background: var(--mn-bg);
  color: var(--mn-text-2);
  max-width: 1040px;
  margin: 0 auto;
  padding: 40px 24px 80px;
  line-height: 1.6;
  font-size: 0.9375rem;
}
a { color: var(--mn-teal); text-decoration: none; }
a:hover { text-decoration: underline; }
h1 {
  font-size: 1.5rem; font-weight: 700; color: var(--mn-text);
  margin: 0 0 4px 0; letter-spacing: -0.02em;
}
h2 { font-size: 1rem; font-weight: 600; color: var(--mn-text); margin: 0 0 4px 0; }
h3 { font-size: 0.875rem; font-weight: 600; color: var(--mn-text-2); margin: 10px 0 3px 0; }
.logo-row { display: flex; align-items: center; gap: 10px; margin-bottom: 24px; }
.logo-badge {
  background: var(--mn-teal); color: #fff;
  font-size: 0.75rem; font-weight: 700; letter-spacing: 0.06em;
  padding: 4px 10px; border-radius: var(--mn-r-md);
}
.meta {
  background: var(--mn-surface); border: 1px solid var(--mn-border-md);
  border-radius: var(--mn-r-xl); padding: 16px 20px; margin: 0 0 20px 0;
  display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 8px 24px;
}
.meta-item { font-size: 0.8125rem; }
.meta-item .lbl { color: var(--mn-text-3); font-size: 0.75rem;
                  text-transform: uppercase; letter-spacing: 0.05em; display: block; }
.meta-item .val { color: var(--mn-text); font-weight: 500; }
.summary-grid {
  display: grid; grid-template-columns: repeat(4, 1fr);
  gap: 12px; margin: 0 0 28px 0;
}
.stat-box {
  background: var(--mn-surface); border: 1px solid var(--mn-border-md);
  border-radius: var(--mn-r-xl); padding: 16px 20px; text-align: center;
}
.stat-box .num { font-size: 2rem; font-weight: 700; line-height: 1; }
.stat-box .lbl { font-size: 0.75rem; color: var(--mn-text-3);
                 text-transform: uppercase; letter-spacing: 0.05em; margin-top: 6px; }
.num-critical { color: #DC2626; }
.num-high     { color: #F59E0B; }
.num-pass     { color: var(--mn-ok); }
.num-neutral  { color: var(--mn-text-3); }

/* ---- findings table ---- */
.table-wrap {
  background: var(--mn-surface); border: 1px solid var(--mn-border-md);
  border-radius: var(--mn-r-xl); margin: 0 0 32px 0; overflow: hidden;
}
.table-wrap h2 {
  padding: 14px 20px 12px; border-bottom: 1px solid var(--mn-border);
  font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--mn-text-3);
}
table { width: 100%; border-collapse: collapse; font-size: 0.8125rem; }
thead th {
  background: var(--mn-surface-2); color: var(--mn-text-3);
  font-size: 0.6875rem; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.06em; padding: 8px 14px; text-align: left;
  border-bottom: 1px solid var(--mn-border-md);
}
tbody tr { border-bottom: 1px solid var(--mn-border); }
tbody tr:last-child { border-bottom: none; }
tbody tr:hover { background: var(--mn-surface-3); }
tbody td { padding: 10px 14px; color: var(--mn-text-2); vertical-align: top; }
.td-id { font-family: 'JetBrains Mono', 'Fira Code', ui-monospace, Menlo, monospace;
         color: var(--mn-text); font-size: 0.75rem; white-space: nowrap; }
.td-cat { color: var(--mn-text-3); font-size: 0.75rem; }

/* ---- severity + status badges ---- */
.badge {
  display: inline-block; font-size: 0.6875rem; font-weight: 700;
  letter-spacing: 0.05em; padding: 2px 7px; border-radius: var(--mn-r-md);
  white-space: nowrap;
}
.sev-critical { background: var(--mn-error-bg);  color: #FCA5A5; }
.sev-high     { background: var(--mn-warn-bg);   color: #FCD34D; }
.sev-medium   { background: var(--mn-teal-08);   color: #67E8F9; }
.sev-low      { background: var(--mn-ok-bg);     color: #6EE7B7; }
.sev-info     { background: rgba(122,133,153,.15); color: var(--mn-text-3); }
.st-finding   { background: var(--mn-error-bg);  color: #FCA5A5; }
.st-pass      { background: var(--mn-ok-bg);     color: #6EE7B7; }
.st-incomplete { background: var(--mn-warn-bg);  color: #FCD34D; }

/* ---- detail sections ---- */
.section-group { margin: 0 0 12px 0; }
.section-group-title {
  font-size: 0.75rem; font-weight: 600; color: var(--mn-text-3);
  text-transform: uppercase; letter-spacing: 0.07em;
  padding: 0 0 8px 0; margin: 28px 0 10px 0;
  border-bottom: 1px solid var(--mn-border);
}
.section {
  background: var(--mn-surface); border: 1px solid var(--mn-border-md);
  border-radius: var(--mn-r-xl); padding: 18px 22px; margin: 0 0 10px 0;
  box-shadow: var(--mn-shadow);
}
.section-finding { border-left: 3px solid var(--mn-error); }
.section-pass    { border-left: 3px solid var(--mn-ok); }
.section-incomplete { border-left: 3px solid var(--mn-warn); }
.header-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
.cat-name { font-size: 0.8rem; color: var(--mn-text-3); margin-left: auto; }

/* ---- probes ---- */
.probe {
  background: var(--mn-surface-2); border: 1px solid var(--mn-border);
  border-radius: var(--mn-r-lg); padding: 12px 14px; margin: 8px 0;
}
.probe-fail { border-left: 2px solid var(--mn-error); }
.probe-pass { border-left: 2px solid var(--mn-ok); }
.what-tested {
  font-size: 0.8rem; color: var(--mn-text-3);
  background: var(--mn-bg); border: 1px solid var(--mn-border);
  border-radius: var(--mn-r-md); padding: 6px 10px; margin: 6px 0;
  font-family: 'JetBrains Mono','Fira Code',ui-monospace,Menlo,monospace;
  word-break: break-all;
}
.what-tested .lbl { color: var(--mn-teal); font-family: inherit; }
.assertion {
  font-size: 0.8rem; padding: 2px 0;
  font-family: 'JetBrains Mono','Fira Code',ui-monospace,Menlo,monospace;
}
.a-pass { color: #6EE7B7; }
.a-fail { color: #FCA5A5; font-weight: 600; }
pre {
  background: var(--mn-bg); border: 1px solid var(--mn-border);
  border-radius: var(--mn-r-md); padding: 8px 10px;
  font-size: 0.775rem; white-space: pre-wrap; word-break: break-all;
  max-height: 120px; overflow-y: auto; color: var(--mn-text-3);
  margin: 6px 0; font-family: 'JetBrains Mono','Fira Code',ui-monospace,Menlo,monospace;
}
.error-msg { font-size: 0.8rem; color: #FCA5A5; margin: 4px 0; }
.remediation {
  background: var(--mn-teal-08); border-left: 3px solid var(--mn-teal);
  padding: 10px 14px; margin: 14px 0 8px; font-size: 0.875rem;
  border-radius: 0 var(--mn-r-md) var(--mn-r-md) 0; color: var(--mn-text-2);
}
.remediation .lbl { color: #67E8F9; font-weight: 600; }
.refs { font-size: 0.8rem; color: var(--mn-text-3); margin-top: 6px; }
.pass-note { font-size: 0.875rem; color: #6EE7B7; margin: 4px 0; }

/* ---- scenario steps ---- */
.step {
  padding: 8px 0; border-top: 1px solid var(--mn-border);
  font-size: 0.875rem;
}
.step:first-child { border-top: none; }
.step-pass { color: #6EE7B7; }
.step-fail { color: #FCA5A5; font-weight: 600; }
.step-resp {
  font-size: 0.775rem; background: var(--mn-bg); border: 1px solid var(--mn-border);
  border-radius: var(--mn-r-md); padding: 6px 10px; margin: 4px 0 0 18px;
  white-space: pre-wrap; word-break: break-all; color: var(--mn-text-3);
  font-family: 'JetBrains Mono','Fira Code',ui-monospace,Menlo,monospace;
}
hr { border: none; border-top: 1px solid var(--mn-border); margin: 32px 0; }
.footer {
  font-size: 0.75rem; color: var(--mn-text-3); text-align: center;
  margin-top: 48px; padding-top: 24px; border-top: 1px solid var(--mn-border);
}
"""


def _safe_url(ref: str) -> str | None:
    stripped = ref.strip()
    for scheme in _SAFE_URL_SCHEMES:
        if stripped.lower().startswith(scheme):
            return stripped
    return None


def _h(text: object) -> str:
    return _html_stdlib.escape(str(text), quote=True)


def _unescape(s: str) -> str:
    return _html_stdlib.unescape(s)


@dataclass
class ProbeContext:
    """What the probe sent and why — shown in the report so findings are self-explanatory."""
    method: str
    payload_summary: str
    assertion_descriptions: list[str]


@dataclass
class HtmlReportSection:
    threat_id: str
    category: str
    severity: Severity
    passed: bool
    probe_results: list[ProbeResult]
    remediation: str
    references: tuple
    probe_contexts: list[ProbeContext] | None = None


@dataclass
class ScenarioStep:
    index: int
    description: str
    passed: bool
    response_summary: str


@dataclass
class HtmlScenarioSection:
    scenario_id: str
    scenario_name: str
    category: str
    passed: bool
    steps: list[ScenarioStep]


class HtmlReportBuilder:
    """Build a self-contained HTML security report styled with Mnemo's design system.

    Security invariants:
    - All dynamic content is html.escape()-d before insertion.
    - CSP meta tag blocks external resources; only inline styles allowed.
    - References rendered as links only when scheme ∈ {http, https}.
    """

    def __init__(self, target_url: str, scan_timestamp: str) -> None:
        self._target_url = target_url
        self._scan_timestamp = scan_timestamp
        self._sections: list[HtmlReportSection] = []
        self._scenarios: list[HtmlScenarioSection] = []

    def add_section(self, section: HtmlReportSection) -> None:
        self._sections.append(section)

    def add_scenario(self, scenario: HtmlScenarioSection) -> None:
        self._scenarios.append(scenario)

    def build(self) -> str:
        total_threats = len(self._sections)
        passed_threats = sum(1 for s in self._sections if s.passed)
        failed_threats = total_threats - passed_threats

        total_scenarios = len(self._scenarios)
        failed_scenarios = sum(1 for s in self._scenarios if not s.passed)
        total_findings = failed_threats + failed_scenarios

        critical_count = sum(
            1 for s in self._sections
            if not s.passed and s.severity.value == "critical"
        )
        high_count = sum(
            1 for s in self._sections
            if not s.passed and s.severity.value == "high"
        )

        status_color = "var(--mn-error)" if total_findings > 0 else "var(--mn-ok)"
        status_text = (
            f"{total_findings} finding(s) detected"
            if total_findings > 0
            else "Clean — no findings"
        )

        findings_table = self._render_findings_table()
        sections_html = self._render_sections()
        scenario_html = self._render_scenarios()

        return (
            "<!DOCTYPE html>\n"
            '<html lang="en">\n'
            "<head>\n"
            '<meta charset="UTF-8">\n'
            f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">\n'
            "<title>CoSAI MCP Security Report</title>\n"
            f"<style>{_CSS}</style>\n"
            "</head>\n"
            "<body>\n"
            "<div class='logo-row'>\n"
            "<span class='logo-badge'>CoSAI-MCP</span>\n"
            "<h1>MCP Security Report</h1>\n"
            "</div>\n"
            "<div class='meta'>\n"
            f"<div class='meta-item'><span class='lbl'>Target</span>"
            f"<span class='val'>{_h(self._target_url)}</span></div>\n"
            f"<div class='meta-item'><span class='lbl'>Scan time</span>"
            f"<span class='val'>{_h(self._scan_timestamp)}</span></div>\n"
            f"<div class='meta-item'><span class='lbl'>Result</span>"
            f"<span class='val' style='color:{status_color}'>{_h(status_text)}</span></div>\n"
            "</div>\n"
            "<div class='summary-grid'>\n"
            f"<div class='stat-box'><div class='num num-critical'>{critical_count}</div>"
            f"<div class='lbl'>Critical</div></div>\n"
            f"<div class='stat-box'><div class='num num-high'>{high_count}</div>"
            f"<div class='lbl'>High</div></div>\n"
            f"<div class='stat-box'><div class='num num-neutral'>{failed_threats + failed_scenarios}</div>"
            f"<div class='lbl'>Total findings</div></div>\n"
            f"<div class='stat-box'><div class='num num-pass'>{passed_threats}</div>"
            f"<div class='lbl'>Categories passed</div></div>\n"
            "</div>\n"
            f"{findings_table}\n"
            f"{sections_html}\n"
            f"{scenario_html}\n"
            "<div class='footer'>"
            "Generated by <strong>cosai-mcp</strong> — "
            "CoSAI / OASIS MCP Security Scanner"
            "</div>\n"
            "</body>\n"
            "</html>\n"
        )

    # ------------------------------------------------------------------
    # Findings summary table (copy-paste to Excel)
    # ------------------------------------------------------------------

    def _render_findings_table(self) -> str:
        rows: list[str] = []

        for s in self._sections:
            for r in s.probe_results:
                status = "PASS" if r.passed else "FINDING"
                st_cls = "st-pass" if r.passed else "st-finding"
                sev_cls = f"sev-{s.severity.value}"
                assertion_summary = ""
                if not r.passed and r.assertions:
                    parts = [
                        f"{a.target} {a.operator} {a.expected} → got {a.actual}"
                        for a in r.assertions
                        if not a.passed
                    ]
                    assertion_summary = "; ".join(parts[:2])
                    if len(parts) > 2:
                        assertion_summary += f" (+{len(parts)-2} more)"

                rows.append(
                    f"<tr>"
                    f"<td class='td-id'>{_h(r.probe_id)}</td>"
                    f"<td class='td-id'>{_h(s.threat_id)}</td>"
                    f"<td class='td-cat'>{_h(_CATEGORY_NAMES.get(s.category, s.category))}</td>"
                    f"<td><span class='badge {sev_cls}'>{_h(s.severity.value.upper())}</span></td>"
                    f"<td><span class='badge {st_cls}'>{_h(status)}</span></td>"
                    f"<td style='font-size:0.775rem;color:var(--mn-text-3)'>{_h(assertion_summary)}</td>"
                    f"</tr>\n"
                )

        for sc in self._scenarios:
            status = "PASS" if sc.passed else "FINDING"
            st_cls = "st-pass" if sc.passed else "st-finding"
            cat_name = _CATEGORY_NAMES.get(sc.category, sc.category)
            failed_steps = [s for s in sc.steps if not s.passed]
            assertion_summary = ""
            if failed_steps:
                assertion_summary = "; ".join(
                    s.description for s in failed_steps[:2]
                )
            rows.append(
                f"<tr>"
                f"<td class='td-id'>{_h(sc.scenario_id)}</td>"
                f"<td class='td-id'>{_h(sc.scenario_id)}</td>"
                f"<td class='td-cat'>{_h(cat_name)} (scenario)</td>"
                f"<td><span class='badge sev-high'>HIGH</span></td>"
                f"<td><span class='badge {st_cls}'>{_h(status)}</span></td>"
                f"<td style='font-size:0.775rem;color:var(--mn-text-3)'>{_h(assertion_summary)}</td>"
                f"</tr>\n"
            )

        rows_html = "".join(rows)
        return (
            "<div class='table-wrap'>\n"
            "<h2>Findings Summary</h2>\n"
            "<table>\n"
            "<thead><tr>"
            "<th>Probe</th><th>Threat</th><th>Category</th>"
            "<th>Severity</th><th>Status</th><th>Assertion detail</th>"
            "</tr></thead>\n"
            f"<tbody>{rows_html}</tbody>\n"
            "</table>\n"
            "</div>\n"
        )

    # ------------------------------------------------------------------
    # Detailed sections
    # ------------------------------------------------------------------

    def _render_sections(self) -> str:
        finding_sections = [s for s in self._sections if not s.passed]
        pass_sections = [s for s in self._sections if s.passed]

        parts: list[str] = []

        if finding_sections:
            parts.append("<div class='section-group-title'>Findings — Action Required</div>\n")
            parts.extend(self._render_section(s) for s in finding_sections)

        if pass_sections:
            parts.append("<div class='section-group-title'>Passed — No Vulnerabilities Detected</div>\n")
            parts.extend(self._render_section(s) for s in pass_sections)

        return "".join(parts)

    def _render_section(self, section: HtmlReportSection) -> str:
        if not section.passed:
            section_cls = "section section-finding"
        else:
            section_cls = "section section-pass"

        sev_cls = f"sev-{section.severity.value}"
        st_cls = "st-pass" if section.passed else "st-finding"
        status_text = "PASS" if section.passed else "FINDING"
        cat_name = _CATEGORY_NAMES.get(section.category, section.category)

        probes_html = "\n".join(
            self._render_probe(r, section.probe_contexts[i] if section.probe_contexts else None)
            for i, r in enumerate(section.probe_results)
        )

        if section.passed:
            body = (
                f"<p class='pass-note'>✓ All probes passed — no {_h(cat_name)} vulnerabilities detected.</p>\n"
                f"{probes_html}\n"
            )
        else:
            refs_html = self._render_references(section.references)
            body = (
                f"{probes_html}\n"
                f"<div class='remediation'><span class='lbl'>How to fix:</span> {_h(section.remediation)}</div>\n"
                f"<div class='refs'>References: {refs_html}</div>\n"
            )

        return (
            f"<div class='{section_cls}'>\n"
            f"<div class='header-row'>\n"
            f"<h2>{_h(section.threat_id)}</h2>\n"
            f"<span class='badge {sev_cls}'>{_h(section.severity.value.upper())}</span>\n"
            f"<span class='badge {st_cls}'>{_h(status_text)}</span>\n"
            f"<span class='cat-name'>{_h(cat_name)}</span>\n"
            f"</div>\n"
            f"{body}"
            f"</div>\n"
        )

    def _render_probe(self, result: ProbeResult, ctx: ProbeContext | None) -> str:
        probe_cls = "probe probe-pass" if result.passed else "probe probe-fail"
        st_cls = "st-pass" if result.passed else "st-finding"
        status_text = "PASS" if result.passed else "FAIL"

        what_tested = ""
        if ctx:
            a_lines = "".join(
                f"<div class='assertion {'a-pass' if result.passed else 'a-fail'}'>"
                f"{'✓' if result.passed else '✗'} {_h(a)}</div>"
                for a in ctx.assertion_descriptions
            )
            what_tested = (
                f"<div class='what-tested'>"
                f"<span class='lbl'>TEST</span> {_h(ctx.payload_summary)}"
                f"</div>\n{a_lines}\n"
            )
        elif result.assertions:
            a_lines = "".join(
                f"<div class='assertion {'a-pass' if a.passed else 'a-fail'}'>"
                f"{'✓' if a.passed else '✗'} {_h(a.target)} {_h(a.operator)} "
                f"{_h(a.expected)} — got {_h(a.actual)}</div>"
                for a in result.assertions
            )
            what_tested = a_lines + "\n"

        body_html = ""
        if result.response_body and not result.passed:
            raw = _unescape(result.response_body)
            body_html = f"<pre>Server response: {_h(raw)}</pre>\n"

        error_html = ""
        if result.error:
            error_html = (
                f"<p class='error-msg'>⚠ {_h(_unescape(result.error))}</p>\n"
            )

        return (
            f"<div class='{probe_cls}'>\n"
            f"<h3>Probe {_h(result.probe_id)}: "
            f"<span class='badge {st_cls}'>{_h(status_text)}</span></h3>\n"
            f"{what_tested}"
            f"{error_html}"
            f"{body_html}"
            f"</div>\n"
        )

    # ------------------------------------------------------------------
    # Scenario sections
    # ------------------------------------------------------------------

    def _render_scenarios(self) -> str:
        if not self._scenarios:
            return ""
        parts = ["<div class='section-group-title'>Stateful Scenario Results</div>\n"]
        parts.extend(self._render_scenario(s) for s in self._scenarios)
        return "".join(parts)

    def _render_scenario(self, scenario: HtmlScenarioSection) -> str:
        section_cls = "section section-pass" if scenario.passed else "section section-finding"
        st_cls = "st-pass" if scenario.passed else "st-finding"
        status_text = "PASS" if scenario.passed else "FINDING"
        cat_name = _CATEGORY_NAMES.get(scenario.category, scenario.category)
        steps_html = "".join(self._render_step(s) for s in scenario.steps)

        return (
            f"<div class='{section_cls}'>\n"
            f"<div class='header-row'>\n"
            f"<h2>{_h(scenario.scenario_id)}</h2>\n"
            f"<span class='badge {st_cls}'>{_h(status_text)}</span>\n"
            f"<span class='cat-name'>{_h(cat_name)} — {_h(scenario.scenario_name)}</span>\n"
            f"</div>\n"
            f"<div style='margin-top:8px'>{steps_html}</div>\n"
            f"</div>\n"
        )

    def _render_step(self, step: ScenarioStep) -> str:
        step_cls = "step-pass" if step.passed else "step-fail"
        icon = "✓" if step.passed else "✗"
        resp_html = ""
        if not step.passed and step.response_summary:
            resp_html = f"<div class='step-resp'>{_h(step.response_summary)}</div>\n"
        return (
            f"<div class='step'>\n"
            f"<span class='{step_cls}'>{icon} Step {step.index}: {_h(step.description)}</span>\n"
            f"{resp_html}"
            f"</div>\n"
        )

    def _render_references(self, references: tuple) -> str:
        parts: list[str] = []
        for ref in references:
            safe = _safe_url(str(ref))
            if safe is not None:
                parts.append(
                    f'<a href="{_h(safe)}" rel="noopener noreferrer">{_h(safe)}</a>'
                )
            else:
                parts.append(_h(str(ref)))
        return " · ".join(parts)
