"""CoSAI category -> compliance-framework control mapping.

ENT-P0-3 (docs/ENTERPRISE_REQUIREMENTS_2026-07-01.md): the signed scorecard
must carry each category's CoSAI + OWASP MCP Top 10 + NIST AI RMF control
mapping *inside the signed payload* — not as a prose claim in a doc, and not
as an owasp_ref buried in the unsigned SARIF (FABLE_AUDIT_2026-07-01 FIND
6/18).

Panel-review finding (ENT-P0-3 review): the OWASP MCP Top 10 titles here
must match docs/THREAT_MAPPING.md's "## OWASP MCP Top 10 Alignment" table
specifically — that is the table cosai_mcp/report/sarif.py's `helpUri`
links to, so it is the tool's own authoritative OWASP alignment. (An
earlier revision of this file copied THREAT_MAPPING.md's *other* table,
the Cross-Reference Table, which used different, CoSAI-relabeled titles for
T6-T10/T12 that never matched the SARIF-linked table — an already-signed
attestation that contradicted the tool's own SARIF output. Both doc tables
have since been reconciled; test_compliance_map_matches_owasp_alignment_table
in tests/scorecard/test_scorecard.py enforces they stay that way.)

T9 and T10 have no distinct 1:1 OWASP MCP Top 10 item in that table — A09
(Security Logging) and A12 both map to T12, and A10 (SSRF) maps to T8, so
T9/T10 are left honestly unmapped rather than assigned an invented title.
"""
from __future__ import annotations

from cosai_mcp.scorecard.models import ComplianceMapping

CATEGORY_COMPLIANCE_MAP: dict[str, ComplianceMapping] = {
    "T1": ComplianceMapping(
        owasp_mcp_top10="A01: Broken Authentication",
        nist_ai_rmf=("MANAGE 1.1 Risk Response", "GOVERN 6.2 Accountability"),
    ),
    "T2": ComplianceMapping(
        owasp_mcp_top10="A02: Broken Access Control",
        nist_ai_rmf=("MANAGE 1.1 Risk Response", "MAP 1.1 System Context"),
    ),
    "T3": ComplianceMapping(
        owasp_mcp_top10="A03: Injection Attacks",
        nist_ai_rmf=("GOVERN 1.2 Accountability", "MEASURE 2.1 Assessment"),
    ),
    "T4": ComplianceMapping(
        owasp_mcp_top10="A04: Prompt Injection",
        nist_ai_rmf=("GOVERN 1.2", "MAP 1.1 System Context"),
    ),
    "T5": ComplianceMapping(
        owasp_mcp_top10="A05: Sensitive Data Exposure",
        nist_ai_rmf=("MAP 1.1", "MEASURE 2.6 Data Quality"),
    ),
    "T6": ComplianceMapping(
        owasp_mcp_top10="A06: Security Misconfiguration / Integrity",
        nist_ai_rmf=("MAP 4.1 Third-party Risks", "MANAGE 2.2"),
    ),
    "T7": ComplianceMapping(
        owasp_mcp_top10="A07: Identification and Authentication Failures",
        nist_ai_rmf=("MAP 1.1 System Context", "MANAGE 1.1"),
    ),
    "T8": ComplianceMapping(
        owasp_mcp_top10="A08: Software and Data Integrity; A10: Server-Side Request Forgery",
        nist_ai_rmf=("MEASURE 2.1 Security Assessment",),
    ),
    "T9": ComplianceMapping(
        owasp_mcp_top10="Not independently mapped in OWASP MCP Top 10 (see NIST AI RMF)",
        nist_ai_rmf=("GOVERN 1.2", "MAP 1.1"),
    ),
    "T10": ComplianceMapping(
        owasp_mcp_top10="Not independently mapped in OWASP MCP Top 10 (see NIST AI RMF)",
        nist_ai_rmf=("MEASURE 2.1", "MANAGE 2.4"),
    ),
    "T11": ComplianceMapping(
        owasp_mcp_top10="A11: Supply Chain",
        nist_ai_rmf=("MAP 4.1 Third-party Risks",),
    ),
    "T12": ComplianceMapping(
        owasp_mcp_top10="A09: Security Logging and Monitoring; A12: Insufficient Logging",
        nist_ai_rmf=("MEASURE 1.1 Performance Monitoring",),
    ),
}
