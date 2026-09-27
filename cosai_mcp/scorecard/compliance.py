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

2026-09-27 (CoSAI MCP Security v2.0 alignment): the OWASP references are the
official OWASP MCP Top 10 (2025) IDs and titles (MCP01:2025 … MCP10:2025),
mapped per CoSAI MCP Security v2.0 §3.3.3 "Threat Coverage Summary". The
earlier "A01…A12" labels were not OWASP's identifiers. T10 has no OWASP MCP
Top 10 counterpart in the CoSAI table and is left honestly unmapped.
"""
from __future__ import annotations

from cosai_mcp.scorecard.models import ComplianceMapping

CATEGORY_COMPLIANCE_MAP: dict[str, ComplianceMapping] = {
    "T1": ComplianceMapping(
        owasp_mcp_top10="MCP01:2025 Token Mismanagement & Secret Exposure; MCP07:2025 Insufficient Authentication & Authorization",
        nist_ai_rmf=("MANAGE 1.1 Risk Response", "GOVERN 6.2 Accountability"),
    ),
    "T2": ComplianceMapping(
        owasp_mcp_top10="MCP02:2025 Privilege Escalation via Scope Creep; MCP07:2025 Insufficient Authentication & Authorization",
        nist_ai_rmf=("MANAGE 1.1 Risk Response", "MAP 1.1 System Context"),
    ),
    "T3": ComplianceMapping(
        owasp_mcp_top10="MCP03:2025 Tool Poisoning; MCP05:2025 Command Injection & Execution; MCP06:2025 Prompt Injection via Contextual Payloads",
        nist_ai_rmf=("GOVERN 1.2 Accountability", "MEASURE 2.1 Assessment"),
    ),
    "T4": ComplianceMapping(
        owasp_mcp_top10="MCP03:2025 Tool Poisoning; MCP06:2025 Prompt Injection via Contextual Payloads",
        nist_ai_rmf=("GOVERN 1.2", "MAP 1.1 System Context"),
    ),
    "T5": ComplianceMapping(
        owasp_mcp_top10="MCP10:2025 Context Injection & Over-Sharing",
        nist_ai_rmf=("MAP 1.1", "MEASURE 2.6 Data Quality"),
    ),
    "T6": ComplianceMapping(
        owasp_mcp_top10="MCP03:2025 Tool Poisoning; MCP04:2025 Software Supply Chain Attacks & Dependency Tampering",
        nist_ai_rmf=("MAP 4.1 Third-party Risks", "MANAGE 2.2"),
    ),
    "T7": ComplianceMapping(
        owasp_mcp_top10="MCP01:2025 Token Mismanagement & Secret Exposure",
        nist_ai_rmf=("MAP 1.1 System Context", "MANAGE 1.1"),
    ),
    "T8": ComplianceMapping(
        owasp_mcp_top10="MCP09:2025 Shadow MCP Servers",
        nist_ai_rmf=("MEASURE 2.1 Security Assessment",),
    ),
    "T9": ComplianceMapping(
        owasp_mcp_top10="MCP02:2025 Privilege Escalation via Scope Creep",
        nist_ai_rmf=("GOVERN 1.2", "MAP 1.1"),
    ),
    "T10": ComplianceMapping(
        owasp_mcp_top10="Not mapped in OWASP MCP Top 10 (CoSAI MCP Security v2.0 §3.3.3)",
        nist_ai_rmf=("MEASURE 2.1", "MANAGE 2.4"),
    ),
    "T11": ComplianceMapping(
        owasp_mcp_top10="MCP04:2025 Software Supply Chain Attacks & Dependency Tampering",
        nist_ai_rmf=("MAP 4.1 Third-party Risks",),
    ),
    "T12": ComplianceMapping(
        owasp_mcp_top10="MCP08:2025 Lack of Audit and Telemetry",
        nist_ai_rmf=("MEASURE 1.1 Performance Monitoring",),
    ),
}
