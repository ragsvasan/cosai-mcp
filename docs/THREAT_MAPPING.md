# Threat Category Mapping

Cross-reference of CoSAI T1–T12 against ISO 27001:2022, NIST AI RMF (2026 Critical Infrastructure Profile), OWASP MCP Top 10, and CWE.

Use this table for compliance evidence, vendor questionnaires, and procurement assessments.

---

## Cross-Reference Table

| CoSAI | Category Name | ISO 27001:2022 Annex A | NIST AI RMF (2026) | OWASP MCP Top 10 | CWE | CoSAI Risk Map |
|-------|--------------|----------------------|-------------------|-----------------|-----|---------------|
| **T1** | Improper Authentication | A.5.15 Access Control, A.5.17 Authentication | MANAGE 1.1 Risk Response, GOVERN 6.2 Accountability | A01: Broken Authentication | CWE-287, CWE-306, CWE-384 | Critical: Contextualized |
| **T2** | Missing Access Control | A.5.15 Access Control, A.5.18 Access Rights | MANAGE 1.1 Risk Response, MAP 1.1 System Context | A02: Broken Access Control | CWE-285, CWE-732, CWE-269 | Critical: Contextualized |
| **T3** | Input Validation Failures | A.8.25 Secure Development, A.8.29 Security Testing | GOVERN 1.2 Accountability, MEASURE 2.1 Assessment | A03: Injection Attacks | CWE-78, CWE-22, CWE-89, CWE-943 | High: Traditional Amplified |
| **T4** | Data/Control Boundary | A.8.25 Secure Development, A.8.29 Security Testing | GOVERN 1.2, MAP 1.1 System Context | A04: Prompt Injection | CWE-74, CWE-77, CWE-116 | High: Novel Vector |
| **T5** | Inadequate Data Protection | A.8.10 Information Deletion, A.8.11 Data Masking | MAP 1.1, MEASURE 2.6 Data Quality | A05: Sensitive Data Exposure | CWE-200, CWE-312, CWE-311 | High: Traditional Amplified |
| **T6** | Integrity/Verification | A.8.25 Secure Development, A.5.21 ICT Supply Chain | MAP 4.1 Third-party Risks, MANAGE 2.2 | A06: Integrity Failures | CWE-345, CWE-494, CWE-1357 | Critical: Supply Chain |
| **T7** | Session Security Failures | A.8.10 Information Isolation, A.5.15 Access Control | MAP 1.1 System Context, MANAGE 1.1 | A07: Session Management | CWE-384, CWE-287, CWE-295 | Medium: Protocol Gap |
| **T8** | Network Binding Failures | A.8.1 User Endpoint Devices, A.8.22 Network Segregation | MEASURE 2.1 Security Assessment | A08: Network Exposure | CWE-668, CWE-441, CWE-918 | High: Traditional Amplified |
| **T9** | Trust Boundary Failures | A.8.25 Secure Development, A.5.36 Compliance | GOVERN 1.2, MAP 1.1 | A09: Overreliance on AI | CWE-602, CWE-807 | High: Novel Vector |
| **T10** | Resource Management | A.8.6 Capacity Management | MEASURE 2.1, MANAGE 2.4 | A10: Resource Exhaustion | CWE-400, CWE-770, CWE-834 | High: Traditional Amplified |
| **T11** | Supply Chain/Lifecycle | A.5.21 ICT Supply Chain, A.8.30 Outsourced Dev | MAP 4.1 Third-party Risks | A11: Supply Chain | CWE-494, CWE-1357, CWE-693 | Critical: Supply Chain |
| **T12** | Insufficient Logging | A.8.15 Logging, A.8.16 Monitoring | MEASURE 1.1 Performance Monitoring | A12: Insufficient Logging | CWE-778, CWE-223, CWE-532 | High: Visibility Gap |

---

## ISO 27001:2022 Control Mapping Detail

For each ISO 27001 control referenced above, how cosai-mcp addresses it:

| ISO 27001 Control | cosai-mcp Coverage |
|------------------|--------------------|
| **A.5.15** Access Control | T1 probes test authentication enforcement; T2 stateful harness tests authorization per tool call |
| **A.5.17** Authentication Information | T1 probes test token replay, cross-session reuse, DPoP binding |
| **A.5.18** Access Rights | T2 confused deputy detection; middleware RBAC enforcement |
| **A.5.21** ICT Supply Chain | T11 probes: typosquatting detection, unsigned tool definitions; Ed25519 signing of catalog |
| **A.8.1** User Endpoint Devices | T8 probes: bind address detection, shadow server detection |
| **A.8.6** Capacity Management | T10 probes: rate limit testing, response size limits, heartbeat detection |
| **A.8.10** Information Isolation | T7 stateful harness: session isolation, context-bleed detection |
| **A.8.11** Data Masking | T5 middleware: PII scrubbing, credential pattern detection |
| **A.8.15** Logging | T12 middleware: hash-chained execution trace, `cosai audit verify` |
| **A.8.16** Monitoring | T12 middleware: real-time boundary violation alerting |
| **A.8.22** Network Segregation | T8 probes: SSRF detection; scanner network allowlist (defense-in-depth) |
| **A.8.25** Secure Development | T3 probes: injection testing; T4 boundary enforcement; SARIF output validation |
| **A.8.29** Security Testing | Full test suite; SARIF output for integration with security tooling |

---

## NIST AI RMF 2026 Critical Infrastructure Profile

The 2026 NIST AI RMF Profile for Critical Infrastructure introduces the **AG-MP.1** subcategory for "Agent Tool Risk Classification." cosai-mcp aligns:

### AG-MP.1 Tool Risk Classification

| Tool Class | AG-MP.1 Risk Level | cosai-mcp enforcement |
|-----------|------------------|----------------------|
| Read-only tools (`tools/list`, `read_file`) | Low | T1 probes verify auth; T2 probes verify access control |
| Write tools (`write_file`, `update_record`) | Medium | T2 probes test confused deputy; stateful harness tests multi-turn escalation |
| Execute tools (`run_command`, `send_email`, `delete_record`) | High | T2 RBAC enforcement; HITL approval gate in middleware |

### GOVERN 1.2 — Accountability Structures
cosai-mcp's execution trace (T12) provides the causal chain required for accountability: prompt → context retrieved → tool call → result, with cryptographic integrity.

### MANAGE 1.1 — Risk Response
T1–T12 probes produce structured findings mapped to remediation guidance. SARIF output integrates into existing risk management workflows via GitHub Security tab.

### MEASURE 2.1 — Security Assessment
cosai-mcp is a continuous measurement tool. Scheduled scans (via GitHub Action or cron) provide ongoing assessment against the 12-category framework.

### MAP 4.1 — Third-party Risks
T11 probes specifically address third-party MCP server risk: typosquatting detection, unsigned tool definitions, and tool list anomaly detection when using external MCP servers.

---

## OWASP MCP Top 10 Alignment

cosai-mcp probes provide runnable test coverage for each OWASP MCP Top 10 item:

| OWASP MCP | Title | cosai-mcp coverage | Engine |
|-----------|-------|-------------------|--------|
| A01 | Broken Authentication | T1 probe suite | Black-box |
| A02 | Broken Access Control | T2 probe suite + stateful harness | Stateful |
| A03 | Injection Attacks | T3 probe suite | Black-box |
| A04 | Prompt Injection | T4 middleware | Middleware |
| A05 | Sensitive Data Exposure | T5 middleware | Middleware |
| A06 | Security Misconfiguration / Integrity | T6 probe suite + stateful harness | Both |
| A07 | Identification and Authentication Failures | T7 stateful harness | Stateful |
| A08 | Software and Data Integrity | T8 probe suite | Black-box |
| A09 | Security Logging and Monitoring | T12 middleware | Middleware |
| A10 | Server-Side Request Forgery | T8 SSRF probes | Black-box |
| A11 | Supply Chain | T11 probe suite | Black-box (partial) |
| A12 | Insufficient Logging | T12 middleware | Middleware |

---

## EU AI Act Alignment

For teams subject to the EU AI Act, cosai-mcp's execution traces (T12) directly support **Article 13 (Transparency)** and **Article 17 (Quality Management System)** requirements.

The hash-chained audit log provides:
- Immutable record of all tool invocations (Article 13: traceability)
- Tamper-evident evidence of system behavior (Article 17: quality management)
- Attribution chain from user instruction to agent action (Article 22: human oversight)

The `cosai audit verify` command produces verification evidence suitable for submission to a conformity assessment body.

---

## SOC 2 Type II Alignment

cosai-mcp supports evidence collection for SOC 2 Trust Service Criteria:

| TSC | Criterion | cosai-mcp evidence |
|-----|-----------|-------------------|
| CC6.1 | Logical access controls | T1/T2 scan reports; finding-free SARIF |
| CC6.3 | Access management | T2 RBAC enforcement; confused deputy findings |
| CC6.7 | Transmission of sensitive information | T5/T7 findings; session security reports |
| CC7.2 | Monitoring | T12 audit log; scheduled scan reports |
| CC8.1 | Change management | T6 tool manifest baseline diff; rug pull detection |
| CC9.2 | Vendor risk | T11 supply chain findings; third-party MCP server scans |

Weekly scheduled scans producing signed reports constitute continuous monitoring evidence for CC7.2.
