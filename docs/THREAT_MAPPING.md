# Threat Category Mapping

Cross-reference of CoSAI T1–T12 against NIST AI RMF (2026 Critical Infrastructure Profile), OWASP MCP Top 10, and CWE. Compliance mapping is scoped to **CoSAI + NIST AI RMF** as the primary frameworks; OWASP MCP Top 10 and CWE are retained because they are carried directly in the signed threat catalog.

Use this table for compliance evidence, vendor questionnaires, and procurement assessments.

---

## Cross-Reference Table

| CoSAI | Category Name | NIST AI RMF (2026) | NIST AG-MP.1 Tool Class | OWASP MCP Top 10 | CWE | CoSAI Risk Map |
|-------|--------------|-------------------|------------------------|-----------------|-----|---------------|
| **T1** | Improper Authentication | MANAGE 1.1 Risk Response, GOVERN 6.2 Accountability | All classes (identity gate) | A01: Broken Authentication | CWE-287, CWE-306, CWE-384 | Critical: Contextualized |
| **T2** | Missing Access Control | MANAGE 1.1 Risk Response, MAP 1.1 System Context | Execute-class (HITL required) | A02: Broken Access Control | CWE-285, CWE-732, CWE-269 | Critical: Contextualized |
| **T3** | Input Validation Failures | GOVERN 1.2 Accountability, MEASURE 2.1 Assessment | Write + Execute classes | A03: Injection Attacks | CWE-78, CWE-22, CWE-89, CWE-943 | High: Traditional Amplified |
| **T4** | Data/Control Boundary | GOVERN 1.2, MAP 1.1 System Context | All classes (data ingestion) | A04: Prompt Injection | CWE-74, CWE-77, CWE-116 | High: Novel Vector |
| **T5** | Inadequate Data Protection | MAP 1.1, MEASURE 2.6 Data Quality | Read + Write classes | A05: Sensitive Data Exposure | CWE-200, CWE-312, CWE-311 | High: Traditional Amplified |
| **T6** | Integrity/Verification | MAP 4.1 Third-party Risks, MANAGE 2.2 | All classes (manifest trust) | A06: Integrity Failures | CWE-345, CWE-494, CWE-1357 | Critical: Supply Chain |
| **T7** | Session Security Failures | MAP 1.1 System Context, MANAGE 1.1 | All classes (session binding) | A07: Session Management | CWE-384, CWE-287, CWE-295 | Medium: Protocol Gap |
| **T8** | Network Binding Failures | MEASURE 2.1 Security Assessment | Read class (network reach) | A08: Network Exposure | CWE-668, CWE-441, CWE-918 | High: Traditional Amplified |
| **T9** | Trust Boundary Failures | GOVERN 1.2, MAP 1.1 | Execute-class (HITL gate) | A09: Overreliance on AI | CWE-602, CWE-807 | High: Novel Vector |
| **T10** | Resource Management | MEASURE 2.1, MANAGE 2.4 | Execute-class (cost amplification) | A10: Resource Exhaustion | CWE-400, CWE-770, CWE-834 | High: Traditional Amplified |
| **T11** | Supply Chain/Lifecycle | MAP 4.1 Third-party Risks | All classes (installation time) | A11: Supply Chain | CWE-494, CWE-1357, CWE-693 | Critical: Supply Chain |
| **T12** | Insufficient Logging | MEASURE 1.1 Performance Monitoring | Execute-class (accountability) | A12: Insufficient Logging | CWE-778, CWE-223, CWE-532 | High: Visibility Gap |

---

## NIST AG-MP.1 Tool Risk Classification Detail

The **AG-MP.1** subcategory (Agent Tool Risk Classification) is the 2026 NIST AI RMF addition most directly relevant to MCP. It classifies tools into three risk levels and mandates different control requirements for each.

| Tool Class | Examples | AG-MP.1 Risk | cosai-mcp control |
|-----------|----------|-------------|------------------|
| **Read-only** | `tools/list`, `read_file`, `search` | Low | T1 auth probes; T3 input validation |
| **Write** | `write_file`, `update_record`, `send_draft` | Medium | T2 RBAC; T3 injection; T5 PII scrub before write |
| **Execute** | `run_command`, `send_email`, `delete_record`, `deploy` | High | T2 RBAC + HITL gate; T9 deterministic validation (not LLM judgment); T12 audit trace |

**HITL requirement for Execute-class tools:** AG-MP.1 mandates human-in-the-loop approval for high-consequence Execute-class actions. cosai-mcp's T9 middleware enforces that this gate is deterministic (schema-based), not model-delegated. The T2 stateful harness tests that a server correctly enforces the Execute-class boundary across a multi-turn session.

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

## OWASP Agentic Security Initiative (ASI) Top 10

The OWASP ASI Top 10 covers risks specific to agentic AI systems — broader than MCP protocol risks. cosai-mcp's three-engine architecture maps onto it as follows:

| OWASP ASI | Title | CoSAI category | cosai-mcp coverage |
|-----------|-------|---------------|-------------------|
| ASI01 | Prompt Injection | T4 | Middleware instrumentation |
| ASI02 | Excessive Agency / Tool Misuse | T2 | Stateful harness (T2-SC-001, T2-SC-002) |
| ASI03 | Unsafe Output Handling | T9 | Middleware instrumentation |
| ASI04 | Memory Poisoning | T4/T9 | Partial — MCP-layer context injection probed; cross-agent state out of scope |
| ASI05 | Insecure Tool Design | T3/T4 | Black-box probe suite |
| ASI06 | Sensitive Information Disclosure | T5 | Middleware instrumentation |
| ASI07 | Inadequate Code Execution Control | T3 | Black-box probe suite |
| ASI08 | Broken Authentication / Authorization | T1/T2 | Black-box + stateful |
| ASI09 | Insecure Plugin / Supply Chain | T11 | Black-box (partial) |
| ASI10 | Insufficient Logging and Monitoring | T12 | Middleware instrumentation |

Note: ASI04 (memory poisoning via multi-agent feedback loops) is partially out of scope for MCP middleware — cross-agent state poisoning requires host-level instrumentation beyond what the MCP transport layer can observe.

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
