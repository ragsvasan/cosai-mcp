# cosai-mcp — Value Proposition and Competitive Positioning

*Last updated: 2026-04-27. Based on landscape survey conducted April 2026.*

---

## The Problem

MCP servers are becoming load-bearing infrastructure for AI agents — they control file systems, databases, APIs, and code execution. Yet the security tooling ecosystem has a structural gap: everything that exists either reads static files before deployment or monitors live traffic passively. Nobody probes a running server the way a penetration tester would.

The CoSAI/OASIS January 2026 whitepaper identified 12 threat categories for MCP. It shipped zero runnable code.

---

## The Genuine Gap

Three capabilities do not exist in any single tool:

**1. Runtime black-box JSON-RPC probing**
Every scanner on the market is either static (reads code/JSON definitions) or a behavioral proxy (intercepts live traffic). No tool sends crafted JSON-RPC requests to a running MCP server to discover vulnerabilities through protocol interaction. This means: batch request amplification, method enumeration, error information disclosure, authentication bypass — all untested by any existing tool.

**2. Stateful multi-turn conformance harness**
MCP security vulnerabilities that only manifest across multiple calls — confused deputy attacks, privilege escalation chains, session token binding failures, tool manifest drift — cannot be detected by one-shot probes. MCPSafetyScanner (academic) approaches this with LLM-generated adversarial samples, but LLM-generated tests are non-deterministic and not CI-reproducible. No tool has a declarative, repeatable multi-turn harness.

**3. All 12 CoSAI categories in one CI gate**
Every existing tool covers 1–3 threat categories. Snyk Agent Scan has the best CI integration but only for its own subset of risks. No tool provides a single pass/fail verdict covering the full CoSAI taxonomy with a standardized exit code contract.

**The triangle nobody has:** CoSAI taxonomy + black-box probing + stateful harness + CI gate.

---

## Landscape Survey (April 2026)

### Static Scanners — Strong, Don't Compete Here

| Tool | What it actually does | Coverage | CI gate |
|------|----------------------|----------|---------|
| **Cisco MCP Scanner** | YARA rules + LLM-as-judge on tool definitions, code, dependencies | Malware patterns, injection templates; not behavioral | JSON file ingestion only |
| **Snyk Agent Scan** | Static analysis + runtime proxy; 15+ specific risks | Tool poisoning, toxic flows; not protocol conformance | ✅ Snyk Studio |
| **Enkrypt AI MCP Scan** | Agentic code + dependency analysis; found 26 vulns in one server | Code injection, path traversal; code-level | Varies |
| **MCPScan.ai** | Pattern matching on tool descriptions + LLM guardrails | Tool poisoning, confused deputy patterns; not live | None |
| **Proximity** | Pattern matching (NOVA rules) + LLM semantic analysis | Jailbreak keywords, content-level; not protocol | None |

**Verdict:** Excellent at what they do. cosai-mcp is a complement, not a competitor — run them before deploy, run cosai-mcp against the running server.

### Runtime Tools — Different Mechanism Class

| Tool | What it actually does | Coverage |
|------|----------------------|----------|
| **MCP-Bastion** | Drop-in middleware wrapping Python/TS servers; PromptGuard + Presidio | Runtime enforcement, not vulnerability discovery |
| **MCPProxy-go** | Routing proxy with BM25 filtering, quarantine, credential detection | Monitoring/observability, not probing |

**Verdict:** These live in production alongside the server. cosai-mcp runs in CI before the server reaches production.

### Academic / Research

| Tool | What it actually does | Limitations |
|------|----------------------|-------------|
| **MCPSafetyScanner** | LLM agents generate adversarial samples | Non-deterministic, not CI-reproducible, not CoSAI-mapped |
| **AgentRFC / AgentConform** | Formal TLA+ conformance checking | Research prototype, not production |
| **MCP-DPT** | Defense placement taxonomy (paper) | No runnable code |

### Complementary: Code Generation Guidance

| Tool | What it is | Relationship |
|------|-----------|-------------|
| **CoSAI Project CodeGuard** (v1.3.1, Apr 2026) | OASIS Open Project — injects secure-by-default rules into AI coding agent workflows (planning → generation → review). Covers 8 domains: auth, input validation, supply chain, crypto, cloud, session, data protection, API security. Ships an MCP server for centralized org deployment. Apache/CC-BY-4.0. | **Write-time complement.** CodeGuard tells the AI agent how to write secure MCP server code. cosai-mcp tests whether the shipped code is actually secure at runtime. Run CodeGuard in the IDE; run cosai-mcp in CI. |

### Standards / Frameworks (No Runnable Code)

| Framework | What it is |
|-----------|-----------|
| **CoSAI/OASIS whitepaper** (Jan 2026) | 12 threat categories — defines the taxonomy cosai-mcp implements. Zero code shipped. |
| **OWASP MCP Top 10** | 10 MCP-specific protocol risks (A01–A12), references "mcp-attack-labs" repo. No standalone scanner. |
| **OWASP Agentic Security Initiative (ASI) Top 10** | 10 agentic AI risks (ASI01–ASI10) — broader than MCP, covers memory poisoning (ASI04), tool misuse (ASI02), unsafe output (ASI03). No scanner. cosai-mcp maps to 9/10 items; ASI04 multi-agent state is partially out of MCP-layer scope. |
| **MITRE ATLAS** | Adversarial Threat Landscape for AI Systems — real-world adversarial ML attack patterns. No MCP-specific scanner. cosai-mcp probe IDs map to ATLAS technique IDs in SARIF output. |
| **CSA AI Controls Matrix** | 243 AI security controls across 17 domains. No automated enforcement tool. cosai-mcp provides runnable evidence for the tool-access and audit-logging control families. |
| **MCP Server Security Standard (MSSS)** | 4 conformance levels with testable evidence requirements. No automated tool. |

---

## Full Capability Matrix

| Tool | Runtime black-box probing | Multi-turn stateful testing | All 12 CoSAI categories | CI/CD gate |
|------|:-------------------------:|:---------------------------:|:-----------------------:|:----------:|
| Cisco MCP Scanner | ❌ | ❌ | ❌ | ⚠️ |
| Snyk Agent Scan | ❌ | ❌ | ❌ | ✅ |
| Enkrypt AI | ❌ | ❌ | ❌ | ⚠️ |
| MCPScan.ai | ❌ | ❌ | ❌ | ❌ |
| Proximity | ❌ | ❌ | ❌ | ❌ |
| MCPSafetyScanner | ⚠️ LLM-based | ⚠️ LLM-based | ⚠️ partial | ❌ |
| MCP-Bastion | ❌ enforcement | ❌ | ❌ | ❌ |
| MCPProxy-go | ❌ monitoring | ❌ | ❌ | ❌ |
| CoSAI / OWASP / MSSS | ❌ docs | ❌ | ✅ defines | ❌ |
| **cosai-mcp** | **✅** | **✅** | **✅** | **✅** |

---

## cosai-mcp Unique Value

**For security engineers:**
Run `cosai scan https://my-mcp-server` and get a SARIF report in GitHub's native security tab — covering all 12 CoSAI categories — without reading any code or deploying any proxy.

**For platform teams:**
Drop `uses: cosai-mcp/scan-action@<SHA>` into CI. Exit code 1 = findings above threshold, exit code 2 = scanner error (treated as failure, never silent). The gate is fail-closed by design.

**For compliance:**
Every finding maps to ISO 27001:2022, NIST AI RMF 2026, and OWASP MCP Top 10 in the report. SARIF output integrates with GitHub Advanced Security, Semgrep, and any SIEM that ingests SARIF.

**For MCP server authors:**
The pytest plugin (`--cosai-target`, `--cosai-severity`) runs conformance checks as part of the normal test suite. No separate tool, no separate CI job.

---

## Three-Engine Architecture — Why It Matters

Black-box probing is structurally wrong for three categories (T4 tool poisoning, T9 trust boundary, T12 audit logging). Detection requires being in the call path. cosai-mcp ships three engines, each the right mechanism class for its category:

| Engine | Categories | Why this mechanism |
|--------|-----------|-------------------|
| Black-box prober | T1, T3, T8, T10, partial T2/T6/T11 | One-shot JSON-RPC probes; no server-side cooperation needed |
| Stateful conformance harness | T2, T6, T7 | Multi-turn session; full `initialize` + scripted scenarios |
| Middleware instrumentation | T4, T9, T12 | Must be in the call path; middleware IS the test |

Existing tools have only one engine class (static or proxy). The three-engine split is what enables full CoSAI coverage.

---

## Positioning Statement

cosai-mcp is the reference implementation of the CoSAI MCP security taxonomy — the first tool that tests a running MCP server against all 12 threat categories using the right mechanism for each one. Static scanners test what you wrote. cosai-mcp tests what you shipped.

---

## Recommended Scanning Workflow

cosai-mcp is a runtime tool. It belongs at the end of the pipeline, after static scanners have already run on source. The full defense-in-depth stack:

```
─── Development ───────────────────────────────────────────────────────────────

  1. IDE / pre-commit
     └── Snyk Agent Scan or Enkrypt AI
         Catches: injection patterns, dependency CVEs, tool description anomalies
         in source code before anything is committed.

─── CI (pull request) ─────────────────────────────────────────────────────────

  2. Static scan job (runs on every PR)
     └── Cisco MCP Scanner  →  fails PR on critical malware / injection templates
     └── Snyk Agent Scan    →  fails PR on known CVEs in dependencies

  3. Conformance scan job (runs on every PR, against a test instance)
     └── cosai-mcp scan $TEST_MCP_URL --fail-on critical
         Catches: auth bypass, session fixation, access-control failures,
         tool shadowing, resource exhaustion — things static analysis cannot see
         because they require a running server.

─── Pre-production (staging gate) ────────────────────────────────────────────

  4. Full conformance scan (all categories, all severities)
     └── cosai-mcp scan $STAGING_URL --categories all --engine all
         Generates: SARIF report → GitHub security tab
                    HTML report  → audit artifact
                    Signed report → cosai audit verify

─── Production ────────────────────────────────────────────────────────────────

  5. Runtime monitoring (always-on, passive)
     └── MCPProxy-go or MCP-Bastion
         Catches: runtime anomalies, credential leakage in live traffic,
         rate-limit violations — things that only appear under real load.
```

**Why this order matters:**
- Static scanners are fast (seconds) and cheap — run them first to catch the easy stuff.
- cosai-mcp is slower (it talks to a live server) — run it against a real instance, not source.
- Runtime monitors see production traffic — they catch what slips through CI.

**GitHub Actions example:**
```yaml
jobs:
  static-scan:
    steps:
      - uses: snyk/actions/node@master
        with: { args: --severity-threshold=high }

  conformance-scan:
    needs: static-scan          # only run if static scan passes
    services:
      mcp-server:
        image: ${{ env.MCP_IMAGE }}
        ports: ["8000:8000"]
    steps:
      - uses: cosai-mcp/scan-action@<COMMIT_SHA>
        with:
          target: http://localhost:8000
          fail_on: high
          engine: all
```

---

## What cosai-mcp Does NOT Do (Be Honest)

- **No static code analysis.** Use Cisco MCP Scanner or Enkrypt AI before deploy.
- **No production traffic monitoring.** Use MCPProxy-go or MCP-Bastion for runtime.
- **No LLM-semantic judgment.** Probes are deterministic; they test protocol behavior, not content quality.
- **No vulnerability in third-party MCP servers is exploited.** The scanner probes and reports; it does not weaponize.

---

## Sources

- [CoSAI/OASIS MCP Security Whitepaper](https://www.oasis-open.org/2026/01/27/coalition-for-secure-ai-releases-extensive-taxonomy-for-model-context-protocol-security/) (Jan 2026)
- [CoSAI ws4 GitHub — model-context-protocol-security.md](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md)
- [CoSAI Practical MCP Security Guide](https://www.coalitionforsecureai.org/securing-the-ai-agent-revolution-a-practical-guide-to-mcp-security/)
- [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner)
- [Snyk Agent Scan](https://github.com/snyk/agent-scan)
- [Proximity](https://github.com/fr0gger/proximity)
- [MCPSafetyScanner](https://arxiv.org/abs/2504.03767)
- [Adversa AI — Top 25 MCP Vulnerabilities](https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [OWASP Agentic Security Initiative (ASI) Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS](https://atlas.mitre.org)
- [CSA AI Controls Matrix](https://cloudsecurityalliance.org/research/working-groups/artificial-intelligence)
- [CSA Agentic AI NIST RMF Profile v1](https://labs.cloudsecurityalliance.org/agentic/agentic-nist-ai-rmf-profile-v1/)
- [MCP Server Security Standard](https://github.com/mcp-security-standard/mcp-server-security-standard)
- [AgentRFC conformance paper](https://arxiv.org/abs/2603.23801)
- [MCP-DPT defense placement taxonomy](https://arxiv.org/abs/2604.07551)
- [MCPProxy-go](https://github.com/smart-mcp-proxy/mcpproxy-go)
- [MCP-Bastion](https://github.com/vaquarkhan/MCP-Bastion)
- [Berkeley CLTC — Agentic AI Risk Profile](https://cltc.berkeley.edu/publication/agentic-ai-risk-profile/)
- [Vectra AI — Agentic AI Security / OWASP ASI analysis](https://www.vectra.ai/topics/agentic-ai-security)
