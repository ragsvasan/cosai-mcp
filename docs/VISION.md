# cosai-mcp — Vision, Why & Use Cases

## The Problem

The Model Context Protocol (MCP) is becoming the nervous system of enterprise AI. Every agentic workflow — code assistants, data pipelines, autonomous decision agents — runs through MCP to reach tools, databases, and external services. That makes MCP the single most consequential attack surface in the agentic enterprise.

The security community responded with documents. OWASP published a Top 10 list. CoSAI published a 12-category taxonomy. NIST published a risk profile. All of them are excellent. None of them are runnable.

Meanwhile, the few code tools that exist are narrow:
- **MCP-Bastion**: middleware only, covers ~2 of 12 threat categories
- **Cisco MCP Scanner**: static analysis only, no runtime enforcement
- **mcp-authx**: OAuth plumbing only, nothing beyond authentication

The result: every team building on MCP is implementing security controls from scratch, inconsistently, with no way to verify they work.

## What cosai-mcp Is

`cosai-mcp` is the **reference implementation** of MCP security — the runnable code that the documents assumed would exist.

It ships three things:

**1. An exhaustive black-box test suite**
Point it at any MCP server — in any language, on any framework — and it tells you which of the 12 CoSAI threat categories you are exposed to. No installation required on the target. No agent. No SDK. Just an HTTP endpoint.

**2. A composable Python middleware stack**
Drop `CoSAIStack` into any FastAPI or FastMCP server and get all 12 controls enforced at runtime. One import, one middleware registration.

**3. A JSON-extensible threat catalog**
New vulnerability discovered? Add a JSON file. Existing threat updated? Edit a JSON file. No code changes, no releases required. The catalog is cryptographically signed — new definitions are trusted only when signed by the project keypair.

## Why No Existing Tool Fills This Gap

The MCP security tooling landscape falls into two categories: static scanners (Cisco, Snyk, Enkrypt) that read what you wrote before deployment, and runtime proxies (MCP-Bastion, MCPProxy-go) that monitor live production traffic. Neither answers the question in between: *what does your running server actually accept?*

Three capabilities exist in no single tool today:

- **Runtime black-box JSON-RPC probing.** No existing scanner sends crafted protocol-level requests to a live server. Batch request amplification, method enumeration, authentication bypass, error information disclosure — none are detectable from static analysis or traffic interception.
- **Stateful multi-turn conformance.** Confused deputy attacks, session token drift, and privilege escalation chains only surface across sequential requests. One-shot probes miss them structurally.
- **Full CoSAI T1–T12 in a single CI gate.** Every existing tool covers 1–3 threat categories. No tool provides a pass/fail verdict against the complete taxonomy with a standardized, fail-closed exit code contract.

The positioning is intentional: run static scanners in your IDE and pre-commit hooks; run cosai-mcp in CI against the server you actually shipped. They test different things. → Full competitive landscape: [VALUE_PROP.md](VALUE_PROP.md)

---

## Design Principles

**Security-first, not security-bolted-on.** The harness itself is a high-value target. We apply the same zero-trust model to our own code that we apply to the MCP servers we test: no code execution in catalog files, OS-level probe isolation, network allowlisting, immutable result objects, tamper-evident reports.

**Zero-friction adoption.** The most secure tool is the one teams actually use. Every adoption path is one command. `uvx cosai-mcp scan http://localhost:8000` requires nothing installed. The pytest plugin drops into existing CI. The GitHub Action is three lines of YAML.

**Fail closed.** A scanner that can't connect to its target reports `scan-incomplete`, not `clean`. An internal scanner error exits with code 2, which the CI gate treats as failure. There is no ambiguous success state.

**Honest coverage claims.** Black-box probing cannot detect T4 (tool poisoning), T9 (LLM trust boundary failures), or T12 (invisible activity). We say so explicitly. The coverage matrix in every report shows which engine covered which category and which were not reachable from outside.

## Why the Scanner Itself Can Be Trusted

The scanner is a high-value target: it runs in CI with broad permissions, handles attacker-controlled content from the servers it probes, and its output feeds directly into security decision systems. A malicious MCP server operator knows this. The harness is designed around five concrete attack goals — result inversion, SSRF pivoting, code execution in CI, SARIF poisoning, catalog tampering — and addresses each structurally:

- **Probe isolation.** Each probe runs in a separate `multiprocessing.Process`. OS process boundaries eliminate shared Python state. A crafted response from a malicious server cannot contaminate a subsequent probe's execution context. Timeouts are enforced at OS level (`SIGKILL`), not via Python threading — a GIL-holding operation in a probe cannot stall the harness.
- **Network allowlist enforced at socket connect time.** The target hostname is resolved to an IP once at scan start. Any connect to a different IP is rejected at the transport layer — not in validation logic — defeating DNS rebinding. Redirects are disabled unconditionally. RFC1918, link-local, loopback, cloud metadata endpoints (`169.254.169.254`), and IPv6 ULA are blocked by default regardless of what a server response says.
- **SARIF structural isolation.** Attacker-controlled bytes appear in exactly one output field: `result.message.text`, as plain text, length-capped, control-characters stripped. Fields that GitHub interprets structurally — `ruleId`, `suppressions`, `partialFingerprints` — are generated from catalog metadata only. They are never derived from server response content.
- **Catalog integrity.** The Ed25519 public key is a bytes literal hardcoded in `cosai_mcp/keys.py` — not loaded from disk, not configurable at runtime. Unsigned official catalog files are rejected outright (not warned about). Template substitution operates on the parsed Python dict, not the serialized JSON string — JSON structural injection through template expansion is impossible.
- **Report signing and credential scrubbing.** Each report is signed with a per-installation key stored in the OS keychain; any tampering breaks verification. CI environment credentials (`*_TOKEN`, `*_KEY`, cloud provider vars) are stripped from the environment before any subprocess launch.

Full threat model with attack scenarios and control rationale: [SECURITY.md](SECURITY.md)

---

## Why Open Source

The CoSAI taxonomy is already a public standard (OASIS Open). A closed implementation of a public standard creates a commercial moat where there should be a community resource. Enterprise procurement teams, security researchers, and framework authors all need a canonical, auditable reference implementation — one they can read, contribute to, and trust.

Target: upstream contribution to the `cosai-oasis` GitHub organization as the official runnable companion to the whitepaper.

License: Apache 2.0.

---

## Use Cases

### 1. Pre-deployment security gate (CI/CD)

**Who:** Platform engineering teams shipping MCP servers internally.

**What:** A GitHub Action runs the full probe suite on every pull request. Critical findings block the merge. The SARIF report surfaces findings directly in the GitHub Security tab alongside SAST and dependency scan results.

```yaml
- uses: cosai-mcp/scan-action@v1
  with:
    target: http://localhost:8000
    fail_on: critical
```

**Value:** Catches authentication gaps, session binding failures, and resource exhaustion vectors before they reach production. No manual review required.

---

### 2. Third-party MCP server vetting

**Who:** Enterprise security teams evaluating vendor or marketplace MCP servers before connecting them to internal agents.

**What:** Run the scanner against the vendor's staging endpoint. The report maps findings to CoSAI T-categories, OWASP MCP Top 10, and NIST AI RMF subcategories. Hand the report to procurement.

```bash
cosai-mcp scan https://vendor.example.com/mcp \
  --report sarif \
  --output vendor-audit.sarif
```

**Value:** Structured, repeatable vendor security assessment in minutes rather than weeks of manual review. Report format is audit-ready.

---

### 3. Developer self-check during local development

**Who:** Individual developers building MCP tools, plugins, or servers.

**What:** The pytest plugin integrates into the existing test suite. Developers run `pytest --cosai-target=http://localhost:8000` alongside their unit tests and see security findings inline with test results.

**Value:** Security feedback in the same loop as functional feedback. Developers fix issues before code review, not after a dedicated security sprint.

---

### 4. Middleware enforcement in production

**Who:** Python/FastAPI teams who want runtime enforcement, not just pre-deployment scanning.

**What:** Add `CoSAIStack` as ASGI middleware. It enforces session binding (T7), confused deputy prevention (T2), tool signature verification (T6), resource budgets (T10), and execution trace logging (T12) on every request.

```python
from cosai_mcp.middleware import CoSAIStack

app.add_middleware(CoSAIStack, config=CoSAIConfig(
    session_binding=True,
    tool_allowlist=["read_file", "search_db"],
    execution_budget_seconds=30,
    audit_log_path="/var/log/cosai/traces",
))
```

**Value:** Converts the scan findings into enforced controls. The middleware and the scanner use the same threat definitions — what the scanner detects, the middleware blocks.

---

### 5. Compliance evidence for enterprise procurement

**Who:** CISOs and legal teams responding to customer security questionnaires or SOC 2 audits.

**What:** Scheduled weekly scans produce signed reports. The report embeds the catalog hash, scan timestamp, and a public key fingerprint. Reports cannot be retroactively altered.

**Value:** Audit-ready evidence of continuous MCP security assessment. Maps directly to CoSAI T1–T12 and NIST AI RMF subcategories — the frameworks enterprise customers ask about.

---

### 6. Security research and threat catalog contribution

**Who:** Security researchers who discover new MCP attack vectors.

**What:** Define the new threat as a JSON file following the catalog schema. Submit a pull request. If merged and signed, the threat definition is distributed to all users on their next catalog update.

**Value:** A living, community-maintained threat library. New attack patterns from real-world incidents become runnable probes within days, not months.

---

## What It Is Not

- **Not a WAF or API gateway.** cosai-mcp does not sit in the production request path by default. The middleware is opt-in and complement to, not a replacement for, network-layer controls.
- **Not a general LLM security scanner.** It is scoped specifically to the MCP protocol. Prompt injection in a non-MCP LLM application is out of scope.
- **Not a commercial audit service.** It produces structured reports suitable for audit evidence, but it does not provide human analysis, remediation consulting, or SLA guarantees.
- **Not a complete substitute for penetration testing.** Black-box probes and middleware instrumentation together cover T1–T12 at protocol depth. They do not replace application-layer pentesting or threat modelling of the business logic built on top of MCP.
