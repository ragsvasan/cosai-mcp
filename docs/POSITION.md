# cosai-mcp — Position Paper

## The Gap

The CoSAI/OASIS January 2026 whitepaper defines a rigorous security taxonomy for the Model Context Protocol — twelve threat categories, from improper authentication (T1) to insufficient logging (T12). The taxonomy is the right framework.

What does not yet exist is a **runtime conformance test** that an MCP server author can run before shipping. Every existing tool falls into one of three buckets:

| Tool class | What it does | What it misses |
|------------|-------------|----------------|
| Static scanners (Cisco, Snyk, Enkrypt) | Analyse source code or tool definitions | Cannot test a running server; cannot detect protocol-layer vulnerabilities |
| Runtime proxies (MCP-Bastion, MCPProxy-go) | Intercept production traffic | Require deployment in the critical path; test what runs, not what should be rejected |
| Commercial services | Black-box evaluation on demand | Not CI-native; cannot be owned by the server team |

None of them test what you shipped against the full T1–T12 taxonomy in a reproducible, developer-owned, CI-gateable way.

---

## The Design

`cosai-mcp` fills the gap the same way `pytest` fills the gap for unit testing: **you write the spec, we verify the running server matches it.**

Three structurally distinct engines cover all twelve categories — no single mechanism can do it alone:

| Engine | Covers | Mechanism |
|--------|--------|-----------|
| **Black-box prober** | T1, T3, T5, T8, T10, partial T2/T6/T11 | One-shot JSON-RPC probes against the live server |
| **Stateful conformance harness** | T2, T6, T7 | Full `initialize` → multi-turn scripted scenarios |
| **Middleware instrumentation** | T4, T9, T12 | Library deployed inside the target server — detection requires being in the call path |

T4 (prompt injection), T9 (LLM trust boundaries), and T12 (audit logging) are **structurally undetectable from outside**. No black-box probe can observe whether content in a tool response contains prompt injection. The middleware IS the test for these categories.

---

## The Contract

### Fail-closed exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no findings at or above threshold |
| 1 | Findings at or above `--fail-on` threshold |
| 2 | Scanner internal error — **treated as failure by CI gate** |
| 3 | Target unreachable |

Exit code 2 is treated as failure by design. A scanner that silently swallows its own errors is not a security gate.

### SARIF 2.1.0 output

Every finding is a structured SARIF result with:
- `ruleId` — the catalog threat-definition ID (e.g. `T03-001`)
- `rule.properties.cwe` — CWE tag(s) from the signed catalog
- `rule.properties.owasp_ref` — OWASP MCP Top 10 reference
- `message.text` — the only field that can contain attacker bytes; sanitized and length-capped

SARIF integrates natively with GitHub's security findings tab (same pipeline as CodeQL and Dependabot). No extra tooling required.

### JSON-extensible threat catalog

New threats: drop a signed JSON file in `catalog/official/`. No code changes required. The catalog schema is versioned; every file is Ed25519-signed by the project keypair before shipping. Unsigned official files are rejected at load time.

Custom catalog entries are supported under `catalog/custom/` with explicit opt-in (`--allow-custom-catalog`) and are marked `UNTRUSTED` in all reports.

---

## The Proposal

We are contributing `cosai-mcp` to the CoSAI MCP Working Group as the **runtime conformance companion to the T1–T12 taxonomy paper** — the same relationship `pytest` has to PEP 8, or OpenSSL has to RFC 5246.

Concretely, we propose:

1. **The catalog format becomes a WS4 standard.** JSON schema + Ed25519 signing model, as defined in `cosai_mcp/catalog/schema.py`, becomes the interchange format for community-contributed MCP threat definitions.

2. **The working group becomes the signing authority for official catalog entries.** Community submits threat definitions; WS4 ratifies and signs. Same model as OWASP Top 10 tool listings.

3. **cosai-mcp ships as the reference CI gate** referenced in future CoSAI MCP security guidance — the tool server authors run before publishing to any MCP registry.

---

## Alignment

| Standard | Coverage |
|----------|----------|
| CoSAI/OASIS T1–T12 | Full — all twelve categories, three engines |
| OWASP MCP Top 10 (A01–A10) | Full — catalog carries `owasp_ref` per threat |
| OWASP Agentic Security Initiative (ASI01–ASI10) | Partial — T4/T9 middleware covers ASI02/ASI03/ASI07 |
| NIST AI RMF 2026 | GOVERN 1.7, MAP 5.1, MEASURE 2.5 |
| SOC 2 Type II | CC6.1, CC6.6, CC7.1 |

---

## Try It

```bash
# Zero install — scan a local server
uvx --from cosai-mcp cosai scan http://localhost:8000

# SARIF output for GitHub security tab
cosai scan http://localhost:8000 --report-sarif findings.sarif

# Adversarial mode with canary tokens (own targets only)
cosai scan http://localhost:8000 --adversarial --i-own-this-target=localhost

# pytest plugin — gate your own MCP server in CI
pytest --cosai-target=http://localhost:8000 --cosai-severity=critical
```

GitHub: <https://github.com/ragsvasan/cosai-mcp>  
License: Apache 2.0  
PyPI: `pip install cosai-mcp`
