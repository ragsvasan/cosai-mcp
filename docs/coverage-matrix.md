# cosai-mcp — Coverage Matrix

Which engine covers which CoSAI threat category, and what is explicitly not covered.

| Category | Name | Engine | Coverage | Not Covered |
|----------|------|--------|----------|-------------|
| T1 | Improper Authentication | Black-box prober | Missing auth header, token replay, cross-session token, OAuth proxy detection, DPoP binding, wrong error code for unknown methods (T01-005), real JTI-replay + distinct JWT header-validation probes (`alg`/`iss`/`aud`/`exp`, T01-006) | JWT cryptographic verification (requires valid key material) |
| T2 | Missing Access Control | Stateful harness + black-box prober | Multi-turn privilege escalation chain, confused deputy; BB: tools/list enumeration (T02-004), read-scope write bypass (T02-005) | Runtime RBAC policy enforcement (use mcp-armor middleware) |
| T3 | Input Validation Failures | Black-box prober | Command injection, path traversal, SQL injection (error-based), NoSQL operator injection, SSTI, XXE, CRLF/header injection, oversized payload, null bytes, Unicode normalization. Payloads bind to discovered tools via adaptive synthesis (not fictional `cmd`/`url` args). | Server-side schema enforcement internals |
| T4 | Data/Control Boundary | **Black-box prober (passive) + Middleware** | Passive manifest scan: `ToolPoisoningDetector` runs on every `tools/list` response fetched during discovery — injection patterns in tool names, descriptions, and `inputSchema` properties surface as findings. Full response-body injection requires middleware in the call path. | Response content from inside tool calls cannot be observed from outside |
| T5 | Inadequate Data Protection | Black-box prober + passive manifest scan | Anchored credential leakage (AWS `AKIA`, GCP service-account JSON, Azure SAS, GitHub `ghp_/gho_/ghs_`, GitLab `glpat-`, Google `AIza`, JWT) + context-leak (internal hostnames, stack traces) in tool responses and in the discovered manifest; strict tier behind `--pii-strict` (SSN, IBAN, US phone, Luhn-corroborated PAN). Passive `_scan_manifest_t5` redacts secrets to `[REDACTED:<type>]`. | PII in encrypted channels (requires MITM); high-FP context-leak patterns are response-body-only (not flagged on the manifest) |
| T6 | Integrity/Verification | Stateful harness + prober | Tool shadowing mid-session, manifest drift, typosquat detection (Levenshtein ≤ 2), homoglyph confusables, optional operator reference allowlist for known-good tool names | Code-level supply chain (use Snyk/Enkrypt pre-deploy) |
| T7 | Session Security Failures | Stateful harness + black-box prober | Session fixation, token replay across sessions, session revocation bypass (T7-SC-002, registered in the stateful engine); BB: CORS wildcard (T07-001); OAuth scope vs MCP confirmation: confirmation-as-auth-bypass detection (T07-002). T07-003 (scope-before-confirmation) is **best-effort only** — it relies on the operator-supplied valid token and a confirmation-referencing rejection message; an unrelated rejection yields INCONCLUSIVE, not a finding (audit COV-04). | TLS MITM (infrastructure concern); strong BB scope-enforcement proof needs a positive control (operator-supplied valid + read tokens) |
| T8 | Network Binding Failures | Black-box prober | 0.0.0.0 binding detection; SSRF via tool-initiated outbound — RFC1918/loopback/link-local, AWS IMDSv1 + IMDSv2 token endpoint, GCP/Azure/Alibaba cloud metadata, `file://` scheme, IPv6 ULA/link-local; shadow server detection | Container network namespace isolation (infrastructure concern); operator-supplied bind-config only (no active interface enumeration) |
| T9 | Trust Boundary Failures | **Middleware only** | Scanner self-protection: all MCP response content sanitised before re-use | Overreliance on LLM judgment requires LLM-in-the-loop (by design out of scope) |
| T10 | Resource Management | Black-box prober + stateful harness | Oversized input (T10-001), rate-limit liveness (T10-002), recursive payload nesting (T10-003), HTTP-layer burst 429/503 (T10-004, probe_count: 30), JSON-RPC-layer per-session call budget -32029 (T10-005); **stateful** recursive/looping tool-chain → per-session call-budget enforcement (denial-of-wallet, T10-SC-001) | Per-tenant quota accounting (application-layer concern); heartbeat / progress-notification timeout and concurrent-connection / slow-loris / gzip-bomb (load/DoS-generation, out of scope — see COVERAGE.md) |
| T11 | Supply Chain/Lifecycle | Black-box prober (passive) | Operator-allowlist supply-chain scan (`--tool-allowlist`): discovered tools within Levenshtein 1 of an approved name = typosquat; tools not on the list = unexpected/unauthorized addition. **INCONCLUSIVE (not clean) without an allowlist** — the legacy "reject a fictional tool" probe is a vacuous liveness check only. | Code-level dependency CVEs (use Snyk/SCA pre-deploy); registry signature / version-pin drift / rug-pull (inventory-drift territory) |
| T12 | Insufficient Logging | **Middleware only** | Hash-chained audit log, DAG execution trace, tamper detection via `cosai audit verify`. The only black-box T12 artifact (`T12-002`, destructive-tool *description* transparency in `tests/probes/test_t12_description_transparency.py`) is a UX/transparency signal, **not** a logging test — audit logging is structurally unobservable from outside the call path. | Audit trail of tool invocations (internal to server, never exposed over JSON-RPC); prompt/LLM reasoning trace; `resources/read` logged as ⚠️ partial |

## Engine Key

| Engine | When to use |
|--------|-------------|
| **Black-box prober** | One-shot JSON-RPC probes against a running server — no server-side cooperation needed |
| **Stateful harness** | Multi-turn scripted scenarios requiring full `initialize` + session state |
| **Black-box prober (passive)** | Passive analysis of data already fetched — no extra probe sent (T4 tool-poisoning, T5 secret/PII, T6 integrity, T11 supply-chain manifest scans) |
| **Middleware only** | Detection requires being in the call path — instrument with mcp-armor for full T4/T9/T12 coverage |

## Explicit Non-Coverage

cosai-mcp does **not** cover:

- **Static code analysis** — use Cisco MCP Scanner, Enkrypt AI, or Snyk Agent Scan before deploy
- **Production traffic monitoring** — use MCPProxy-go or MCP-Bastion at runtime
- **LLM-semantic judgment** — probes are deterministic; content quality is out of scope
- **Container/network isolation** — gVisor/Kata sandboxing is infrastructure, not MCP-layer
- **TLS/PKI** — certificate validation is the TLS stack's responsibility

See [VALUE_PROP.md](VALUE_PROP.md) for the full competitive landscape and recommended scanning workflow.
