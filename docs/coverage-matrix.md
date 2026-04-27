# cosai-mcp — Coverage Matrix

Which engine covers which CoSAI threat category, and what is explicitly not covered.

| Category | Name | Engine | Coverage | Not Covered |
|----------|------|--------|----------|-------------|
| T1 | Improper Authentication | Black-box prober | Missing auth header, token replay, cross-session token, OAuth proxy detection, DPoP binding | JWT cryptographic verification (requires valid key material) |
| T2 | Missing Access Control | Stateful harness | Multi-turn privilege escalation chain, confused deputy | Runtime RBAC policy enforcement (use mcp-armor middleware) |
| T3 | Input Validation Failures | Black-box prober | Command injection, path traversal, SQL injection, oversized payload, null bytes, Unicode normalization | Server-side schema enforcement internals |
| T4 | Data/Control Boundary | **Middleware only** | Prompt injection pattern detection, control token stripping | Cannot be detected from outside; middleware must be in the call path |
| T5 | Inadequate Data Protection | Black-box prober | API key / JWT / SSN / credit card leakage in tool responses, credential exfiltration | PII in encrypted channels (requires MITM) |
| T6 | Integrity/Verification | Stateful harness + prober | Tool shadowing mid-session, manifest drift, typosquat detection (Levenshtein ≤ 2) | Code-level supply chain (use Snyk/Enkrypt pre-deploy) |
| T7 | Session Security Failures | Stateful harness | Session fixation, token replay across sessions, session revocation bypass (T7-SC-002) | TLS MITM (infrastructure concern, not MCP-layer) |
| T8 | Network Binding Failures | Black-box prober | 0.0.0.0 binding detection, SSRF via tool-initiated outbound, shadow server detection | Container network namespace isolation (infrastructure concern) |
| T9 | Trust Boundary Failures | **Middleware only** | Scanner self-protection: all MCP response content sanitised before re-use | Overreliance on LLM judgment requires LLM-in-the-loop (by design out of scope) |
| T10 | Resource Management | Black-box prober | Rate limit absence, unbounded response size, recursive depth, heartbeat enforcement | Per-tenant quota accounting (application-layer concern) |
| T11 | Supply Chain/Lifecycle | Black-box prober (partial) | Typosquatted tool names, unsigned tool definitions, unexpected registry origin | Code-level dependency CVEs (use Snyk/SCA pre-deploy) |
| T12 | Insufficient Logging | **Middleware only** | Hash-chained audit log, DAG execution trace, tamper detection via `cosai audit verify` | Prompt/LLM reasoning trace (outside MCP layer); `resources/read` logged as ⚠️ partial |

## Engine Key

| Engine | When to use |
|--------|-------------|
| **Black-box prober** | One-shot JSON-RPC probes against a running server — no server-side cooperation needed |
| **Stateful harness** | Multi-turn scripted scenarios requiring full `initialize` + session state |
| **Middleware only** | Detection requires being in the call path — instrument with mcp-armor for T4/T9/T12 |

## Explicit Non-Coverage

cosai-mcp does **not** cover:

- **Static code analysis** — use Cisco MCP Scanner, Enkrypt AI, or Snyk Agent Scan before deploy
- **Production traffic monitoring** — use MCPProxy-go or MCP-Bastion at runtime
- **LLM-semantic judgment** — probes are deterministic; content quality is out of scope
- **Container/network isolation** — gVisor/Kata sandboxing is infrastructure, not MCP-layer
- **TLS/PKI** — certificate validation is the TLS stack's responsibility

See [VALUE_PROP.md](VALUE_PROP.md) for the full competitive landscape and recommended scanning workflow.
