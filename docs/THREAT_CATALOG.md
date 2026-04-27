# CoSAI Threat Catalog — T1 through T12

Reference for all 12 CoSAI threat categories, their attack patterns, what cosai-mcp tests, and remediation guidance. Based on the CoSAI/OASIS January 2026 whitepaper.

---

## Coverage Matrix (Three-Engine Model)

See [COVERAGE.md](COVERAGE.md) for the authoritative implementation status. This table is the intended final-state design.

| Category | Name | Engine | Intended coverage | Current status |
|----------|------|--------|------------------|---------------|
| T1 | Improper Authentication | Black-box prober | Full | Partial (2/4 probes done) |
| T2 | Missing Access Control | Stateful harness + partial BB | Full | Partial (1 BB probe; stateful P6) |
| T3 | Input Validation Failures | Black-box prober | Full | Done |
| T4 | Data/Control Boundary | Middleware instrumentation | Requires middleware | Done |
| T5 | Inadequate Data Protection | Middleware instrumentation | Requires middleware | Planned P4c |
| T6 | Integrity/Verification | Stateful harness + partial BB | Full | Partial (manifest check done; typosquat P4c; stateful P6) |
| T7 | Session Security Failures | Stateful harness | Full | Planned P6 |
| T8 | Network Binding Failures | Black-box prober | Full | Partial (SSRF done; 0.0.0.0 binding P4c) |
| T9 | Trust Boundary Failures | Middleware instrumentation | Requires middleware | Done |
| T10 | Resource Management | Black-box prober | Full | Partial (size/rate done; DoW/heartbeat P4c) |
| T11 | Supply Chain/Lifecycle | Black-box prober (partial) | Partial — static analysis | Partial (allowlist done; typosquat P4c) |
| T12 | Insufficient Logging | Middleware instrumentation | Requires middleware | Done |

**Why "Requires middleware" for T4, T9, T12?**
These categories are observable only from inside the call path. A black-box scanner sees what the server returns — it cannot observe what content flows into the LLM's reasoning loop (T4, T9) or whether execution is being logged (T12). The cosai-mcp middleware deployed in the target server instruments those boundaries. See [ARCHITECTURE.md](ARCHITECTURE.md) for the three-engine rationale.

---

## T1 — Improper Authentication

**CoSAI ref:** T1 | **OWASP MCP Top 10:** A01 | **ISO 27001:** A.5.15 | **CWE:** CWE-287, CWE-306

### What it is
Insufficient verification of identity across agent chains. MCP servers must validate that every request carries a legitimate, correctly scoped credential — not just that a credential exists.

### Attack patterns
- **Missing auth header accepted:** server responds to unauthenticated `tools/call` without rejecting it
- **Token replay:** same token accepted across multiple sessions (no nonce or jti validation)
- **Cross-session token:** token issued for session A accepted in session B
- **OAuth proxy / credential passthrough:** server forwards a user's OAuth token to downstream services without re-scoping — downstream sees the user's full credential, not a scoped delegation
- **DPoP binding not enforced:** server issues DPoP-bound tokens but does not verify the `DPoP` proof header on subsequent requests

### What cosai-mcp tests (black-box prober)
- Missing auth header → server accepts (FAIL) or rejects with 401 (PASS)
- Replayed token (same `jti`) → accepted (FAIL) or rejected (PASS)
- Token from a different session → accepted (FAIL) or rejected (PASS)
- DPoP-bound token sent without DPoP proof header → accepted (FAIL) or rejected (PASS)

### Remediation
- Validate token `jti` for replay prevention; reject tokens used more than once
- Bind session tokens to the initiating session; reject cross-session reuse
- Implement session-bound identity per RFC 8693 (Token Exchange) + RFC 9449 (DPoP)
- Never forward user credentials to downstream services; generate scoped delegation tokens

---

## T2 — Missing Access Control

**CoSAI ref:** T2 | **OWASP MCP Top 10:** A02 | **ISO 27001:** A.5.15 | **CWE:** CWE-285, CWE-732

### What it is
Insufficient authorization checks for autonomous tool calls. The "confused deputy" problem: the MCP server executes a request using its own elevated privileges rather than verifying the calling user has the right to perform that action.

### Attack patterns
- **Confused deputy:** agent with service-account-level DB credentials executes `DELETE * FROM records` because the user asked for it, without verifying the user has DELETE permission
- **Multi-turn privilege escalation:** attacker gains access to a low-privilege tool, uses it to extract information that enables calling a high-privilege tool in a subsequent turn
- **Scope elevation:** agent re-negotiates tool access mid-session to include tools outside the initial authorization scope

### What cosai-mcp tests
- **Black-box (partial):** call privileged tool without appropriate scope claim in token → accepted (FAIL) or rejected (PASS)
- **Stateful harness (full):** scripted 3-turn sequence: low-priv tool call → scope inspection → high-priv tool call; asserts server rejects step 3 without elevated scope grant

### Remediation
- Validate the calling user's permissions for every tool invocation — do not rely on agent-level credentials
- Implement per-tool RBAC; scope tokens to specific tools, not broad resource access
- Use RFC 8693 delegation tokens that encode both agent identity and user identity; backend validates both
- Log all privilege checks; alert on unexpected scope elevation

---

## T3 — Input Validation Failures

**CoSAI ref:** T3 | **OWASP MCP Top 10:** A03 | **ISO 27001:** A.8.25 | **CWE:** CWE-78, CWE-22, CWE-89

### What it is
Treating LLM-generated tool arguments as trusted input. The LLM constructs `arguments` for `tools/call` — these arguments must be validated by the MCP server with the same rigor as any user-supplied input.

### Attack patterns
- **Command injection:** `{"cmd": "; cat /etc/passwd"}` in a shell-executing tool
- **Path traversal:** `{"path": "../../etc/shadow"}` in a file-reading tool
- **SQL injection:** `{"query": "'; DROP TABLE users; --"}` in a database tool
- **Oversized payload:** argument value of 100MB causes OOM or timeout
- **Null bytes / Unicode normalization:** bypasses naive string validation

### What cosai-mcp tests
All probes assert `response.error.code` is in the invalid-params range (`-32602`), not `Internal error` (`-32603`) — an internal error on an injection payload may indicate the payload reached the execution layer.

- Command injection patterns in every discovered tool's string arguments
- Path traversal patterns in path-type arguments
- SQL injection patterns in query-type arguments
- Null byte injection
- Oversized arguments (10MB+)
- Unicode normalization bypasses (`%2e%2e/` → `../`)

### Remediation
- Validate every tool argument against a strict JSON Schema before execution
- Use parameterized queries — never string interpolation for DB calls
- Reject paths containing `..` after normalization; resolve to absolute paths and assert they are within the allowed root
- Apply input length limits per argument type
- Return `-32602` (Invalid params) for validation failures — never `-32603` (Internal error) which leaks implementation details

---

## T4 — Data/Control Boundary Violations

**CoSAI ref:** T4 | **OWASP MCP Top 10:** A04 | **ISO 27001:** A.8.25 | **CWE:** CWE-74, CWE-77

### What it is
The inability to distinguish between instructions and data in the LLM's context window. An attacker who can write content that the agent reads (a document, a database record, a web page) can inject instructions that redirect the agent's behavior.

### Attack patterns
- **Tool poisoning:** attacker modifies an MCP tool's JSON schema description. When the LLM discovers tools, it reads the poisoned description and may execute the malicious tool or exfiltrate data to an attacker-controlled endpoint. Success rate ~84% with auto-approval enabled.
- **Rug pull:** MCP server appears legitimate during initial security scanning but silently modifies tool definitions via remote update after deployment.
- **Indirect prompt injection:** content retrieved by the agent (a document, search result, email) contains instructions that hijack the agent's next action.

### What cosai-mcp tests (middleware instrumentation)
T4 requires being in the call path. The middleware detects:
- Prompt injection patterns in tool responses (fixed keyword list + RE2 regex)
- Tool definition changes between initial discovery and mid-session re-fetch (rug pull signal)
- Control tokens in data fields that should contain only data

### Remediation
- Enforce strict JSON Schema on tool definitions; reject unknown fields
- Cryptographically sign tool definitions; verify signature on every tool list fetch
- Sanitize all content retrieved via tools before it enters the LLM's context
- Implement `ControlBoundaryViolation` detection; log and alert on detection
- Deploy the cosai-mcp middleware for runtime detection

---

## T5 — Inadequate Data Protection

**CoSAI ref:** T5 | **OWASP MCP Top 10:** A05 | **ISO 27001:** A.8.10, A.8.11 | **CWE:** CWE-200, CWE-312

### What it is
Sensitive data leaking through the MCP context: tool responses containing PII, secrets, or proprietary data being logged in plaintext, passed to unauthorized agents, or included in LLM context that flows to third-party model APIs.

### Attack patterns
- **Context leakage:** database tool returns rows containing PII; LLM includes them verbatim in a response to a lower-privileged user
- **Cross-agent context bleed:** stateful context from a high-privilege session leaks into a shared SSE queue consumed by a low-privilege session
- **Credential exfiltration:** tool response contains an API key; agent uses it in a subsequent (unauthorized) tool call

### What cosai-mcp tests (middleware instrumentation)
- PII pattern detection (SSN, credit card, email, phone) in tool responses before they reach the LLM context
- Credential pattern detection (API key formats, JWT headers) in tool responses
- Context isolation between concurrent sessions

### Remediation
- Apply PII scrubbing to all tool responses before they enter the LLM context
- Log tool responses only after scrubbing; never log raw API keys or credentials
- Implement session isolation; never share SSE queues between sessions
- Scope database queries to return only fields the requesting user is authorized to see

---

## T6 — Integrity and Verification Failures

**CoSAI ref:** T6 | **OWASP MCP Top 10:** A06 | **ISO 27001:** A.5.21 | **CWE:** CWE-345, CWE-494

### What it is
Lack of cryptographic verification for MCP server definitions and tool schemas. Attackers can substitute a tool definition with one that routes data to a malicious endpoint, or shadow a trusted tool name with a malicious implementation.

### Attack patterns
- **Tool shadowing:** malicious server registers a tool with the same name as a trusted tool; agent calls the malicious version
- **Mid-session tool list mutation (rug pull):** server's `tools/list` response changes between the initial discovery and a mid-session re-fetch; new tools appear without warning
- **Unsigned tool definitions:** tool metadata can be modified in transit without detection

### What cosai-mcp tests
- **Black-box (partial):** tool list manifest anomaly detection — compare current `tools/list` against a stored baseline; new or changed tools flagged
- **Stateful harness (full):** `tools/list` baseline → multi-turn session → `tools/list` re-fetch → diff; mid-session additions flagged as `T6-SHADOW-DETECTED`

### Remediation
- Sign tool definitions with a server keypair; verify signature on every `tools/list` fetch
- Maintain a baseline manifest of expected tools; alert on additions or schema changes
- Implement an approved server allowlist; reject connections to unlisted servers
- Monitor tool name collision with allowlisted names (Levenshtein distance check)

---

## T7 — Session Security Failures

**CoSAI ref:** T7 | **OWASP MCP Top 10:** A07 | **ISO 27001:** A.8.10 | **CWE:** CWE-384, CWE-287

### What it is
Weak binding of MCP sessions to user identity. Session tokens that can be fixed by the client, replayed across transport switches, or shared across users enable session hijacking and context-bleed attacks.

### Attack patterns
- **Session fixation:** server accepts a client-supplied session ID rather than generating its own; attacker pre-sets a known session ID and hijacks subsequent authentication
- **Session token in URL:** `Mcp-Session-Id` exposed in server logs, access logs, or referrer headers
- **Cross-transport session replay:** session token issued over HTTPS reused over a downgraded connection
- **Context-bleed:** shared SSE event queue allows session N's events to appear in session M

### What cosai-mcp tests (stateful harness)
- Client-supplied session ID accepted without server regeneration → FAIL
- Session token in URL query parameter → FAIL
- Token replayed in a new session after original session close → accepted (FAIL) or rejected (PASS)
- Concurrent sessions sharing any context → FAIL

### Remediation
- Always generate session IDs server-side using a CSPRNG; reject client-supplied session IDs
- Transmit session IDs only in headers (`Mcp-Session-Id`), never in URLs
- Bind session tokens to the originating IP + user identity; reject tokens used from a different binding
- Implement per-session SSE streams; never share a queue between sessions
- Short-lived session tokens (15–60 minutes); refresh via RFC 8693 token exchange

---

## T8 — Network Binding Failures

**CoSAI ref:** T8 | **OWASP MCP Top 10:** A08 | **ISO 27001:** A.8.1 | **CWE:** CWE-668, CWE-441

### What it is
MCP endpoints exposed beyond their intended network boundary. A local MCP server bound to `0.0.0.0` is reachable from the network, not just localhost. Poorly isolated multi-tenant environments expose one tenant's MCP server to another.

### Attack patterns
- **0.0.0.0 binding:** local development server exposed to the network; reachable by other hosts on the same network
- **SSRF via tool:** tool designed to fetch URLs can be called with `file://`, `http://169.254.169.254/`, or internal RFC1918 addresses
- **Shadow MCP server:** attacker runs an MCP server on the same host that intercepts tool calls intended for the legitimate server

### What cosai-mcp tests
- Server responds on a non-loopback interface when it should be loopback-only → flagged
- SSRF probe: call URL-fetching tools with RFC1918, link-local, and `file://` arguments; check if they are rejected
- Tool list diff between two scans — new tools appearing without deployment signal a shadow server

### Remediation
- Bind local MCP servers to `127.0.0.1` only; never `0.0.0.0` in development
- Implement URL allowlisting for any tool that fetches external content
- Block RFC1918, link-local, and loopback targets in URL-fetching tools before execution
- Run MCP servers in network-isolated containers; only expose the endpoint explicitly

---

## T9 — Trust Boundary Failures

**CoSAI ref:** T9 | **OWASP MCP Top 10:** A09 | **ISO 27001:** A.8.25 | **CWE:** CWE-602, CWE-807

### What it is
Delegating security-critical validation to the LLM's judgment. A model may be deceived into approving actions it should reject, treating attacker-controlled content as trusted instructions, or failing to apply security checks consistently.

### Attack patterns
- **Auto-approval reliance:** security checks are implemented as LLM prompts ("only proceed if this looks safe") rather than deterministic controls
- **Semantic bypass:** attacker rephrases a malicious request in a way that reads as benign to the model
- **Context overflow:** flooding the context window with benign content pushes safety instructions out of the model's effective window

### What cosai-mcp tests (middleware instrumentation)
T9 requires observing the agent's decision-making. The middleware instruments:
- Whether validation is deterministic (schema-based) or model-delegated
- Whether model output is sanitized before being re-fed as input to another tool call
- Whether safety instructions are present and properly positioned in the context

### Remediation
- Never use LLM judgment as a security gate; implement deterministic, schema-based validation
- Treat all LLM output as untrusted; sanitize before re-use as tool input
- Place safety instructions at the end of the system prompt, not at the beginning (less vulnerable to context overflow)
- Implement HITL (human-in-the-loop) approval for high-consequence actions (`Execute`-class tools per NIST AG-MP.1)

---

## T10 — Resource Management Failures

**CoSAI ref:** T10 | **OWASP MCP Top 10:** A10 | **ISO 27001:** A.8.6 | **CWE:** CWE-400, CWE-770

### What it is
Unbounded resource consumption by agentic workflows. Infinite reasoning loops, recursive tool calls, or unbounded API calls incur extreme costs ("Denial of Wallet") or exhaust system resources.

### Attack patterns
- **Infinite tool call loop:** agent design allows tool A to call tool B which calls tool A; no depth limit
- **Unbounded response size:** tool returns gigabyte-sized responses; scanner or agent OOMs
- **No rate limiting:** attacker calls `tools/call` at maximum rate; server exhausts DB connections or API quota
- **Cost amplification:** each tool call triggers expensive LLM inference; attacker triggers thousands of calls

### What cosai-mcp tests
- Rapid-fire `tools/call` requests; checks for rate limiting (429 or equivalent) → no rate limit (FAIL)
- Tools/call that requests maximum response size; checks for size limits → no size limit (FAIL)
- Recursive tool call chain simulation; checks for depth limits → no depth limit (FAIL)
- Long-running SSE connection with no progress notification; checks for heartbeat → absent (FAIL)

### Remediation
- Implement per-session rate limits on `tools/call`
- Cap tool response sizes; stream large responses with explicit size limits
- Implement execution depth limits; detect and abort recursive call chains
- Implement progress notifications per MCP spec; provide heartbeat for long-running operations
- Set execution budget per session (wall time + token count); abort when exceeded

---

## T11 — Supply Chain and Lifecycle

**CoSAI ref:** T11 | **OWASP MCP Top 10:** A11 | **ISO 27001:** A.5.21 | **CWE:** CWE-494, CWE-1357

### What it is
Malicious or compromised MCP server packages distributed via agent marketplaces or package registries. The MCP ecosystem's nascent marketplace ("skills", "plugins") creates a supply chain analogous to npm or PyPI but with fewer established security practices.

### Attack patterns
- **Typosquatting:** `anthropic-mcp-tools` vs `anthropic-mcp-tool` — one character difference, one is malicious
- **Poisoned package:** legitimate package taken over; malicious update ships with modified tool definitions
- **Unsigned skills:** marketplace skills distributed without code signing; no integrity verification at install
- **Dependency confusion:** internal MCP server package name matches a public package; public version installed instead

### What cosai-mcp tests (partial — static analysis)
- Tool name Levenshtein distance check against a configured allowlist; close matches flagged
- Tool definitions lacking integrity signatures flagged
- Tools with unexpected origins (registry mismatch) flagged

Full supply chain verification (provenance, dependency graph analysis) requires the cosai-mcp static scanner component (`cosai-mcp scan-static --manifest mcp-manifest.json`).

### Remediation
- Maintain an explicit allowlist of approved MCP servers by origin and version
- Require cryptographic signatures for all installed MCP skills; verify at install time
- Use dependency pinning with hash verification (similar to `pip install --require-hashes`)
- Run SCA (Software Composition Analysis) on MCP server dependencies before deployment
- Monitor for new versions of installed MCP packages; verify signatures before auto-update

---

## T12 — Insufficient Logging

**CoSAI ref:** T12 | **OWASP MCP Top 10:** A12 | **ISO 27001:** A.8.15 | **CWE:** CWE-778, CWE-223

### What it is
Lack of immutable, causally-linked execution traces for agentic workflows. Traditional event logging records what happened; agentic systems require execution traces that record why it happened — the causal chain from user prompt through LLM reasoning to tool invocation.

### What's missing without execution traces
When an incident occurs (agent leaks proprietary data, executes unauthorized action), a log of the event provides no evidence of culpability. The investigation cannot determine whether the cause was:
- Direct prompt injection from a user
- Indirect prompt injection from a tool (T4)
- Model hallucination due to context overflow
- A legitimate authorized action

### What cosai-mcp tests (middleware instrumentation)
The audit middleware instruments:
- Whether tool invocations are logged with their causal chain (prompt → context retrieved → tool call)
- Whether logs are append-only and tamper-evident (hash-chained)
- Whether log content is sufficient to reconstruct the reasoning path

### The cosai-mcp audit log
cosai-mcp's own middleware implements the 2026 standard for execution traces:

```json
{
  "seq": 42,
  "timestamp": "2026-04-26T14:32:01.123Z",
  "data": {
    "session_id": "sess_abc123",
    "user_id": "user:eng123",
    "agent_id": "agent:infrabot",
    "prompt_hash": "sha256:...",
    "context_refs": ["tool:read_file:result_hash"],
    "tool_name": "send_email",
    "tool_args_hash": "sha256:...",
    "result_status": "success"
  },
  "prev_hash": "sha256:...",
  "entry_hash": "sha256:..."
}
```

Tool argument values are hashed, not logged in plaintext — preserving auditability without logging PII.

### Remediation
- Implement hash-chained execution trace logging for all tool invocations
- Log: session ID, user ID, agent ID, prompt hash, context references, tool name, argument hash, result status
- Store traces in an append-only log; verify chain integrity on demand
- Retain traces per your compliance requirement (typically 90 days minimum for SOC 2)
- Integrate traces into your SIEM with alerts on chain breaks or unexpected tool call patterns

---

## Adding New Threat Definitions

See [CONTRIBUTING.md](CONTRIBUTING.md) for the JSON schema and signing process to add new threat definitions to the catalog.
