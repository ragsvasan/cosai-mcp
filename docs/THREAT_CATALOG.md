# CoSAI Threat Catalog — T1 through T12

Reference for all 12 CoSAI threat categories, their attack patterns, what cosai-mcp tests, and remediation guidance. Based on the CoSAI/OASIS January 2026 whitepaper.

---

## Coverage Matrix (Three-Engine Model)

| Category | Name | Engine | Status |
|----------|------|--------|--------|
| T1 | Improper Authentication | Black-box prober | Done — 5 probes (missing auth, token replay, cross-session, DPoP, wrong error code T01-005) |
| T2 | Missing Access Control | Black-box prober + stateful harness | Done — BB: privilege scope + destructive one-shot (T02-003) + tools/list enumeration (T02-004) + read-scope write bypass (T02-005); Stateful: privilege escalation chain + confused deputy |
| T3 | Input Validation Failures | Black-box prober | Done — command/path/SQL injection, NoSQL operator injection, SSTI, XXE, CRLF/header injection, null bytes, oversized payloads (payloads bound to discovered tools via synthesis) |
| T4 | Data/Control Boundary | Middleware instrumentation | Done — requires middleware in target server |
| T5 | Inadequate Data Protection | Black-box prober + passive manifest scan | Done — anchored credential set (AWS/GCP/Azure/GitHub/GitLab/Google/JWT) + context-leak (internal host, stack trace); strict tier (`--pii-strict`): SSN, IBAN, phone, Luhn-PAN |
| T6 | Integrity/Verification | Black-box prober + stateful harness | Done — BB: typosquat detection; Stateful: mid-session manifest diff (rug pull) |
| T7 | Session Security Failures | Stateful harness + black-box prober | Done — Stateful: session fixation, token-in-URL, cross-session replay, revocation (T7-SC-002); BB: CORS wildcard (T07-001), MCP confirmation bypass (T07-002, critical), scope-before-confirmation (T07-003, high) |
| T8 | Network Binding Failures | Black-box prober | Done — 0.0.0.0 binding, SSRF (RFC1918/link-local/loopback, AWS IMDSv1+IMDSv2, GCP/Azure/Alibaba metadata, `file://`, IPv6 ULA/link-local), shadow server detection |
| T9 | Trust Boundary Failures | Middleware instrumentation | Done — requires middleware in target server |
| T10 | Resource Management | Black-box prober | Done — rate limiting with probe_count (T10-004), response size limits, recursive depth, heartbeat |
| T11 | Supply Chain/Lifecycle | Black-box prober (passive) | Done — operator-allowlist scan (`--tool-allowlist`): typosquat (Levenshtein 1) + unexpected/unauthorized tool; **INCONCLUSIVE without an allowlist** (legacy fictional-tool probe is a vacuous liveness check) |
| T12 | Insufficient Logging | Middleware + black-box prober | Done — middleware: hash-chained audit log; BB: T12-002 tool description transparency |

**Why "Requires middleware" for T4, T9, T12?**
These categories are observable only from inside the call path. A black-box scanner sees what the server returns — it cannot observe what content flows into the LLM's reasoning loop (T4, T9) or whether execution is being logged (T12). The cosai-mcp middleware deployed in the target server instruments those boundaries. See [ARCHITECTURE.md](ARCHITECTURE.md) for the three-engine rationale.

---

## T1 — Improper Authentication

**CoSAI ref:** T1 | **OWASP MCP Top 10:** A01 | **CWE:** CWE-287, CWE-306

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
- **T01-005:** Unknown JSON-RPC method returns wrong error code — `unknown/method` and `tools/doesNotExist` must return `-32601` (Method Not Found), not `-32603` (Internal Error) or a 500; an Internal Error on an unknown method may indicate the method reached execution logic (D-03)

### Remediation
- Validate token `jti` for replay prevention; reject tokens used more than once
- Bind session tokens to the initiating session; reject cross-session reuse
- Implement session-bound identity per RFC 8693 (Token Exchange) + RFC 9449 (DPoP)
- Never forward user credentials to downstream services; generate scoped delegation tokens

---

## T2 — Missing Access Control

**CoSAI ref:** T2 | **OWASP MCP Top 10:** A02 | **CWE:** CWE-285, CWE-732

### What it is
Insufficient authorization checks for autonomous tool calls. The "confused deputy" problem: the MCP server executes a request using its own elevated privileges rather than verifying the calling user has the right to perform that action.

### Attack patterns
- **Confused deputy:** agent with service-account-level DB credentials executes `DELETE * FROM records` because the user asked for it, without verifying the user has DELETE permission
- **Multi-turn privilege escalation:** attacker gains access to a low-privilege tool, uses it to extract information that enables calling a high-privilege tool in a subsequent turn
- **Scope elevation:** agent re-negotiates tool access mid-session to include tools outside the initial authorization scope
- **Destructive one-shot tool execution:** a tool that permanently deletes, destroys, or deploys accepts a single call with no prior confirmation step — an agentic LLM can trigger irreversible actions (data deletion, infra teardown, financial transactions) without any human in the loop. Severity is amplified by root-scoped credentials and the speed of agentic execution (see [Compound Threat Patterns](#compound-threat-patterns))

### What cosai-mcp tests
- **Black-box (partial):** call privileged tool without appropriate scope claim in token → accepted (FAIL) or rejected (PASS)
- **Black-box (T02-003):** call any tool with destructive argument patterns (`action:delete`, `force:true`, `dry_run:false`, `operation:destroy`) → server executes without prior confirmation token (FAIL) or rejects (PASS)
- **Black-box (T02-004):** `tools/list` without elevated scope must not disclose admin/write-scope tool names — if `purge`, `admin`, or write-scoped tools appear in the manifest returned to a read-only caller, the server is leaking attack surface (D-05)
- **Black-box (T02-005):** call a write or delete tool using a `read`-scope token (`probe_token: "read"`) → write tool executes (FAIL) or returns 401/403 (PASS); requires `--read-token` to be configured (A-05/A-06)
- **Stateful harness (full):** scripted 3-turn sequence: low-priv tool call → scope inspection → high-priv tool call; asserts server rejects step 3 without elevated scope grant

### Remediation
- Validate the calling user's permissions for every tool invocation — do not rely on agent-level credentials
- Implement per-tool RBAC; scope tokens to specific tools, not broad resource access
- Use RFC 8693 delegation tokens that encode both agent identity and user identity; backend validates both
- **Implement two-stage commit for all destructive tools:** a `plan` call returns a human-readable description and a short-lived confirmation token; an `execute` call requires the token. One-shot destructive tools are a CoSAI T2/T9 violation regardless of how their description is worded
- Log all privilege checks; alert on unexpected scope elevation

---

## T3 — Input Validation Failures

**CoSAI ref:** T3 | **OWASP MCP Top 10:** A03 | **CWE:** CWE-78, CWE-22, CWE-89

### What it is
Treating LLM-generated tool arguments as trusted input. The LLM constructs `arguments` for `tools/call` — these arguments must be validated by the MCP server with the same rigor as any user-supplied input.

### Attack patterns
- **Command injection:** `{"cmd": "; cat /etc/passwd"}` in a shell-executing tool
- **Path traversal:** `{"path": "../../etc/shadow"}` in a file-reading tool
- **SQL injection:** `{"query": "'; DROP TABLE users; --"}` in a database tool (error-based reflection)
- **NoSQL operator injection:** `{"$ne": null}` smuggled into a query argument
- **SSTI:** `{{1337*1337}}` / `${1337*1337}` evaluated server-side (response echoes `1787569`)
- **XXE:** an XML argument with an external entity referencing `file:///etc/passwd`
- **CRLF / header injection:** `\r\nX-Cosai-Injected: 1` smuggled into a reflected value
- **Oversized payload:** argument value of 100MB causes OOM or timeout
- **Null bytes / Unicode normalization:** bypasses naive string validation

### What cosai-mcp tests
Payloads are **bound to discovered tools** via adaptive synthesis (`cosai_mcp.synthesis`) — the adversarial value is injected into a real string parameter of each discovered tool, not a fictional `cmd`/`query` field, so probes reach the tool's validation logic instead of returning a vacuous `-32602`. A protocol-validation error (`-32602`/`-32601`) on an injection probe is treated as **INCONCLUSIVE**, never a pass.

- Command injection (`T03-001`) + path traversal (`T03-002`) in string/path arguments
- SQL injection — error-based reflection of DB error signatures (`T03-004`)
- NoSQL operator injection (`T03-005`)
- SSTI — distinctive `1337*1337` product detection, near-zero FP (`T03-003`)
- XXE — external-entity `/etc/passwd` exfiltration (`T03-006`)
- CRLF / header injection — reflected response-header smuggling (`T03-007`)
- Null byte injection, oversized arguments (10MB+), Unicode normalization (`%2e%2e/` → `../`)

### Remediation
- Validate every tool argument against a strict JSON Schema before execution
- Use parameterized queries — never string interpolation for DB calls
- Reject paths containing `..` after normalization; resolve to absolute paths and assert they are within the allowed root
- Apply input length limits per argument type
- Return `-32602` (Invalid params) for validation failures — never `-32603` (Internal error) which leaks implementation details

---

## T4 — Data/Control Boundary Violations

**CoSAI ref:** T4 | **OWASP MCP Top 10:** A04 | **CWE:** CWE-74, CWE-77

### What it is
The inability to distinguish between instructions and data in the LLM's context window. An attacker who can write content that the agent reads (a document, a database record, a web page) can inject instructions that redirect the agent's behavior.

### Attack patterns
- **Tool poisoning:** attacker modifies an MCP tool's JSON schema description. When the LLM discovers tools, it reads the poisoned description and may execute the malicious tool or exfiltrate data to an attacker-controlled endpoint. Success rate ~84% with auto-approval enabled.
- **Rug pull:** MCP server appears legitimate during initial security scanning but silently modifies tool definitions via remote update after deployment.
- **Indirect prompt injection:** content retrieved by the agent (a document, search result, email) contains instructions that hijack the agent's next action.
- **Dynamic tool description loading:** tool descriptions are not static strings — they are assembled at runtime by fetching content from an external URL or database record. An attacker who compromises that external source injects malicious instructions into the tool description *after* the MCP server passes any static scanner. This is T4 + T11 combined: the supply chain is the tool description's data source, not its code. (Observed in the wild: ClawHub malicious skill campaign, 2026-Q1.)

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

**CoSAI ref:** T5 | **OWASP MCP Top 10:** A05 | **CWE:** CWE-200, CWE-312

### What it is
Sensitive data leaking through the MCP context: tool responses containing PII, secrets, or proprietary data being logged in plaintext, passed to unauthorized agents, or included in LLM context that flows to third-party model APIs.

### Attack patterns
- **Context leakage:** database tool returns rows containing PII; LLM includes them verbatim in a response to a lower-privileged user
- **Cross-agent context bleed:** stateful context from a high-privilege session leaks into a shared SSE queue consumed by a low-privilege session
- **Credential exfiltration:** tool response contains an API key; agent uses it in a subsequent (unauthorized) tool call

### What cosai-mcp tests (black-box passive scan + middleware)
- **Passive manifest secret scan** (`_scan_manifest_t5`): credentials embedded in tool names/descriptions — AWS `AKIA`, GCP service-account JSON, Azure SAS, GitHub `ghp_/gho_/ghs_`, GitLab `glpat-`, Google `AIza`, JWT. Secrets are redacted to `[REDACTED:<type>]` (never echoed) and HTML-escaped at ingestion.
- **Context-leak patterns** (response-body, middleware): internal hostnames (`*.internal`, `*.svc.cluster.local`), stack traces — T5 is context leakage, not only credentials.
- **Strict tier** (`--pii-strict`, off by default): SSN, IBAN, US phone, and **Luhn-corroborated PAN** (primary regex + Luhn checksum keeps the false-positive rate low).
- Credential/PII scrubbing of tool responses (middleware `PIIScrubber`); context isolation between concurrent sessions.

### Remediation
- Apply PII scrubbing to all tool responses before they enter the LLM context
- Log tool responses only after scrubbing; never log raw API keys or credentials
- Implement session isolation; never share SSE queues between sessions
- Scope database queries to return only fields the requesting user is authorized to see

---

## T6 — Integrity and Verification Failures

**CoSAI ref:** T6 | **OWASP MCP Top 10:** A06 | **CWE:** CWE-345, CWE-494

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

**CoSAI ref:** T7 | **OWASP MCP Top 10:** A07 | **CWE:** CWE-384, CWE-287

### What it is
Weak binding of MCP sessions to user identity. Session tokens that can be fixed by the client, replayed across transport switches, or shared across users enable session hijacking and context-bleed attacks.

### Attack patterns
- **Session fixation:** server accepts a client-supplied session ID rather than generating its own; attacker pre-sets a known session ID and hijacks subsequent authentication
- **Session token in URL:** `Mcp-Session-Id` exposed in server logs, access logs, or referrer headers
- **Cross-transport session replay:** session token issued over HTTPS reused over a downgraded connection
- **Context-bleed:** shared SSE event queue allows session N's events to appear in session M
- **Token revocation bypass:** server does not honour explicit token revocation; a revoked credential issued before a privilege change continues to grant access after the change takes effect
- **MCP confirmation as authorization bypass:** server treats `confirmation=true` in tool arguments as sufficient authorization, skipping OAuth scope validation. An attacker who can influence tool arguments (e.g. via prompt injection) can invoke privileged tools without a valid OAuth scope. Per IETF draft-klrc-aiagent-auth-01: "The agent MUST NOT treat local UI confirmation alone as sufficient authorization."
- **Inverted authorization model:** server requires `confirmation=true` even when the caller holds a valid OAuth scope, effectively delegating the authorization decision to the MCP UI layer rather than to the OAuth authorization server. This is both a usability failure and a security anti-pattern — it makes the server's access control dependent on client-side state.

### What cosai-mcp tests (stateful harness + black-box prober)
- Client-supplied session ID accepted without server regeneration → FAIL
- Session token in URL query parameter → FAIL
- Token replayed in a new session after original session close → accepted (FAIL) or rejected (PASS)
- Concurrent sessions sharing any context → FAIL
- **Revocation scenario (T7-SC-002):** initialize session → call `tools/list` (assert success) → signal revocation via DELETE `/session/{id}` or equivalent → call `tools/list` again using the same session token → must return 401/error (PASS) or continues succeeding (FAIL — revocation not honoured)
- **Black-box (T07-001):** send `Origin: https://evil.example.com` with `tools/list` and `tools/call`; if server echoes `Access-Control-Allow-Origin: *`, any web page can make credentialed MCP requests on behalf of an authenticated user — CORS wildcard must not appear on MCP endpoints (G-02). Uses `probe_headers: {"Origin": "..."}` and `response.header.access-control-allow-origin` assertion target.
- **Black-box (T07-002, critical):** call a sensitive tool with `confirmation=true` in arguments but with a Bearer token whose OAuth scope does not include the tool's required permission. A vulnerable server accepts the call; a secure server returns 403. Two probes: (p1) wrong-scope token + confirmation=true; (p2) no Authorization header + confirmation=true. Both must be rejected. References IETF draft-klrc-aiagent-auth-01.
- **Black-box (T07-003, high):** call a sensitive tool with a valid-scope Bearer token but without a `confirmation=true` argument. A secure server honors the OAuth scope and processes the request; a vulnerable server rejects the call because confirmation is absent, indicating it has inverted its authorization model (confirmation is the gate, not scope).

### Remediation
- Always generate session IDs server-side using a CSPRNG; reject client-supplied session IDs
- Transmit session IDs only in headers (`Mcp-Session-Id`), never in URLs
- Bind session tokens to the originating IP + user identity; reject tokens used from a different binding
- Implement per-session SSE streams; never share a queue between sessions
- Short-lived session tokens (15–60 minutes); refresh via RFC 8693 token exchange
- Implement and test explicit token revocation; a POST to an OAuth revocation endpoint must immediately invalidate all active sessions backed by that token
- **OAuth scope is the authorization gate.** Enforce it on every tool call, evaluated before (not instead of) any MCP UI confirmation check. `confirmation=true` in tool arguments is a UX safeguard that may accompany scope validation but must never replace it.
- Never delegate authorization decisions to client-side state (`confirmation` flag, user-visible dialogs). Authorization must be deterministic server policy backed by the OAuth authorization server.

---

## T8 — Network Binding Failures

**CoSAI ref:** T8 | **OWASP MCP Top 10:** A08 | **CWE:** CWE-668, CWE-441

### What it is
MCP endpoints exposed beyond their intended network boundary. A local MCP server bound to `0.0.0.0` is reachable from the network, not just localhost. Poorly isolated multi-tenant environments expose one tenant's MCP server to another.

### Attack patterns
- **0.0.0.0 binding:** local development server exposed to the network; reachable by other hosts on the same network
- **SSRF via tool — cloud metadata:** a URL-fetching tool called with `http://169.254.169.254/` (AWS IMDSv1 **and** the IMDSv2 token endpoint), `http://metadata.google.internal/` (GCP), Azure IMDS, or Alibaba `100.100.100.200` — steals instance credentials
- **SSRF via tool — schemes & internal nets:** `file:///etc/passwd`, RFC1918, IPv6 ULA/link-local (`fd00::`, `fe80::`) targets
- **Shadow MCP server:** attacker runs an MCP server on the same host that intercepts tool calls intended for the legitimate server

### What cosai-mcp tests
- Server responds on a non-loopback interface when it should be loopback-only → flagged
- SSRF probes call URL-fetching tools with cloud-metadata endpoints and assert the metadata signature does **not** appear in the response:
  - AWS IMDSv1 (`T08-001`) + IMDSv2 token endpoint (`T08-006`)
  - GCP metadata (`T08-004`), Azure IMDS (`T08-005`), Alibaba ECS (`T08-007`)
  - `file://` scheme (`T08-008`); IPv6 ULA/link-local (`T08-009`) — a fetch instead of rejection is the finding
- Tool list diff between two scans — new tools appearing without deployment signal a shadow server

### Remediation
- Bind local MCP servers to `127.0.0.1` only; never `0.0.0.0` in development
- Implement URL allowlisting for any tool that fetches external content
- Block RFC1918, link-local, and loopback targets in URL-fetching tools before execution
- Run MCP servers in network-isolated containers; only expose the endpoint explicitly

---

## T9 — Trust Boundary Failures

**CoSAI ref:** T9 | **OWASP MCP Top 10:** A09 | **CWE:** CWE-602, CWE-807

### What it is
Delegating security-critical validation to the LLM's judgment. A model may be deceived into approving actions it should reject, treating attacker-controlled content as trusted instructions, or failing to apply security checks consistently.

### Attack patterns
- **Auto-approval reliance:** security checks are implemented as LLM prompts ("only proceed if this looks safe") rather than deterministic controls
- **Semantic bypass:** attacker rephrases a malicious request in a way that reads as benign to the model
- **Context overflow:** flooding the context window with benign content pushes safety instructions out of the model's effective window

### What cosai-mcp tests (passive manifest scan — Totem layer)
The scanner passively inspects `tools/list` for **Totem violations**: destructive tools that lack a two-stage commit pattern. A tool is flagged when its name contains an unambiguously-destructive verb (delete, remove, drop, destroy, wipe, purge, reset, revoke, terminate, cancel, truncate, flush, erase, uninstall, deactivate, deregister) and it has neither a `confirmed`/`dry_run` boolean parameter nor a `_preview`/`_plan` sibling tool. This is the structural check for TKA Totem compliance — the first layer of the CoSAI WS4 T9 contribution: *no probabilistic component holds commit authority over irreversible state without explicit human confirmation*. Findings surface as SARIF rule `T09-001` at HIGH severity.

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

**CoSAI ref:** T10 | **OWASP MCP Top 10:** A10 | **CWE:** CWE-400, CWE-770

### What it is
Unbounded resource consumption by agentic workflows. Infinite reasoning loops, recursive tool calls, or unbounded API calls incur extreme costs ("Denial of Wallet") or exhaust system resources.

### Attack patterns
- **Infinite tool call loop:** agent design allows tool A to call tool B which calls tool A; no depth limit
- **Unbounded response size:** tool returns gigabyte-sized responses; scanner or agent OOMs
- **No rate limiting:** attacker calls `tools/call` at maximum rate; server exhausts DB connections or API quota
- **Cost amplification:** each tool call triggers expensive LLM inference; attacker triggers thousands of calls

### What cosai-mcp tests
- **T10-004:** Rapid-fire requests (`probe_count: 30` for `tools/list`, `probe_count: 20` for `tools/call`); if all requests return HTTP 200, no rate limiting is enforced — at least one must return 429 or 503 (PASS) (H-03)
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

**CoSAI ref:** T11 | **OWASP MCP Top 10:** A11 | **CWE:** CWE-494, CWE-1357

### What it is
Malicious or compromised MCP server packages distributed via agent marketplaces or package registries. The MCP ecosystem's nascent marketplace ("skills", "plugins") creates a supply chain analogous to npm or PyPI but with fewer established security practices.

### Attack patterns
- **Typosquatting:** `anthropic-mcp-tools` vs `anthropic-mcp-tool` — one character difference, one is malicious
- **Poisoned package:** legitimate package taken over; malicious update ships with modified tool definitions (real-world: **CVE-2026-21852** — MCP server package on PyPI with identical name to a widely-used internal tool; post-compromise update shipped a reverse shell as a tool definition)
- **Unsigned skills:** marketplace skills distributed without code signing; no integrity verification at install
- **Dependency confusion:** internal MCP server package name matches a public package; public version installed instead
- **ClawHub malicious skill campaign (2026-Q1):** 1,184 skills identified on the ClawHub marketplace containing dormant payloads that activated on specific prompt patterns; 63K live instances reachable via Censys

### What cosai-mcp tests (passive manifest scan — `--tool-allowlist`)
The legacy "ask for a fictional tool name, treat `-32601` as a pass" probe is a **vacuous liveness check** — every conformant server passes it. The real black-box T11 surface an external scanner *can* decide is the operator's approved-tool allowlist (`_scan_manifest_t11`):

- **Typosquat:** a discovered tool within Levenshtein distance 1 of an approved name but not equal to it (e.g. `serch` vs approved `search`) → flagged.
- **Unexpected tool:** a discovered tool not on the allowlist and not a near-miss → flagged as a possible unauthorized / rug-pull addition.
- **Without `--tool-allowlist`:** there is no approved set to compare against, so T11 is reported **INCONCLUSIVE (not clean)** and the scan warns — it never silently false-greens.

Registry-signature verification, version-pin drift, and rug-pull detection are inventory/middleware concerns — use `cosai inventory` drift tracking and SCA pre-deploy.

### Remediation
- Maintain an explicit allowlist of approved MCP servers by origin and version
- Require cryptographic signatures for all installed MCP skills; verify at install time
- Use dependency pinning with hash verification (similar to `pip install --require-hashes`)
- Run SCA (Software Composition Analysis) on MCP server dependencies before deployment (Snyk Agent Scan or Enkrypt AI); catches CVEs like CVE-2026-21852 before deploy
- Monitor for new versions of installed MCP packages; verify signatures before auto-update
- **Deploy MCP servers in hardware-isolated containers** (gVisor or Kata Containers) with remote attestation — a compromised supply chain package cannot escape the container boundary; remote attestation verifies the execution environment before the server is trusted by the orchestrator

---

## T12 — Insufficient Logging

**CoSAI ref:** T12 | **OWASP MCP Top 10:** A12 | **CWE:** CWE-778, CWE-223

### What it is
Lack of immutable, causally-linked execution traces for agentic workflows. Traditional event logging records what happened; agentic systems require execution traces that record why it happened — the causal chain from user prompt through LLM reasoning to tool invocation.

### What's missing without execution traces
When an incident occurs (agent leaks proprietary data, executes unauthorized action), a log of the event provides no evidence of culpability. The investigation cannot determine whether the cause was:
- Direct prompt injection from a user
- Indirect prompt injection from a tool (T4)
- Model hallucination due to context overflow
- A legitimate authorized action

### What cosai-mcp tests (middleware instrumentation + black-box)
The audit middleware instruments:
- Whether tool invocations are logged with a DAG causal chain (parent_id linking concurrent/nested calls)
- Whether logs are append-only and tamper-evident (SHA-256 hash chain)
- Whether log content carries enough context to reconstruct the tool-call sequence

The black-box prober (T12-002) checks tool description transparency:
- **T12-002-p1:** `tools/list` must succeed — tool descriptions must be enumerable for audit
- **T12-002-p2 (info):** at least one tool description must include explicit irreversibility disclosure for destructive operations. FAIL means either no tool warns about irreversibility or no destructive tools exist (manual review required)

### The cosai-mcp audit log
cosai-mcp's own middleware implements an MCP-layer execution trace:

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

### MCP-layer scope vs the full CoSAI "flight recorder"

The CoSAI whitepaper describes a DAG that cryptographically links: **prompt → retrieved context → internal thought → tool invocation**. The MCP middleware layer can only observe the tool-invocation segment. Here is the honest boundary:

| Component | In cosai-mcp audit log? | Why |
|-----------|------------------------|-----|
| Tool invocations (name, arg-hash, result-status) | ✅ Yes | MCP middleware sees every `tools/call` |
| DAG causal chain (parent_id, nested/concurrent calls) | ✅ Yes | Built via parent_id field + `build_dag()` |
| Session binding (session_id per entry) | ✅ Yes | Session token injected at middleware boundary |
| Hash chain (tamper-evident append-only log) | ✅ Yes | SHA-256 chain, `cosai audit verify` |
| `resources/read` context retrieval | ⚠️ Gap | MCP middleware could log this; not yet implemented |
| Original user prompt | ❌ Out of scope | Lives in the LLM host application, not MCP layer |
| LLM internal reasoning ("thought") | ❌ Out of scope | LLM-internal; inaccessible to any middleware |

**The prompt and reasoning pathway cannot be recorded by MCP middleware** — they exist entirely within the LLM host (e.g., Claude, GPT-4). No MCP scanner or middleware can reach them. Complying with the full CoSAI "flight recorder" concept requires the LLM host to emit a trace that is then *correlated* with the MCP-layer trace using the session ID.

**The `resources/read` gap is fixable.** Context retrieval via `resources/read` is an MCP-layer event that cosai-mcp middleware currently does not log. Adding it would close the middle segment of the causal chain (prompt_hash → context_refs → tool invocation) that the example JSON above already shows as populated. This is tracked as a P8 enhancement.

### Remediation
- Implement hash-chained execution trace logging for all tool invocations
- Log: session ID, user ID, agent ID, prompt hash, context references, tool name, argument hash, result status
- Store traces in an append-only log; verify chain integrity on demand
- Retain traces per your compliance requirement (typically 90 days minimum for SOC 2)
- Integrate traces into your SIEM with alerts on chain breaks or unexpected tool call patterns
- **Tool description transparency:** tool descriptions for destructive operations must explicitly state that the action is irreversible (e.g. "This action permanently deletes the resource and cannot be undone"). Combine with T02-003 two-stage commit so the LLM sees the warning before issuing a confirmation

---

## Compound Threat Patterns

Some incidents involve multiple CoSAI categories firing simultaneously. Understanding compound patterns is critical for agentic systems where a single autonomous decision can chain multiple failures.

### "Destructive Agentic Blast Radius" — T2 + T9 + T12

**Pattern:** An agentic LLM calls a destructive tool without human confirmation, executing irreversible changes at machine speed.

**Anatomy:**
| Layer | Failure | CoSAI category |
|-------|---------|----------------|
| Authorization | Tool accepts one-shot destructive call — no confirmation token required | T2 (Missing Access Control) |
| Trust boundary | Agent relies on LLM judgment to decide whether destructive action is safe — no deterministic policy gate | T9 (Trust Boundary Failures) |
| Observability | No pre-execution signal or tool description warning — operator cannot interrupt before damage occurs | T12 (Insufficient Logging) |

**Amplifiers:**
- Root-scoped or overly broad credentials (no least-privilege on the service account)
- Backup stored alongside primary data — deletion is total
- Agentic execution speed: 9 seconds from decision to irreversible action (documented in PocketOS 2026 incident)

**Remediation (all three layers required):**
1. **T2:** Two-stage commit — plan call returns description + confirmation token; execute requires token
2. **T9:** Deterministic policy gate — server enforces confirmation, never delegates to LLM judgment
3. **T12:** Pre-execution logging + description transparency — operator sees what will happen before it does

**Detection with cosai-mcp:**
```bash
cosai scan http://your-mcp-server --categories T2,T9,T12 --fail-on critical
```

T02-003 (destructive one-shot) fires first. If it passes, T12-002 checks description transparency. A server that passes both gives operators a meaningful human-in-the-loop opportunity before irreversible actions execute.

### PocketOS 2026 Incident Reference

A Railway volume containing production data and its only backup was deleted by an agentic system in under 10 seconds. Root causes mapped to CoSAI categories:

| Root cause | CoSAI category | cosai-mcp probe |
|------------|---------------|-----------------|
| Railway API volume delete accepted single call — no confirmation required | T2 | T02-003 |
| Root-scoped token with no tool restriction | T2 | T02-001 (privilege scope) |
| Agent acted on LLM judgment without deterministic policy gate | T9 | Middleware |
| No pre-execution warning in tool description | T12 | T12-002 |
| Backup co-located with primary (no off-volume backup) | Out of scope | Infrastructure |

The T2 + T9 failure was necessary and sufficient for the data loss. T12 transparency failure removed the last human-observable signal before execution.

---

## Probe Modifier Fields

Catalog probes support three optional modifier fields that extend basic JSON-RPC probing:

### `probe_token: "read"`

Instructs the scanner to use `config.read_token` (set via `--read-token`) instead of the primary auth token. Used by T02-005 to test whether write tools correctly reject read-scope callers.

```json
{
  "id": "T02-005-p1",
  "probe_token": "read",
  "method": "tools/call",
  "payload": {"name": "{{tool_name}}", "arguments": {}},
  "assertions": [{"target": "response.error", "operator": "eq", "value": true}]
}
```

If `--read-token` is not configured, the probe reports `INCONCLUSIVE` rather than `FAIL` — scope enforcement cannot be tested without two distinct tokens.

### `probe_count: N`

Repeats the probe N times and passes on the first response that satisfies all assertions. Used by T10-004 to detect rate limiting: 30 rapid `tools/list` calls must trigger at least one 429.

```json
{
  "id": "T10-004-p1",
  "probe_count": 30,
  "method": "tools/list",
  "assertions": [{"target": "response.status_code", "operator": "status_in", "value": [429, 503]}]
}
```

### `probe_headers`

Extra HTTP headers injected into the probe request. Used by T07-001 to test CORS policy:

```json
{
  "id": "T07-001-p1",
  "probe_headers": {"Origin": "https://evil.example.com"},
  "method": "tools/list",
  "assertions": [
    {"target": "response.header.access-control-allow-origin", "operator": "ne", "value": "*"}
  ]
}
```

### `response.header.<name>` assertion target

Assertions can target any HTTP response header by name (case-insensitive). Used by T07-001 to inspect `Access-Control-Allow-Origin`. Example: `"target": "response.header.retry-after"`.

---

## Adding New Threat Definitions

See [CONTRIBUTING.md](CONTRIBUTING.md) for the JSON schema and signing process to add new threat definitions to the catalog.
