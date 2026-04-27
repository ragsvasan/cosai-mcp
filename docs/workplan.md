# cosai-mcp — End-to-End Implementation Workplan

**Date:** 2026-04-26
**Status:** Architecture panel complete (CONDITIONAL PASS). Ready to implement.
**Full panel record:** [architecture-decisions.md](architecture-decisions.md)

---

## How to read this document

- **→** means "depends on" (sequential)
- **‖** means "can run in parallel"
- **[T1]** / **[T2]** = panel tier per global CLAUDE.md rules
- Panel = agents spawned to review before commit gate
- Every phase ends with: panel → fix → tests green → commit

---

## Dependency Graph

```
P0: Scaffold
  ‖
  ├── P1: Transport + MCPSession
  ‖
  └── P2: Catalog System
        ↓ (both complete)
      P3: Probe Harness
        ↓
  ┌─────┴──────┬─────────┬──────────┐
  P4a          P4b       P5         P6
  Probes T1/T3 Probes    Report     Stateful
  T8/T10       T2/T6/T11 Engine     Harness T2/T6/T7
  (‖ within)             ‖          ‖
  └─────┬──────┘─────────┤──────────┘
        ↓                ↓          ‖
      P4c                P7
      Gap probes         Middleware
      T5/T8-003          T4/T9/T12
      T10-003            ‖
      T06-002            ‖
        ↓                ↓
      P8: CLI +
      Adoption Paths
        ↓
      P9: CI/CD + Supply Chain
```

P1 ‖ P2 → P3 → (P4a ‖ P4b ‖ P5 ‖ P6 ‖ P7) → P4c → P8 → P9

---

## Phase 0 — Project Scaffold

**What:** Bare project skeleton. No logic. Just the structure every subsequent phase builds into.

**Delivers:**
- `pyproject.toml` with all declared deps (`httpx`, `google-re2`, `joserfc`, `keyring`, `websockets`, optional groups: `[pytest]`, `[dev]`)
- Package namespace: `cosai_mcp/` with `__init__.py` stubs only
- Directory structure per CLAUDE.md "Planned Project Structure"
- `catalog/official/` and `catalog/custom/` with `.gitkeep`
- `tests/` with `conftest.py` stub (MCP_TARGET_URL fixture placeholder)
- `pytest.ini` / `pyproject.toml` test config
- `.github/workflows/ci.yml` skeleton (lint + test jobs, no logic)
- `LICENSE` (Apache 2.0)

**Tests:** None — scaffold only. `pytest --collect-only` must exit 0 (no collection errors).

**Panel:** T3 — Skip (no logic, no auth/db paths).

**Commit gate:**
```
pytest --collect-only   # exits 0
python -m cosai_mcp --help   # exits 0 (stub)
```

**Commit:** `scaffold: project skeleton, pyproject.toml, CI stub`

---

## Phase 1 — Transport Layer + MCPSession  ‖  Phase 2

**What:** The two foundational systems. Run in parallel — no interdependency until Phase 3.

---

### Phase 1 — Transport Layer + MCPSession

**Delivers:**
- `cosai_mcp/transport/base.py` — `Transport` ABC: `connect()`, `send(method, params)`, `recv()`, `close()`
- `cosai_mcp/transport/streamable_http.py` — Streamable HTTP (MCP 2025-03-26 primary)
  - Custom `httpx` transport: `follow_redirects=False`, `trust_env=False`, IP-pinned socket-level allowlist
  - RFC1918 / link-local / loopback / IPv6 ULA rejection at connect time
  - Single endpoint, returns direct JSON or `text/event-stream`
  - `Mcp-Session-Id` header handling
- `cosai_mcp/transport/legacy_sse.py` — LegacySSE (2024-11-05 backward compat only)
- `cosai_mcp/transport/stdio.py` — stdio with: `shell=False`, fixed argv, `close_fds=True`, filtered env (PATH + COSAI_* only), `start_new_session=True`, stdout/stderr size-capped 10MB, line-length-capped, control-char-stripped
- `cosai_mcp/session.py` — `MCPSession`:
  - `initialize()` → sends `initialize` request, handles `protocolVersion` negotiation (2024-11-05 / 2025-03-26), triggers transport fallback if needed
  - `initialized()` → sends `initialized` notification
  - `tools_list()` → fetches and caches tool manifest
  - `tools_call(name, arguments)` → asserts handshake complete first
  - `close()`
  - Returns `scan-incomplete` status if handshake fails (never `clean`)

**Tests (`tests/transport/`):**
- `test_streamable_http_connect` — mock server, asserts IP pinned at resolve
- `test_network_allowlist_rejects_rfc1918` — connect to 10.0.0.1 rejected
- `test_network_allowlist_rejects_link_local` — connect to 169.254.x.x rejected
- `test_network_allowlist_no_redirect` — 307 to evil.example.com not followed; flagged SUSPICIOUS
- `test_network_allowlist_dns_rebinding` — IP changes between resolve and connect; rejected
- `test_trust_env_false` — HTTP_PROXY env var not honored
- `test_stdio_shell_false_injection` — argv with `; rm -rf /tmp/x`; asserts OSError not shell exec
- `test_stdio_env_filtered` — child cannot read COSAI_PUBKEY
- `test_stdio_stderr_size_cap` — 11MB stderr stream; asserts truncated at 10MB
- `test_session_initialize_before_tools_call` — asserts `initialize` sent before any `tools/call`
- `test_session_protocol_version_negotiation` — server offers 2024-11-05; asserts SSE fallback
- `test_session_tools_list_cached` — `tools_list()` called once; asserts second call uses cache
- `test_session_incomplete_on_handshake_fail` — server rejects `initialize`; asserts status=`scan-incomplete`
- `test_regression_initialize_before_tools_call`
- `test_regression_transport_fallback_sse`

**Panel:** T1 Full — new auth/network security handshake.
- Sonnet: Correctness + Security + MCP Protocol (parallel)
- Opus: Adversary — "the network allowlist is the primary defense; construct the bypass that works in Python without OS-level controls"
- Must include: "Is this the industry-standard approach for this problem class? Name the standard. Would this pass a SOC 2 / penetration test review?"

**Commit gate:**
```
pytest tests/transport/ -v          # all green
pytest tests/transport/ --tb=short  # zero failures
```

**Commit:** `feat(transport): Streamable HTTP + stdio + MCPSession with handshake lifecycle`

---

### Phase 2 — Catalog System  ‖  Phase 1

**Delivers:**
- `cosai_mcp/catalog/schema.py` — JSON meta-schema (jsonschema strict mode); unknown fields rejected
- `cosai_mcp/catalog/loader.py` — `CatalogLoader`:
  - Ed25519 signature verification; public key as bytes literal in `cosai_mcp/keys.py`
  - `COSAI_PUBKEY` env var override path
  - Provenance from load path only (`catalog/official/` vs `catalog/custom/`)
  - Path resolution confined to `catalog/`; absolute paths rejected
  - Custom catalog gated behind `--allow-custom-catalog` (off by default)
  - `matches_regex` patterns validated via `google-re2` at load time; RE2 refusal → `UnsafePatternError`
  - `matches_regex` disabled in custom files unless `--allow-regex-in-custom`
- `cosai_mcp/catalog/models.py` — frozen dataclasses with `tuple`/`MappingProxyType` for all containers
- `cosai_mcp/catalog/template.py` — template substitution:
  - Operates on parsed Python dict (before `json.dumps`)
  - Variable allowlist: `{{target_url}}`, `{{session_id}}`, `{{tool_name}}`
  - Post-substitution `{{` detection → abort with `TemplateInjectionError`
  - Probe destination (target host) is NOT substitutable — comes from CLI config only
- `catalog/official/` — first signed threat definition: `T01-001.json` (example for testing)
- `cosai_mcp/keys.py` — Ed25519 public key as bytes literal

**Tests (`tests/catalog/`):**
- `test_signature_valid` — valid Ed25519 signature; loads cleanly
- `test_signature_tampered` — wrong key; raises `SignatureVerificationError`
- `test_signature_wrong_pubkey_env` — COSAI_PUBKEY override with wrong key; fails
- `test_schema_unknown_field_rejected` — extra field in JSON; raises `SchemaValidationError`
- `test_schema_closed_operator_enum` — invalid operator value; rejected
- `test_path_traversal_rejected` — `../../../etc/passwd` in path field; rejected
- `test_custom_catalog_disabled_by_default` — no flag; custom files not loaded
- `test_custom_catalog_enabled_with_flag` — `--allow-custom-catalog`; loads
- `test_redos_pattern_rejected` — `(a+)+$` in `matches_regex`; raises `UnsafePatternError`
- `test_regex_disabled_in_custom_without_flag` — custom file with `matches_regex`; rejected
- `test_template_no_double_expansion` — variable value is `{{target_url}}`; not recursively expanded
- `test_template_no_json_injection` — value contains `"; "evil": true`; no injected key
- `test_template_injection_detected` — value contains `{{` after sub; raises `TemplateInjectionError`
- `test_probe_destination_not_catalog_controlled` — catalog cannot specify arbitrary URL target
- `test_provenance_from_load_path` — custom dir file cannot claim official provenance
- `test_frozen_dataclass_no_list_mutation` — `cwe` field is `tuple`; `.append()` raises `AttributeError`
- `test_regression_redos_pattern_rejected`
- `test_regression_template_no_double_expansion`
- `test_regression_template_no_json_injection`

**Panel:** T1 Full — catalog is security-critical (code execution prevention, supply chain).
- Sonnet: Correctness + Security
- Opus: Adversary — "construct the catalog entry that achieves code execution or data exfiltration from within the allowlist model"
- Must include standard question.

**Commit gate:**
```
pytest tests/catalog/ -v    # all green
```

**Commit:** `feat(catalog): JSON loader, Ed25519 verification, schema validation, RE2 pattern guard`

---

## Phase 3 — Probe Harness  (→ P1 + P2)

**What:** The execution engine. Bridges the transport/session layer and catalog models into runnable, isolated probe jobs.

**Delivers:**
- `cosai_mcp/harness/runner.py` — `ProbeRunner`:
  - Dispatches each probe to its own `multiprocessing.Process`
  - Results returned as JSON-serialized frozen dataclasses (no shared memory)
  - OS-level timeout via `multiprocessing` terminate (not Python thread timeout)
  - Catches process exit codes, OOM, segfault — maps all to `ProbeStatus.ERROR` (fail-closed)
  - HTML-escapes all response content at ingestion (`html.escape(quote=True)`), stored in result; raw content in `_raw_unsafe` field (internal only)
- `cosai_mcp/harness/result.py` — `ProbeResult` frozen dataclass: `status`, `finding`, `evidence` (escaped), `_raw_unsafe`, `elapsed_ms`, `probe_id`, `error_code`
- `cosai_mcp/harness/assertions.py` — assertion evaluator for all operators including `error_code_in`; evaluates against structured response (not string), checking `response.error.code` not just `response.error == true`
- `cosai_mcp/harness/context.py` — `ProbeContext`: wraps `MCPSession` + current `target_host` IP + scan config; passed into each probe process
- `cosai_mcp/harness/mock_server.py` — test-only MCP mock server (in-process, configurable responses, full handshake support) — used by all test phases

**Tests (`tests/harness/`):**
- `test_probe_state_isolation` — probe-1 sets module-level sentinel; probe-2 cannot observe it
- `test_probe_timeout_os_enforced` — probe sleeps forever; terminated at timeout; result is ERROR not hang
- `test_probe_crash_maps_to_error` — probe raises RuntimeError; result status is ERROR
- `test_probe_oom_maps_to_error` — probe allocates 2GB; process killed; result is ERROR
- `test_html_escape_at_ingestion` — response body `<script>alert(1)</script>`; asserts result.evidence contains `&lt;script&gt;`
- `test_raw_unsafe_not_in_serialized_result` — `_raw_unsafe` field not present in JSON output
- `test_assertion_error_code_granularity` — assertion targets `response.error.code eq -32602`; mock returns -32603; asserts FAIL
- `test_assertion_error_code_in` — `error_code_in [-32602, -32601]`; mock returns -32602; asserts PASS
- `test_probe_result_immutable` — attempts mutation of ProbeResult; raises
- `test_regression_probe_state_isolation`
- `test_regression_html_escape_before_template`
- `test_regression_error_code_assertion`

**Panel:** T1 Full — probe harness is the highest-risk component (process isolation, fail-closed semantics, HTML escaping).
- Sonnet: Correctness + Security (process isolation model, assertion evaluator, escaping order)
- Opus: Adversary — "construct the malicious MCP response that escapes the harness or contaminates a subsequent probe's result"
- Standard question required.

**Commit gate:**
```
pytest tests/transport/ tests/catalog/ tests/harness/ -v   # all green (full regression)
```

**Commit:** `feat(harness): multiprocessing probe runner, OS-level isolation, fail-closed result model`

---

## Phase 4a — Black-box Probes: T1 / T3 / T8 / T10  ‖  4b / 5 / 6 / 7

**What:** The probe definitions for the four categories where black-box probing is the primary mechanism. All four probe files can be written in parallel within this phase.

### Parallel workstreams within Phase 4a

**T1 — Improper Authentication (`tests/probes/t01_auth_probes.py` + `catalog/official/T01-*.json`)**
- Probes: missing auth header accepted, token replay accepted, cross-session token accepted, OAuth proxy detection, DPoP binding not enforced
- `cosai_mcp/middleware/auth.py` — scanner self-protection: ephemeral DPoP key pair via `joserfc`; `htu`/`htm`/`iat`/`jti` claims; `DPoP-Nonce` challenge/response; separate from T1 probe logic

**T3 — Input Validation (`tests/probes/t03_validation_probes.py` + `catalog/official/T03-*.json`)**
- Probes: command injection via tool args, path traversal in file params, SQL injection in query params, oversized payload, null bytes, Unicode normalization attacks
- Each probe asserts `response.error.code` in invalid-params range (not Internal error)
- `cosai_mcp/middleware/validation.py` — scanner self-protection: JSON schema strict mode on all inbound responses before processing

**T8 — Network Binding (`tests/probes/t08_network_probes.py` + `catalog/official/T08-*.json`)**
- Probes: server bound to 0.0.0.0 instead of localhost, SSRF via tool-initiated outbound, shadow server detection (tool list changes between scans)
- `cosai_mcp/middleware/network.py` — scanner self-protection: bind address validation (already in Transport layer; middleware asserts it)

**T10 — Resource Management (`tests/probes/t10_resources_probes.py` + `catalog/official/T10-*.json`)**
- Probes: no rate limiting (rapid-fire tools/call), unbounded response size, infinite SSE stream with no timeout, recursive tool call loop detection
- `cosai_mcp/middleware/resources.py` — scanner self-protection: heartbeat, budget counter, loop detection (probe harness already enforces per-probe timeout; middleware adds cross-probe budget)

**Tests per category file:**
- Unit tests for each probe definition (mock server returns vulnerable / patched responses; asserts correct PASS/FAIL)
- Assertion correctness: verify `error_code` granularity on injection probes (T3)
- `test_regression_tools_list_before_call` (all categories)
- `test_regression_probe_uses_discovered_tools` (T3, T8)

**Panel:** T2 Sonnet — probe definitions are security-relevant but not new auth/session handshakes.
- Sonnet: Correctness + Security (are the probes actually testing what they claim? false-positive/false-negative analysis)
- Standard question: "Would these probes pass a penetration tester's coverage review for each category?"

**Commit gate:**
```
pytest tests/transport/ tests/catalog/ tests/harness/ tests/probes/t01_* tests/probes/t03_* tests/probes/t08_* tests/probes/t10_* -v
```

**Commit:** `feat(probes): black-box probe suite T1/T3/T8/T10 + middleware self-protection`

---

## Phase 4b — Black-box Probes: T2 / T6 / T11 (partial)  ‖  4a / 5 / 6 / 7

**What:** Partial black-box coverage for T2, T6, T11. Full coverage requires the stateful harness (Phase 6). README matrix must document what is and is not covered here.

**T2 — Missing Access Control (partial) (`tests/probes/t02_authz_probes.py`)**
- Probes coverable by one-shot: cross-tool auth bypass (call privileged tool without scope), confused deputy via crafted tool name
- NOT covered by black-box: multi-turn privilege escalation chains → flagged as `partial-coverage` in report
- `cosai_mcp/middleware/authz.py` — scanner self-protection: per-tool RBAC; tool name in `tools/list` validates against allowlist before call

**T6 — Integrity / Verification (partial) (`tests/probes/t06_integrity_probes.py`)**
- Probes coverable by one-shot: tool list manifest anomaly detection (new tool since baseline scan), unsigned tool definition, tool with mismatched schema
- NOT covered: shadowing activated mid-session → stateful harness (Phase 6)
- `cosai_mcp/middleware/integrity.py` — scanner self-protection: baseline manifest diff on re-scan; `tools/list` response signed or schema-validated

**T11 — Supply Chain (partial) (`tests/probes/t11_supply_chain_probes.py`)**
- Probes coverable by one-shot: tool with typosquatted name (Levenshtein distance vs. allowlist), tool returning unexpected registry origin
- `cosai_mcp/middleware/supply_chain.py` — scanner self-protection: tool name allowlist at scan config level

**Tests:** Same pattern as 4a — mock server, PASS/FAIL per probe, partial-coverage markers verified in output.

**Panel:** T2 Sonnet.

**Commit gate:**
```
pytest tests/probes/t02_* tests/probes/t06_* tests/probes/t11_* -v
```

**Commit:** `feat(probes): partial black-box coverage T2/T6/T11 with partial-coverage markers`

---

## Phase 4c — Gap Closure: T5 / T8-003 / T10-003 / T6-002 / T1-003  (→ P4a + P4b)

**What:** Fills the coverage gaps identified in the 2026 CoSAI whitepaper cross-reference. Five targeted additions — new catalog entries, probe tests, and two middleware implementations. This is the last black-box phase before the stateful harness (P6) and report engine (P5).

**Status:** NEXT — slotted after P4a + P4b + P7 complete.

### T5 — Inadequate Data Protection (`protection.py` + catalog probes)

**Delivers:**
- `cosai_mcp/middleware/protection.py` — PII scrubber:
  - RE2 patterns for: SSN (`\d{3}-\d{2}-\d{4}`), credit card (Luhn-checkable 13–16 digits), email, US phone, JWT header (`eyJ`...), common API key formats (40-char hex, `sk-...`, `ghp_...`)
  - `PIIScrubber.scrub(text) -> ScrubResult`: replaces matches with `[REDACTED:<type>]`; returns `ScrubResult(text, redacted_count, findings)`
  - `ContextLeakChecker.check(session_id, content)`: flags content that contains another session's ID (cross-session bleed signal)
  - All patterns RE2-only — no backtracking; validated at module load
- `catalog/official/T05-001.json` — context leakage probe: tools/call to a data-returning tool; asserts response body does NOT contain SSN / credit card / API key patterns
- `catalog/official/T05-002.json` — credential exfiltration probe: tool response with `Authorization: Bearer sk-...`; asserts scrubbed before reaching caller

**Tests (`tests/middleware/test_t5_protection.py`):**
- `test_ssn_pattern_scrubbed` — `"SSN: 123-45-6789"` → `"SSN: [REDACTED:ssn]"`
- `test_credit_card_scrubbed` — 16-digit Luhn-valid number scrubbed
- `test_jwt_header_scrubbed` — `eyJhbGciOi...` replaced
- `test_api_key_sk_scrubbed` — `sk-abc123...` (40 chars) replaced
- `test_ghp_token_scrubbed` — `ghp_...` GitHub PAT replaced
- `test_clean_text_unchanged` — benign text; `redacted_count == 0`
- `test_multiple_pii_types` — SSN + email in same string; both redacted
- `test_context_leak_checker_flags_foreign_session_id` — content contains `sess_XYZ` while current session is `sess_ABC` → flagged
- `test_context_leak_checker_passes_own_session` — own session ID in own response → not flagged
- `test_re2_patterns_validated_at_load` — confirm module loads without RE2 compile error
- `test_t05_001_catalog_loads` — T05-001.json passes schema validation + signature check
- `test_t05_001_secure_server_passes` — server returns clean data → probe passes
- `test_t05_001_vulnerable_server_fails` — server returns SSN in body → probe fails
- `test_t05_002_credential_exfil_rejected` — server returns Bearer token in body → probe fails

**Catalog signing:** `catalog/official/T05-001.json.sig` + `T05-002.json.sig` (Ed25519).

---

### T8-003 — 0.0.0.0 Binding Detection (`catalog/official/T08-003.json`)

**Context:** T08-001 and T08-002 cover SSRF and protocol version. The primary T8 risk from the CoSAI whitepaper — a server bound to `0.0.0.0` instead of loopback — has no catalog entry yet.

**Delivers:**
- `catalog/official/T08-003.json` — probe: connect to the target on a non-loopback interface IP (the scanner detects the server's actual bind address by checking if it responds on its LAN IP, not just localhost); assert that if the scan target is `127.0.0.1:PORT`, connecting to the same PORT on the non-loopback interface FAILS (connection refused or timeout)
  - Implementation note: this probe sends an `initialize` to `http://<LAN_IP>:<port>` (substituted via scan config, not catalog-controlled); asserts `response.error == true` or connection refused → PASS means server is properly loopback-bound
- `cosai_mcp/middleware/network.py` — `BindAddressValidator`:
  - `is_loopback_only(host) -> bool`: resolves hostname; returns `True` if all resolved IPs are in loopback range
  - `check_bind_address(host, port) -> BindCheckResult`: attempts connect; classifies as loopback-only or exposed

**Tests (`tests/probes/test_t08_binding.py`):**
- `test_t08_003_catalog_loads` — T08-003.json passes schema + signature
- `test_loopback_bound_server_passes` — server only responds on 127.0.0.1; probe passes
- `test_exposed_server_fails` — server responds on 0.0.0.0 equivalent; probe fails
- `test_bind_address_validator_loopback` — `127.0.0.1` classified as loopback-only
- `test_bind_address_validator_nonloopback` — `0.0.0.0` classified as exposed
- `test_all_t08_probes_pass_on_secure_server` — T08-001 + T08-002 + T08-003 all pass

---

### T10-003 — Recursive Payload / Denial of Wallet (`catalog/official/T10-003.json` + `resources.py`)

**Context:** DoW (Denial of Wallet) — one tool call triggering unbounded recursive LLM inference — is the highest-cost T10 attack pattern. Rate limiting (T10-002) and size limiting (T10-001) are done. Recursive depth and progress notifications are not.

**Delivers:**
- `catalog/official/T10-003.json` — two probes:
  - p1: tools/call with a payload designed to trigger maximum depth (nested JSON structure `{"a": {"a": {"a": ...}}}` 20 levels deep); asserts response.error (server rejects or depth-limits)
  - p2: long-running tools/call (simulated via SSE stream); asserts a `notifications/progress` event appears within 5 seconds (heartbeat present)
- `cosai_mcp/middleware/resources.py` — `BudgetEnforcer` + `LoopDetector`:
  - `BudgetEnforcer(max_calls, max_wall_seconds)`: counts `tools/call` per session; raises `BudgetExceededError` when limit hit
  - `LoopDetector(max_depth)`: tracks parent_id chain in audit log; raises `RecursiveLoopError` when depth > max
  - `HeartbeatMonitor.expect_progress(tool_name, timeout_seconds)`: raises `MissingHeartbeatError` if no `notifications/progress` within timeout

**Tests (`tests/middleware/test_t10_resources.py`):**
- `test_budget_enforcer_allows_within_limit` — 9 calls, limit 10 → no error
- `test_budget_enforcer_rejects_at_limit` — 11th call → `BudgetExceededError`
- `test_loop_detector_allows_shallow_chain` — depth 3, limit 5 → no error
- `test_loop_detector_rejects_deep_chain` — depth 6, limit 5 → `RecursiveLoopError`
- `test_heartbeat_monitor_passes_with_progress` — progress event at 2s, timeout 5s → passes
- `test_heartbeat_monitor_fails_without_progress` — no progress event within timeout → `MissingHeartbeatError`
- `test_t10_003_catalog_loads` — T10-003.json passes schema + signature
- `test_t10_003_p1_secure_server_rejects_deep_payload` → probe passes
- `test_t10_003_p1_vulnerable_server_executes_deep_payload` → probe fails
- `test_t10_003_p2_heartbeat_present` → probe passes
- `test_t10_003_p2_heartbeat_absent` → probe fails

---

### T06-002 — Typosquatting Detection (`catalog/official/T06-002.json` + `integrity.py`)

**Context:** The CoSAI whitepaper identifies typosquatting as a primary supply chain vector. T11-001 covers unlisted tool names. T06-002 covers names that are close to — but not identical to — trusted names (Levenshtein distance ≤ 2).

**Delivers:**
- `catalog/official/T06-002.json` — probe: `tools/list` response includes a tool named `anthropic_mcp_tool` (one character off from a canonical `anthropic-mcp-tools` style name); asserts server does NOT silently include it without flagging (`response.result.tools` must not contain a tool whose name has Levenshtein distance ≤ 2 from any allowlisted name unless explicitly approved)
  - Implementation: probe sends `tools/list`, response tools are checked against the scanner's configured allowlist; close matches → `T6-TYPOSQUAT-DETECTED`
- `cosai_mcp/middleware/integrity.py` — `TyposquatDetector`:
  - `levenshtein(a, b) -> int`: pure Python, O(m*n) — safe for tool names (short strings)
  - `check_tools(tools: list[dict], allowlist: list[str], max_distance: int = 2) -> list[TyposquatFinding]`
  - `TyposquatFinding(frozen): tool_name, closest_match, distance, severity`
  - Also: `ManifestBaselineChecker`: stores `tools/list` response hash at scan start; re-fetches mid-session; diffs for additions → `T6-MANIFEST-DRIFT-DETECTED`

**Tests (`tests/middleware/test_t6_integrity.py` + `tests/probes/test_t06_typosquat.py`):**
- `test_levenshtein_exact_match` — distance 0
- `test_levenshtein_one_char` — `"anthropic-mcp-tool"` vs `"anthropic-mcp-tools"` → 1
- `test_levenshtein_two_chars` — distance 2
- `test_levenshtein_above_threshold_not_flagged` — distance 5 → not a finding
- `test_typosquat_detector_flags_close_name` — tool `"anthropic_mcp_tool"` vs allowlist `["anthropic-mcp-tools"]` → finding
- `test_typosquat_detector_passes_exact_name` — exact match in allowlist → no finding
- `test_typosquat_detector_empty_allowlist` — no allowlist configured → no findings (opt-in)
- `test_manifest_baseline_detects_new_tool` — re-fetch adds `"evil_tool"` → `T6-MANIFEST-DRIFT-DETECTED`
- `test_manifest_baseline_same_manifest_passes` — identical re-fetch → no finding
- `test_t06_002_catalog_loads` — T06-002.json passes schema + signature
- `test_t06_002_clean_server_passes` — tools/list has no close-match names → probe passes
- `test_t06_002_typosquat_server_fails` — server returns typosquatted tool → probe flags

---

### T1 Additional Probes (T01-003, T01-004)

**Context:** Gap analysis found replay attack (jti validation) and DPoP binding probes missing. `auth.py` middleware is a stub.

**Delivers:**
- `catalog/official/T01-003.json` — token replay probe: send same `Authorization: Bearer <token>` twice in two separate requests to the same endpoint; assert second request is rejected (`401` or error code in [-32600, -32601])
  - Note: most black-box targets won't have true jti tracking; this probe is a behavioral signal, not a cryptographic verification
- `catalog/official/T01-004.json` — auth header format probe: send malformed auth headers (empty string, `Bearer `, non-Bearer scheme); assert all rejected with appropriate error
- `cosai_mcp/middleware/auth.py` — `SessionBoundIdentity`:
  - `generate_dpop_proof(method, url, nonce=None) -> str`: ephemeral Ed25519 keypair via `joserfc`; constructs DPoP JWT with `htu`, `htm`, `iat`, `jti` (UUID4), optional `nonce`
  - `JtiCache(maxsize=10_000)`: thread-safe LRU set; `check_and_add(jti) -> bool` returns False on replay
  - Protects the scanner's own outbound requests — not a probe of the target

**Tests (`tests/probes/test_t01_extended.py` + `tests/middleware/test_t1_auth.py`):**
- `test_t01_003_catalog_loads`
- `test_t01_003_server_rejects_replay` → probe passes
- `test_t01_003_server_accepts_replay` → probe fails
- `test_t01_004_malformed_auth_rejected` → probe passes for each malformed case
- `test_jti_cache_first_use_allowed`
- `test_jti_cache_replay_rejected`
- `test_jti_cache_different_jti_allowed`
- `test_dpop_proof_has_required_claims` — iat, jti, htm, htu present in generated proof

---

### Phase 4c Summary

**New catalog entries:** T05-001, T05-002, T06-002, T08-003, T10-003, T01-003, T01-004 (7 entries)  
**New middleware logic:** `protection.py` (T5), `resources.py` (T10 budget/loop/heartbeat), `integrity.py` (T6 Levenshtein + manifest baseline), `network.py` (bind address), `auth.py` (DPoP + jti cache)  
**New tests:** ~50 tests across 5 new/extended test files

**Panel:** T2 Sonnet — new catalog entries and middleware; not a new auth handshake but `auth.py` DPoP is security-relevant.
- Sonnet: Correctness + Security (RE2 patterns, Levenshtein correctness, jti cache thread safety, DPoP claim coverage)
- For `auth.py` DPoP specifically: "Is this the industry-standard approach for this problem class? Name the standard. Would this pass a SOC 2 / penetration test review?"

**Commit gate:**
```
pytest tests/middleware/test_t5_protection.py tests/middleware/test_t10_resources.py tests/middleware/test_t6_integrity.py tests/middleware/test_t1_auth.py -v
pytest tests/probes/ -v
pytest tests/ -v   # full regression
```

**Commit:** `feat(p4c): T5 PII scrubber, T08-003 binding probe, T10-003 DoW/heartbeat, T06-002 typosquat, T01-003/004 replay probes`

---

## Phase 5 — Report Engine  ‖  4a / 4b / 6 / 7

**What:** SARIF + HTML report generation. Highest XSS/injection risk surface after the harness.

**Delivers:**
- `cosai_mcp/report/sarif.py` — SARIF 2.1.0 builder:
  - Uses structured builder (not string interpolation)
  - Attacker bytes confined to `message.text` only (plain text, length-capped at 4096 chars, control-char-stripped)
  - `ruleId`, `suppressions`, `partialFingerprints` scanner-generated only
  - `invocation.executionSuccessful: false` on partial scan (exit code 2 or 3)
  - Validates output against SARIF 2.1.0 JSON schema before writing
- `cosai_mcp/report/html.py` — HTML report builder:
  - CSP: `default-src 'none'; style-src 'self'; script-src 'none'`
  - `references` rendered as text; URLs only if scheme ∈ {http, https} + `rel="noopener noreferrer"`
  - All content sourced from escaped `ProbeResult.evidence` (already escaped at ingestion in harness)
- `cosai_mcp/report/sign.py` — report signing:
  - Per-installation Ed25519 key via `keyring` (OS keychain)
  - Signs: scan timestamp + catalog hash + SARIF content hash
  - Embeds public key fingerprint in report for verification
- `cosai_mcp/report/verify.py` — `cosai audit verify` logic: chain integrity check on hash-chained audit log

**Tests (`tests/report/`):**
- `test_sarif_no_json_injection` — response body `","level":"error","ruleId":"INJECTED"`; output SARIF validates against schema; correct result count
- `test_sarif_attacker_bytes_confined_to_message_text` — no attacker byte appears outside `message.text`
- `test_sarif_ruleId_scanner_generated` — `ruleId` in output matches probe catalog ID, never response content
- `test_sarif_suppressions_not_from_response` — response containing `"suppressions"` key; asserts none appear in SARIF output
- `test_sarif_partial_scan_execution_unsuccessful` — exit code 2; asserts `executionSuccessful: false`
- `test_html_csp_default_src_none` — asserts CSP header in HTML report
- `test_html_references_text_only` — `references: ["javascript:alert(1)"]`; asserts rendered as text not link
- `test_html_references_valid_url` — `https://` URL; rendered as `<a>` with `rel="noopener noreferrer"`
- `test_report_signature_verifiable` — signed report; verifier using embedded fingerprint verifies without private key
- `test_audit_chain_tamper_detection` — entry 3 modified; verify returns CHAIN_BROKEN at entry 4
- `test_regression_sarif_no_json_injection`
- `test_regression_html_escape_before_template`

**Panel:** T1 Full — report engine is a primary injection surface; SARIF suppression is an inversion attack.
- Sonnet: Correctness + Security
- Opus: Adversary — "construct the malicious MCP response that causes the scanner's SARIF output to suppress findings in an unrelated file in the victim's GitHub Security tab"
- Standard question required.

**Commit gate:**
```
pytest tests/report/ -v
pytest tests/transport/ tests/catalog/ tests/harness/ tests/report/ -v   # full regression
```

**Commit:** `feat(report): SARIF 2.1.0 builder, HTML report, report signing, audit log verification`

---

## Phase 6 — Stateful Conformance Harness  ‖  4a / 4b / 5 / 7

**What:** Multi-turn session engine for T2, T6, T7. Structurally distinct from the one-shot prober.

**Delivers:**
- `cosai_mcp/stateful/harness.py` — `StatefulHarness`:
  - Full MCP `initialize` → `initialized` → scripted multi-turn scenario execution
  - Scenario DSL: ordered list of `(action, assertion)` tuples; state carried between steps
  - Session replay: record legitimate session, replay with attacker-controlled step substitution
- `cosai_mcp/stateful/scenarios/` — scenario definitions for:
  - **T2**: multi-turn privilege escalation chain (low-priv tool call → scope elevation → high-priv call); confused deputy (upstream token + downstream call)
  - **T6**: tool shadowing mid-session (`tools/list` baseline → re-fetch mid-session → diff)
  - **T7**: session fixation (client-supplied session ID accepted), session token in URL (logged in transit), MITM via session token replay across transport switch
- `tests/stateful/` — integration tests against mock server supporting multi-turn scenarios

**Tests (`tests/stateful/`):**
- `test_t2_privilege_escalation_chain` — scripted 3-turn sequence; asserts server rejects step 3 without elevated scope
- `test_t2_confused_deputy` — upstream token used in downstream call; asserts rejection
- `test_t6_tool_shadowing_mid_session` — `tools/list` re-fetch returns new tool; asserts flagged
- `test_t7_session_fixation_rejected` — client-supplied session ID accepted by server; flagged FAIL
- `test_t7_session_token_replay` — token replayed across sessions; asserts rejection or flagged
- `test_stateful_harness_reports_partial_on_abort` — mid-scenario crash; asserts `scan-incomplete` not `clean`

**Panel:** T1 Full — new session-layer security logic.
- Sonnet: Correctness + Security + MCP Protocol
- Opus: Adversary — "construct the multi-turn scenario the stateful harness cannot detect because it requires LLM-in-the-loop"
- Standard question required.

**Commit gate:**
```
pytest tests/stateful/ -v
pytest tests/transport/ tests/catalog/ tests/harness/ tests/stateful/ -v
```

**Commit:** `feat(stateful): multi-turn conformance harness for T2/T6/T7`

---

## Phase 7 — Middleware Instrumentation: T4 / T9 / T12  ‖  4a / 4b / 5 / 6

**What:** For T4, T9, T12, the middleware IS the test — these categories are undetectable from outside. The middleware ships as the reference implementation AND as the detection mechanism.

**Delivers:**
- `cosai_mcp/middleware/boundary.py` — T4: data/control boundary enforcement
  - Strips control tokens from tool response content before passing to downstream processor
  - Detects prompt injection patterns (fixed keyword list + regex, RE2 only)
  - Raises `ControlBoundaryViolation` on detection; logs to audit
- `cosai_mcp/middleware/trust.py` — T9: scanner self-protection
  - All MCP response content treated as untrusted; never re-fed to a processor without sanitization
  - Sanitization pipeline: control-char strip → length cap → schema validate → escape
  - Documents explicitly: this module protects the scanner's own pipeline; T9 probes test the target
- `cosai_mcp/middleware/audit.py` — T12: hash-chained append log
  - Entry format: `{"seq": N, "data": {...}, "prev_hash": "sha256:...", "entry_hash": "sha256:..."}`
  - Write: O_APPEND + fsync per entry
  - Read: walk chain, verify each entry's hash
  - `cosai audit verify` surfaces CHAIN_BROKEN with sequence number
- `cosai_mcp/middleware/protection.py` — T5 (non-parallel but fits here): PII scrubbing (regex on response content; RE2 only), context leak prevention

**Tests (`tests/middleware/`):**
- `test_t4_control_boundary_strips_injection` — response with `IGNORE ALL PREVIOUS INSTRUCTIONS`; asserts stripped before downstream
- `test_t4_violation_logged_to_audit` — boundary violation; asserts audit log entry created
- `test_t9_response_sanitized_before_reuse` — raw response not accessible after ingestion
- `test_t12_audit_chain_integrity` — 10 entries; verify passes
- `test_t12_audit_tamper_detected` — entry 5 modified; CHAIN_BROKEN at 6
- `test_t12_audit_append_only` — no truncation possible via public API
- `test_t5_pii_scrubbed_from_evidence` — SSN pattern in response; asserts scrubbed in ProbeResult.evidence
- `test_regression_audit_chain_tamper_detection`

**Panel:** T1 Full — boundary enforcement and audit log are security-critical.
- Sonnet: Correctness + Security
- Opus: Adversary — "construct the prompt injection payload that crosses the T4 boundary undetected; construct the audit log write that produces a valid-looking but falsified chain"
- Standard question required.

**Commit gate:**
```
pytest tests/middleware/ -v
pytest tests/ -v   # full suite regression (all phases)
```

**Commit:** `feat(middleware): T4/T9/T12 instrumentation — boundary enforcement, trust pipeline, audit log`

---

## Phase 8 — CLI + All Adoption Paths  (→ all Phase 4–7)

**What:** The user-facing surface. Wires everything together. Locks exit codes.

**Delivers:**
- `cosai_mcp/cli.py` — `cosai scan` + `cosai audit`:
  - `cosai scan <target>` — runs prober + stateful harness; writes SARIF + HTML
  - `cosai scan --categories T1,T3` — selective category scan
  - `cosai scan --engine prober|stateful|all` — explicit engine selection
  - `cosai audit verify <report>` — verifies audit chain and report signature
  - Exit codes: 0=clean, 1=findings≥threshold, 2=scanner-error (fail-closed), 3=unreachable
  - Scrubbed env at process start: strip `*_TOKEN`, `*_KEY`, cloud creds before any subprocess
- `cosai_mcp/pytest_plugin.py` — `--cosai-target`, `--cosai-severity`, `--cosai-categories` fixtures
- `cosai_mcp/api.py` — `Scanner` class for Python API
- Coverage matrix generated in `--report-coverage` flag output

**Tests (`tests/cli/` + `tests/api/`):**
- `test_exit_code_0_clean` — mock clean server; exit 0
- `test_exit_code_1_findings` — mock vulnerable server; exit 1
- `test_exit_code_2_scanner_crash` — harness OOM; exit 2
- `test_exit_code_3_unreachable` — target not running; exit 3
- `test_ci_exit_2_is_failure` — GitHub Action config treats exit 2 as failure (config test)
- `test_env_scrubbed_github_token_not_visible` — GITHUB_TOKEN in env; asserts not present in scan subprocess
- `test_coverage_matrix_in_output` — `--report-coverage`; asserts T4/T9/T12 marked `middleware-only`
- `test_pytest_plugin_collects` — `pytest --cosai-target=...` collects probe test cases
- `test_python_api_scanner_run` — `Scanner(...).run(categories=["T1"])` returns `ScanResult`

**Panel:** T2 Sonnet — CLI wiring is not new auth logic but exit codes and env scrub are security-relevant.

**Commit gate:**
```
pytest tests/ -v                      # full suite
cosai scan --help                     # exits 0
cosai audit verify --help             # exits 0
python -c "from cosai_mcp import Scanner; print('ok')"
```

**Commit:** `feat(cli): cosai scan/audit CLI, pytest plugin, Python API, fail-closed exit codes`

---

## Phase 9 — CI/CD + Supply Chain  (→ Phase 8)

**What:** Distribution, supply chain hardening, the GitHub Action. Closes the Opus adversary Finding 7.

**Delivers:**
- `.github/workflows/ci.yml` — full CI: lint, type-check, test, SARIF upload
- `.github/workflows/cosai-gate.yml` — reusable scan action: `uses: cosai-mcp/scan-action@<SHA>` (commit SHA in examples, never tag)
- `Dockerfile` — `--network=none` except explicit target IP rule; minimal base image
- `pyproject.toml` — `[tool.cosai.publish]` Sigstore/PEP 740 attestation config
- `SLSA.md` — provenance declaration, build reproducibility instructions
- `docs/threat-mapping.md` — CoSAI T1–T12 ↔ ISO 27001:2022 ↔ NIST AI RMF 2026 ↔ OWASP MCP Top 10
- `docs/coverage-matrix.md` — definitive table: which engine covers which category, what is not covered

**Tests (`tests/ci/`):**
- `test_docker_network_isolation` — scanner in Docker cannot reach 10.0.0.1 or 169.254.x.x
- `test_action_permissions_minimal` — GH Action YAML asserts `contents: read` + `security-events: write` only
- `test_action_uses_commit_sha` — examples in README use SHA not tag
- `test_sarif_upload_on_exit_2` — partial SARIF with `executionSuccessful: false` still uploaded

**Panel:** T1 Full — supply chain is an Opus adversary finding; GitHub Action is high blast radius.
- Sonnet: Correctness + Security (CI config, Docker isolation, SARIF upload semantics)
- Opus: Adversary — "the GitHub Action runs in the victim's CI with `security-events: write`; construct the compromise chain from PyPI account takeover to phantom findings in the victim's repo"
- Standard question required.

**Commit gate:**
```
pytest tests/ -v                          # full suite
docker build -t cosai-mcp-test .          # builds cleanly
cosai scan http://localhost:8000 || true  # exits with a defined code (not unhandled exception)
```

**Commit:** `feat(ci): GitHub Action, Docker, Sigstore attestation, threat-mapping docs`

---

## Summary: Phase Order + Panel Tier

| Phase | What | Deps | ‖ With | Panel Tier | Commit |
|-------|------|------|--------|------------|--------|
| P0 | Scaffold | — | — | T3 Skip | scaffold |
| P1 | Transport + MCPSession | P0 | P2 | **T1 Full** | feat(transport) |
| P2 | Catalog System | P0 | P1 | **T1 Full** | feat(catalog) |
| P3 | Probe Harness | P1+P2 | — | **T1 Full** | feat(harness) |
| P4a | Probes T1/T3/T8/T10 | P3 | P4b P5 P6 P7 | T2 Sonnet | feat(probes) T1/T3/T8/T10 |
| P4b | Probes T2/T6/T11 | P3 | P4a P5 P6 P7 | T2 Sonnet | feat(probes) T2/T6/T11 |
| **P4c** | **Gap probes T5/T8-003/T10-003/T6-002/T1-003** | **P4a+P4b** | **P5 P6** | **T2 Sonnet** | **feat(p4c): gap closure** |
| P5 | Report Engine | P3 | P4a P4b P6 P7 | **T1 Full** | feat(report) |
| P6 | Stateful Harness | P3 | P4a P4b P5 P7 | **T1 Full** | feat(stateful) |
| P7 | Middleware T4/T9/T12 | P3 | P4a P4b P5 P6 | **T1 Full** | feat(middleware) ✅ DONE |
| P8 | CLI + Adoption | P4c P5 P6 P7 | — | T2 Sonnet | feat(cli) |
| P9 | CI/CD + Supply Chain | P8 | — | **T1 Full** | feat(ci) |

**T1 Full panels:** P1, P2, P3, P5, P6, P7, P9 (7 panels total)
**T2 Sonnet panels:** P4a, P4b, P4c, P8 (4 panels total)

**Phase completion status (2026-04-26):**
- ✅ P0, P1, P2, P3, P4a, P4b, P7 — complete (242 tests passing)
- 🔜 P4c — next
- ⏳ P5, P6, P8, P9 — planned

---

## Test Philosophy

**Tests are part of the deliverable.** Never commit a phase without its tests passing.

| Test type | Where | When written |
|-----------|-------|-------------|
| Unit | `tests/<module>/` | Same response as the code |
| Regression | Named `test_regression_*` | One per panel finding, same response as the fix |
| Integration (mock server) | `tests/integration/` | P3 onward; mock server from `harness/mock_server.py` |
| End-to-end | `tests/e2e/` | P8 onward; real scan against a deliberately vulnerable MCP server |

**Mock discipline:** `create_autospec(real_fn, return_value=...)` for all external mocks. Never bare `MagicMock`.

**Regression test rule:** one test per panel finding. A finding without a test is not closed.

---

## LLM Panel Model Selection

| Panel type | Model | Parallelism |
|------------|-------|-------------|
| Correctness + Security + MCP Protocol | Sonnet | Run in parallel (single agent covering all three) |
| Adversary | Opus | Separate agent, separate pass — never combined with Sonnet panel |

Opus adversary prompt always includes explicit license: "The current design may be the wrong mechanism class entirely. Construct the failure scenario that compromises the scanner itself."

Both panel types always include: "Is this the industry-standard approach for this problem class? Name the standard. Would this pass a SOC 2 / penetration test review?"

---

## Gate Template (copy for each phase)

```
## Phase N Gate Checklist

### Panel
- [ ] Sonnet panel run (Correctness + Security [+ MCP Protocol if transport/session])
- [ ] Opus adversary panel run (separate agent)
- [ ] All CRITICAL findings fixed
- [ ] All HIGH findings fixed (or explicitly deferred with written rationale)
- [ ] Each finding has a regression test named test_regression_<finding>

### Tests
- [ ] Phase N unit tests: pytest tests/<module>/ -v → all green
- [ ] Full regression: pytest tests/ -v → all green (no regressions from prior phases)

### Code Review
- [ ] Re-read each finding verbatim before marking resolved
- [ ] Each distinct requirement in a finding has its own test

### Commit
- [ ] Commit message format: feat(<scope>): <description>
- [ ] No --no-verify, no --amend on published commits
```
