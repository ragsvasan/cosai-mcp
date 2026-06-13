# cosai-mcp — Coverage Status

**Date:** 2026-05-04
**Build:** 860/860 tests passing
**Catalog:** 20 signed threat definitions + 4 adversarial (Ed25519, signatures now enforced)
**Status:** All phases P0–P13 complete. Codex P1/P2 findings resolved.

---

## Three-Engine Model

cosai-mcp uses three fundamentally different detection mechanisms. The right engine depends on what the threat requires — not all categories are detectable by all engines.

| Engine | How it works | What it can see |
|--------|-------------|-----------------|
| **Black-box prober** | One-shot JSON-RPC probes against the target | Protocol responses — what the server returns |
| **Stateful conformance harness** | Scripted multi-turn sessions with state tracking | Session state changes, mid-session mutations |
| **Middleware instrumentation** | Library deployed inside the target server | Content flowing through the call path |

**Critical constraint (locked architecture decision):** T4 response-body injection, T9, and T12 are structurally undetectable from outside the call path. However, T4, T6, and T9 each have a passively-detectable structural layer the scanner runs over the already-fetched `tools/list` manifest:
- **T4 manifest poisoning** (injection hidden in `tools/list` metadata): the scanner runs `ToolPoisoningDetector` on the already-fetched manifest and surfaces findings with `threat_id="T04"`.
- **T6 manifest integrity** (tool shadowing / typosquat): `_scan_manifest_t6` flags exact name collisions, tool names within Levenshtein 1 of a reserved MCP method (e.g. `tools_call` vs `tools/call`), and near-duplicate tool names (plural variants suppressed). Findings surface with `threat_id="T06"`; a clean manifest emits a PASS marker.
- **T9 Totem violations** (destructive tools missing two-stage commit): the scanner inspects `tools/list` for tools with unambiguously-destructive verb names (delete, remove, drop, destroy, wipe, purge, reset, revoke, terminate, etc.) that lack a `confirmed`/`dry_run` boolean parameter and have no `_preview`/`_plan` sibling — the structural signal for TKA Totem non-compliance (CoSAI WS4 T9 contribution). Findings surface with `threat_id="T09"`.

Full T4/T9/T12 coverage still requires middleware instrumentation inside the target.

---

## Category Coverage Matrix

| # | Category | Engine | Catalog entries | Status |
|---|----------|--------|----------------|--------|
| T1 | Improper Authentication | Black-box prober | T01-001–004 | **Done** — missing auth, cross-session token, token replay (jti), DPoP binding |
| T2 | Missing Access Control | Black-box + stateful harness | T02-001, T02-003 | **Done** — privilege scope probe; destructive one-shot (T02-003); stateful privilege escalation chain + confused deputy |
| T3 | Input Validation Failures | Black-box prober | T03-001, T03-002 | **Done** — command injection, path traversal, SQL injection, null bytes, oversized payloads |
| T4 | Data/Control Boundary | Black-box prober (passive) + Middleware | — | **Done** — passive manifest scan wired into `_run_scan`; `ToolPoisoningDetector` + `ResponseBoundaryGuard` for full response-path coverage |
| T5 | Inadequate Data Protection | Black-box prober | T05-001, T05-002 | **Done** — PII pattern detection, credential pattern detection in tool responses |
| T6 | Integrity/Verification | Passive manifest scan + stateful harness | `_scan_manifest_t6` | **Done** — passive manifest-integrity scan (name collision, reserved-method shadow, Levenshtein-1 typosquat); stateful mid-session manifest-drift diff enforced in `run_scenario` (rug pull) |
| T7 | Session Security Failures | Stateful harness | — | **Done** — session fixation, token-in-URL, cross-session replay, explicit revocation (T7-SC-002) |
| T8 | Network Binding Failures | Black-box prober | T08-001–003 | **Done** — SSRF (RFC1918/link-local/loopback/file://), protocol version, 0.0.0.0 binding detection |
| T9 | Trust Boundary Failures | Middleware + passive manifest scan | — | **Done** — passive Totem manifest scan (destructive tools missing two-stage commit); full coverage via LLMOutputSanitizer + TrustBoundaryChecker (deploy middleware in target) |
| T10 | Resource Management | Black-box prober | T10-001–003 | **Done** — oversized input, rate limiting (429), recursive payload / DoW, heartbeat |
| T11 | Supply Chain/Lifecycle | Black-box prober | T11-001 | **Done** — tool allowlist enforcement, typosquatting (Levenshtein ≤ 1), signature verification |
| T12 | Insufficient Logging | Middleware only | — | **Middleware-only** — hash-chained DAG audit log via `cosai audit verify`. (The former black-box T12-002 transparency probe never ran in a real scan — T12 is middleware-skipped by the prober — so it was relocated out of the production catalog to `tests/fixtures/`; audit COV-05.) |

---

## Adversarial Mode

Four adversarial catalog definitions embed CSPRNG canary tokens in probe payloads. If a canary appears in a server response or outbound request, exfiltration or prompt injection echoing is detected from outside the call path.

| File | Category | What it detects |
|------|----------|-----------------|
| T03-ADV-001 | T3 | Input echoing — canary reflected in server response |
| T05-ADV-001 | T5 | Data exfiltration — canary appears in outbound request |
| T07-ADV-001 | T7 | Session token leakage |
| T11-ADV-001 | T11 | Supply chain exfiltration path |

Requires `--adversarial --i-own-this-target`. Blocked against RFC1918 and loopback by default.

---

## Middleware Implementations

**T4 — `cosai_mcp/middleware/boundary.py` + wired into `_run_scan`**
- `ToolPoisoningDetector`: scans `tools/list` manifest for prompt injection hidden in tool name, description, and `inputSchema` properties. **Called automatically by the scanner** on the manifest fetched during discovery — findings surface as `ProbeResult(threat_id="T04", passed=False)` in scan output and SARIF.
- `ResponseBoundaryGuard`: scans tool call response bodies for indirect prompt injection — deploy server-side for full response-path coverage
- 18 RE2-compatible injection patterns

**T9 — `cosai_mcp/middleware/trust.py`**
- `LLMOutputSanitizer`: 5-step pipeline — length cap → null byte removal → control char stripping → dangerous Unicode scrubbing → injection pattern scan
- `TrustBoundaryChecker.require_safe()`: raises `TrustBoundaryViolation` on flagged content

**T12 — `cosai_mcp/middleware/audit.py`**
- `AuditLogger`: append-only (`'ab'` mode), hash-chained, thread-safe
- SHA-256 chain: each entry includes `prev_hash` and `chain_hash`
- DAG structure: each entry carries `parent_id` for concurrent/nested tool call tracing
- `verify_chain()`: raises `AuditChainError` on tampering; `build_dag()`: parent→children mapping

---

## Test Suite

**860 tests passing** across:

| Module | What |
|--------|------|
| `tests/harness/` | Probe harness unit + regression tests |
| `tests/probes/` | Black-box probe definitions (T1–T4, T5–T6, T8, T10–T12) |
| `tests/stateful/` | Stateful harness (T2 privilege chain, T6 shadowing, T7 session) |
| `tests/middleware/` | Boundary, trust, audit middleware |
| `tests/adversarial/` | Adversarial mode, canary detection, enforcer |
| `tests/discovery/`, `tests/synthesis/` | Adaptive probe synthesis |
| `tests/profiles/` | Server profiles (5 built-ins) |
| `tests/report/` | HTML, SARIF, CSV, remediation, adversarial report |
| `tests/transport/` | Transport layer, Mnemo scan regressions |
| `tests/api/`, `tests/ci/`, `tests/cli/` | Python API, GitHub Action, CLI |

---

## How to Read the Coverage Reports

When `cosai scan` runs, each category in the SARIF output includes a `coverage` field:

```json
{
  "category": "T4",
  "coverage": "middleware-only",
  "engine": "instrumentation",
  "note": "Deploy cosai_mcp.middleware.boundary in the target server for detection"
}
```

Categories with `"coverage": "partial"` include a `partial_reason` field explaining what the middleware would additionally detect.

---

## Security Fixes (2026-04-29 — Codex P1/P2 Review)

Five blocking findings from the Codex review were resolved:

| Finding | Severity | Fix |
|---------|----------|-----|
| Unsigned adversarial catalog files loaded as official | P1 | `_load_adversarial` now delegates to `_load_official` (same Ed25519 check). All 4 adversarial `.sig` sidecars generated and committed. |
| Stateful adversarial probes not gated in scan loop | P1 | `ThreatDefinition.mode` field added; `_run_scan` checks `mode == "stateful"` and raises `UnsafeProbeError` unless `--allow-stateful-adversarial` is set. |
| 2024-11-05 fallback label-only (no actual transport switch) | P1 | `MCPSession` now accepts `target_url`; on `2024-11-05` negotiation it closes the old transport, instantiates `LegacySSETransport`, and re-runs `initialize` + `initialized`. |
| Failed `tools/list` became a ready session (fail-open) | P2 | `tools/list` error or exception now raises `SessionIncompleteError` — session stays INCOMPLETE, scan reports `scan-incomplete`, not `clean`. |
| Adversarial SARIF output crashed on `T##-ADV-###` rule IDs | P2 | `_RULE_ID_RE` widened from `^T\d{2}-\d{3}$` to `^T\d{2}(-[A-Z]{2,5})?-\d{3}$`. |

Each fix has an independent regression test. README quickstart `--i-own-this-target` example corrected to include the required hostname value.
