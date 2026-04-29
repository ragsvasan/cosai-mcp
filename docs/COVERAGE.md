# cosai-mcp — Coverage Status

**Date:** 2026-04-28
**Build:** 801/801 tests passing
**Catalog:** 20 signed threat definitions + 4 adversarial (Ed25519)
**Status:** All phases P0–P13 complete.

---

## Three-Engine Model

cosai-mcp uses three fundamentally different detection mechanisms. The right engine depends on what the threat requires — not all categories are detectable by all engines.

| Engine | How it works | What it can see |
|--------|-------------|-----------------|
| **Black-box prober** | One-shot JSON-RPC probes against the target | Protocol responses — what the server returns |
| **Stateful conformance harness** | Scripted multi-turn sessions with state tracking | Session state changes, mid-session mutations |
| **Middleware instrumentation** | Library deployed inside the target server | Content flowing through the call path |

**Critical constraint (locked architecture decision):** T4, T9, and T12 are structurally undetectable from outside. No black-box probe can observe whether content in a tool response contains prompt injection (T4), whether LLM output is sanitized before re-feed (T9), or whether execution is being logged (T12). The middleware IS the test for these categories.

---

## Category Coverage Matrix

| # | Category | Engine | Catalog entries | Status |
|---|----------|--------|----------------|--------|
| T1 | Improper Authentication | Black-box prober | T01-001–004 | **Done** — missing auth, cross-session token, token replay (jti), DPoP binding |
| T2 | Missing Access Control | Black-box + stateful harness | T02-001, T02-003 | **Done** — privilege scope probe; destructive one-shot (T02-003); stateful privilege escalation chain + confused deputy |
| T3 | Input Validation Failures | Black-box prober | T03-001, T03-002 | **Done** — command injection, path traversal, SQL injection, null bytes, oversized payloads |
| T4 | Data/Control Boundary | Middleware instrumentation | — | **Done** — ToolPoisoningDetector + ResponseBoundaryGuard (deploy middleware in target) |
| T5 | Inadequate Data Protection | Black-box prober | T05-001, T05-002 | **Done** — PII pattern detection, credential pattern detection in tool responses |
| T6 | Integrity/Verification | Black-box + stateful harness | T06-001, T06-002 | **Done** — typosquat detection (Levenshtein ≤ 1); stateful mid-session manifest diff (rug pull) |
| T7 | Session Security Failures | Stateful harness | — | **Done** — session fixation, token-in-URL, cross-session replay, explicit revocation (T7-SC-002) |
| T8 | Network Binding Failures | Black-box prober | T08-001–003 | **Done** — SSRF (RFC1918/link-local/loopback/file://), protocol version, 0.0.0.0 binding detection |
| T9 | Trust Boundary Failures | Middleware instrumentation | — | **Done** — LLMOutputSanitizer + TrustBoundaryChecker (deploy middleware in target) |
| T10 | Resource Management | Black-box prober | T10-001–003 | **Done** — oversized input, rate limiting (429), recursive payload / DoW, heartbeat |
| T11 | Supply Chain/Lifecycle | Black-box prober | T11-001 | **Done** — tool allowlist enforcement, typosquatting (Levenshtein ≤ 1), signature verification |
| T12 | Insufficient Logging | Middleware + black-box prober | T12-002 | **Done** — middleware: hash-chained DAG audit log; BB: T12-002 tool description transparency |

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

**T4 — `cosai_mcp/middleware/boundary.py`**
- `ToolPoisoningDetector`: scans `tools/list` manifest for prompt injection hidden in tool name, description, and `inputSchema` properties
- `ResponseBoundaryGuard`: scans tool call response bodies for indirect prompt injection
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

**801 tests passing** across:

| Module | What |
|--------|------|
| `tests/harness/` | Probe harness unit + regression tests |
| `tests/probes/` | Black-box probe definitions (T1–T3, T5–T6, T8, T10–T12) |
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
