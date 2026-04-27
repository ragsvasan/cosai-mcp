# cosai-mcp — Coverage Status

**Date:** 2026-04-26  
**Build:** 242/242 tests passing  
**Catalog:** 11 signed threat definitions (Ed25519)

This document is the authoritative record of what cosai-mcp covers today, what is stubbed, and what is planned. See [workplan.md](workplan.md) for the implementation roadmap.

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

| # | Category | Engine | Catalog Entries | Middleware | Status |
|---|----------|--------|----------------|------------|--------|
| T1 | Improper Authentication | Black-box | T01-001, T01-002 | `auth.py` stub | **Partial** — replay/OAuth/DPoP probes planned P4c |
| T2 | Missing Access Control | Stateful harness + partial black-box | T02-001 | `authz.py` stub | **Partial** — stateful harness (P6) not yet built |
| T3 | Input Validation Failures | Black-box | T03-001, T03-002 | `validation.py` stub | **Done** — command injection + path traversal probes |
| T4 | Data/Control Boundary | Middleware | — | `boundary.py` **done** | **Done** — ToolPoisoningDetector + ResponseBoundaryGuard |
| T5 | Inadequate Data Protection | Middleware | — | `protection.py` stub | **Planned P4c** — PII scrubber + catalog probes |
| T6 | Integrity/Verification | Stateful + partial black-box | T06-001 | `integrity.py` stub | **Partial** — tools/list manifest check done; typosquatting + stateful (P4c/P6) planned |
| T7 | Session Security Failures | Stateful harness | — | `session.py` stub | **Planned P6** — stateful harness not yet built |
| T8 | Network Binding Failures | Black-box | T08-001, T08-002 | `network.py` stub | **Partial** — SSRF probes done; 0.0.0.0 binding probe (T08-003) planned P4c |
| T9 | Trust Boundary Failures | Middleware | — | `trust.py` **done** | **Done** — LLMOutputSanitizer + TrustBoundaryChecker |
| T10 | Resource Management | Black-box | T10-001, T10-002 | `resources.py` stub | **Partial** — oversized input + rate limit done; DoW/recursive payload (T10-003) planned P4c |
| T11 | Supply Chain/Lifecycle | Black-box (partial) | T11-001 | `supply_chain.py` stub | **Partial** — unlisted tool rejection done; update hijacking + Levenshtein planned P4c |
| T12 | Insufficient Logging | Middleware | — | `audit.py` **done** | **Done** — hash-chained append-only DAG audit log |

**Legend:** done = implemented and tested · partial = some coverage, gaps identified · planned = architecture defined, implementation queued · stub = file exists, no logic

---

## What Is Done Today

### Middleware (T4, T9, T12)

All three "requires middleware" categories have working implementations with full test coverage.

**T4 — `cosai_mcp/middleware/boundary.py`**
- `ToolPoisoningDetector`: scans `tools/list` manifest for prompt injection hidden in tool name, description, and `inputSchema` properties
- `ResponseBoundaryGuard`: scans tool call response bodies for indirect prompt injection
- 18 RE2-compatible injection patterns; extended `_TOOL_DESCRIPTION_PATTERNS` for HTML comments and LLM instruction tokens
- `InjectionFinding(frozen)`, `ScanResult(mutable)` — clean separation of detection from policy

**T9 — `cosai_mcp/middleware/trust.py`**
- `LLMOutputSanitizer`: 5-step pipeline — length cap (32,768 chars) → null byte removal → C0/C1 control char stripping (preserving `\t \n \r`) → dangerous Unicode scrubbing (Cf/Cs/Co/Cn categories) → injection pattern scan
- `TrustBoundaryChecker.require_safe()`: raises `TrustBoundaryViolation` on flagged content; callers must catch, never silently ignore
- `SanitizedOutput(frozen)`: `text` (HTML-escaped), `flagged`, `truncated`, `findings(tuple)`

**T12 — `cosai_mcp/middleware/audit.py`**
- `AuditLogger`: append-only (`'ab'` mode), hash-chained, thread-safe (single `threading.Lock`)
- SHA-256 chain: each entry includes `prev_hash` and `chain_hash = SHA-256(prev_hash + canonical_json_without_chain_hash)`
- DAG structure: each entry carries `parent_id` for concurrent/nested tool call tracing
- `AuditEntry(frozen)`: params stored as digest only — no PII in log
- `verify_chain()`: raises `AuditChainError` on tampering; `build_dag()`: parent→children mapping
- Genesis hash: `"0" * 64`

### Black-Box Probes

**Catalog:** 11 signed threat definitions in `catalog/official/`, each with Ed25519 `.json.sig` sidecar. Public key hardcoded in `cosai_mcp/keys.py` as bytes literal (not loaded from disk).

| File | Category | Probes | What it tests |
|------|----------|--------|---------------|
| T01-001.json | T1 | 1 | Missing auth header → must reject |
| T01-002.json | T1 | 1 | Cross-session token → must reject |
| T02-001.json | T2 | 1 | Privileged tool without scope → must reject |
| T03-001.json | T3 | 1 | Command injection (`; cat /etc/passwd`) |
| T03-002.json | T3 | 1 | Path traversal (`../../etc/passwd`) |
| T06-001.json | T6 | 1 | `tools/list` must succeed (shadowing detection prerequisite) |
| T08-001.json | T8 | 2 | SSRF: AWS metadata URL + localhost:22 |
| T08-002.json | T8 | 1 | `initialize` response must use correct protocol version |
| T10-001.json | T10 | 1 | Oversized input (100,000 chars) → must reject |
| T10-002.json | T10 | 1 | Rate limiting: rapid-fire calls → must see 429 |
| T11-001.json | T11 | 2 | Unlisted tool name + path-traversal tool name → must reject |

### Test Suite

**242 tests passing** across:

| Module | Tests | What |
|--------|-------|------|
| `tests/harness/` | 129 | Probe harness + P3 panel regressions |
| `tests/probes/` | 55 | Black-box probe definitions (T1/T2/T3/T6/T8/T10/T11) |
| `tests/middleware/` | 58 | Boundary + trust + audit middleware |

---

## What Is Partially Done

### T1 — Improper Authentication
**Done:** missing auth header, cross-session token rejection probes.  
**Gap:** token replay (jti validation), OAuth proxy detection, DPoP binding verification. These require auth-aware probes that simulate token lifecycles. Planned in **P4c**.

### T2 — Missing Access Control
**Done:** one-shot confused deputy probe (privileged tool without scope claim).  
**Gap:** multi-turn privilege escalation chain requires the stateful harness (P6). `authz.py` middleware stub has no logic.

### T6 — Integrity/Verification
**Done:** `tools/list` must succeed probe (prerequisite for shadowing detection).  
**Gap:** typosquatting detection (Levenshtein distance check vs allowlist) in `integrity.py` — planned P4c. Mid-session tool shadowing requires stateful harness (P6).

### T8 — Network Binding Failures
**Done:** SSRF probes (AWS metadata, localhost:22), protocol version probe.  
**Gap:** 0.0.0.0 binding probe (T08-003) — server responding on non-loopback interface when it should be loopback-only. Planned P4c.

### T10 — Resource Management
**Done:** oversized input rejection, rate limiting presence.  
**Gap:** recursive payload / Denial of Wallet probe (T10-003). `resources.py` heartbeat and loop detection middleware. Planned P4c.

### T11 — Supply Chain/Lifecycle
**Done:** unlisted tool name rejection, path-traversal tool name rejection.  
**Gap:** typosquatting (Levenshtein), update hijacking probe. Planned P4c.

---

## What Is Planned

### P4c (next phase)
Full scope: [workplan.md — Phase 4c](workplan.md#phase-4c)

- **T5** — `protection.py` PII scrubber + context leak prevention + catalog probes
- **T08-003** — 0.0.0.0 binding probe
- **T10-003** — recursive payload / DoW probe + `resources.py` budget/heartbeat middleware  
- **T06-002** — typosquatting probe + `integrity.py` Levenshtein check
- **T01-003/004** — replay attack + DPoP binding probes

### P6 (stateful harness)
Covers T2 full (multi-turn privilege escalation), T6 full (mid-session tool shadowing), T7 full (session fixation, token replay, context-bleed).

### P5 (report engine)
SARIF 2.1.0, HTML report, report signing, `cosai audit verify`.

### P8/P9 (CLI + CI/CD)
`cosai scan` CLI, pytest plugin, Python API, GitHub Action, Docker, Sigstore attestation.

---

## Stubs (files exist, no logic)

These files exist with module-level docstrings and empty class skeletons. They will be filled in across P4c and P5–P9.

| File | Category | Phase |
|------|----------|-------|
| `cosai_mcp/middleware/auth.py` | T1 session-bound identity, DPoP | P4c / P8 |
| `cosai_mcp/middleware/authz.py` | T2 per-tool RBAC | P4c / P6 |
| `cosai_mcp/middleware/validation.py` | T3 JSON schema strict mode | P4a |
| `cosai_mcp/middleware/protection.py` | T5 PII scrubbing | P4c |
| `cosai_mcp/middleware/integrity.py` | T6 typosquatting detection | P4c |
| `cosai_mcp/middleware/session.py` | T7 cryptographic session binding | P6 |
| `cosai_mcp/middleware/network.py` | T8 bind address validation | P4c |
| `cosai_mcp/middleware/resources.py` | T10 heartbeat, budget, loop detection | P4c |
| `cosai_mcp/middleware/supply_chain.py` | T11 tool allowlist, registry sig | P4c |

---

## Coverage Gaps from 2026 CoSAI Whitepaper

The following concepts from the whitepaper are documented but not yet probe-covered:

| Concept | Category | Gap | Phase |
|---------|----------|-----|-------|
| Dual-Subject Tokens (agent + user identity in single credential) | T1/T2 | No probe; `auth.py` stub | P4c |
| DPoP (RFC 9449) proof-of-possession | T1 | No probe; `auth.py` stub | P4c |
| Progress Notifications / Heartbeat | T10 | No probe; `resources.py` stub | P4c |
| Typosquatting detection (Levenshtein) | T11/T6 | No probe; `integrity.py` stub | P4c |
| 0.0.0.0 loopback binding detection | T8 | No T08-003 catalog entry | P4c |
| Recursive tool call / DoW | T10 | No T10-003 catalog entry | P4c |
| PII scrubbing (T5) | T5 | No `protection.py` logic, no catalog entries | P4c |
| Context isolation between sessions (T7) | T7 | Requires stateful harness | P6 |
| NIST AG-MP.1 Execute-class HITL gate | T9 | Middleware stub | P4c |

---

## How to Read the Coverage Reports

When `cosai scan` runs (available in P8), each category in the SARIF output will include a `coverage` field:

```json
{
  "category": "T4",
  "coverage": "middleware-only",
  "engine": "instrumentation",
  "note": "Deploy cosai_mcp.middleware.boundary in the target server for detection"
}
```

Categories with `"coverage": "partial"` include a `partial_reason` field explaining what the stateful harness or middleware would additionally detect.
