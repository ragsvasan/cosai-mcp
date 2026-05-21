# Extending cosai-mcp: IETF Agent Authentication Standards Coverage

**Status:** Approved — proceed  
**Date:** 2026-05-21  
**References:** [draft-klrc-aiagent-auth-01](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/), RFC 9449 (DPoP), RFC 8693 (Token Exchange), WIMSE Architecture, SPIFFE/SPIRE, OpenID CIBA, OpenID SSF

---

## Thesis

The IETF draft *Authentication and Authorization for AI Agent Interactions* (draft-klrc-aiagent-auth-01) consolidates how OAuth 2.0, WIMSE workload identity, transaction tokens, and cross-domain authorization chaining apply to AI agent deployments. It validates every major T1/T7/T12 decision already locked in cosai-mcp — and simultaneously exposes six concrete threat surfaces that the tool does not yet probe. This document defines the requirements and design for closing those gaps, making cosai-mcp the only scanner that tests against both the CoSAI whitepaper threat taxonomy **and** the emerging IETF agent authentication standards.

---

## Why

### The problem the draft is solving

AI agents call tools. Tools call services. Services issue tokens. Somewhere in that chain, one of three things goes wrong:

1. **Broad tokens leak context.** An agent receives an OAuth access token scoped for the whole session and forwards it unchanged to every tool it calls. When that token appears in a log, crash dump, or network trace from any microservice in the chain, an attacker can replay it with different parameters — not just observe data, but invoke actions.

2. **Chains don't check trust domains.** Agent A gets a token from Authorization Server 1. It invokes Agent B, which needs a resource from AS-2. The lazy path — forward the AS-1 token — should be rejected by AS-2, but real deployments often don't enforce audience restrictions strictly. The draft calls this out as a pattern with no existing tooling to detect it.

3. **UI confirmation is mistaken for authorization.** MCP-style confirmation dialogs (the "user approved" event) are treated by many server implementations as the authorization signal for sensitive actions. The IETF draft is explicit: "MCP confirmation does not constitute authorization. The agent MUST NOT treat local UI confirmation alone as sufficient authorization." This misimplementation is widespread and undetected.

### Why cosai-mcp is the right place to test this

The draft frames these as **runtime protocol failures**, not static code defects. You cannot detect them by scanning source code. You detect them by conducting the flows — sending a token issued for one purpose and observing whether the server enforces scope, audience, and transaction binding at the protocol layer. That is exactly what cosai-mcp's three-engine architecture exists to do.

No existing tool tests these flows:
- Static scanners (Cisco, Snyk, Enkrypt) test what you wrote, not what you shipped.
- Runtime proxies (MCP-Bastion, MCPProxy-go) observe traffic but don't conduct adversarial flows.
- The IETF draft itself has an empty Security Considerations section — it describes the requirements without providing verification tooling.

### Why now

The draft is at revision -01, which is the point where implementations begin and the patterns diverge. If cosai-mcp ships coverage before implementations calcify, it can influence how the standard gets built in practice — particularly the transaction token and cross-domain chaining patterns, which have no reference implementation yet.

---

## Current Coverage

The table below maps the draft's mechanisms to existing cosai-mcp coverage.

| IETF Draft Mechanism | cosai-mcp Coverage | Status |
|---|---|---|
| DPoP (RFC 9449) cryptographic binding | `middleware/auth.py`, `T01-002.json` | **Covered** |
| JTI replay cache | `T01-003.json`, `auth.py` | **Covered** |
| Short-lived tokens / anti-static-key | `T01-001.json`, `T01-004.json` | **Covered** |
| RFC 8693 token exchange | `identity/` module architecture | **Partial** |
| Confused deputy prevention | `T02-001.json`, `T02-004.json`, `authz.py` | **Covered** |
| Append-only tamper-evident audit log | `middleware/audit.py`, `T12-002.json` | **Covered** |
| Tool definition signing | `middleware/supply_chain.py`, `keys.py` | **Covered** |
| Two-stage commit for destructive tools | `T02-003.json` | **Covered** |
| **Transaction tokens (downscoped)** | — | **Gap** |
| **WIMSE workload identity / SPIFFE** | — | **Gap** |
| **Cross-domain token chaining** | — | **Gap** |
| **OpenID SSF revocation propagation** | — | **Gap** |
| **CIBA vs. MCP confirmation** | — | **Gap** |
| **mTLS channel binding enforcement** | — | **Gap** |

---

## Requirements

### R1 — Transaction Token Probes

**Requirement:** The scanner MUST probe whether an MCP server enforces transaction-scoped token binding on tool calls.

**Rationale:** The draft's transaction token mechanism prevents a broad session-scoped access token from being replayed with different parameters. The attack surface: the token is visible in any log, trace, or crash dump across all microservices in the chain. A server that accepts a token issued for transaction A when executing transaction B is vulnerable regardless of DPoP binding (DPoP binds key→token, not token→transaction).

**Acceptance criteria:**
- Probe `T01-006`: Send a valid bearer token issued for a different tool/resource combination; assert server returns 4xx, not 200.
- Probe `T01-007`: Send a token with an unknown or mismatched `aud` claim; assert server rejects it.
- Probe `T01-008`: In a multi-turn harness session, assert that tool responses do not echo back the original access token, and that subsequent tool calls require a fresh token or transaction token exchange.

### R2 — WIMSE Workload Identity Validation

**Requirement:** The scanner MUST probe whether an MCP server validates workload identity on inbound agent calls.

**Rationale:** The draft recommends SPIFFE IDs (`spiffe://<trust-domain>/agent-name`) as the standard workload identity primitive for agents. Workload Identity Tokens (WITs) carry attestation evidence, trust domain, and workload metadata that bearer JWTs do not. A server that accepts any well-formed JWT without validating the workload identity cannot distinguish a legitimate agent from a compromised process.

**Acceptance criteria:**
- Probe `T01-009`: Send a JWT with no `sub_jwk`, no SPIFFE-format subject, and no workload attestation claims; assert server requires workload identity or degrades gracefully to DPoP-only.
- Scanner documentation MUST clearly state that workload identity validation is advisory (many servers legitimately use DPoP-only) and report as `ADVISORY` not `FAIL` unless the server accepts anonymous calls.

### R3 — Cross-Domain Authorization Chaining

**Requirement:** The stateful conformance harness MUST include a scenario that tests cross-domain token forwarding.

**Rationale:** Agent chains that span multiple trust domains are the norm in enterprise deployments. The draft's correct pattern requires token exchange (RFC 8693) at each domain boundary. The incorrect pattern — forwarding the upstream token — is undetectable without conducting the multi-hop flow.

**Acceptance criteria:**
- Scenario `SC-11`: Multi-hop token delegation chain. `initialize` → agent-A-token → `tools/call` triggering an agent-B action → assert agent-B issued a fresh downscoped token, NOT forwarded agent-A's token.
- Scenario `SC-12`: Cross-domain chaining. `initialize` with AS-1 token → `tools/call` targeting AS-2 resource → assert audience on resource call matches AS-2, not AS-1. Assert token exchange occurred.
- Findings for these scenarios classified under T2 (access control) and T7 (session security).

### R4 — OpenID Shared Signals Framework Revocation

**Requirement:** The stateful harness MUST include a scenario testing whether a server continues accepting a token after revocation.

**Rationale:** The draft mandates real-time remediation on SSF signals: token revoked → terminate session → re-acquire. A server that caches tokens and continues accepting calls after revocation violates both T7 (session security) and the IETF requirement. This is currently undetectable because single-probe tools cannot revoke and then probe in the same session.

**Acceptance criteria:**
- Scenario `SC-13`: SSF revocation. `initialize` → establish session → trigger token revocation (via mock AS or by sending a revocation request) → assert subsequent `tools/call` returns 401, not 200.
- If the target MCP server does not expose a revocation endpoint, the scenario reports `INCONCLUSIVE` with an explanation — not `PASS`.

### R5 — CIBA vs. MCP Confirmation

**Requirement:** The scanner MUST probe whether a server enforces OAuth-level authorization separately from MCP UI confirmation.

**Rationale:** The draft is explicit: "MCP confirmation does not constitute authorization." A server that gates a sensitive action on a `confirmation=true` parameter without requiring a valid OAuth scope for that action is implementing authorization incorrectly. This is the single most common misimplementation in deployed MCP servers today.

**Acceptance criteria:**
- Probe `T07-002`: Call a sensitive tool with `confirmation=true` but with a token whose scope does not include that tool's required scope; assert server returns 403, not 200.
- Probe `T07-003`: Call a sensitive tool with a valid scope but without the MCP confirmation; assert the server does not require UI confirmation as a *substitute* for scope — it may require it in addition, but scope must be checked first.
- Both probes report findings under T7 (session security).

### R6 — WIMSE Module in the Identity Layer

**Requirement:** The `identity/` module MUST be extended with a WIMSE WIT validator and WPT generator.

**Rationale:** The scanner currently generates DPoP proofs for outbound requests. To probe WIMSE-aware servers, it must also be able to generate structurally valid WITs (to test positive cases) and structurally invalid WITs (to test negative cases). Without this, WIMSE probes can only test absence of workload identity, not active forgery/downgrade attempts.

**Acceptance criteria:**
- `identity/wimse.py` exports `generate_wit(spiffe_id, private_key, ttl)` and `generate_wpt(wit, private_key, method, url)`.
- Both functions produce tokens that pass structural validation against the WIMSE draft schema.
- A `--probe-wimse` flag in the CLI enables WIMSE-specific probes (off by default; requires the target to declare WIMSE support).

### R7 — Coverage Matrix and README Update

**Requirement:** The coverage matrix (`docs/coverage-matrix.md`) and README MUST be updated to distinguish "CoSAI T1–T12 coverage" from "IETF agent auth coverage" and clearly mark partial and gap entries.

**Rationale:** Honest coverage reporting is a core project commitment. Adding new threat categories that overlap with (but are not identical to) the CoSAI taxonomy requires explicit mapping so users understand what each probe covers and against which standard.

---

## Design

### New Catalog Entries

Six new JSON threat definitions, all signed and added to `catalog/official/`:

```
T01-006.json   Transaction token absent — broad token forwarded to tools
T01-007.json   Unknown workload identity — server accepts any JWT issuer
T01-008.json   Token forwarding anti-pattern — tool echoes or re-uses agent token
T07-002.json   MCP confirmation treated as OAuth authorization (CIBA gap)
T07-003.json   OAuth scope checked after MCP confirmation, not before
T07-004.json   SSF revocation not respected — server continues post-revocation
```

Each entry follows the existing schema (`schema_version`, `id`, `category`, `severity`, `probes`, `assertions`, `remediation`, `references`) with `owasp_ref` and `cwe` populated from the IETF draft's threat descriptions.

### New Stateful Harness Scenarios

Three new scenarios added to `tests/harness/`:

```
sc11_token_delegation_chain.py
sc12_cross_domain_chaining.py
sc13_ssf_revocation.py
```

Each scenario follows the existing harness pattern: full `initialize` + `initialized` + `tools/list` handshake, multi-turn scripted interactions, assertions on both protocol responses and (where applicable) audit log entries.

### New Identity Module

```
cosai_mcp/identity/wimse.py
```

Exports:
- `WIMSEIdentity(spiffe_id, private_key)` — holds the workload identity keypair
- `generate_wit(identity, ttl_seconds) -> str` — produces a signed WIT JWT
- `generate_wpt(wit, identity, method, url) -> str` — produces a signed WPT JWT
- `validate_wit(token, trust_domain) -> WITClaims` — validates a WIT against a trust domain

Dependencies: `joserfc` (already in runtime deps). No new dependencies required.

### CLI Flag

```bash
cosai-mcp scan http://localhost:8000 --probe-wimse
```

When `--probe-wimse` is set, WIMSE-specific probes (`T01-007`, `T01-009`) are included in the scan. Off by default because most MCP servers today do not declare WIMSE support and the probes would generate `ADVISORY` noise.

### Coverage Matrix Update

Do NOT add a new `IETF draft-klrc-aiagent-auth-01` column. Frame all new probes as extensions of existing CoSAI categories: T01-006 through T01-009 extend T1, T07-002 through T07-004 extend T7. The coverage matrix gains new rows under existing columns — the IETF draft reference belongs in each catalog entry's `references` array, not as a top-level axis. This preserves the primary positioning claim ("covers all 12 CoSAI threats") without diluting it with a partial second standard.

---

## Value

### For cosai-mcp as a project

The IETF draft has an empty Security Considerations section. The draft authors describe requirements but provide no verification tooling. cosai-mcp ships verification tooling. Publishing coverage before implementations calcify gives the project a seat at the standards table — the reference implementation for testing IETF agent auth compliance as an extension of CoSAI T1/T7 coverage.

**Explicit goal:** open a PR to the IETF draft citing cosai-mcp as a verification implementation for the Security Considerations section. This is a delivery commitment, not a nice-to-have.

### For users

| User type | Concrete benefit |
|---|---|
| MCP server developers | Can verify their token validation is correct before the IETF draft becomes a ratified standard — and fix it before auditors check |
| Enterprise security teams | The cross-domain chaining and SSF revocation scenarios cover exactly the attack surface that internal red teams can't easily script today |
| CI/CD gate operators | New probes slot into the existing `--fail-on critical` gate with no configuration change — the exit code contract is unchanged |
| Standards contributors | The probe suite can be cited in the IETF draft's Security Considerations as a reference implementation for the verification procedures described in the spec |

### Competitive positioning

The six gaps identified are not covered by any existing tool in the landscape (see `docs/VALUE_PROP.md` for full competitive analysis). Transaction token enforcement and cross-domain chaining are novel enough that shipping coverage first creates a durable differentiation — these flows require a stateful multi-turn harness that proxies and static scanners fundamentally cannot replicate.

### Effort estimate

| Deliverable | Estimated effort |
|---|---|
| 6 new catalog JSON entries + signatures | 1 day |
| 3 new harness scenarios (SC-11, SC-12, SC-13) | 3 days |
| `identity/wimse.py` module | 2 days |
| 6 black-box probes (T01-006 through T07-004) | 2 days |
| Coverage matrix + README update | 0.5 days |
| **Total** | **~8.5 days** |

All work is additive. Nothing in the existing architecture requires modification — new catalog entries are drop-in, new harness scenarios are independent files, and the WIMSE module extends (not replaces) the existing `identity/` layer.

---

## Resolved Design Decisions

The following questions were raised in the Crucible audit (`docs/IETF_AGENT_AUTH_CRUCIBLE.md`) and resolved before build start.

1. **WIMSE probe opt-in:** `--probe-wimse` stays off by default. When enabled, WIMSE probes run and report `ADVISORY` (not `FAIL`) unless the server accepts completely anonymous calls. This avoids noise for users whose servers don't declare WIMSE support.

2. **SC-13 mock AS:** Ship a minimal in-process mock AS as a `pytest` fixture in `tests/fixtures/`. It is not a runtime dependency — it runs only during test execution. Exposes `/token` (issue) and `/revoke` (revoke by JTI). This also serves SC-11/SC-12.

3. **IETF draft maturity:** Catalog entries for new probes carry `"draft_stability": "experimental"` in their metadata. Reports render this as a footnote: "This finding references an IETF draft at revision -01; requirements may change before ratification." The field is added to the meta-schema as an optional string.

4. **Cross-domain scenario fixture:** SC-11/SC-12 use the same in-process two-AS fixture (decision 2 above). Not user-configurable at MVP — both AS instances run in-process. Users needing real AS testing configure `--as1-url` and `--as2-url` as an advanced option.

5. **T01-006 probe mechanism:** Redesigned as a bring-your-own-token probe. The user supplies `--token <jwt>` on the CLI; the scanner replays it with mismatched `aud` and tool parameters. Fully automated replay is architecturally impossible without a trust relationship with the target AS.

6. **Probe ID assignment (final):**
   - `T01-006` — transaction token absent / broad token forwarded to tools
   - `T01-007` — mismatched `aud` claim (token issued for wrong audience)
   - `T01-008` — token forwarding anti-pattern (tool echoes agent token)
   - `T01-009` — unknown workload identity (no SPIFFE subject, no `sub_jwk`)
   - `T07-002` — MCP confirmation treated as OAuth authorization
   - `T07-003` — OAuth scope checked after MCP confirmation, not before
   - `T07-004` — SSF revocation not respected

7. **Coverage framing:** No new standards column in the coverage matrix. All new probes are rows under existing CoSAI T1 and T7 columns. IETF draft reference goes in each catalog entry's `references` array only.

8. **IETF PR goal:** Opening a PR to the IETF draft citing cosai-mcp as a verification implementation is an explicit delivery commitment, not a nice-to-have. Target: submit alongside the first probe release.
