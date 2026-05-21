# Crucible Audit — IETF Agent Auth Extension

**Decision:** Extend cosai-mcp with IETF draft-klrc-aiagent-auth-01 coverage: 6 probes, 3 harness scenarios, WIMSE identity module  
**Tier:** T1 — Strategic  
**Date:** 2026-05-21  
**Mnemo:** `dec_cf1626f7ae`

---

## Verdicts

| Lens | Verdict | Reason |
|---|---|---|
| Market | CHALLENGED | CIBA probes have immediate pull; WIMSE/transaction-token work has no testable targets for 12+ months |
| CTO | CHALLENGED | Transaction token probes have an unsolvable chicken-and-egg; SC-11/SC-12 require multi-target fixture architecture that doesn't exist; probe ID namespace collision |
| CPO | CHALLENGED | R5 (CIBA) is a 2-day win with immediate value; R1–R4/R6 are 6.5 days for near-universal INCONCLUSIVE results today; no success metric stated |

**Outcome: HOLD → PROCEED** *(open questions resolved by CEO — see below)*

---

## Market Lens

**Who adopts this and why?**
The concrete person is a security engineer at a company shipping an enterprise MCP server who needs to demonstrate compliance with emerging IETF standards in a procurement or audit conversation. A secondary person: a contributor to the IETF draft who wants tooling they can cite in Security Considerations. Both are real; both are currently rare.

**Prior art:**
SPIFFE/SPIRE has a mature ecosystem but zero MCP-specific testing. No tool tests WIMSE/transaction-token enforcement in MCP context. The stateful multi-hop harness (SC-11/SC-12) is structurally unreplicable by static scanners or traffic proxies.

**Adoption risk:**
The IETF draft is at revision -01 with an empty Security Considerations section. WIMSE adoption in MCP deployments is realistically 12–18 months post-ratification. WIMSE probes will return `INCONCLUSIVE` on most real targets in the near term. The CIBA gap probes (`T07-002`, `T07-003`) are the exception — every deployed MCP server can be tested today.

**VERDICT: CHALLENGED** — immediate market pull exists for CIBA probes; WIMSE/transaction-token work is a research-bet timing call.

---

## CTO Lens

**Architecture risk — three blocking design gaps:**

1. **Transaction token probes (R1) have a chicken-and-egg problem.** `T01-006` requires sending a "valid bearer token issued for a different tool/resource combination." The scanner has no trust relationship with the target AS — it cannot obtain a legitimately-issued token to replay incorrectly. Every automated run returns `INCONCLUSIVE`. **Fix:** redesign as a `--token` flag (bring-your-own-token) so the user supplies a real token from their own AS; the scanner then replays it with mismatched parameters.

2. **SC-11/SC-12 require multi-target harness infrastructure that doesn't exist.** Current harness tests a single `MCP_TARGET_URL`. Cross-domain scenarios require simultaneous connections to two trust domains. This is a fixture architecture addition, not a new scenario file. **Fix:** decide before build: (a) ship a minimal two-AS in-process fixture server, or (b) require user to configure `--as1-url` and `--as2-url` explicitly.

3. **SC-13 (SSF revocation) requires a mock AS with revocation endpoint.** The scanner cannot revoke a token at a real AS it doesn't hold credentials for. **Fix:** ship a minimal in-process mock AS as a test fixture (scoped to the harness test runtime, not a new runtime dependency).

**Additional gaps:**
- Probe ID collision: `T01-007` assigned twice (mismatched `aud` in R1 and unknown workload identity in R2). Seven distinct probes described across R1–R5 but only six catalog IDs in the Design section. Reconcile before writing any catalog JSON.
- `joserfc` covers JWT/JWS operations. HTTP Message Signatures (RFC 9421), required for WIMSE Proof Tokens (WPTs), may need a separate library. Verify before writing `wimse.py`.

**VERDICT: CHALLENGED** — design gaps are solvable but must be resolved before implementation starts; no architectural contradiction with locked decisions in `CLAUDE.md`.

---

## CPO Lens

**User value — sharply uneven:**

| Requirement | Value now | Value in 12 months |
|---|---|---|
| R5 (CIBA/MCP confirmation) | High — every server testable today | High |
| R1 (transaction tokens) | Near-zero — no servers implement this | Medium |
| R2 (WIMSE workload identity) | Near-zero — advisory-only by design | Medium |
| R3 (cross-domain chaining) | Near-zero — no test infrastructure | Medium |
| R4 (SSF revocation) | Near-zero — requires mock AS | Medium |
| R6 (WIMSE module) | Enabling only | Medium |

**Scope risk:** The 8.5-day bundle obscures a 2-day win (R5 alone = 80% of immediate value).

**Cannibalization:** Adding a second coverage column "IETF draft-klrc-aiagent-auth-01" alongside "CoSAI T1–T12" dilutes the primary positioning before CoSAI coverage is fully deployed.

**Missing success metric:** "Seat at the IETF standards table" is not measurable in 30 days.

**VERDICT: CHALLENGED** — ship R5 as a standalone first; gate the rest on design resolution and a stated success metric.

---

## Open Questions — CEO Answers

| # | Question | Answer |
|---|---|---|
| 1 | Is "cited in IETF Security Considerations" a goal worth 8.5 days, or a nice-to-have? | **It is a goal.** Assign someone to open a PR to the IETF draft citing cosai-mcp. |
| 2 | At what WIMSE adoption signal do R1–R4/R6 become worth building? | **Build now.** No adoption threshold gate — proceed with full scope. |
| 3 | Does "two coverage columns" (CoSAI + IETF) strengthen or weaken positioning? | **Frame as "CoSAI T1/T7 extended."** Not a separate standards column. |

---

## Resolved Blockers Before Build Starts

Given CEO decision to proceed now, these design questions must be answered before the first line of code:

1. **T01-006 mechanism:** Redesign as `--token <jwt>` (BYOT) probe. Scanner replays the user-supplied token with mismatched `aud`/tool. Document this in R1 acceptance criteria before implementation.

2. **SC-11/SC-12 fixture:** Ship a minimal in-process two-AS fixture (no new external dependency — implemented as a `pytest` fixture server in `tests/fixtures/`). Not user-configurable at MVP.

3. **SC-13 mock AS:** Same in-process fixture as above. Revocation endpoint is a single `/revoke` POST handler that marks a JTI as revoked in a dict.

4. **Probe ID reconciliation:** Assign IDs cleanly before any catalog JSON is written:
   - `T01-006` — transaction token absent / broad token forwarded
   - `T01-007` — mismatched `aud` claim (token replay with wrong audience)
   - `T01-008` — token forwarding anti-pattern (tool echoes agent token)
   - `T01-009` — unknown workload identity (no SPIFFE subject, no `sub_jwk`)
   - `T07-002` — MCP confirmation treated as OAuth authorization
   - `T07-003` — OAuth scope checked after MCP confirmation, not before
   - `T07-004` — SSF revocation not respected

5. **`joserfc` / HTTP Message Signatures:** Verify RFC 9421 coverage before writing `wimse.py`. If not covered, add `http-message-signatures` to locked runtime deps in `CLAUDE.md`.

6. **Success metric:** At least one real MCP server returns `FAIL` (not `INCONCLUSIVE`) on `T07-002` or `T07-003` within 30 days of shipping. If none do, probe logic is wrong — not the servers.

---

## Assumptions Logged to Mnemo

| ID | Assumption | Criticality | Review date |
|---|---|---|---|
| `asm_bb220f06e1` | WIMSE adoption >10% of new MCP servers within 18mo of ratification | high | 2027-01-01 |
| `asm_dd13641a4a` | `joserfc` covers WIT/WPT crypto (HTTP Message Signatures unverified) | high | 2026-06-15 |
| `asm_83a18c1b88` | IETF draft reaches ratification (at -01, not guaranteed) | medium | 2026-12-01 |
| `asm_22075a9c4b` | MCP servers widely misimplement CIBA confirmation as authorization | critical | 2026-06-21 |
| `asm_e92582a067` | T01-006 buildable as BYOT `--token` flag probe | high | 2026-07-01 |
