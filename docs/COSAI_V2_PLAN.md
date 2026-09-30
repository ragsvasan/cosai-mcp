# CoSAI MCP Security v2.0 — Alignment Plan

**Source:** CoSAI Workstream 4, *Model Context Protocol (MCP) Security* v2.0 (12 Aug 2026, updated for the MCP **2026-07-28** release) and the announcement post *"MCP Security Version 2.0: From Threat Taxonomy to a Model You Can Actually Audit Against"*.
**Plan date:** 2026-09-27 · **Owner:** cosai-mcp maintainers · **Decision ledger:** Mnemo `cosai` / `dec_a8957a9070` (lifecycle amendment)

---

## 1. What changed in v2.0

| Area | v1.0 | v2.0 | Impact on cosai-mcp |
|---|---|---|---|
| Taxonomy | T1–T12, 34 threats | **Unchanged** (strict superset); IDs now written `MCP-T1`…`MCP-T12`; threats split into Tier 1 MCP-specific (7), Tier 2 contextualized (8), Tier 3 conventional (19) | Catalog layout and three-engine architecture stand. Add `MCP-Tn` alias + threat number (1–34) to catalog metadata. |
| Protocol baseline | 2025-06-18 / 2025-11-25 | Adds **2026-07-28**: no `initialize`, no `Mcp-Session-Id`; `server/discover`; per-request `_meta` identity; `MCP-Protocol-Version` / `Mcp-Method` / `Mcp-Name` headers; `requestState` (MRTR); Tasks extension; `ttlMs`/`cacheScope`; JSON Schema 2020-12; Roots/Sampling/Logging deprecated | **P0 — scanner was blind to modern-only servers.** Done in this change. |
| New attack surface | — | Header/body split-brain; `_meta` identity spoofing; legacy-path downgrade; tampered sealed state; task-ID enumeration; tasks outliving revoked grants; cross-tenant caching; `$ref`/schema bombs; MCP Apps UI; elicitation phishing | P1 probes (§4). |
| **Security Assurance Profiles** (§3.3) | — | L1 Sandbox · L2 Internal · L3 Production · L4 Regulated; MUST/SHOULD matrix across 8 dimensions; **L3 hard-requires DPoP/mTLS token binding** | P1 level verifier (§5). §3.3.5 explicitly calls for automated tooling that verifies a claimed level — this is our product. |
| OWASP cross-refs | titles | `MCP01`…`MCP10` IDs (e.g. T9→MCP02, T5→MCP10, T10→none) | `scorecard/compliance.py` uses `A01…` titles that diverge — signed scorecards currently attest a mapping that contradicts CoSAI's. P1 fix (§6). |
| Open questions | — | #4 **Evidence-per-level annex** deferred | Upstream contribution opportunity (§7). |

---

## 2. Backward-compatibility contract (applies to every phase)

1. **Legacy servers see no behaviour change** except one extra `server/discover` request per scan (answered `-32601`), after which the era is pinned to `legacy` and every per-probe session is byte-identical to the pre-v2 scanner.
2. `--protocol-era legacy` (or `ScanConfig(protocol_era="legacy")`) reproduces the pre-v2 wire sequence exactly — no `server/discover`, no `_meta`, no new headers. This is the escape hatch for fragile stdio servers that crash on unknown methods.
3. Exit codes, SARIF shape, scorecard schema, catalog schema, and the public `Scanner` / `ScanConfig` / `SessionInfo` APIs are unchanged. New fields are additive with defaults (`ScanConfig.protocol_era="auto"`, `SessionInfo.protocol_era="legacy"`).
4. Catalog changes (P1 §6) are additive metadata; official files are re-signed, never re-numbered.
5. Supported protocol revisions: 2024-11-05 (LegacySSE), 2025-03-26, 2025-06-18, 2025-11-25, 2026-07-28.

---

## 3. P0 — MCP 2026-07-28 support ✅ (this change)

**Problem:** `session.py` hard-coded `initialize` with `2025-03-26`; a modern-only server rejects `initialize`, so every scan reported `scan-incomplete`.

**Delivered**

| Item | Where |
|---|---|
| Wire helpers: versions, `_meta` keys, error codes `-32020/-32021/-32022`, header encoding (`=?base64?…?=`), `Mcp-Name`, `x-mcp-header` → `Mcp-Param-*`, era classifier | `cosai_mcp/protocol.py` |
| Dual-era `MCPSession.start()`: modern `server/discover` → `tools/list`; spec fallback to legacy handshake; **no downgrade** of a recognisably modern server; `_meta` merged into every modern request (probe keys win) | `cosai_mcp/session.py` |
| Streamable HTTP request-metadata headers; `Mcp-Session-Id` suppressed in modern mode; probe `override_headers` applied last | `cosai_mcp/transport/streamable_http.py`, `transport/base.py` |
| Era detected once per scan and pinned for all per-probe processes | `discovery.detect_protocol_era`, `api._run_scan` |
| `--protocol-era auto|modern|legacy` (CLI, `Scanner`, `ScanConfig`) | `cli.py`, `api.py`, `config.py` |
| Inventory capture runs both eras through the pinned dual-era session (raw unpinned httpx path removed; SSE-aware; loop-safe sync API) | `inventory/snapshot.py` |
| Unauthenticated (T1) probes keep the *requested* era so a dual-era server's open legacy `initialize` is still caught; a 401 on `server/discover` alone is verified against the probe's actual request in both wire framings — PASS only if both are rejected 401/403, never on an unverifiable result (2026-07-28 has no handshake gate) | `api._run_scan`, `harness/runner.py`, `session.enter_unverified` |
| Scanner-caused envelope rejections `-32020/-32021/-32022` are INCONCLUSIVE, never a vacuous PASS; probe-spoofed `_meta` version mirrored into the header | `harness/context.py`, `transport/streamable_http.py` |
| Total deadlines on parent-process era detection and tool discovery (drip-feed stall) | `discovery.py` |
| `--protocol-era` rejected in fleet mode (was silently ignored) | `cli.py` |
| `server/discover`, `subscriptions/listen` added to reserved-method sets (T6 shadowing) | `api.py`, `middleware/integrity.py`, `stateful/harness.py` |
| Mock server `protocol_era=legacy|modern|dual` enforcing spec header–body validation | `harness/mock_server.py` |
| Locked lifecycle contract amended | `CLAUDE.md` |
| Tests: unit, real-HTTP session, no-downgrade, auth-reject keyword preservation, ProbeRunner subprocess, `Scanner` entry point, inventory | `tests/test_protocol_era.py` |

**Known limits (tracked into P1):** fleet mode (`--targets`) always auto-detects per target (`--protocol-era` is rejected there); a dual-era server is scanned over its modern path for authenticated probes (legacy-path coverage for non-auth categories is the P1 *legacy downgrade* probe); stdio legacy servers that *hang* on unknown methods cost one probe-timeout before fallback (use `--protocol-era legacy`); `resultType: input_required` (MRTR) responses are not yet driven — reported as data, not followed; the era in use is not yet written into SARIF/scorecard.

---

## 4. P1 — New probes for the 2026-07-28 attack surface

**P1a batch 1 — shipped** (schema 1.2 adds optional probe `requires_protocol_era`; era-gated probes report INCONCLUSIVE "not applicable" on the other era):

| ID | Check | Vulnerable → | Secure → |
|---|---|---|---|
| T07-004 (high) | `Mcp-Method` / `Mcp-Name` header ≠ body accepted | served | 400 + `-32020` |
| T07-005 (medium) | Unknown `_meta` protocolVersion served (no version floor) | served | `-32022` |
| T07-006 (low) | Modern server still accepts legacy `initialize` (downgrade path) | handshake accepted | declined |
| T11-002 (info) | Deprecated protocol `logging` capability advertised | advertised | absent |
| passive T3 | Tool schema: external `$ref`, spec-invalid `x-mcp-header`, validator-DoS size | finding per tool | clean marker |

**P1a batch 2 — shipped:**

| ID | Check | Engine |
|---|---|---|
| T01-007 (high) | Unauthenticated request with spoofed `_meta` clientInfo/capabilities served | prober (T1 no-auth path; era-gated verification uses the probe's own framing) |
| T07-007 (high) | `tasks/list` enumeration still served; guessable `tasks/get` IDs return tasks | prober |
| T05-003 (medium) | Tool result marked `cacheScope: public` | prober |

These link to assurance controls SD-02, SD-01 and TI-05 as *optional* disproof links. A conclusive finding fails the control, but a probe that doesn't apply to the target doesn't block attestation.

**Withdrawn:** a black-box MRTR `requestState` tamper check. It would have to alter a live server's client-held state and run a real tool to completion. Its verdict also depends on guessing the state format: sealed vs. unsealed, JSON vs. opaque, MAC field names, and handle shapes. Three review rounds kept finding cases where it misjudged a server or risked acting on another operation's state. SD-03 (client-held state integrity) is therefore covered by operator evidence plus the P2 middleware: a sealing helper that binds HMAC/AEAD to principal, expiry and request ID, with verification on receipt.

**OAuth discovery / audience — shipped:**
- **Passive RFC 9728 Protected Resource Metadata check** (`cosai_mcp/wellknown.py`, SARIF `T01-100`, disproves SD-04). It runs when the server answers an unauthenticated request with HTTP 401, and uses the `WWW-Authenticate` `resource_metadata` or the well-known path.
  - It requires `resource` to name this server and `authorization_servers` to be HTTPS.
  - Requests are same-origin only, through the pinned transport (Mnemo `dec_451b2d49f9`). An off-origin `resource_metadata` is reported, never fetched.
- **T01-008 (high):** a valid token issued for another resource (`--foreign-audience-token`) must be rejected. This is an optional link to AZ-06.

Still open (need server-specific hooks or a full OAuth client): RFC 9207 `iss` validation (a client-side authorization-response check); tasks outliving a revoked grant (needs a revoke hook); T12 trace-context overwrite (middleware); MCP Apps UI / elicitation-credential checks.

Original list (for reference):

All black-box unless noted. Each gets a catalog entry (signed), a mock-server vulnerable/secure mode, and an entry-point test.

| ID (proposed) | Cat | Check | Engine |
|---|---|---|---|
| T07-0xx | T7 | **Header/body mismatch** — `Mcp-Name`/`Mcp-Method` disagree with body → must be `400` + `-32020` | prober (uses `override_headers`, already expressible) |
| T07-0xx | T7 | **Legacy downgrade** — server advertising 2026-07-28 still accepts `initialize`; if so, verify per-request auth on the legacy path | stateful |
| T07-0xx | T7 | **Version floor** — requests below policy minimum must get `-32022` | prober |
| T07-0xx | T7 | **Tampered `requestState`** — flip one byte of an `InputRequiredResult.requestState` → must reject | stateful |
| T07-0xx | T7 | **Task handles** — entropy/enumeration; tenant IDs leaked in task ID; task continues after grant revocation | stateful |
| T01-0xx | T1 | **`_meta` identity spoof** — claimed `clientInfo`/capabilities must not change authorization | prober (already expressible via probe `_meta`) |
| T01-0xx | T1 | RFC 8707 audience; RFC 9728 Protected Resource Metadata present; RFC 9207 `iss` | prober |
| T02/T05-0xx | T2/T5 | User-scoped result advertised `cacheScope: public` / long `ttlMs` | prober |
| T03-0xx | T3 | Manifest: external/deep `$ref`, composition bombs, missing `additionalProperties:false`, invalid `x-mcp-header` | passive manifest scan |
| T04-0xx | T4 | MCP Apps `ui://` resources without CSP / with inline script; form-mode elicitation requesting credentials | passive + prober |
| T12-0xx | T12 | Server overwrites client `traceparent`; baggage leaks tenant data | prober |
| INFO | — | Server advertises deprecated Roots / Sampling / Logging | passive |

Middleware counterparts (P2, §8) supply T4/T9/T12 detection per the three-engine rule — never claim black-box coverage for those.

---

## 5. P1 — Assurance-level verifier (`--assurance-level N`)

**P1b — shipped.** `cosai scan TARGET --assurance-level {1..4} [--evidence DIR] [--report-assurance out.json] [--scorecard sc.json]` (advanced flags).

- **Controls:** 47 rows across all 8 v2.0 dimensions in `cosai_mcp/assurance/controls.py`. They are frozen in-package data, not a signed JSON catalog (Mnemo `dec_64a81342b1`). `probe_threats` link catalog probes, passive scans, and stateful scenarios that can **disprove** a control. `verify_with` lists the positive-signal probes, those asserting a specific rejection code or status, that can **prove** it up to `blackbox_max_level`. Negative assertions ("did not leak X"), reachability checks, and generic `error == true` checks never prove a control. Today only TN-04 (request-metadata validation: T07-004/005, up to L3) is provable black-box.
- **Verdicts** (Mnemo `dec_8575e56c7c`), in precedence order:
  1. FAIL: any linked conclusive finding, including baseline-suppressed ones.
  2. UNVERIFIED: a linked test did not run or produced no conclusive result; evidence cannot override this.
  3. ATTESTED: operator evidence was supplied.
  4. PASS: every result of every `verify_with` probe passed conclusively.
  5. UNVERIFIED otherwise.
- **Level results:** NOT_MET, INDETERMINATE, MET (every MUST is PASS) or MET_WITH_ATTESTATION (≥1 MUST is ATTESTED). Both MET forms exit 0; anything else exits 1. Exit 2 is never downgraded.
- **Scope:** a level claim requires a full scan. `--categories`, `--engine` other than `all`, a profile with `skip_categories`, and `--allow-custom-catalog` are all rejected. The effective scope is signed inside the block: engine, profile, protocol era, token presence, adaptive mode, method overrides, baseline, and attested control IDs.
- **Evidence intake:** `DIR/evidence.json` (`schema_version` 1.0, required `target` matching the scanned URL, `controls: {ID: {artifact, note}}`).
  - Strict keys, and only known control IDs.
  - Artifacts must be non-empty regular files inside DIR, with no symlinked component; sizes are capped and each SHA-256 is recorded.
  - Display strings are stripped of control characters and HTML-escaped.
  - Any violation exits 2 before a probe is sent.
- **Scorecard:** the additive `assurance` block is signed. It is omitted when absent, so older scorecards still verify. `scorecard verify` and `scorecard show` reject duplicate JSON keys and any field that differs from the canonical signed form, and they print the claim. `show` labels an unverified claim as such.
- **Assurance report:** `--report-assurance` is written after the scorecard, as an explicitly unsigned copy bound to the scorecard's signature.
- **Not yet built:** an HTML report section; the evidence-per-level annex (artefact names per control) for upstream; positive-signal verifier probes for more controls (for example a dedicated 413/-32600 size-limit probe for TN-05).

Original design notes (superseded where they differ):

**Goal:** answer the v2.0 §3.3.5 call — *"automated checks … that validate whether a deployment meets a claimed level"* — with a signed, per-control verdict.

- **Control catalog** (`catalog/assurance/`, signed like the threat catalog): one entry per matrix row × level. Fields: `control_id` (e.g. `AUTH-TOKEN-BINDING`), `dimension` (8), `level`, `strength` (MUST/SHOULD), `mcp_t` refs, `owasp` refs, `verification` ∈ {`probe`, `stateful`, `middleware`, `evidence`}, linked probe IDs.
- **Verdicts per control:** `PASS` / `FAIL` / `EVIDENCE-REQUIRED` / `NOT-TESTABLE-BLACKBOX` / `INCONCLUSIVE`. Organisational controls (SBOM, inventory, SIEM, TEE, decommissioning) are **never** reported PASS from a black-box scan.
- **Evidence intake:** `--evidence <dir>` accepts the artefacts named in v2.0 open question #4 (discovery response, PRM endpoint, SBOM attestation, egress policy, sample audit record, extension inventory…); each verified or rejected, recorded in the scorecard.
- **Gate:** claimed level not met on any MUST → exit 1; verifier error → exit 2 (locked exit-code contract).
- **Scorecard:** level claim, per-control verdicts, and evidence hashes inside the signed payload (Sigstore path already exists).
- Naming: "assurance level", not "profile" — `cosai_mcp/profiles/` already means *server profiles*.

---

## 6. P1 — Mapping reconciliation

**P1c — shipped:** compliance map, both THREAT_MAPPING.md tables, CLI passive-scan stubs, and every official catalog `owasp_ref` (re-signed) now use the official OWASP MCP Top 10 (2025) IDs `MCP01:2025`…`MCP10:2025` per v2.0 §3.3.3 (T10 unmapped). Pinned by `test_regression_compliance_map_matches_cosai_v2_table` and `test_regression_catalog_owasp_ref_matches_cosai_v2_table`. **Catalog labels — shipped (schema 1.3):**
- Every official entry, including adversarial ones, now carries `mcp_t_ref` (`MCP-T1`…`MCP-T12`) and `threat_refs`, the v2.0 §3.1 threat numbers 1–34 it tests.
- Each number is constrained to the v2.0 threat table for the entry's category, enforced by `tests/catalog/test_v2_threat_refs.py`.
- The tier (1 MCP-specific, 2 contextualized, 3 conventional) is derived from the numbers, not stored.
- SARIF rule properties carry `cosai_mcp_t`, `cosai_threats` and `cosai_threat_tiers`.
- The backfill script is `scripts/backfill_v2_threat_refs.py`.

- Replace `A01…` titles in `scorecard/compliance.py`, `docs/THREAT_MAPPING.md`, and the SARIF `helpUri` target with the v2.0 `MCP01…MCP10` cross-reference; extend `test_compliance_map_matches_owasp_alignment_table` to pin all three to the v2.0 table.
- Add `mcp_t_ref` (`MCP-T4`), `threat_refs` (1–34), and `tier` (1/2/3) to the catalog meta-schema as **optional** fields; backfill official files and re-sign.
- Reports display `MCP-Tn` alongside `Tn`.

---

## 7. P2/P3 — Middleware, docs, upstream

**Middleware (P2):** CSPRNG, tenant-bound, revocable task/continuation handles + per-principal task enumeration (`session.py`); HMAC/AEAD seal helper for `requestState` bound to principal + expiry + request ID; `_meta` claim ↔ authenticated-principal reconciliation (`auth.py`, DPoP already present); header/body consistency + bounded JSON Schema 2020-12 validation (`validation.py`); OCSF agentic fields `delegation_path`, `attestation_state`, `correlation_id`, `mcp_method`, `mcp_name` + W3C Trace Context (`telemetry/ocsf.py`). Mirror into mcp-armor.

**Docs (P3):** README coverage matrix gains per-level columns and a protocol-support line; `VALUE_PROP.md` positions cosai-mcp as the §3.3.5 automated verifier; post-quantum (ML-DSA catalog signing, hybrid X25519+ML-KEM-768) recorded as roadmap only.

**Upstream:** contribute the **evidence-per-level annex** (v2.0 open question #4) and the control catalog to `cosai-oasis` as a reference implementation.

---

## 8. Sequencing & acceptance

| Phase | Exit criterion |
|---|---|
| P0 ✅ | Modern-only, dual-era, and legacy mocks all scan to completion via `Scanner`; legacy wire sequence unchanged under `--protocol-era legacy`; full suite green |
| P1a probes | Each new probe: vulnerable-mode FAIL + secure-mode PASS through `Scanner.run`, SARIF + HTML survive |
| P1b verifier | `--assurance-level 2/3` on mock profiles yields expected per-control verdicts; unsigned control catalog refused |
| P1c mapping | Compliance map, THREAT_MAPPING.md, SARIF helpUri agree with v2.0 table (test-enforced) |
| P2 | Middleware unit + integration tests; mcp-armor parity |
| P3 | Docs updated; annex PR opened upstream |

Every phase follows the project Code Review Gate (tiered panels) before commit.

**RUNNER EFFICIENCY RULES** (serial execution of this plan in one session)
1. `/compact` between phases. > COMPACT CHECKPOINT — [human: type `/compact` | autonomous runner: summarize verdicts so far in a tight table and drop raw tool payloads before continuing]
2. Terse runner output: nothing before a tool call; nothing after unless it is the verdict/finding; one line per tool: `tool_name → key_return_value`.
