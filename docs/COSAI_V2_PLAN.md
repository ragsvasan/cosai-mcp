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

Remaining P1a (next batches):

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

**Goal:** answer the v2.0 §3.3.5 call — *"automated checks … that validate whether a deployment meets a claimed level"* — with a signed, per-control verdict.

- **Control catalog** (`catalog/assurance/`, signed like the threat catalog): one entry per matrix row × level. Fields: `control_id` (e.g. `AUTH-TOKEN-BINDING`), `dimension` (8), `level`, `strength` (MUST/SHOULD), `mcp_t` refs, `owasp` refs, `verification` ∈ {`probe`, `stateful`, `middleware`, `evidence`}, linked probe IDs.
- **Verdicts per control:** `PASS` / `FAIL` / `EVIDENCE-REQUIRED` / `NOT-TESTABLE-BLACKBOX` / `INCONCLUSIVE`. Organisational controls (SBOM, inventory, SIEM, TEE, decommissioning) are **never** reported PASS from a black-box scan.
- **Evidence intake:** `--evidence <dir>` accepts the artefacts named in v2.0 open question #4 (discovery response, PRM endpoint, SBOM attestation, egress policy, sample audit record, extension inventory…); each verified or rejected, recorded in the scorecard.
- **Gate:** claimed level not met on any MUST → exit 1; verifier error → exit 2 (locked exit-code contract).
- **Scorecard:** level claim, per-control verdicts, and evidence hashes inside the signed payload (Sigstore path already exists).
- Naming: "assurance level", not "profile" — `cosai_mcp/profiles/` already means *server profiles*.

---

## 6. P1 — Mapping reconciliation

**P1c — shipped:** compliance map, both THREAT_MAPPING.md tables, CLI passive-scan stubs, and every official catalog `owasp_ref` (re-signed) now use the official OWASP MCP Top 10 (2025) IDs `MCP01:2025`…`MCP10:2025` per v2.0 §3.3.3 (T10 unmapped). Pinned by `test_regression_compliance_map_matches_cosai_v2_table` and `test_regression_catalog_owasp_ref_matches_cosai_v2_table`. Still open: `mcp_t_ref` / `threat_refs` / `tier` catalog metadata.

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
