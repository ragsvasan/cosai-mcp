# Audit 2026-06-12 — Resolution Tracker

Status of each finding from [AUDIT_2026-06-12.md](AUDIT_2026-06-12.md). Updated as roadmap batches land.

Legend: ✅ fixed-with-tests · 🔁 handed-back (needs human/credentialed step) · ⏳ in progress · ⬜ not started · ❎ wontfix/refuted

| ID | Cat | Batch | Status | Notes |
|----|-----|-------|--------|-------|
| COV-04 | T07 | 1 | ✅ | T07-003 forged `alg=none` token removed; now relies on operator token + `contains "onfirmation"` corroboration. A secure server yields PASS/INCONCLUSIVE, never the old HIGH false-positive. Verified live: T07-003 absent from mnemo SARIF. Re-signed. |
| COV-06 | T02 | 1 | ✅ | `-32601`/`-32602`/`-32600`/`-32700` on a `response.error`-only probe → INCONCLUSIVE (forced `passed=False`); never a vacuous PASS. Probes asserting `error_code` are exempt. Live: T02 categories now INCONCLUSIVE vs mnemo. |
| EFF-ALL (core) | — | 1 | ✅ | `-32601`/schema errors → INCONCLUSIVE not PASS (context.py); scorecard grades all-inconclusive categories NOT_TESTED, excludes inconclusive from findings. 21 inconclusive on live mnemo (was vacuous PASS). |
| COV-08 (partial) | T8 | 1 | ⏳ | T8 SSRF boundary-rejection now INCONCLUSIVE (no positive evidence the tool fetches URLs). Metadata-marker positive-evidence assertions = Batch 7. |
| COV-11 (partial) | T11 | 1 | ⏳ | T11-001-p2 bare error-presence → INCONCLUSIVE on `-32601` (rejection-because-tool-absent is not allowlist proof). Real typosquat detection = Batch 2. T11-001-p1 (`error_code_in`) still exempt — pre-existing, tracked for Batch 2. |
| COV-02 | T6 | 2 | ✅ | Added `_scan_manifest_t6` (api.py): name-collision + reserved-MCP-method-shadow + Levenshtein-1 near-collision (plural pairs suppressed). A shadowed/typosquatted manifest now FAILS T6; clean manifest emits a PASS marker. Scorecard `_category_from_threat_id` fallback categorises manifest results (also fixes latent T4/T9 gap). `_run_scan` wiring covered. T06-001/002 retained as redundant liveness checks (real signal is the scan). |
| COV-03 | T6 | 2 | ✅ | `_detect_manifest_drift` in `run_scenario` diffs tools/list manifests across scenario steps; a drifting 2nd manifest appends a synthetic failing step → scenario FAILS. Integration test drives changed/empty 2nd manifest. |
| EFF-05 | T2 | 3 | ✅ | `--read-token` / `COSAI_READ_TOKEN` CLI flag added; threaded through `_run_scan` → `ScanConfig.read_token`. T02-005 scope probes now run instead of silently INCONCLUSIVE. README.md:123 example now matches reality. |
| COV-10 | T7 | 3 | ✅ | `t7_session_revocation` (T7-SC-002) registered in the stateful engine. **Hardened in Batch 6**: registration alone false-positived against secure mnemo (the synthetic `session/terminate` returns -32602 → nothing revoked → post-call succeeds → false "bypass"). Added an unsupported-method gate: a NON-standard-method step returning a protocol-validation error (-32601/-32602/-32600/-32700) → scenario INCONCLUSIVE, not a finding. Verified live: T7-SC-002 INCONCLUSIVE vs mnemo, exit 0. |
| COV-05 | T12 | 3 | ✅ | Dead T12-002.json + .sig moved OUT of `catalog/official/` (T12 is middleware-only; the prober skipped it) into `tests/fixtures/catalog/official/`. Sig verifies by bytes regardless of path; probe-mechanism tests retained via a fixture-rooted loader. No longer ships as dead production catalog. |
| EFF-01 | Ent | 4 | 🔁 | pyproject.toml is already PyPI-ready. Remaining = credentialed/human: PyPI publish, `cosai-mcp` org + `scan-action` repo, release workflow, fixing install docs once published. All steps documented in [RELEASE_HANDOFF.md](RELEASE_HANDOFF.md). |
| EFF-02 | Ent | 5 | ⬜ | `compliance_mappings` on CategoryResult from signed catalog (NIST/RMF). Not started — handed back. |
| EFF-06 | Ent | 5 | ⬜ | `--expected-catalog-hash` (exit 2 on mismatch). Not started — handed back. |
| EFF-07 | Ent | 5 | ⬜ | Target-scoped baseline → SARIF suppressions w/ scanner-generated partialFingerprints. Not started — handed back. |
| EFF-03 | Cov | 6 | ✅ | HTML report now renders a "Coverage — all CoSAI categories" matrix from the scorecard: every T1–T12 category shows its grade, with NOT-TESTED styled distinctly and an explicit "It is NOT a pass" note + per-category inconclusive counts. |
| EFF-04 | X | 6 | ✅ | `--fail-on` default changed critical→high (matches cosai-gate.yml), so HIGH auth/session findings now exit 1. |
| EFF-11 | T5 | 6 | 🔁 | Deferred. Needs a "partial" grade concept for middleware-primary categories with only black-box signal; a half-baked change risks mislabeling T5's legitimate black-box probes. Low severity — handed back as a small design item. |
| COV-09 | T2 | 7 | ⬜ | T02-004 manifest substring scan → relabel informational / real enumeration. (Currently the 2 live "findings".) |
| EFF-ALL (T3/T12) | T3/T12 | 7 | ⬜ | SQLi + malformed-JSON-RPC probes for T3; passive `_meta.attestation` for T12. |
| EFF-12 | Ent | 8 | ✅ | Repo hygiene: `.testmondata*` and `cosai-*-report.*` / `cosai-report.*` added to .gitignore (other patterns already present). No stray reports are tracked. Default-to-out-dir CLI change deferred (minor). |
| EFF-08 | Ent | 8 | 🔁 | Auth plugin (RFC 8693 token-exchange, DPoP, secret-resolver). Scoped in [RELEASE_HANDOFF.md](RELEASE_HANDOFF.md); larger than this pass. |
| EFF-09 | Ent | 8 | 🔁 | `--targets` fleet mode + bounded concurrency. Scoped in RELEASE_HANDOFF.md. |
| EFF-10 | Ent | 8 | 🔁 | Signer-identity PKI (X.509 vs Sigstore/PEP 740) — a key-management DESIGN decision; options doc in RELEASE_HANDOFF.md, not picked unilaterally. |
| COV-01 | T2 | — | ❎ | Refuted in audit appendix (precondition gate exists). No action. |
| EFF-ALL (-32029) | T10 | — | ❎ | Refuted (backoff exists). No action. |

## Batch 1 — panel results (T1 tier)

- **Defense (Sonnet):** FIX[1] missing subprocess-roundtrip test for `protocol_error_is_expected` → added `test_regression_protocol_error_is_expected_survives_subprocess_roundtrip`. FIX[2] no `-32601`→INCONCLUSIVE catalog tests for T02-001/003/T07-002 → added `TestT02MethodNotFoundIsInconclusive`.
- **Adversary (Opus):** EXPLOIT[1] (real, self-introduced) blanket opt-out let a tool-absent `-32601` vacuously PASS T10/T11 → fixed: opt-out now suppresses only request-level `-32600`/`-32700`; `-32601`/`-32602` always downgrade. Regression tests added. EXPLOIT[2] `_probe_inspects_error_code` exemption on T11-001-p1 is pre-existing; deferred to Batch 2 (positive-control via manifest enumeration). T07-003/exit-code regressions: no exploit.
- Full suite: 1297 passed, 1 skipped. Live mnemo: CLEAN, 21 inconclusive, T07-003 false-positive gone.
