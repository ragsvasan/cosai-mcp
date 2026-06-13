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
| COV-02 | T6 | 2 | ⬜ | Replace T06-001/002 tools/list-succeeds probes with manifest name-collision + Levenshtein enumeration. |
| COV-03 | T6 | 2 | ⬜ | Implement manifest-drift diff in `run_scenario`. |
| EFF-05 | T2 | 3 | ⬜ | Wire `--read-token` / `COSAI_READ_TOKEN` → `ScanConfig.read_token`. |
| COV-10 | T7 | 3 | ⏳ | T7-SC-002 claim struck from coverage-matrix.md T7 row pending registration in api.py. |
| COV-05 | T12 | 3 | ⬜ | Remove/relocate dead T12-002.json (+.sig). |
| EFF-01 | Ent | 4 | ⬜ | PyPI package + scan-action repo + fix install docs; publish steps handed back. |
| EFF-02 | Ent | 5 | ⬜ | `compliance_mappings` on CategoryResult from signed catalog. (Stub field reserved.) |
| EFF-06 | Ent | 5 | ⬜ | `--expected-catalog-hash` (exit 2 on mismatch). |
| EFF-07 | Ent | 5 | ⬜ | Target-scoped baseline → SARIF suppressions w/ scanner-generated partialFingerprints. |
| EFF-03 | Cov | 6 | ⬜ | HTML report: NOT-TESTED distinct from PASS. (Scorecard JSON already does via NOT_TESTED + inconclusive_count.) |
| EFF-04 | X | 6 | ⬜ | Default `--fail-on` → `high`. |
| EFF-11 | T5 | 6 | ⬜ | Grade middleware-primary categories partial/not_tested with no middleware signal. |
| COV-09 | T2 | 7 | ⬜ | T02-004 manifest substring scan → relabel informational / real enumeration. (Currently the 2 live "findings".) |
| EFF-ALL (T3/T12) | T3/T12 | 7 | ⬜ | SQLi + malformed-JSON-RPC probes for T3; passive `_meta.attestation` for T12. |
| EFF-08/09/10/12 | Ent | 8 | ⬜ | Auth plugin / fleet mode / signer PKI (design hand-back) / repo hygiene. |
| COV-01 | T2 | — | ❎ | Refuted in audit appendix (precondition gate exists). No action. |
| EFF-ALL (-32029) | T10 | — | ❎ | Refuted (backoff exists). No action. |

## Batch 1 — panel results (T1 tier)

- **Defense (Sonnet):** FIX[1] missing subprocess-roundtrip test for `protocol_error_is_expected` → added `test_regression_protocol_error_is_expected_survives_subprocess_roundtrip`. FIX[2] no `-32601`→INCONCLUSIVE catalog tests for T02-001/003/T07-002 → added `TestT02MethodNotFoundIsInconclusive`.
- **Adversary (Opus):** EXPLOIT[1] (real, self-introduced) blanket opt-out let a tool-absent `-32601` vacuously PASS T10/T11 → fixed: opt-out now suppresses only request-level `-32600`/`-32700`; `-32601`/`-32602` always downgrade. Regression tests added. EXPLOIT[2] `_probe_inspects_error_code` exemption on T11-001-p1 is pre-existing; deferred to Batch 2 (positive-control via manifest enumeration). T07-003/exit-code regressions: no exploit.
- Full suite: 1297 passed, 1 skipped. Live mnemo: CLEAN, 21 inconclusive, T07-003 false-positive gone.
