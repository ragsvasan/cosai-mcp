# cosai-mcp Audit — 2026-07-01 (Fable)

Five-lens, evidence-first audit (security/detection-effectiveness, source paper,
functionality, usability, enterprise-readiness) run against the current
`feat/method-overrides-cli` branch and a live, stock **FastMCP 3.4.2** target.
Every finding below is backed by a `file:line` reference or a command actually
run with its real output. Deduplicated against
[AUDIT_2026-06-12.md](AUDIT_2026-06-12.md),
[AUDIT_2026-06-12_RESOLUTION.md](AUDIT_2026-06-12_RESOLUTION.md), and
[PRODUCT_REVIEW_2026-06-16.md](PRODUCT_REVIEW_2026-06-16.md).

---

## 1. Executive summary

**No — not ready to ship as a reference implementation today.** The prior two
reviews focused on *whether a CLEAN verdict was meaningful* (vacuous PASS /
inverted assertions) and *whether the on-ramps existed* (PyPI, examples, API).
Substantial, real work has landed since: the `-32601`→INCONCLUSIVE gate now
holds, the inverted T07-003 is repaired, the Python API imports and constructs
as documented, PyYAML is a declared dep, the example servers exist, the HTML
report honestly shows NOT-TESTED, `--fail-on` defaults to `high`, and — verified
live — Ed25519 catalog signature verification, the socket-time network
allowlist / DNS-rebinding defense, and RE2 pattern safety all actually fire.
The engine's *foundations* are genuinely solid and, in places, more honest than
any competitor.

But this round surfaces a more fundamental problem than either predecessor: **the
scanner cannot complete a scan against a stock, spec-compliant FastMCP server —
the single most common Python MCP framework — over the spec's primary transport.
Pointed at its own shipped demo, following the README verbatim, it exits code 2
(scanner internal error).** Layered on top: the headline "1558 tests passing"
claim is false (the suite is 1461-passed/1-**failed**/1465-collected, with a
live red test on this branch), and the source paper materially overclaims
against the shipping code — the MC-INPATH "engine," the OIDC/KMS key-provider
chain, the signed control-mapping, and scorecard freshness/nonce are all
described in shipping present-tense but do not exist. The signed-attestation
trust story is undermined by a **committed** default signing seed. This is a
strong core trapped behind a broken primary workflow and a paper that describes
a more complete system than the one in the repo.

---

## 2. The headline verdict question

> **When cosai-mcp is pointed at a real, spec-compliant MCP server, does it
> produce a security verdict — or a scanner error?**
>
> Right now, against the dominant Python framework (FastMCP) over Streamable
> HTTP (the spec's primary transport), it produces a **scanner error (exit 2)** —
> on its own shipped demo, running the README's exact command.

I chose this question because it dominates every other finding. The 2026-06-12
audit could ask "does CLEAN mean secure?" only because it *assumed the scan
completes*. This round the more basic discovery is that the scan itself does not
complete against the most common real target. Catalog assertion quality, paper
rigor, and enterprise features are all downstream of "can the tool run at all,"
and today the answer for the mainstream case is no.

**Evidence (reproduced live, this session):**

```
$ python examples/fastmcp/server.py &        # the repo's own shipped demo, fastmcp 3.4.2
$ cosai scan http://127.0.0.1:8000 --report-sarif /tmp/scan.sarif ...
Target: http://127.0.0.1:8000
Probes: 46/48 failed   Scenarios: 5/5 failed
[ERROR] Scan completed with internal errors — treat as failure.
$ echo "exit: $?"  →  exit: 2
```

Every probe errored with one of two messages, both confirmed by curl:

```
# bare origin: scanner rewrites http://…:8000 → http://…:8000/mcp/ (trailing slash);
# fastmcp 3.x mounts at /mcp (no slash) and 307-redirects /mcp/ → /mcp:
"initialize request failed: Received redirect response (307). cosai-mcp never follows redirects."

# explicit /mcp/ path: initialize succeeds over SSE, but session id is dropped, so:
"Server returned error on tools/list: {'code': -32600, 'message': 'Bad Request: Missing session ID'}"
```

The one mitigation: it fails *loud* (exit 2, `executionSuccessful:false`), not as
a false CLEAN. But the primary advertised workflow — "point at any MCP server,
get a SARIF report" — is broken for the mainstream case.

---

## 3. Findings (ranked, deduplicated)

### CRITICAL

**FIND 1: `cosai_mcp/transport/streamable_http.py`:206-211 (and :115-117) /
Category: functionality/security / Severity: Critical**
- **What's wrong:** The Streamable-HTTP transport captures `Mcp-Session-Id`
  *only on the non-SSE (`else`) branch*. FastMCP (and any spec-compliant server)
  returns the `initialize` response as `text/event-stream` with the session id
  in the **HTTP header**; the SSE branch (`_consume_sse_response`) never reads
  it, so `self._session_id` stays `None` and every post-handshake request is
  rejected `-32600 "Missing session ID"`. Compounding it, :115-117 rewrites a
  bare origin to `…/mcp/` (trailing slash) on the stale assumption that
  "Mount('/mcp') issues a 307 to '/mcp/'"; fastmcp 3.x does the **opposite**
  (redirects `/mcp/`→`/mcp`), so bare-origin scans hit a 307 and the
  (correct, locked) no-follow-redirects policy turns every probe into an ERROR.
  This directly contradicts whitepaper §4.2 ("the harness uses this header on
  all subsequent requests after the handshake").
- **Evidence:**
  ```
  $ curl -sD - -o /dev/null -X POST http://127.0.0.1:8000/mcp -H 'Accept: application/json, text/event-stream' -d '{...initialize...}'
  HTTP/1.1 200 OK
  content-type: text/event-stream
  mcp-session-id: 1892cc354da8442f956e2c4ffa632e1f      ← header IS present
  ```
  streamable_http.py:206-211 — `if "text/event-stream" in content_type: data = await self._consume_sse_response(response)` (no session capture) `else: … if sid := response.headers.get("Mcp-Session-Id"): self._session_id = sid`.
  Test gap: `grep session_id tests/transport/*.py` → empty (no test asserts SSE-initialize session-id capture).
- **Fix:** Capture `Mcp-Session-Id` from `response.headers` *before* branching on
  content-type (the header is on the HTTP response regardless of body framing);
  and canonicalize the endpoint by probing the server's actual mount (or accept
  a same-IP, same-origin trailing-slash 307 as non-suspicious).
- **Test:** `test_regression_streamable_http_captures_session_id_over_sse` —
  asserts that after an SSE `initialize` carrying `Mcp-Session-Id`, the next
  request sends that header (mock server returns SSE + header, then requires it
  on `tools/list`).

### HIGH

**FIND 2: `README.md`:10,202 + `docs/COVERAGE.md`:4,84 + `tests/cli/test_cli.py`:588 /
Category: functionality/paper / Severity: High**
- **What's wrong:** The headline "1558 tests passing" is false on two counts:
  the true collected count is **1465**, and the suite is **not green** on this
  branch — `test_plain_help_shows_only_core_flags` fails because the most recent
  commit (947b68b, "add --tool-allowlist flag") added `--tool-allowlist` to the
  core `--help` surface without updating `_CORE_FLAGS`.
- **Evidence:**
  ```
  $ python -m pytest -q  →  1 failed, 1461 passed, 3 skipped in 222.70s
  $ python -m pytest --collect-only -q | tail -1  →  1465 tests collected
  AssertionError: plain --help must show exactly the 8 core flags;
    got [..., '--tool-allowlist']   (test_cli.py:588)
  ```
- **Fix:** Add `--tool-allowlist` to `_CORE_FLAGS` (or move it out of core help),
  then reconcile the count to 1465 in README/COVERAGE and add a CI guard that
  regenerates the number.
- **Test:** existing `test_plain_help_shows_only_core_flags` (make it pass) +
  `test_regression_docs_test_count_matches_collect` — asserts the README figure
  equals `pytest --collect-only` count.

**FIND 3: `cosai_mcp/signing.py`:43,71 (+ `cosai_mcp/keys.py`:17-19; whitepaper §4.4/§5) /
Category: security/paper / Severity: High**
- **What's wrong:** The "official" catalog's Ed25519 trust root is a **committed
  secret**: `_DEV_SIGNING_SEED = b"cosai-mcp-dev-catalog-signing-k0"`, used as
  the default signing seed when `COSAI_SIGNING_SEED` is unset. Anyone with the
  repo can sign a malicious file that verifies as "official." The signature
  *mechanism* works (tampered files are rejected — verified live), but the
  default trust anchor provides **zero** integrity. Whitepaper §4.4 says "the
  public key is hardcoded … so a disk-key swap does not change the trust root"
  and §5 leans on Ed25519 *non-repudiation* — neither discloses that the
  corresponding private seed ships in the tree.
- **Evidence:** `signing.py:43` `_DEV_SIGNING_SEED: bytes = b"cosai-mcp-dev-catalog-signing-k0"`; `signing.py:71` `seed = env_seed if env_seed is not None else _DEV_SIGNING_SEED`; `keys.py:19` "(deterministic dev/reference seed…)".
- **Fix:** Ship the official catalog signed by a key whose private half is *not*
  in the repo (org key via `COSAI_SIGNING_SEED`/KMS); make the committed seed a
  clearly-labeled test-only fixture that never verifies as `official/` provenance
  in a released build; disclose the trust model in §4.4/§5.
- **Test:** `test_regression_official_catalog_not_signed_by_dev_seed` — asserts a
  release build refuses `official/` files signed by `_DEV_SIGNING_SEED`.

**FIND 4: `docs/whitepaper.md` §5.6 (+ abstract) / Category: paper / Severity: High**
- **What's wrong:** The "priority-ordered key provider chain" (OIDC workload
  identity → Cloud KMS → OS keychain → env var), HKDF session-key derivation,
  and a `key_provider` attestation field are described in shipping present-tense
  and claimed as an **abstract contribution** — with no code behind them.
- **Evidence:** `grep -rniE "COSAI_OIDC|COSAI_KMS|hkdf|key_provider|env_var_legacy" cosai_mcp/` → no matches. Real signing is seed/keyfile/dev-seed only (signing.py). RELEASE_HANDOFF.md:51 lists signer identity (EFF-10) as an unresolved design decision.
- **Fix:** Rewrite §5.6 + abstract to describe only keychain/env-var (what
  ships); move OIDC/KMS/HKDF to §9 future work; drop from contributions.
- **Test:** N/A — doc fix.

**FIND 5: `docs/whitepaper.md` §7.3 (+ §4.3 code fragment) & `cosai_mcp/middleware/{boundary,trust}.py` /
Category: paper/functionality / Severity: High**
- **What's wrong:** The paper's flagship MC-INPATH "engine" is presented as a
  runnable third engine with a concrete `T4InterceptLayer` ASGI class
  (`MAX_MANIFEST_BYTES`, baseline-vs-delivered description-hash compare, "decides
  the mutation sub-property *exactly*") and a T9 engine that "instruments the
  authorization decision path and flags any data dependency on model output,"
  including a reported T9 false-positive metric. **Neither exists.** `boundary.py`
  ships only heuristic regex scanners; `trust.py` is a content sanitizer — exactly
  the pattern-matching the paper's own §3.2 says cannot decide T9. No code
  inserts instrumentation into a target's call path; no example wires
  `CoSAIStack`.
- **Evidence:** `grep -rn "T4InterceptLayer\|MAX_MANIFEST_BYTES" cosai_mcp/` → none; `grep -rln "async def __call__.*scope\|ASGIApp" cosai_mcp/` → none; only reachable middleware is the *passive manifest scan* `_scan_manifest_t4` (api.py:616, black-box, not in-path) and `AuditLogger.verify_chain` via the offline `cosai audit verify` CLI.
- **Fix:** Relabel MC-INPATH T4/T9 as not-yet-implemented; delete the fabricated
  code fragment and the "mutation exact" / T9 false-positive claims, or implement
  the harness. (T12 single-server hash-chain *is* real — keep it.)
- **Test:** `test_regression_inpath_engine_runnable` — asserts a scanner entry
  point attaches an in-path harness to a target ASGI app (none exists today).

**FIND 6: `docs/whitepaper.md` §5.4/§5.5 + `cosai_mcp/scorecard/models.py` /
Category: paper/enterprise / Severity: High**
- **What's wrong:** The paper claims (also in the abstract) that the signed
  scorecard "embeds the control mapping" and that "every scorecard payload embeds
  `issued_at`/`expires_at` (24h TTL) and a signed `nonce`." The signed
  `Scorecard` payload contains none of these.
- **Evidence:** live scorecard keys from my scan → `['catalog_hash','categories','conformance_level','public_key','scan_id','scan_timestamp','signature','target_url','tool_version']` (no control mapping, no expiry, no nonce). `owasp_ref` is emitted only in the *unsigned* SARIF (report/sarif.py), never in the signed payload; NIST AI RMF appears nowhere in any output. This is EFF-02, still open (RESOLUTION.md:20).
- **Fix:** Add a per-category control mapping (CoSAI/OWASP/NIST) + `issued_at`/
  `expires_at` to the signed `Scorecard`, or correct §5.4/§5.5/abstract to say
  the mapping lives in the unsigned SARIF and freshness is future work.
- **Test:** `test_regression_scorecard_embeds_mapping_and_expiry` — asserts a
  signed scorecard round-trips a control mapping and an expiry a gateway enforces.

**FIND 7: `docs/whitepaper.md` §3.2 line 88 / Category: paper / Severity: High**
- **What's wrong:** The Rice's-Theorem construction is formally wrong. It defines
  the index set over **Turing degrees** — `I = {[F] : S violates T4/T9}` where
  `[f]` is "the Turing degree of f" — but Rice's Theorem concerns index sets of
  *program indices* `{i : φ_i ∈ C}` for an extensional set of functions `C`.
  Turing-degree equivalence is coarser than "computes the same function." Worse,
  non-triviality is argued "relative to `M₀`'s hidden state," a **non-extensional**
  property — Rice applies only to properties of the I/O function. A hostile theory
  reviewer flags this as a category error that invalidates the direct Rice
  application as written.
- **Evidence:** whitepaper.md:88 verbatim; the stochastic (PFA-isolation) half is
  the sounder argument.
- **Fix:** Recast the index set as `{i : φ_i ∈ C}` over program indices with `C`
  an extensional set of I/O functions; drop "Turing degree"; or ground
  undecidability solely in the PFA-isolation reduction and demote the Rice half.
- **Test:** N/A — doc fix.

**FIND 8: `SLSA.md`:5-7,27,31,36 / Category: enterprise / Severity: High**
- **What's wrong:** SLSA.md claims (a) "releases are built via GitHub Actions and
  attested using Sigstore per PEP 740," (b) "all dependencies are pinned in
  `requirements-lock.txt`," (c) a digest-pinned Docker base, (d) "pip-audit SCA
  on every PR." None hold: there is no `release.yml`, no Sigstore/PEP-740 step,
  no `requirements-lock.txt`, the Dockerfile base is unpinned, and no pip-audit
  runs — and the package is unpublished (PyPI JSON → 404).
- **Evidence:** `ls .github/workflows/` → `ci.yml, cosai-gate.yml` only; `ls requirements-lock.txt` → No such file; `grep -rniE "sigstore|pep.?740|pip-audit|provenance" .github/` → none; `curl -s -o /dev/null -w "%{http_code}" https://pypi.org/pypi/cosai-mcp/json` → 404.
- **Fix:** Gate every SLSA.md claim behind "planned (blocked on EFF-01)" until the
  release workflow, lockfile, digest pin, and pip-audit actually exist; add a CI
  check that fails if SLSA.md references a workflow file absent from
  `.github/workflows/`.
- **Test:** `test_regression_slsa_claims_have_artifacts` — asserts referenced
  files/steps exist.

**FIND 9: `docs/whitepaper.md` §7.3 lines 233,241 / Category: paper / Severity: High**
- **What's wrong:** Abstract and §7.3 claim "1315 tests"; the per-engine table
  sums to **917** with specific median/P99 latency and false-positive incident
  data that no in-repo harness reproduces, and the table describes an MC-INPATH
  engine (203 probes) the scanner never runs against a target. True count is 1465.
- **Evidence:** `pytest --collect-only -q` → 1465; `grep -rlniE "p99|median_latency|benchmark|false_pos" --include=*.py` (non-test) → nothing; "412 MC-BLACKBOX probes" is irreconcilable with 31 catalog files (~54 probes).
- **Fix:** Regenerate to 1465; quarantine or delete the unreproducible 917 table;
  stop describing MC-INPATH as measured against live targets.
- **Test:** N/A — doc fix (add the count-guard from FIND 2).

### MEDIUM

**FIND 10: `cosai_mcp/inventory/*` + `README.md`:70,73,116 / Category: functionality/usability / Severity: Medium**
- **What's wrong:** The README's #1-recommended "front door,"
  `cosai inventory capture http://localhost:8000`, fails on a stock server via a
  *separate, more-broken* HTTP path than `scan`: it POSTs to the bare origin
  (404, no `/mcp`) and, given the explicit `/mcp` path, sends no SSE `Accept`
  header (`406 Not Acceptable`).
- **Evidence:**
  ```
  $ cosai inventory capture http://127.0.0.1:8000 -o /tmp/inv.json
  [ERROR] Inventory capture failed: Client error '404 Not Found' for url 'http://127.0.0.1:8000'
  $ cosai inventory capture http://127.0.0.1:8000/mcp --allow-private-targets -o /tmp/inv.json
  [ERROR] Inventory capture failed: Client error '406 Not Acceptable' for url 'http://127.0.0.1:8000/mcp'
  ```
- **Fix:** Route inventory capture through the same `StreamableHTTPTransport`
  (path canonicalization + SSE `Accept` + session-id) that `scan` uses, instead
  of a bespoke client.
- **Test:** `test_regression_inventory_capture_over_sse` — asserts capture
  succeeds against an SSE server requiring a session id.

**FIND 11: `cosai_mcp/scorecard/models.py`:29 / Category: enterprise/security / Severity: Medium**
- **What's wrong:** The **signed** scorecard labels T5's `coverage_engine` as
  `"middleware_instrumentation"`, but T5 is probed black-box. The auditor-facing
  signed artifact ships a false engine label that contradicts the paper (§7.2),
  both coverage docs, and the runtime (api.py:43 `"T5": "black-box-partial"`;
  T5 ∉ `MIDDLEWARE_ONLY_CATEGORIES`).
- **Evidence:** `models.py:29` `"T5": "middleware_instrumentation"` vs `api.py:43` `"T5": "black-box-partial"`.
- **Fix:** Change models.py:29 to `black_box_prober` (or `black_box_partial`).
- **Test:** `test_regression_scorecard_t5_engine_is_blackbox`.

**FIND 12: `catalog/official/T01-006.json`:40,59,78,97,116 / Category: security / Severity: Medium**
- **What's wrong:** T01-006 advertises six *distinct* JWT-claim-validation probes
  (iss/aud/exp/scope/DPoP) but p2–p6 all carry the identical invalid HS256
  signature `.ZmFrZXNpZw`. A server that validates the signature first rejects
  all five for the *same* reason, so the claim checks are never the deciding
  factor — and a server that checks signatures but not audience/issuer (a real
  confused-deputy gap) is graded secure (false negative). The distinctness guard
  only checks byte-tuples differ, not that each claim is independently exercised.
- **Evidence:** `grep -c "ZmFrZXNpZw" catalog/official/T01-006.json` → 5; distinctness test `test_t01_extended.py:178-190`.
- **Fix:** Sign p2–p6 with a token the target accepts (or the operator token) so
  the wrong claim is the sole rejection cause; if the scanner cannot sign,
  relabel p2–p6 as "forged-token rejection," not distinct claim validation.
- **Test:** `test_regression_t01_006_claim_is_sole_reject_reason`.

**FIND 13: `catalog/official/T01-002.json`:34 (+ `cosai_mcp/harness/assertions.py`:88-93) / Category: security / Severity: Medium**
- **What's wrong:** T01-002-p1's `error_code_in` bypasses the -32601/-32602
  downgrade and its PASS allowlist includes **-32603** (internal error);
  combined with the content-layer fallback (`if actual is None and
  response.error: passed=True`), a server that *crashes* (-32603) or whose tool
  *actually executed* and returned a content-layer `isError` is graded PASS =
  "authentication enforced" — on a CWE-306 missing-auth probe. A tool-executed
  content error proves the unauthenticated call reached the tool: a false
  negative.
- **Evidence:** `T01-002.json:34` `"error_code_in": [-32600, -32603, -32001]`; `assertions.py:88-93`.
- **Fix:** Drop -32603 from the allowlist; gate PASS on an auth-class code
  (-32001 / 401 / 403) only; do not treat a content-layer `isError` as satisfying
  `error_code_in` for a reject=secure auth probe.
- **Test:** `test_regression_t01_002_internal_error_and_content_error_are_inconclusive`.

**FIND 14: `catalog/official/T08-002.json`,`T08-003.json` / Category: security / Severity: Medium**
- **What's wrong:** T08-002 (plaintext-TLS, CWE-319) and T08-003 (non-loopback
  bind, CWE-668) each assert only that `initialize` returns `response.error ==
  false`. A successful handshake says nothing about TLS posture or bind
  interface, so a plaintext-HTTP server or a `0.0.0.0`/LAN-bound server — exactly
  the vulnerabilities — are graded **PASS "secure."** These are structurally
  incapable of detecting the claimed threat. (Note: AUDIT_2026-06-12 §4
  mischaracterized these as "false-pass on method-not-found"; the actual defect
  is success=secure vacuity, and it is untracked in the resolution doc.)
- **Evidence:** sole assertion in each `{"target":"response.error","operator":"eq","value":false}` on an `initialize` call.
- **Fix:** Derive the verdict from the target URL scheme / resolved address
  out-of-band, or mark T08-002/003 NOT_TESTED for black-box.
- **Test:** `test_regression_t08_00{2,3}_vulnerable_target_not_clean`.

**FIND 15: `catalog/official/T11-001.json` (p1) / Category: security / Severity: Medium**
- **What's wrong:** T11-001-p1 probes a hardcoded absent tool
  `__cosai_probe_unlisted_tool__`, which any server returns `-32601` for; that
  code is in the probe's own `error_code_in` allowlist, so the probe **always
  passes** regardless of the server's supply-chain posture — a guaranteed vacuous
  PASS. (COV-11 tracked T11 corroboration generally; this specific
  always-green construction is called out here.)
- **Evidence:** catalog agent trace; `error_code_in` exemption via
  `_probe_inspects_error_code` (context.py:76-83).
- **Fix:** Replace with real manifest enumeration (the recently-landed typosquat
  work in `_scan_manifest_t6`/`supply_chain.py` is the right mechanism), or mark
  p1 NOT_TESTED.
- **Test:** `test_regression_t11_001_p1_not_auto_pass`.

**FIND 16: `docs/whitepaper.md` §8 line 356 / Category: paper / Severity: Medium**
- **What's wrong:** Related work omits the most load-bearing MCP-specific prior
  art: Invariant Labs' open-source `mcp-scan` and the tool-poisoning / "rug pull"
  disclosure — which *is* the §3.2 T4 attack (benign description at `tools/list`,
  poisoned at `tools/call`) — and Willison's canonical prompt-injection work. The
  paper claims T4-mutation-detection novelty without engaging the work that first
  demonstrated the attack.
- **Evidence:** §8 cites only Cisco/MCPScan.ai/Enkrypt/Proximity + Greshake/Perez.
- **Fix:** Add Invariant `mcp-scan`, the tool-poisoning disclosure, and Willison;
  position the mutation sub-property relative to them.
- **Test:** N/A — doc fix.

**FIND 17: `docs/whitepaper.md` §7.4 lines 316-336 / Category: paper / Severity: Medium**
- **What's wrong:** The cross-server DAG audit — `X-Cosai-Trace-Context` header,
  `context_status`, `cosai-context-evicted` header, `UNKNOWN_PARENT`/
  `CONTEXT_EVICTED` emission — is written in present tense as server behavior, but
  no code implements the header or the trace schema (§9 does concede collection
  is "in progress," but §7.4 states emitted behaviors as if shipping).
- **Evidence:** `grep -rniE "X-Cosai-Trace|traceparent|context_status|UNKNOWN_PARENT" cosai_mcp/` → none.
- **Fix:** Reframe §7.4 as a proposed interface (subjunctive), matching §9.
- **Test:** N/A — doc fix.

**FIND 18: `cosai_mcp/report/sarif.py`:26-27 / Category: enterprise / Severity: Medium**
- **What's wrong:** A comment claims "compliance mapping is trimmed to CoSAI +
  NIST AI RMF only," but no NIST AI RMF mapping is emitted anywhere; the SARIF
  carries only `cosai_ref`/`owasp_ref`/`cwe`. EFF-02's NIST/RMF mapping is
  unimplemented and the comment misleads.
- **Evidence:** `grep -rin "nist\|ai rmf" cosai_mcp/ /tmp/scan.*` → only the
  comment + `determi**nist**ic` false-positives; scorecard keys carry no mapping.
- **Fix:** Emit a NIST AI RMF field (populate from catalog) or correct the comment
  to "CoSAI + OWASP + CWE."
- **Test:** `test_regression_sarif_nist_mapping`.

### LOW

**FIND 19: `cosai_mcp/catalog/loader.py`:13 / Category: security / Severity: Low**
- **What's wrong:** On `import re2` failure the loader silently aliases stdlib
  `re` (which backtracks) with only a `RuntimeWarning`, silently defeating the
  locked "RE2 linear-time, no-backtracking" ReDoS guarantee (relevant with
  `--allow-regex-in-custom`). Unreachable in a correct install (google-re2 is a
  hard dep) but a silent-downgrade trap.
- **Evidence:** `loader.py:13` `except ImportError: import re as re2`.
- **Fix:** Raise a hard error instead of substituting a backtracking engine.
- **Test:** `test_regression_re2_missing_hard_fails`.

**FIND 20: `catalog/official/T07-002.json`:16 / Category: security / Severity: Low**
- **What's wrong:** T07-002-p1 claims to test insufficient-OAuth-scope
  authorization but sends a forged `alg=none` token; a signature-validating
  server rejects on algorithm, not scope, so the advertised property is never
  exercised (mislabel; direction is safe, no false positive).
- **Evidence:** header segment base64-decodes to `{"alg":"none"}`.
- **Fix:** Use the operator valid-signature token with a deliberately narrow
  scope (as T07-003 now does).
- **Test:** `test_regression_t07_002_scope_token_is_validly_signed`.

**FIND 21: `catalog/official/T01-003.json` / Category: security / Severity: Low**
- **What's wrong:** Titled/remediated as JTI token-replay (CWE-294/384) but the
  probe issues a single unauthenticated `tools/call` and never presents a token
  twice — it cannot demonstrate replay. Commit 0eb31f1 acknowledged this in its
  message yet added T01-006 instead of fixing T01-003.
- **Evidence:** T01-003-p1 payload `{"name":"{{tool_name}}","arguments":{}}`, single call.
- **Fix:** Make it a two-step same-token replay, or relabel as a generic
  unauthenticated-call test.
- **Test:** `test_regression_t01_003_second_presentation_rejected`.

**FIND 22: `docs/COVERAGE.md`:5 / Category: enterprise / Severity: Low**
- **What's wrong:** "26 signed threat definitions + 4 adversarial" — there are 27
  signed non-adversarial files (all with `.sig`) + 4 adversarial = 31. COVERAGE.md
  is also dated 2026-05-04 and lists T1 as "T01-001–004" though T01-005/006 exist.
- **Evidence:** `ls catalog/official/*.json | wc -l` → 27; `find catalog/official -name '*.json' | wc -l` → 31.
- **Fix:** Update to 27 + 4; regenerate from the build.
- **Test:** N/A — doc fix.

**FIND 23: `docs/whitepaper.md` §3.2 line 86 / Category: paper / Severity: Low**
- **What's wrong:** PFA-isolation undecidability is misattributed to Condon &
  Lipton 1989 (probabilistic Turing machines / space-bounded IP), not the
  probabilistic-automaton cutpoint/emptiness isolation problem (Paz 1971;
  Blondel–Canterini 2003; Bertoni for isolated cutpoint).
- **Fix:** Replace the Condon & Lipton cite with Blondel–Canterini / Bertoni.
- **Test:** N/A — doc fix.

**FIND 24: `cosai_mcp/cli.py` + `docs/RELEASE_HANDOFF.md`:70-78 / Category: enterprise / Severity: Low**
- **What's wrong:** EFF-06 (`--expected-catalog-hash`), EFF-08 (auth/SSO plugin),
  and EFF-09 (`--targets` fleet mode) remain unimplemented, so no reproducible,
  multi-target, release-blocking CI gate is possible today.
- **Evidence:** `grep -n "targets\|expected-catalog" cosai_mcp/cli.py` → none.
- **Fix:** See [ENTERPRISE_REQUIREMENTS_2026-07-01.md](ENTERPRISE_REQUIREMENTS_2026-07-01.md).
- **Test:** `test_regression_cli_targets_fleet`.

---

## 4. Spot-check results on prior "fixed" claims

Cross-checked ≥5 rows marked ✅ / locked-defense by re-running the test or
command myself. **All held; none regressed.**

| Prior claim | Status | My verification |
|---|---|---|
| EFF-03 — HTML NOT-TESTED banner | ✅ HELD | `grep -i "not tested\|not a pass" /tmp/scan.html` → 13× "NOT TESTED", 1× "NOT a pass" |
| EFF-04 — `--fail-on` default `high` | ✅ HELD | `cli.py:163` `default="high"` |
| Python API (PRODUCT §5.2) | ✅ FIXED | `from cosai_mcp import Scanner, ScanConfig` imports; `ScanConfig(target=…, categories=…, fail_on=…)` + `Scanner(config)` construct (config.py:17 now has `target`) |
| PyYAML dep (PRODUCT §6) | ✅ FIXED | `pyproject.toml:37,43` — pyyaml in `[pytest]` and `[dev]` |
| Example servers ship (PRODUCT §8.3) | ✅ FIXED | both `examples/*/server.py` present (fastmcp 62 lines, fastapi 122). Caveat: the FastAPI one won't start under this env's fastapi 0.121/starlette 0.49 (`on_startup` kwarg) — an environment conflict, not a repo bug |
| COV-04 — T07-003 inversion | ✅ HELD | `T07-003.json` now asserts `response.error eq false` on a scope-valid operator token; the `alg=none` forgery is gone |
| COV-06 — `-32601`→INCONCLUSIVE | ✅ HELD | catalog agent: 12 gate tests pass, `_detect_protocol_error` (context.py:86-120); only `error_code_in` probes exempt (by design) |
| COV-02/05/10 — T6 manifest scan / T12 removed / T7 revocation | ✅ HELD | `_scan_manifest_t6` api.py:639; no T04/T09/T12 in `catalog/official/`; `t7_session_revocation` api.py:738 |
| Locked defense — Ed25519 sig verify | ✅ FIRES | tampered official file → `Ed25519 signature verification failed`; deleted `.sig` → `Missing signature sidecar`; `COSAI_PUBKEY` override present (keys.py:29) |
| Locked defense — network allowlist / DNS-rebind | ✅ FIRES | `check_dns_rebinding('93.184.216.34','10.0.0.5')` → `DNSRebindingError`; `follow_redirects=False`+`trust_env=False` on both transports |
| Locked defense — RE2 safety | ✅ FIRES | backreference `(\w+)\1` → `UnsafePatternError`; google-re2 is the live engine |
| Theorem vs code — no black-box T4/T9/T12 | ✅ HELD | `MIDDLEWARE_ONLY_CATEGORIES={T4,T9,T12}` (api.py:54) skipped at api.py:667 — code does not contradict the proof |

---

## 5. Refuted / downgraded (suspected, then disproved)

| Suspicion | Verdict | Why |
|---|---|---|
| "Scanner emits a false CLEAN on a broken scan" | **Refuted** | The failing fastmcp scan honestly exits 2 with SARIF `executionSuccessful:false` and scorecard `insufficient_coverage`. It fails loud, not silently green. The problem is that it fails *at all* against the mainstream target (FIND 1), not that it lies. |
| "`owasp_ref` is unpopulated / not surfaced (PRODUCT Phase-3 item 12)" | **Refuted (partially done)** | `owasp_ref` is populated in all 27 catalog files and surfaced in SARIF (`MCP-Top10-A01`, `OWASP/www-project-mcp-top-10`). Gap remaining: it is absent from the *signed* scorecard, and NIST AI RMF is emitted nowhere (that part is FIND 6/18). |
| "A black-box probe still attempts T4/T9/T12, contradicting the theorem" | **Refuted** | No such probe. `MIDDLEWARE_ONLY_CATEGORIES` correctly excludes them from the prober loop. |
| "The middleware modules are stubs / label-only" | **Refuted** | All 12 are real enforcement logic with tests. The real gap (FIND 5) is that they are an *unwired library*, not that they are hollow — 10 of 12 are reachable only by importing them, and no example wires `CoSAIStack`. |
| "AUDIT_2026-06-12 §4: T08-002/003 false-pass on method-not-found" | **Corrected, not refuted** | The defect is real but mischaracterized: the probes assert `error==false`, so the vacuity is success=secure, not method-not-found (FIND 14). |
| "The signing seed being committed is a re-litigation of the locked hardcoded-pubkey decision" | **Refuted** | The locked decision hardcodes the *public* key (fine). The *private* seed shipping in the tree (FIND 3) is an implementation reality that undermines the integrity intent — a bug, not a re-litigation. |

---

## 6. Bottom line

The delta since 2026-06-12 is real and mostly positive: the assertion framework
is now trustworthy (INCONCLUSIVE gate holds), the honest-reporting surface is in
place, and the three locked security defenses demonstrably fire. But a reference
implementation has to *run* against the reference ecosystem, and today it does
not: FIND 1 alone blocks the mainstream FastMCP case, FIND 2 means the headline
metric is wrong on a non-green branch, and FIND 3–9 mean the paper — the
project's primary credibility artifact — describes a materially more complete
system than the repo contains. Fix the transport (FIND 1), green the suite and
correct the counts (FIND 2/9/22), align the paper to the code (FIND 4–9, 16–17,
23), and move the signing trust root off the committed seed (FIND 3), and this
becomes the honest, category-leading tool its foundations already support.
