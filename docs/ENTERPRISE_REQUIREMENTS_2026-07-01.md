# cosai-mcp — Enterprise Adoption Requirements (2026-07-01)

Forward-looking capability backlog — **not** bug reports (those are in
[FABLE_AUDIT_2026-07-01.md](FABLE_AUDIT_2026-07-01.md)). These are the net-new
capabilities a real enterprise security team would require before putting
cosai-mcp in a CI gate that **blocks releases** or standing it up as a shared
service. Each item is stated as a user story with an acceptance criterion and a
rough effort (S ≤ 3 days · M ≈ 1–2 weeks · L > 2 weeks). Items are cross-linked
to the open EFF-* rows in
[AUDIT_2026-06-12_RESOLUTION.md](AUDIT_2026-06-12_RESOLUTION.md) where they
extend an already-tracked gap; the rest are new.

**Framing:** three personas recur — **(DEV)** an app team scanning their own MCP
server, **(SEC)** a security engineer owning the CI gate and the shared runner,
**(GRC)** a compliance/audit stakeholder consuming the signed attestation. The
priority tiers answer one question: *what has to be true before a `security` VP
signs off on this blocking a production release?*

---

## P0 — Blocks a release-gate deployment at all

### ✅ ENT-P0-1 · Reproducible, pinned, offline scans *(extends EFF-06)* — SHIPPED 2026-07-02
**As** SEC, **I need** `--expected-catalog-hash <sha>` (exit 2 on mismatch) plus
a fully offline mode that loads a vendored, signed catalog with no network
except to the target, **so that** a release gate is deterministic and cannot be
silently altered by a catalog change between the PR run and the merge run.
- **Why P0:** a gate whose ruleset can drift under it is not a control; auditors
  reject non-reproducible gates outright.
- **Effort:** S–M
- **Acceptance:** two runs of the same target + same `--expected-catalog-hash`
  in an air-gapped container (no egress except target) produce byte-identical
  scorecard `catalog_hash`; a changed catalog exits 2 with a clear message.
- **Shipped:** `--expected-catalog-hash` on `cosai scan` (`cosai_mcp/cli.py`,
  `cosai_mcp/api.py::_run_scan`) and on `cosai scorecard verify`/`show`
  (a valid signature alone doesn't prove which catalog produced the
  artifact — the pin is also enforced on the signed-scorecard-consumption
  path, not just the live-scan path). Exposed as an input on the reusable
  `cosai-gate.yml` workflow. "Offline mode" was already true structurally
  (catalog loads from local disk only, no remote fetch exists) — verified
  by the adversary panel, not built as a new toggle. Panel review (Defense +
  Adversary + security-review) caught and fixed two real gaps before this
  shipped: `_canonical_threat`'s hash view omitted
  `Probe.protocol_error_is_expected` (a catalog tamper changing only that
  field passed the pin unnoticed — see FABLE_AUDIT-style regression test
  `test_protocol_error_is_expected_binds_catalog_hash`), and an empty
  `--expected-catalog-hash ""` produced a confusing error instead of a
  clear validation message.

### 🔶 ENT-P0-2 · Signer identity you can actually verify *(extends EFF-10; ties to AUDIT FIND 3)* — DIRECTION DECIDED, NOT YET BUILT
**As** GRC, **I need** the signed scorecard to be verifiable against an
*organizational* identity — an X.509 cert chain or Sigstore/Fulcio OIDC identity —
**not** a keypair whose private seed ships in the repo, **so that** a conformance
claim means "org X's scanner asserted this," not "anyone who cloned the repo
could have."
- **Why P0:** today the default trust root is the committed `_DEV_SIGNING_SEED`
  (signing.py:43); non-repudiation is void by default. A signed artifact nobody
  can attribute is theater.
- **Effort:** L
- **Acceptance:** a scorecard verifies to a named identity (cert subject or OIDC
  `sub`) on a machine that never had the private key; a scorecard signed by the
  dev seed is rejected by a released build; key-rotation is a documented, tested
  procedure.
- **Status (2026-07-02):** direction decided — Sigstore/Fulcio + PEP 740
  (keyless, OIDC-bound, composes with the PyPI Trusted Publishing already
  planned for EFF-01) over X.509/managed PKI. Logged to the project decision
  ledger; not deferred. This is the largest single P0 item (L-effort) and
  was sequenced last among the four; implementation has not started.

### ✅ ENT-P0-3 · Compliance mapping *inside* the signed artifact *(extends EFF-02; ties to FIND 6/18)* — SHIPPED 2026-07-02
**As** GRC, **I need** each category result in the *signed* scorecard to carry
its CoSAI + OWASP MCP Top 10 + NIST AI RMF control mapping, **so that** the
attestation I file with an auditor is self-describing and tamper-evident — not a
prose claim in a doc and an `owasp_ref` buried in an unsigned SARIF.
- **Why P0:** the paper (§5.4/§5.5) already promises this; GRC cannot accept an
  attestation whose scope lives outside the signature.
- **Effort:** M
- **Acceptance:** `cosai scorecard verify` prints, per category, the mapped
  controls from the signed payload; the mapping is covered by the signature
  (edit → verify fails); NIST AI RMF is populated, not just referenced in prose.
- **Shipped:** `ComplianceMapping` on `CategoryResult` (`cosai_mcp/scorecard/
  models.py`) + a static `CATEGORY_COMPLIANCE_MAP` (`cosai_mcp/scorecard/
  compliance.py`, new module) attached by the builder. Because
  `_signable_dict()` signs the whole `scorecard.to_dict()` tree, the mapping
  is inside the Ed25519-signed payload with no separate signing-path change.
  Printed by both `cosai scorecard verify` and `show`. Panel review caught
  that `docs/THREAT_MAPPING.md` carried two internally-contradictory OWASP
  MCP Top 10 tables and the code copied the wrong one for T6–T10/T12 — the
  signed attestation would have contradicted the tool's own SARIF output.
  Both doc tables were reconciled to the one SARIF's `helpUri` references;
  T9/T10 have no clean 1:1 OWASP MCP Top 10 item, so they're left honestly
  unmapped rather than assigned an invented title. A test now parses the doc
  table and cross-checks it against the code table so the two can't drift
  again silently.

### ✅ ENT-P0-4 · Fleet / multi-target gate with one verdict *(extends EFF-09)* — SHIPPED 2026-07-02
**As** SEC, **I need** `cosai scan --targets targets.yaml` with bounded per-host
concurrency, aggregating N servers into one exit code + one merged SARIF + one
roll-up scorecard, **so that** an org with 40 MCP servers can gate a release on
the *fleet*, not script 40 invocations and hand-merge results.
- **Why P0:** no enterprise runs one MCP server; a per-server-only tool doesn't
  fit a release gate.
- **Effort:** M–L
- **Acceptance:** a 3-target file yields one aggregated scorecard, a merged SARIF
  that renders in GitHub, and an exit code that is the max severity across
  targets; one unreachable target degrades to exit 3 for that host without
  masking findings on the others.
- **Shipped:** `--targets <file>` on `cosai scan` (`cosai_mcp/fleet.py`, new
  module: `run_fleet_scan`, `merge_sarif`, `build_fleet_scorecard`).
  Bounded-concurrency `ThreadPoolExecutor` (`--fleet-concurrency`, default
  5) — safe because probes within one target's scan already run strictly
  sequentially (one `multiprocessing.Process` at a time), so fleet-level
  concurrency doesn't multiply subprocess counts. Targets file is plain
  text (one URL per line, `#` comments), not YAML — adding `pyyaml` as a new
  core runtime dependency would have extended the locked minimal-dependency
  list in CLAUDE.md, which wasn't this feature's call to make unilaterally.
  Panel review (Defense + Adversary + security-review) found and fixed five
  real issues before this shipped: (1) a loop-variable-leak bug in
  `_validate_sarif_structure` meant only the *last* run in a merged
  multi-run document got its results validated — every run before it
  silently skipped the `ruleId`/`suppressions`/`partialFingerprints` checks;
  (2) `TargetOutcome.error` (exception text from scanning a target server)
  reached the fleet scorecard JSON unsanitized, violating this project's own
  ingestion-time HTML-escaping rule for target-influenced content; (3)
  `--auth-token`/`--read-token`/`--tool-allowlist`/etc. were silently
  dropped in fleet mode — every target got scanned unauthenticated with no
  warning, a false-green on auth-gated servers (now threaded through for
  flags with fleet-wide semantics; flags with per-server semantics like
  `--profile`/`--adversarial`/`--baseline` now fail loudly with `--targets`
  instead of being silently ignored); (4) `--skip-reachability` was
  similarly dropped, force-failing any target that doesn't accept a bare TCP
  connect; (5) `ThreadPoolExecutor`'s default shutdown blocks until every
  submitted future completes, so one hung target blocked the *entire* fleet
  run indefinitely — a `--fleet-target-timeout` (default 600s) now bounds
  this.

---

## P1 — Required for a mature, shared, multi-team rollout

### ENT-P1-1 · SSO/OIDC on every hosted component *(net-new)*
**As** SEC, **I need** any hosted surface — the continuous-compliance validation
gateway the paper describes (§5.4/§5.6), a results dashboard, or a shared runner
API — to authenticate via the org IdP (OIDC/SAML), **so that** access to
conformance data and scan-triggering is tied to corporate identity and
deprovisioning.
- **Why P1:** the moment there is a shared endpoint, unauthenticated access is a
  data-leak and a DoW vector. (No hosted component ships today — build it
  auth-first.)
- **Effort:** L
- **Acceptance:** the gateway/dashboard rejects unauthenticated requests; access
  is gated by IdP group; a revoked user loses access within the token TTL.

### ENT-P1-2 · RBAC on custom-catalog write + signing authority *(net-new)*
**As** SEC, **I need** role separation between who may *add/modify* custom threat
definitions, who may *sign* them as org-trusted, and who may only *run* scans,
**so that** a single developer cannot introduce a catalog rule (or a
`matches_regex` with `--allow-regex-in-custom`) that silently weakens or DoSes
the org-wide gate.
- **Why P1:** the catalog is executable policy; unrestricted write to it is
  unrestricted write to the security gate.
- **Effort:** M
- **Acceptance:** custom-catalog changes require a reviewer role to sign before a
  gate will load them as trusted; unsigned custom files run only in an explicitly
  UNTRUSTED, non-gating mode; the role that can sign is distinct from the role
  that can author.

### ENT-P1-3 · Immutable audit trail: who ran what scan, when, against what *(net-new; dogfoods T12)*
**As** GRC, **I need** every scan invocation recorded in an append-only,
hash-chained log — operator identity, target, catalog hash, tool version,
resulting grade, timestamp — **so that** I can answer "who last certified server
X, and on what ruleset" during an incident or an audit.
- **Why P1:** a control with no record of its own operation is not auditable; this
  is literally the T12 property the tool checks in others.
- **Effort:** M
- **Acceptance:** `cosai audit trail` returns a verifiable chain of past scans;
  tampering with any entry breaks verification; entries never include raw target
  credentials (presence/absence only).

### ENT-P1-4 · Target credential & secrets management *(extends EFF-08)*
**As** SEC, **I need** a pluggable secret resolver (env, Vault, cloud secret
manager) plus first-class OAuth2 client-credentials / RFC 8693 token-exchange /
DPoP for authenticating *to* protected targets, **so that** scanning an
authenticated MCP server in CI does not require pasting a long-lived bearer token
into a pipeline variable.
- **Why P1:** most enterprise MCP servers require auth; a single `--auth-token`
  string is a secret-sprawl and rotation problem.
- **Effort:** M–L
- **Acceptance:** a scan authenticates to a protected target using a
  short-lived token minted at runtime from a secret-manager reference; no raw
  secret appears in argv, logs, SARIF, or the scorecard.

### ENT-P1-5 · Baseline → SARIF suppressions / dismissal flow *(extends EFF-07)*
**As** DEV, **I need** an accepted-risk baseline that emits GitHub-native SARIF
`suppressions` with scanner-generated `partialFingerprints`, **so that** a
triaged, risk-accepted finding stays dismissed across runs instead of re-breaking
the build every PR.
- **Why P1:** without a dismissal flow, teams disable the gate; a gate teams turn
  off is worse than none.
- **Effort:** M
- **Acceptance:** a finding accepted in the baseline renders as *dismissed* in the
  GitHub security tab on the next run; fingerprints are target-scoped and stable
  across catalog-hash-identical runs.

### ENT-P1-6 · Policy-as-code: environment-tiered gating *(net-new)*
**As** SEC, **I need** a committed policy file mapping (environment × category ×
severity) → gate/warn/ignore, **so that** `staging` can warn on HIGH while
`production` blocks on HIGH, from one versioned source of truth rather than
scattered `--fail-on` flags per pipeline.
- **Why P1:** real orgs need differentiated enforcement; per-invocation flags
  don't scale or audit.
- **Effort:** S–M
- **Acceptance:** the same target scanned under `--policy prod.yaml` vs
  `staging.yaml` yields different exit codes per the policy; the policy is part of
  the signed scan context.

---

## P2 — Scale, ecosystem, and lifecycle

### ENT-P2-1 · TypeScript in-path instrumentation (IPIS) *(net-new; paper §9)*
**As** DEV on a Node/TypeScript MCP server (the majority of the deployed
ecosystem), **I need** the MC-INPATH engine available as Express/Fastify
middleware, **so that** T4/T9/T12 are decidable for my server instead of
permanently `indeterminate`.
- **Why P2:** high strategic value but large; unlocks the biggest server
  population. (Also requires FIND 5 — building the Python in-path engine as a
  real, wired engine first.)
- **Effort:** L
- **Acceptance:** a reference TS MCP server instrumented with the IPIS middleware
  produces T4 mutation findings and a T12 hash-chain verifiable by the same
  cross-server verifier as the Python path.

### ENT-P2-2 · Catalog versioning + update SLA + signed changelog *(net-new)*
**As** SEC, **I need** semver'd catalog releases with a published cadence, a
signed changelog, and a compatibility guarantee that a pinned hash keeps
verifying, **so that** I can adopt new threat coverage on my schedule without a
silent change breaking attestation reproducibility.
- **Why P2:** a threat catalog is only useful if it evolves; enterprises need a
  predictable, verifiable update contract (an implicit SLA on new-threat
  turnaround).
- **Effort:** M
- **Acceptance:** `cosai catalog list --versions` shows signed releases; upgrading
  is one pinned-hash change; the changelog is signed and diff-able; a documented
  target latency exists for landing a newly-disclosed MCP threat.

### ENT-P2-3 · Result store, history & drift trend *(net-new)*
**As** SEC, **I need** scans to persist to a store (SARIF + scorecard) queryable
over time, with per-target grade trend and tool-inventory drift history, **so
that** I can see "server X regressed from PASS to HIGH on 6/20" rather than
diffing report files by hand.
- **Why P2:** point-in-time reports don't answer posture-over-time questions that
  security leadership asks.
- **Effort:** M–L
- **Acceptance:** a dashboard/API returns the grade timeline and inventory-drift
  events for a target across N historical scans.

### ENT-P2-4 · Multi-tenant isolation for a shared runner *(net-new)*
**As** SEC operating cosai-mcp as an internal shared service, **I need** tenant
isolation so team A cannot read team B's targets, findings, baselines, or signing
keys, **so that** one hosted deployment can safely serve the whole org.
- **Why P2:** only relevant once ENT-P1-1 (hosted) exists; then isolation is
  mandatory.
- **Effort:** L
- **Acceptance:** a tenant-scoped token can enumerate only its own scans/baselines
  /keys; cross-tenant access is denied and logged (verifiable against a real
  isolation canary, not a mock).

### ENT-P2-5 · Ticketing / SOAR integration for findings *(net-new; extends paper §6 OCSF)*
**As** SEC, **I need** findings above a threshold to open a tracked ticket
(Jira/ServiceNow) or fire the existing OCSF Security Incident into our SOAR with
dedup by fingerprint, **so that** a HIGH finding becomes owned work, not a line
in a report nobody re-reads.
- **Why P2:** closes the loop from detection to remediation ownership; the OCSF
  emitter (§6) is the hook, but ticketing/dedup is the enterprise-grade layer.
- **Effort:** M
- **Acceptance:** a new HIGH finding opens exactly one ticket; a repeat of the same
  fingerprint updates rather than duplicates; resolution closes it.

---

## Dependency & sequencing note

- **Status as of 2026-07-02:** ENT-P0-1, ENT-P0-3, and ENT-P0-4 are shipped.
  ENT-P0-2 (signer identity) is the only open P0 item — direction decided
  (Sigstore/Fulcio + PEP 740), implementation not started. P1/P2 are all
  still open.
- **ENT-P0-2 (signer identity)** and **ENT-P0-3 (signed mapping, shipped)** are
  the spine of the whole attestation value proposition and should land before
  any hosted component (ENT-P1-1) leans on them — ENT-P0-2 is now the sole
  remaining blocker on that spine.
- **ENT-P2-1 (TS IPIS)** presupposes the audit's FIND 5 is resolved — i.e. the
  Python MC-INPATH engine is turned from an unwired library into a real, wired
  in-path engine first; otherwise there is no reference implementation to port.
- **ENT-P1-1 (SSO)** must precede **ENT-P2-4 (multi-tenancy)** — build auth before
  isolation, not after.
- Nothing here matters until the mainstream **scan actually runs** (FABLE_AUDIT
  FIND 1); the transport fix is the true P-1 that gates this entire list —
  fixed 2026-07-02, live-verified against a real FastMCP 3.4.2 server.
