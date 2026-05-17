# cosai-mcp — Analysis, Rationale, and What Landed

*Written May 2026 — internal reference document, not for publication.*

---

## 1. What We Started With: The CoSAI Whitepaper

The source material is the **CoSAI/OASIS January 2026 whitepaper** — "Security Taxonomy and Governance Framework for the Model Context Protocol." The whitepaper was produced by the Coalition for Secure AI's Working Group 4 (WS4 — Secure Design for Agentic Systems) and ratified by the OASIS standards body.

**What the whitepaper contains:**

- A 12-category threat taxonomy (T1–T12) covering every meaningful attack surface of an MCP server: authentication, access control, input validation, data/control boundary violations, data protection, integrity/supply chain, session security, network binding, LLM trust boundary failures, resource management, supply chain lifecycle, and audit logging.
- For each category: a threat description, attack pattern examples, and a list of mitigations.
- Cross-references to OWASP MCP Top 10, OWASP ASI Top 10, NIST AI RMF 2026, and CWE.
- Zero runnable code. The whitepaper is a specification document, not an implementation.

**What the whitepaper does NOT contain:**

- Any scanner, probe framework, or automated test suite.
- Any SARIF output, CI integration, or exit-code contract.
- Any mechanism to actually *verify* conformance for a running server.
- Any signing, inventory, SIEM integration, or IR capability.

The gap was explicit: the CoSAI taxonomy defines what to test; it ships no way to test it.

---

## 2. Gap Analysis: What Existed Before cosai-mcp

We surveyed the full landscape of MCP security tooling in April 2026. The findings:

### Static scanners (analyze source or definitions — can't probe a running server)

| Tool | What it tests | Gap |
|------|--------------|-----|
| Cisco MCP Scanner | YARA rules + LLM-as-judge on tool definitions | Tool descriptions and code at rest. Cannot probe protocol behavior. |
| Snyk Agent Scan | Dependencies + static flow analysis | Dependency CVEs and flow patterns. Not behavioral. |
| Enkrypt AI | Source code injection patterns | Code-level analysis. Nothing runtime. |
| MCPScan.ai | Pattern matching on tool descriptions | Tool poisoning patterns. No live server. |
| Proximity | NOVA rules + LLM semantic analysis | Content-level jailbreak keywords. No protocol. |

**Common gap:** all static scanners test *what you wrote*, not *what you shipped*. An MCP server can pass every static check and still echo raw arguments into a shell at runtime.

### Runtime proxies (monitor production traffic — can't gate CI)

| Tool | What it does | Gap |
|------|-------------|-----|
| MCP-Bastion | Drop-in middleware: PromptGuard + Presidio | Runtime enforcement, not vulnerability discovery. Lives in production, not CI. |
| MCPProxy-go | Routing proxy with BM25 filtering and quarantine | Monitoring and anomaly detection on live traffic. Not a pre-deploy gate. |

**Common gap:** runtime proxies require deployment. They catch anomalies on production traffic. They cannot gate what gets to production in the first place.

### Academic tools

| Tool | What it does | Gap |
|------|-------------|-----|
| MCPSafetyScanner | LLM agents generate adversarial samples | Non-deterministic, not CI-reproducible, not CoSAI-mapped. |
| AgentRFC / AgentConform | Formal TLA+ conformance | Research prototype, no production path. |

### Standards (no code)

CoSAI whitepaper, OWASP MCP Top 10, OWASP ASI Top 10, NIST AI RMF — all documents, no scanners.

### The structural gap (three things nobody had together)

1. **Runtime black-box JSON-RPC probing** — no tool sends crafted protocol messages to a live server to discover vulnerabilities through actual protocol interaction.
2. **Stateful multi-turn conformance** — MCP attacks like confused deputy, privilege escalation chains, and session token binding failures span multiple calls. One-shot probes can't catch them.
3. **The CoSAI taxonomy in one CI gate** — every other tool covers 1–3 categories. cosai-mcp scans 9 categories zero-config and covers T4/T9/T12 when its middleware is deployed in the target; no single pass/fail verdict spanning the taxonomy existed before.

---

## 3. What We Built: cosai-mcp

### 3.1 The Core Scanner (Baseline)

A runtime conformance scanner that:

- **Points at a running MCP server** via HTTP (Streamable HTTP primary, stdio, LegacySSE fallback)
- **Completes the full MCP session lifecycle** before probing: `initialize` → `initialized` → `tools/list` → iterate tools
- **Runs three scan engines** across the CoSAI taxonomy (9 categories zero-config; T4/T9/T12 require the middleware in the target call path):
  - *Black-box prober*: one-shot JSON-RPC probes (T1, T3, T5, T8, T10, partial T2/T6/T11)
  - *Stateful conformance harness*: multi-turn scripted scenarios (T2, T6, T7)
  - *Middleware instrumentation*: detection-from-inside the call path (T4, T9, T12). Implemented modules: `auth`, `boundary`, `protection`, `integrity`, `network`, `trust`, `resources`, `audit`. Not yet implemented (raise `NotImplementedError`): `authz` (T2), `validation` (T3), `session` (T7), `supply_chain` (T11).
- **Outputs SARIF 2.1.0** for GitHub's native security findings tab
- **Exits with a deterministic code** (0 = clean, 1 = findings above threshold, 2 = scanner error, 3 = unreachable) — CI-gate-safe

**Why three engines?** Black-box probing is structurally wrong for T4 (tool poisoning / indirect prompt injection), T9 (LLM trust boundary), and T12 (audit logging). These require being *in the call path* — you can't detect prompt injection from outside the server. The three-engine split is what makes full T1–T12 coverage possible.

### 3.2 Track A — Tool Inventory & Drift Detection

**What it is:** Captures a signed Ed25519 snapshot of every tool a server exposes — name, description, input schema — and computes a content-addressed hash. Subsequent snapshots can be diffed to detect additions, removals, or silent schema changes between deploys.

**Why we built it:**

T6 (Integrity/Verification) and T11 (Supply Chain) attacks often arrive as a single undetected change — a parameter renamed, a schema field added, a description modified. These changes are invisible to code review if they come from a JSON manifest or a dependency update. The scanner alone can't catch drift between two clean scans; you need a signed baseline to diff against.

Without signed inventory, a supply-chain attack that poisons the tool manifest after the scanner runs would be invisible.

**Technical architecture:**

- `cosai inventory capture`: connects to the MCP server, runs `tools/list`, hashes the canonical JSON of the manifest, and signs the whole artifact with an Ed25519 key from the OS keychain (`keyring` library, service name `cosai-mcp-inventory`).
- `cosai inventory diff`: loads two artifacts (verifying signatures by default), computes a structural diff, and exits 1 if drift is detected with `--fail-on-drift`.
- Trust model: per-installation key generated on first use. Cross-machine verification uses `COSAI_INVENTORY_PUBKEY` env var (base64-encoded public key). Re-signed snapshots from a different key are rejected without the env var override.

### 3.3 Track B — OCSF Telemetry to SIEM/SOAR

> **Experimental:** Track B is available behind the `--experimental` flag and is not enabled by default.

**What it is:** After every scan, each probe result is serialised as an OCSF Detection Finding (class_uid 2004) and POSTed to a configurable SIEM webhook. An in-process anomaly detector fires alerts when finding rates or critical burst counts exceed thresholds.

**Why we built it:**

A scanner that only writes SARIF to disk requires a human to read the file. Enterprises route security events through SIEM — Splunk, Elastic, Panther, Microsoft Sentinel all natively ingest OCSF. A single `--emit-to` flag turns cosai-mcp into a continuous SIEM data source with no adapter or ETL required.

The anomaly detection layer (HIGH_FINDING_RATE, CRITICAL_BURST, SEVERITY_ESCALATION rules) means the SIEM can alert on scan result patterns, not just individual findings.

**Technical architecture:**

- `HttpEmitter`: `httpx.Client` instance (connection pool, not per-request), `trust_env=False` (blocks HTTP_PROXY injection per locked architecture §3), `follow_redirects=False`.
- `AnomalyDetector`: rolling window counters, configurable thresholds via `--anomaly-threshold` and `--critical-burst-threshold`.
- `build_detection_finding()`: constructs OCSF Detection Finding from probe result + severity (derived from `result.threats` catalog on the scan result object).
- URL credential redaction before any CLI output: `urlparse` + `urlunparse` strips userinfo from logged URLs.

### 3.4 Track D — Automated IR Containment

> **Experimental:** Track D is available behind the `--experimental` flag and is not enabled by default.

**What it is:** When anomaly thresholds are exceeded, the scanner (1) builds an `IncidentRecord`, (2) emits an OCSF Security Incident (class_uid 2001) to trigger SOAR playbooks, (3) writes a signed quarantine report to disk, and (4) generates firewall block commands for operator review. Block commands are never auto-executed.

**Why we built it:**

The gap between "alert fired" and "server contained" is where attackers operate. By emitting a standard OCSF Security Incident event, cosai-mcp triggers existing SOAR playbooks — without requiring any vendor agent on an MCP server. The structured event format means Splunk SOAR, Palo Alto XSOAR, and similar systems receive actionable context, not a raw string alert.

Firewall commands are intentionally never auto-executed. Automatic network changes in production are a blast-radius risk. The SOAR playbook (triggered by the OCSF event) owns automation beyond the scanner's boundary.

**Technical architecture:**

- `IncidentRecord`: frozen dataclass — immutable IR artifact capturing findings, anomaly rules triggered, worst-case severity, recommended `ContainmentAction` values.
- `ContainmentAction` enum: `EMIT_INCIDENT`, `QUARANTINE_REPORT`, `BLOCK_EGRESS`, `SESSION_KILL`.
- `perform_containment()`: dispatches to HTTP emit (OCSF Security Incident), quarantine report write, `iptables`/`pfctl` command generation, and best-effort session kill.
- `_run_ir_containment()` in CLI: called after scan, before `sys.exit()`. Errors are caught and logged to stderr without altering the exit code.
- `cosai ir contain <incident.json>` and `cosai ir status <incident.json>`: standalone IR commands for post-hoc containment from a saved incident report.

### 3.5 Track E — Signed Conformance Scorecard

**What it is:** After every scan, produces a per-category conformance grade across all 12 CoSAI categories (categories with no zero-config coverage — e.g. T4/T9/T12 without the middleware deployed — are graded accordingly rather than reported as passing), signs the scorecard with the per-installation Ed25519 key, and writes it as a machine-verifiable JSON artifact. Any post-hoc modification invalidates the signature.

**Why we built it:**

Compliance audits require *evidence*, not just reports. A signed scorecard is an attestation — the scanner cryptographically asserts that a specific server, at a specific time, with a specific threat catalog, achieved a specific conformance level. Auditors can verify the signature offline without trusting the reporting party.

This maps directly to:
- **CoSAI T1–T12 conformance levels** (full_conformance / partial_conformance / non_conformant / insufficient_coverage)
- **NIST AI RMF (2026 Critical Infrastructure Profile)** subcategory evidence (GOVERN / MAP / MEASURE / MANAGE, AG-MP.1)

**Technical architecture:**

- `Grade` enum: PASS, WARN, FAIL, NOT_TESTED — assigned per category based on probe count, finding count, critical count, high count.
- `ConformanceLevel` determination: FULL_CONFORMANCE (all pass/warn), PARTIAL_CONFORMANCE (≤3 failing, no critical), NON_CONFORMANT (any critical or >3 failing), INSUFFICIENT_COVERAGE (>4 not tested).
- `sign_scorecard()`: canonical JSON of all non-signature fields (`json.dumps` with sorted keys) → Ed25519 sign → embed public key + hex signature in the artifact.
- `verify_scorecard()`: trust anchor check (embedded public key must match installation key or `COSAI_SCORECARD_PUBKEY` env var) → Ed25519 verify.
- `ScorecardVerificationError`: raised for unsigned, key mismatch, or bad signature.
- Same keyring architecture as Track A inventory signing; same cross-machine verification pattern.

---

## 4. Why This Is Differentiated

### The four-axis differentiation

| Axis | Every existing tool | cosai-mcp |
|------|-------------------|-----------|
| **Test mechanism** | Static analysis OR runtime proxy | Runtime black-box probing + stateful harness |
| **Category coverage** | 1–3 CoSAI categories | All 12 (via three-engine split) |
| **Operations lifecycle** | Detection only | Detection → Inventory → SIEM → IR → Attestation |
| **Evidence format** | Report files | Signed, machine-verifiable artifacts |

### Why the three-engine split matters

No single probe mechanism can cover T1–T12. The mechanism class has to match the threat class:

- **T4 (tool poisoning / indirect prompt injection)**: The attack vector is a malicious tool description that changes AI behavior. Detecting it requires being in the call path — the middleware intercepts the tool response before it reaches the LLM. A black-box probe from outside sees the same tool description as the model and cannot tell whether it's poisoned.
- **T9 (LLM trust boundary)**: Whether a server over-relies on LLM judgment for authorization decisions cannot be detected by sending it crafted inputs — it requires instrumenting the decision path.
- **T12 (audit logging)**: Whether audit logs are tamper-evident and append-only cannot be probed externally. The middleware IS the test.

All static scanners use one mechanism class (source analysis). All runtime proxies use one mechanism class (traffic monitoring). cosai-mcp is the only tool that uses three mechanism classes, matched to the structural requirements of the threat categories.

### Why signed artifacts matter

Every other tool produces a report (HTML, JSON, SARIF). Reports can be modified after generation. A signed Ed25519 artifact is a cryptographic claim: the scanner asserts, under its private key, that these specific findings were produced against this specific server at this specific time with this specific threat catalog. An auditor can verify the claim without calling the scanner author.

This is the same trust model that Sigstore uses for software supply chain attestation (PEP 740). We adapted it to conformance scanning.

### Why OCSF matters

OCSF (Open Cybersecurity Schema Framework) is the native event format for commercial SIEM. Every enterprise already has OCSF ingestion pipelines. By emitting class_uid 2004 (Detection Finding) and class_uid 2001 (Security Incident), cosai-mcp plugs directly into existing alert routing, correlation, and SOAR automation — without any adapter layer. This is what makes the SIEM integration "one flag" (`--emit-to`) rather than a multi-week integration project.

---

## 5. Technical Architecture Summary

```
┌─────────────────────────────────────────────────────────────────────┐
│                         cosai-mcp v0.2+                             │
│                                                                     │
│  CLI entry point: cosai scan <target>                               │
│         │                                                           │
│         ▼                                                           │
│  ┌─────────────────────────────────────────────────────────┐       │
│  │                      Scanner Core                        │       │
│  │                                                          │       │
│  │  MCP Session: initialize → initialized → tools/list     │       │
│  │       │                                                  │       │
│  │       ├── Black-box prober (T1, T3, T5, T8, T10)        │       │
│  │       ├── Stateful harness (T2, T6, T7)                 │       │
│  │       └── Middleware instrumentation (T4, T9, T12)      │       │
│  │                                                          │       │
│  │  Each probe in its own multiprocessing.Process           │       │
│  │  Results: frozen dataclasses, immutable                  │       │
│  └────────────────────┬────────────────────────────────────┘       │
│                        │ ScanResult                                 │
│                        ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │                   Post-Scan Pipeline                      │      │
│  │                                                           │      │
│  │  ① SARIF / HTML / CSV report output                       │      │
│  │                                                           │      │
│  │  ② OCSF telemetry (Track B)                              │      │
│  │     HttpEmitter → SIEM webhook                           │      │
│  │     AnomalyDetector → [ANOMALY] alerts to stderr         │      │
│  │                                                           │      │
│  │  ③ IR containment (Track D)                              │      │
│  │     IncidentRecord → perform_containment()               │      │
│  │       → OCSF Security Incident → SIEM (SOAR trigger)    │      │
│  │       → signed quarantine report → disk                  │      │
│  │       → iptables/pfctl commands → stdout (human review)  │      │
│  │                                                           │      │
│  │  ④ Signed scorecard (Track E)                            │      │
│  │     build_scorecard() → Ed25519 sign → JSON artifact     │      │
│  └──────────────────────────────────────────────────────────┘      │
│                                                                     │
│  Separate commands:                                                 │
│    cosai inventory capture/diff/verify  (Track A)                  │
│    cosai ir contain/status              (Track D)                   │
│    cosai scorecard verify/show          (Track E)                   │
└─────────────────────────────────────────────────────────────────────┘
```

### Key design decisions and why

**Probe isolation via `multiprocessing.Process`**
Each probe runs in a separate OS process. This prevents a malicious MCP server from breaking out of one probe and affecting others. Results return as JSON-serialized frozen dataclasses — no shared memory. This is the same isolation level as browser tab sandboxing.

**Frozen dataclasses everywhere**
All result objects (ProbeResult, ScanResult, Scorecard, IncidentRecord, ToolInventory) use frozen dataclasses with `tuple` and `MappingProxyType` for container fields. This makes tampering impossible in memory and ensures serialization is deterministic.

**`trust_env=False` on all HTTP clients**
The HTTP_PROXY environment variable can redirect scanner traffic to an attacker-controlled endpoint if not disabled. `trust_env=False` on every `httpx.Client` instance prevents this. This is a locked architecture requirement (§3) applied consistently across the scanner core, the SIEM emitter, and the IR containment HTTP calls.

**URL credential redaction before any output**
Any URL that could contain credentials (e.g., `https://user:token@siem.example.com`) is parsed with `urlparse` and reconstructed without the userinfo component before being printed to stdout or logs.

**Signing architecture**
Both inventory snapshots (Track A) and scorecards (Track E) use the same Ed25519 trust model:
- Per-installation key in OS keychain (`keyring`)
- `COSAI_INVENTORY_PUBKEY` / `COSAI_SCORECARD_PUBKEY` env vars for cross-machine verification
- Trust anchor check before Ed25519 verify: embedded public key must match the trusted key or be explicitly authorized via env var. This prevents a "tamper + re-sign with different key" attack.

**Firewall commands are printed, never executed**
`iptables` and `pfctl` commands generated by Track D are written to the incident report and printed to stdout with a human-review header. Automatic network changes in production environments are a blast-radius risk — a false positive could take down legitimate traffic. The SOAR playbook triggered by the OCSF Security Incident event is the right place to automate network isolation.

---

## 6. What Landed: Commit Summary

### Baseline (pre-tracks)

The scanner core spanning the CoSAI taxonomy via the three-engine architecture (9 categories zero-config; T4/T9/T12 via deployed middleware) with SARIF output, adversarial mode, adaptive probe synthesis, server profiles, HTML/CSV reports, and the full test suite.

### Track A — cosai inventory (branch: track-a-inventory)

**Commit:** `Track A: cosai inventory CLI — capture, sign, verify, drift gate`

Files added:
- `cosai_mcp/inventory/snapshot.py` — `ToolInventory` dataclass, `capture()` function (MCP handshake + `tools/list`)
- `cosai_mcp/inventory/signing.py` — `sign_inventory()`, `verify_inventory()`, Ed25519 keyring integration
- `cosai_mcp/inventory/drift.py` — `detect_drift()`, `DriftReport`, `DriftEntry`, `DriftKind` enum
- `cosai_mcp/inventory/__init__.py`
- `tests/inventory/test_inventory.py` — 481 lines of tests

CLI additions in `cosai_mcp/cli.py`:
- `cosai inventory capture` — with `--output`, `--no-sign`, `--timeout`, `--allow-private`
- `cosai inventory verify`
- `cosai inventory diff` — with `--fail-on-drift`, `--skip-verify-signatures`

### Track B — OCSF telemetry (branch: track-b-siem)

**Commit:** `Track B: OCSF telemetry emission for SIEM/SOAR integration`

Files added:
- `cosai_mcp/telemetry/emitter.py` — `HttpEmitter` with connection pooling, `trust_env=False`, credential redaction
- `cosai_mcp/telemetry/ocsf.py` — `build_detection_finding()`, OCSF Detection Finding schema (class_uid 2004)
- `cosai_mcp/telemetry/anomaly.py` — `AnomalyDetector`, rolling window rules: HIGH_FINDING_RATE, CRITICAL_BURST, SEVERITY_ESCALATION
- `cosai_mcp/telemetry/__init__.py`
- `tests/telemetry/test_telemetry.py`

CLI additions:
- `--emit-to` / `--emit-auth-header` / `--anomaly-threshold` / `--critical-burst-threshold` options on `cosai scan`
- `_emit_scan_telemetry()` helper wired into scan post-scan pipeline

### Track D — IR containment (branch: track-d-ir)

**Commit:** `Track D: Agent IR containment with OCSF Security Incident emission`

Files added:
- `cosai_mcp/ir/incident.py` — `ContainmentAction`, `IncidentSeverity`, `FindingSummary`, `IncidentRecord`, `build_incident()`
- `cosai_mcp/ir/ocsf_incident.py` — `build_ocsf_incident()`, OCSF Security Incident schema (class_uid 2001)
- `cosai_mcp/ir/containment.py` — `perform_containment()`, `_emit_ocsf_incident_http()`, `_session_kill()`, `_generate_block_commands()`, `ContainmentResult`
- `cosai_mcp/ir/__init__.py`
- `tests/ir/test_ir.py` — 39 tests

CLI additions:
- `--contain-on-anomaly` / `--ir-report` options on `cosai scan`
- `_run_ir_containment()` helper wired into scan post-scan pipeline
- `cosai ir contain <incident.json>` — execute containment from saved report
- `cosai ir status <incident.json>` — print incident summary

### Track E — Signed scorecard (branch: track-e-scorecard)

**Commit:** `Track E: Signed Conformance Scorecard with Ed25519 attestation`

Files added:
- `cosai_mcp/scorecard/models.py` — `Grade`, `ConformanceLevel`, `CategoryResult`, `Scorecard`
- `cosai_mcp/scorecard/builder.py` — `_grade_category()`, `_determine_conformance()`, `build_scorecard()`
- `cosai_mcp/scorecard/signing.py` — `sign_scorecard()`, `verify_scorecard()`, `ScorecardVerificationError`, trust anchor check
- `cosai_mcp/scorecard/__init__.py`
- `tests/scorecard/test_scorecard.py` — 32 tests including trust anchor regression tests

CLI additions:
- `--scorecard <path>` / `--no-sign-scorecard` options on `cosai scan`
- `cosai scorecard verify <scorecard.json>`
- `cosai scorecard show <scorecard.json> [--verify]`

### Documentation

**Commit:** `docs: add PLATFORM_GUIDE, update README and VALUE_PROP for v0.2+ platform`

- `docs/PLATFORM_GUIDE.md` — new standalone positioning doc: full operational loop, audience map, per-track deep dives, GitHub Actions reference, capability comparison matrix
- `README.md` — test count 885→1161, Quick Start expanded with all new commands, docs table updated
- `docs/VALUE_PROP.md` — Platform Capabilities section (Tracks A/B/D/E), capability matrix extended to 8 columns, SOC/CISO audience paragraphs added

### Test count

| Milestone | Tests |
|-----------|-------|
| Baseline (pre-tracks) | 885 |
| + Track A (inventory) | +481 lines of tests |
| + Track B (telemetry) | added |
| + Track D (IR) | +39 tests |
| + Track E (scorecard) | +32 tests |
| **Total (all tracks merged)** | **1161** |

---

## 7. What This Enables That Didn't Exist Before

**A CISO can now say:** "We run cosai-mcp in CI on every deploy. We have a signed Ed25519 scorecard for every scan showing per-category conformance against the CoSAI/OASIS taxonomy. The scorecard is machine-verifiable by our auditor without calling us."

**A SOC analyst can now say:** "Every cosai-mcp scan streams OCSF Detection Findings to our SIEM in real time. When our MCP staging server had 7 critical findings in 2 minutes, a CRITICAL_BURST anomaly alert fired, an OCSF Security Incident was emitted, and our SOAR playbook auto-opened a P1 ticket."

**A DevSecOps engineer can now say:** "Our CI pipeline captures a signed inventory snapshot on every deploy. If any tool description changes without a code review that touches the manifest, the drift gate fails the PR. We caught two supply-chain probe changes this quarter."

**A security engineer can now say:** "I added `--scorecard scorecard.json` to our CI job. The scorecard shows T2 is still failing (confused deputy — known issue, tracked). Everything else is full conformance. That's the evidence we submit to our SOC 2 auditor."

None of these capabilities existed in any single tool before cosai-mcp v0.2+.
