# cosai-mcp — Brutal Product Review (2026-06-16)

## 1. Bottom line up front — is this viable?

The engine is the real deal: 15,877 LOC, 1,314 passing tests, a defensible three-engine architecture, valid SARIF 2.1.0, CSP-hardened HTML, fail-closed exit codes, and a whitepaper whose central theorem (T4/T9/T12 are undecidable by black-box probing) is intellectually serious and genuinely rare in this space. But as a *product* it is unshippable today: every single copy-paste on-ramp a new user would actually try — PyPI install, example server, Python API, pytest plugin, inventory front-door — is broken, empty, or misleading, and the package was never published to PyPI, so the two headline install commands 404. None of this is a code-quality problem; it is a distribution-and-docs problem, all of it fixable in roughly a day. It is a strong tool trapped behind a 0-for-5 first-15-minutes experience, with zero external adoption signal (solo 7-week repo, one author, no contributors).

**Verdict: SHIP — after a one-day distribution-and-docs fix.** The core is good enough to lead the category; do not ship the README as-is, because it dies at the trial.

---

## 2. What actually works (verified-true positives, with evidence)

These survived four independent investigators and adversarial fact-checking. State them plainly: the engine is good.

- **Real handshake + scan against a live target.** Completes the MCP `initialize` handshake, runs 43+ probes plus 5 stateful multi-turn conformance scenarios. (Confirmed by both the AppSec-lead and DX investigators against a live target.)
- **Valid, schema-conformant output.** Emits schema-valid SARIF 2.1.0 and CSP-hardened HTML. SARIF renders natively in GitHub's security tab.
- **Fail-closed CI contract.** Exits 1 on findings at/above threshold (locked exit-code contract honored).
- **No stub/dead-code traps.** Every load-bearing capability checked is wired-and-tested code, not stub or label-only assignments — a deliberate guard against the failure modes Codex caught on 2026-04-29.
- **Honest about its own limits.** T4/T9/T12 are marked *indeterminate*, not *clean*, and the Rice's-Theorem argument for why black-box probing cannot reach them is more intellectually credible than any competitor's marketing. This honesty is the single biggest differentiator.
- **Genuinely green suite once unblocked.** `1314 passed, 1 skipped in 204.89s` after the one missing dep is installed.
- **The pytest plumbing exists and is correct where it is wired.** `cosai_scan_result` runs a real `Scanner` scan and is tested (`tests/cli/test_cli.py:363-390`); it correctly skips only when `--cosai-target` is absent. (This is why the "pytest no-ops entirely" market-thesis finding was *rejected* — see §10.)

---

## 3. Product viability & market fit

**The architecture is defensible; the category is a wedge, not a moat.** This is the OSS reference implementation of a Jan-2026 CoSAI/OASIS whitepaper, competing against funded commercial scanners (Cisco, Snyk, Enkrypt) and free runtime proxies (MCP-Bastion, MCPProxy-go) — which CLAUDE.md:13 itself frames as complements, not competitors. The buyer (MCP-server security) barely exists as a budget line today.

**Zero external adoption signal — the fatal gap for a "reference implementation."**
- ~7 weeks old: first commit 2026-04-26, head 2026-06-13.
- 98 commits, **single author**, no co-authors (`git shortlog -sne` returns one author).
- No root `CONTRIBUTING.md` / `CODE_OF_CONDUCT.md` (a `docs/CONTRIBUTING.md` exists, but the standard discovery location is empty).
- Hosted at `github.com/ragsvasan/cosai-mcp` — a personal namespace, **not** the `cosai-oasis` org the strategy targets.
- The project's own vision doc concedes it: `agentic_security_vision.md:67` — *"What does not exist is adoption, a reference implementation..."*

A reference implementation with no reference users is a demo, however well-engineered. **Strong as a credibility artifact and standards-body contribution bid; not yet a thing a community can form around.** The most realistic goal is a standards-body submission (given the whitepaper depth) plus one named design partner running it in CI — a single real external user is worth more than 5,000 more LOC.

---

## 4. Ease of use & adoption curve — the real first-15-minutes experience

Adoption dies in the first 15 minutes. Here is what a skeptical evaluator following the README actually hits, in order:

| Step | What the docs say | What actually happens |
|---|---|---|
| 1. Install (zero-install) | `uvx --from cosai-mcp cosai scan ...` (README.md:13) | **Fails** — not on PyPI. |
| 2. Install (pip) | `pip install cosai-mcp` (README.md:16) | **Fails** — `No matching distribution found`. |
| 3. Point at a server | `cosai scan http://localhost:8000` | **Nothing to scan** — both `examples/` dirs are empty `.gitkeep`. |
| 4. Python API | `from cosai_mcp import Scanner, ScanConfig` (GETTING_STARTED.md:121) | **ImportError on line one.** |
| 5. pytest plugin | `pytest --cosai-target=URL` (README.md:126) | **`no tests ran in 0.00s`** — silent false-green. |
| 6. Front door | `cosai inventory capture http://localhost:8000` (README.md:66) | **Hard error** — SSRF guard blocks loopback, flag undocumented. |

The only working install path — `pip install -e .` from a git clone — appears nowhere as the recommended quickstart. A contributor who clones and runs `pytest` hits a collection error (missing PyYAML) before they can verify the headline "1314 tests passing." **0-for-5 on the advertised on-ramps; the green suite and working scan are hidden behind all of them.**

---

## 5. Features that don't do what they say (claim → reality → evidence)

### 5.1 PyPI install — `pip install cosai-mcp` / `uvx --from cosai-mcp` — **CRITICAL**
- **Claim:** README.md:13/16 lead with these as the zero-install and pip on-ramps; README.md:3 carries a live PyPI version badge.
- **Reality:** The package was never published. The pypi.org/project page returns HTTP 200 only because it serves a bot "Client Challenge" interstitial — the JSON API 404s.
- **Evidence:** `curl pypi.org/pypi/cosai-mcp/json` → HTTP 404; `pip index versions cosai-mcp` → `ERROR: No matching distribution found for cosai-mcp`; pypi project page title = `Client Challenge`.

### 5.2 Python API — `from cosai_mcp import Scanner, ScanConfig` — **BLOCKER (copy-paste path)**
- **Claim:** GETTING_STARTED.md:121-129 and the README Python API section: `Scanner(ScanConfig(target=..., categories=..., fail_on=...)).run()`.
- **Reality:** Three independent breakages on copy-paste. (1) `ScanConfig` is not in `__all__` → ImportError. (2) Its real fields are `target_host`/`target_port`; there is no `target` and no `fail_on` → TypeError. (3) `Scanner.__init__` takes a URL string, not a ScanConfig → opaque `'ScanConfig' object has no attribute 'decode'` inside `.run()`. Only the undocumented-in-prose `Scanner(url).run(categories=[...])` works.
- **Evidence:** `cosai_mcp/__init__.py:4` `__all__ = ["Scanner", "ScanResult", "COVERAGE_MATRIX", "scrub_env"]` (no ScanConfig); `config.py:8-34` ScanConfig has `target_host`/`target_port`, no `target`, no `fail_on`. Investigator: ImportError → TypeError → `ScannerInternalError ... no attribute 'decode'`.

### 5.3 pytest plugin — "works without conftest changes, findings appear inline, critical findings fail the suite" — **MAJOR**
- **Claim:** README.md:126 sells `pytest --cosai-target=URL --cosai-severity=critical` as turnkey.
- **Reality:** The plugin registers only `pytest_addoption` + fixtures. There is **no** `pytest_collection`/`pytest_generate_tests` hook, so a bare run in a fresh project runs zero tests, scans nothing, finds nothing, and trivially passes — a silent false-green a CI engineer would trust as a passing security gate. The user must hand-author a test consuming the `cosai_scan_result` fixture; the docs never say so.
- **Evidence:** `cosai_mcp/pytest_plugin.py` defines `pytest_addoption` (:18) and fixtures only (:54-124); grep for `pytest_collect`/`pytest_generate` → none. Investigator in empty dir → `no tests ran in 0.00s`.
- **Note:** The plugin internals are correctly built (§2); the lie is specifically the "no conftest changes / inline findings" framing, not the existence of the plugin.

### 5.4 Inventory "front door" — `cosai inventory capture http://localhost:8000` — **MAJOR**
- **Claim:** README.md:58/66/110 call this "the single command most teams should wire into CI first."
- **Reality:** Fails on loopback because the SSRF guard blocks RFC1918/loopback and the documented command has no flag to allow it. The required `--allow-private` flag (cli.py:760) appears nowhere in README or GETTING_STARTED. Worse, it's **inconsistent**: `cosai scan` defaults `--allow-private-targets=True` (cli.py:170, hidden), so the *same* localhost target scans fine but won't inventory — and the error message names `allow_private_targets` while the real flag is `--allow-private`.
- **Evidence:** `grep allow-private README.md` → not documented; investigator → `[ERROR] ... Target IP 127.0.0.1 is a private/loopback/link-local address.`; with `--allow-private` → signed artifact written.

### 5.5 "All twelve categories as black-box probes" — **MINOR (self-contradiction)**
- **Claim:** `cto_article.md:53` and `agentic_security_vision.md:45`: "run all twelve CoSAI/OASIS threat categories as black-box and stateful probes."
- **Reality:** Directly contradicts the project's own locked theorem — `whitepaper.md:229` puts T4/T9/T12 under *middleware instrumentation*, and CLAUDE.md states "Never claim black-box probe coverage for T4, T9, or T12." For a tool whose differentiator is honesty, this is a self-inflicted credibility leak.

### 5.6 Stale / inconsistent metrics — **MINOR (credibility leak)**
- **Claim vs reality:** Test count disagrees across docs — actual `1315` collected; README.md:9 says `1314`; `whitepaper.md:233` says `917`; `COVERAGE.md:4` says `860`. Catalog size: `COVERAGE.md:5` says "20 signed + 4 adversarial"; actual `ls catalog/official/*.json | wc -l` → `26` (+4 adversarial).
- **Evidence:** `pytest --co -q` → 1315 collected. A diligence-checking AppSec buyer who finds a 1315/917/860 spread starts doubting every other claim — including the well-earned ones.

---

## 6. Basic scenarios that don't work (with command output)

```
# Scenario 1 — install the way the README's first command says
$ pip index versions cosai-mcp
ERROR: No matching distribution found for cosai-mcp
$ curl -s pypi.org/pypi/cosai-mcp/json   # → HTTP 404 (project page is a bot "Client Challenge")

# Scenario 2 — clone, install dev deps, verify the headline test count
$ pip install -e .[dev] && pytest -q
ERROR collecting tests/ci/test_ci.py
ModuleNotFoundError: No module named 'yaml'
# (PyYAML is in NO dependency group: `grep -i yaml pyproject.toml` → no match)
$ pip install pyyaml && pytest -q
1314 passed, 1 skipped in 204.89s      # green only after an undocumented manual step

# Scenario 3 — use the documented Python API
>>> from cosai_mcp import Scanner, ScanConfig
ImportError: cannot import name 'ScanConfig'
>>> ScanConfig(target="http://localhost:8000")
TypeError: unexpected keyword argument 'target'
>>> Scanner(ScanConfig(...)).run()
ScannerInternalError: 'ScanConfig' object has no attribute 'decode'

# Scenario 4 — run the pytest plugin as advertised
$ pytest --cosai-target=http://127.0.0.1:PORT --cosai-severity=critical
no tests ran in 0.00s                  # silent false-green

# Scenario 5 — run the recommended "front door" command on localhost
$ cosai inventory capture http://localhost:8000 -o baseline.json
[ERROR] Inventory capture failed: Target IP 127.0.0.1 is a private/loopback/link-local address.
$ cosai inventory capture http://localhost:8000 -o baseline.json --allow-private
Inventory written ... (signed, 1 tool(s))    # works only with the undocumented flag

# Scenario 6 — point the scanner at the shipped example server
$ ls -la examples/fastmcp/ examples/fastapi-mcp/
.gitkeep   (0 bytes, each)             # nothing to scan
```

---

## 7. Competitive comparison

Competitor set independently verified via web research (June 2026), every row cited to a fetched URL.

| Tool | Type | MCP threat coverage | Traction | URL |
|---|---|---|---|---|
| **Invariant mcp-scan** (now Snyk "Agent Scan") | OSS Apache-2.0; static scan + runtime proxy/gateway | Tool poisoning, prompt injection, cross-origin escalation, rug pulls, PII/secret guardrails, tool pinning (~15 risks). No CoSAI mapping | ~2.6k stars; absorbed into Snyk Agent Security, GA at RSAC 2026 | [github.com/invariantlabs-ai/mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) |
| **Cisco AI Defense MCP Scanner** | OSS Apache-2.0; static + some runtime; offline JSON mode for CI/CD | Command/prompt injection, tool poisoning, data leakage, malware (VirusTotal); maps to Cisco AI Threat Taxonomy, not CoSAI | ~962 stars, 116 forks; Cisco-backed, RSAC 2026 launch | [github.com/cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) |
| **Snyk Agent Security / Agent Scan** | Commercial + OSS; static pre-deploy + real-time MCP proxy + runtime controls | Prompt injection, malicious code, suspicious downloads; full-lifecycle for Claude Code/Cursor/Devin | GA RSAC 2026; established DevSecOps vendor, CoSAI sponsor | [github.com/invariantlabs-ai/mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) |
| **Enkrypt AI MCP Scanner** | Commercial (free single-server scans); hosted, protocol-aware | Protocol-aware vuln scan w/ severity + remediation ("13 MCP vulnerabilities") | "First MCP scanner" PR; published 1,000-server study (33% critical) | [enkryptai.com](https://www.enkryptai.com/product/mcp-scanner) |
| **Lasso Security** | Commercial; runtime detection | Real-time prompt-injection blocking, PII masking, tool reputation scoring | 2024 Gartner Cool Vendor for AI Security | [practical-devsecops.com](https://www.practical-devsecops.com/top-mcp-security-tools/) |
| **Operant AI** | Commercial; inline runtime gateway | Inline redaction, AI-DR for live workloads, MCP gateway | Featured in Gartner MCP cybersecurity guide | [operant.ai](https://www.operant.ai/art-kubed/operant-ai-gartner-featured-operant-ai-mcp-gateway-in-mcp-cybersecurity-guide) |
| **mcpproxy-go** | OSS; Go proxy/gateway | Quarantine + pluggable scanners (Snyk/Semgrep/Trivy/Cisco), normalized to SARIF + composite risk | Active OSS proxy | [github.com/smart-mcp-proxy/mcpproxy-go](https://github.com/smart-mcp-proxy/mcpproxy-go) |
| **Semgrep MCP** | OSS; static code scanner exposed as MCP server | Static code vuln scanning for coding agents (not an MCP-server prober) | Semgrep brand; native Claude Code/Cursor | [github.com/semgrep/mcp](https://github.com/semgrep/mcp) |
| **cosai-mcp** (under review) | OSS Apache-2.0; runtime black-box JSON-RPC prober + stateful multi-turn conformance harness + middleware + SARIF/CI gate | Full CoSAI T1–T12 via three engines (8 zero-config + 4 via middleware); honest "indeterminate" labeling | **No public traction signal found** | github.com/ragsvasan/cosai-mcp |

**Honest read (verified June 2026):** The "only tool that combines runtime probing + stateful conformance + T1–T12 + CI gate" claim is **partially eroded but not dead**. No single confirmed competitor advertises that exact four-way combination — the closest, Invariant/Snyk Agent Scan, overlaps heavily on runtime scanning, proxy guardrails and tool-poisoning detection but is *not* a stateful multi-turn protocol-conformance harness and maps to Snyk's own taxonomy, not CoSAI ([mcp-scan](https://github.com/invariantlabs-ai/mcp-scan)). The genuinely surviving differentiators are the **stateful conformance harness** and the **CoSAI T1–T12 mapping** — a 2026 practitioner roundup found no other tool offering stateful multi-turn conformance + black-box JSON-RPC probing + SARIF CI gate + CoSAI references ([practical-devsecops](https://www.practical-devsecops.com/top-mcp-security-tools/)). **But "unique combination" is a weak moat against distribution.** A buyer today most likely picks Snyk Agent Scan or Cisco's MCP Scanner: both free/OSS, vendor brand-trust, RSAC-2026 launches, real traction (~2.6k and ~962 stars), and Cisco's offline JSON mode already covers the CI/CD use case ([cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner)) — while cosai-mcp has no discoverable adoption signal. **The strategic risk is the taxonomy bet:** CoSAI's taxonomy is real and credible (12 categories, released Jan 27 2026, multi-vendor sponsored — [oasis-open.org](https://www.oasis-open.org/2026/01/27/coalition-for-secure-ai-releases-extensive-taxonomy-for-model-context-protocol-security/)), but it is **not** the dominant tooling framing — OWASP MCP Top 10 is described as "the most developer-friendly and widely adopted in practice" with MITRE ATLAS leading red-team framing ([straiker.ai](https://www.straiker.ai/blog/comparing-ai-security-frameworks-owasp-csa-nist-and-mitre)), and the shipping scanners map to OWASP or their own taxonomies, not T1–T12. Net: the technical niche is defensible, but cosai-mcp is betting on a taxonomy the tooling market hasn't adopted, against vendor-backed competitors with the distribution and traction it lacks. **Mapping findings to OWASP MCP Top 10 alongside CoSAI is the cheapest way to de-risk that bet.**

---

## 8. Blockers (ranked)

1. **[CRITICAL] Not on PyPI — both headline install commands 404.** 100% of new users following the README fail on command one. Time-to-first-value via the advertised path is infinite.
2. **[BLOCKER] Documented Python API ImportErrors on line one.** The highest-intent adopter path (custom CI integration) is broken in three independent ways.
3. **[MAJOR] No example server ships.** Both `examples/` dirs are empty; nothing to scan out of the box. Highest-leverage *adoption* fix — converts a 2-minute demo into a research project.
4. **[MAJOR] pytest plugin runs zero tests / silent false-green.** Advertised as turnkey; a CI engineer trusts a passing gate that scanned nothing. Worst *trust* failure mode for a security tool.
5. **[MAJOR] Inventory front-door fails on localhost + inconsistent default.** The recommended first command errors on the most common target, with the wrong flag name in the error.
6. **[MAJOR] Test suite won't collect on clean install — undeclared PyYAML dep.** The headline "1314 tests passing" is unverifiable without an undocumented `pip install pyyaml`.
7. **[MAJOR] Zero external adoption / wrong GitHub namespace.** No contributors, no CONTRIBUTING at root, personal namespace not cosai-oasis. Fatal for a "reference implementation" thesis until one design partner exists.
8. **[MINOR] Stale/contradictory metrics + black-box overclaim.** Erodes the one asset (honesty) that differentiates the tool.

---

## 9. Remediation plan — phased (problem → action → effort → priority)

Ordered so the highest-leverage viability fixes land first. **Phase 1 is the ~1-day "make the trial succeed" sprint.**

### Phase 1 — Make the first 15 minutes work (do this before anything else)

| # | Problem | Action | Effort | Priority |
|---|---|---|---|---|
| 1 | Not on PyPI | Publish 0.1.0 (sdist+wheel, Trusted Publishing + Sigstore/PEP 740 per locked spec), verify `pip install` and `uvx --from` resolve in a clean venv. *Interim if not ready:* replace README.md:13/16 with `git clone && pip install -e .` and drop the PyPI badge. | M | **P0** |
| 2 | `pytest` won't collect (PyYAML) | Add `pyyaml` to the `[dev]`/`[test]` group in pyproject.toml (one line). | S | **P0** |
| 3 | No example server | Ship one runnable, deliberately-vulnerable example server (~30–50 line FastMCP/FastAPI) + a `cosai demo` subcommand or `python examples/fastmcp/server.py` launcher, so `cosai scan` finds something in <60s. | M | **P0** |
| 4 | Python API broken on copy-paste | Make docs+code agree on `Scanner("http://...").run(categories=[...], fail_on=...)`; if ScanConfig is public, export it + add `target`/`fail_on` + a `Scanner(config)` overload. | S | **P0** |
| 5 | pytest plugin no-ops | Either add a `pytest_collection_modifyitems`/`pytest_generate_tests` hook that synthesizes one test per category and fails on findings ≥ `--cosai-severity`, OR rewrite README.md:126 to show the required user-authored test. Stop claiming "no conftest changes." | M | **P0** |
| 6 | Inventory front-door fails on localhost | Make `inventory capture` and `scan` consistent on private-target default; fix the error to name `--allow-private`; add the flag to README:66/110. | S | **P1** |

### Phase 2 — Stop the build from drifting again

| # | Problem | Action | Effort | Priority |
|---|---|---|---|---|
| 7 | Docs drift silently | Add a CI job that runs the documented install commands verbatim in a clean container, imports-and-runs the exact README/GETTING_STARTED Python snippet (doctest), and runs the plugin end-to-end asserting a critical finding fails the run. | M | **P1** |
| 8 | Stale metrics | Generate test count + catalog size from the build into a badge/JSON the docs reference; fail CI on drift. Reconcile whitepaper §7.3 and COVERAGE.md to 1315 / 26-official. | S | **P1** |
| 9 | Black-box overclaim | Fix `cto_article.md:53` and `agentic_security_vision.md:45` to name the three-engine split (T4/T9/T12 = middleware). | S | **P1** |

### Phase 3 — Earn the "reference implementation" claim

| # | Problem | Action | Effort | Priority |
|---|---|---|---|---|
| 10 | Zero adoption / wrong namespace | Decide the goal. If standards-body bid: submit to cosai-oasis, land **one named design partner** running it in CI, report that as the proof point. Move/mirror the repo to the cosai-oasis org. | L | **P2** |
| 11 | No contributor scaffolding | Add root `CONTRIBUTING.md` + `CODE_OF_CONDUCT.md`. | S | **P2** |
| 12 | Taxonomy bet on CoSAI alone, while OWASP MCP Top 10 is the framing the tooling market actually adopted (verified §7) | Dual-map every finding to OWASP MCP Top 10 alongside CoSAI T1–T12 (the schema already carries an `owasp_ref` field — populate and surface it in reports). Cheapest de-risk of the strategic taxonomy bet; widens addressable audience to OWASP-aligned buyers. | M | **P1** |
| 13 | Vendor-backed competitors (Snyk Agent Scan ~2.6k★, Cisco MCP Scanner ~962★) own distribution; cosai-mcp has zero traction (verified §7) | Lead positioning with the two surviving differentiators — **stateful multi-turn conformance harness** and **honest "indeterminate" T4/T9/T12 labeling** — not "covers all 12." Those are the only claims no competitor matches. | S | **P1** |

---

## 10. Findings the panel raised that did NOT survive fact-checking

In the interest of honesty, one panel finding was **rejected** after adversarial verification:

- **"Market wedge is unproven — buyer, budget, and 'who pays/contributes' are all undefined" (REJECTED).** The cited artifacts exist, but the load-bearing claims were unverifiable market opinion or contradicted by the repo: (1) "No monetization path stated" is false — `agentic_security_vision.md:79` gives an explicit revenue framing (signed conformance scorecards / SOC2-style liability shift) and `when_software_loses_its_user.md` is an entire pricing-strategy essay; the give-it-away posture is a *deliberate stated strategy*, not a gap. (2) "No established buyer / no budgeted need" is an unfalsifiable absence-of-evidence judgment with no external evidence cited. (3) The one concrete hook — "the pytest-CI wedge no-ops" — does **not** check out: `cosai_mcp/pytest_plugin.py` is fully implemented and wired (`pytest_addoption:18`, `cosai_target` fixture, `cosai_scan_result` runs a real scan, tested at `tests/cli/test_cli.py:363-390`); it skips only when `--cosai-target` is absent, which is correct. The verifiable evidence was accurate but repurposed to support a speculative TAM thesis — a strategy opinion dressed as a "major" technical finding.

*(Note: the pytest finding in §5.3 is distinct and survived — it concerns the false "auto-scans without conftest" claim for a bare run, not a claim that the plugin internals are broken.)*
