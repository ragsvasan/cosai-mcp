# cosai-mcp

**Status: Alpha — install from source (not yet on PyPI).**

[![CI](https://github.com/ragsvasan/cosai-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/ragsvasan/cosai-mcp/actions)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Open-source MCP security framework for the 12 CoSAI threat categories (T1–T12): **9 categories with zero-config black-box/stateful coverage; 3 (T4, T9, T12) require the cosai-mcp middleware deployed in the target.**

**Status:** Alpha — 1461 tests passing, Apache 2.0. Zero-config scan covers 9 categories (T1–T3, T5–T8, T10–T11). T4/T9/T12 detection needs the middleware in the target's call path. All 12 middleware modules are implemented: `auth`, `authz`, `boundary`, `protection`, `integrity`, `network`, `trust`, `resources`, `audit`, `validation`, `session`, and `supply_chain`.

```bash
# Install from source (interim — package not yet on PyPI)
git clone https://github.com/ragsvasan/cosai-mcp && cd cosai-mcp && pip install -e .
cosai scan http://localhost:8000   # loopback/RFC1918 allowed by default

# After the 0.1.0 PyPI release — not yet published:
#   uvx --from cosai-mcp cosai scan http://localhost:8000
#   pip install cosai-mcp
```

---

## What it is

`cosai-mcp` is the runnable reference implementation of the [CoSAI/OASIS January 2026 MCP Security whitepaper](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md). It ships three things:

- **Exhaustive test suite** — black-box probes + stateful conformance harness with zero-config coverage of 9 categories (T1–T3, T5–T8, T10–T11); point at any MCP server, get a SARIF report
- **Composable Python middleware** — drop `CoSAIStack` into FastAPI/FastMCP for runtime enforcement (all 12 modules implemented: T1–T12 enforcement, JWT/DPoP validation, RBAC, supply-chain verification)
- **JSON-extensible threat catalog** — add new threats by dropping a signed JSON file; no code changes

## Key capabilities

- **Three-engine architecture** — black-box prober, stateful harness, and middleware instrumentation. No single engine can cover all 12 categories; the guide explains why and which categories belong to which engine.
- **Remediation-first reports** — every finding includes an exact fix shape and a verify command, not just a description. HTML, SARIF 2.1.0, and CSV output.
- **Adaptive probe synthesis** — discovers tool schemas via `tools/list` and synthesizes type-correct payloads; eliminates schema-mismatch false negatives. Synthesis is automatically suppressed for T2 (confused-deputy) probes, which test security via adversarial parameter *names* — synthesizing a schema-correct payload would defeat the probe and produce a false positive.
- **Adversarial mode** — embeds CSPRNG canary tokens in payloads; detects exfiltration and prompt-injection echoing from outside the server. Dual opt-in required (`--adversarial --i-own-this-target=<hostname>`). Stateful adversarial probes are additionally gated behind `--allow-stateful-adversarial`.
- **Server profiles** — zero-config scanning for known MCP server types (FastMCP, FastAPI-MCP, etc.).
- **SARIF 2.1.0 output** — integrates with GitHub's native security findings tab (same as CodeQL, Dependabot).

## Coverage matrix

| Category | Name | Engine |
|----------|------|--------|
| T1 | Improper Authentication | Black-box prober |
| T2 | Missing Access Control | Stateful harness |
| T3 | Input Validation Failures | Black-box prober |
| T4 | Data/Control Boundary | Middleware (deploy in target) |
| T5 | Inadequate Data Protection | Black-box prober |
| T6 | Integrity/Verification | Passive manifest scan + stateful harness |
| T7 | Session Security Failures | Stateful harness + black-box prober |
| T8 | Network Binding Failures | Black-box prober |
| T9 | Trust Boundary Failures | Passive manifest scan + Middleware |
| T10 | Resource Management | Black-box prober |
| T11 | Supply Chain/Lifecycle | Passive manifest scan (`--tool-allowlist`) |
| T12 | Insufficient Logging | Middleware (deploy in target) |

T4, T6, and T9 each have a passive manifest-scan layer: T4 detects tool-description poisoning in `tools/list`; T6 detects tool-name collisions, reserved-method shadowing, and Levenshtein-1 typosquats, plus a stateful mid-session manifest-drift check; T9 detects destructive tools missing two-stage commit (the TKA Totem structural check). Full T4/T9/T12 coverage requires the cosai-mcp middleware deployed in the target. See [docs/THREAT_CATALOG.md](docs/THREAT_CATALOG.md) for the full rationale.

## Front door — detect tool drift in CI

The fastest way to get value: capture a signed inventory of a server's tool
surface, then gate CI on drift. A new or mutated tool definition is the
earliest signal of a supply-chain (T11) or tool-poisoning (T4) change.

```bash
# Once: capture the trusted baseline (signed artifact)
# (loopback/RFC1918 targets like localhost are allowed by default, matching
#  `cosai scan`; pass --block-private-targets in CI to enforce public-only)
cosai inventory capture http://localhost:8000 -o baseline.json

# In CI: fail the build if the live tool surface drifted from the baseline
cosai inventory capture http://localhost:8000 -o current.json
cosai inventory diff baseline.json current.json --fail-on-drift
```

`cosai inventory diff` exits non-zero on drift (with `--fail-on-drift`),
verifies the Ed25519 signatures on signed artifacts, and is the single
command most teams should wire into CI first. Then add a full `cosai scan`
for the conformance scorecard.

## Quick start

```bash
# Scan a server — all categories, all engines
cosai scan http://localhost:8000

# HTML report with remediation blocks
cosai scan http://localhost:8000 --report-html report.html

# SARIF output for GitHub security tab
cosai scan http://localhost:8000 --report-sarif findings.sarif

# Signed conformance scorecard (machine-verifiable by auditors)
cosai scan http://localhost:8000 --scorecard scorecard.json
cosai scorecard verify scorecard.json
cosai scorecard show scorecard.json --verify

# Stream findings to SIEM as OCSF Detection Finding events
# (Track B — EXPERIMENTAL, requires --experimental; not part of the
#  default scan surface and may change or be removed)
cosai scan http://localhost:8000 --experimental \
  --emit-to https://siem.example.com/webhook/cosai \
  --emit-auth-header "Bearer $SIEM_TOKEN"

# Auto-quarantine on anomaly + IR containment
# (Track D — EXPERIMENTAL, requires --experimental)
cosai scan http://localhost:8000 --experimental \
  --contain-on-anomaly --anomaly-threshold 3 \
  --ir-report ./incident.json \
  --emit-to https://siem.example.com/webhook

# Tool inventory: capture a snapshot, diff for drift
# (loopback/RFC1918 targets like localhost allowed by default; use
#  --block-private-targets to enforce public-only)
cosai inventory capture http://localhost:8000 -o baseline.json
cosai inventory diff baseline.json current.json --fail-on-drift

# Adversarial mode (read-only probes; own targets only)
cosai scan http://localhost:8000 --adversarial --i-own-this-target=localhost

# Use a built-in server profile
cosai scan http://localhost:8000 --profile fastmcp

# Avoid triggering server-side rate limiters (2.5 s between probes)
cosai scan http://localhost:8080 --auth-token "$TOKEN" --probe-delay 2.5

# Scope enforcement test (T02-005): provide both primary and read-only tokens
cosai scan http://localhost:8000 --auth-token "$WRITE_TOKEN" --read-token "$READ_TOKEN"

# pytest plugin — turnkey: auto-runs the scan and FAILS the suite on any
# finding at or above --cosai-severity. No test file required; the plugin
# injects a `cosai_scan_gate` item when --cosai-target is supplied.
pytest --cosai-target=http://localhost:8000 --cosai-severity=critical

# For custom assertions, consume the `cosai_scan_result` fixture in your own test:
#   def test_no_critical_findings(cosai_scan_result):
#       assert not cosai_scan_result.has_findings
# (The auto gate still runs alongside your test.) Without --cosai-target the
# plugin/fixtures cleanly skip, so a normal `pytest` run is unaffected.
```

## Implementation Status

| Feature | Status |
|---|---|
| Black-box prober (T1, T3, T5, T8, T10, T11) | Shipped |
| Stateful conformance harness (T2, T6, T7) | Shipped |
| T4 passive manifest scan (adversarial canary mode) | Shipped |
| Middleware: `auth`, `boundary`, `protection`, `integrity`, `network`, `trust`, `resources`, `audit` | Shipped |
| Middleware: `authz` (T2), `validation` (T3), `session` (T7), `supply_chain` (T11) | Shipped |
| `CoSAIStack` middleware orchestrator | Shipped (`cosai_mcp/middleware/__init__.py`) |
| Static tool definition analyzer (`cosai_mcp/scanner/`) | Planned (`__init__.py` is 0 bytes) |

The scanner (black-box prober + stateful harness) covers 9 of 12 categories zero-config. All 12 middleware modules are implemented and composable via `CoSAIStack`.

## Documentation

New to cosai-mcp? Start with [docs/VISION.md](docs/VISION.md) — it covers what this is, why no existing tool fills the gap, why the scanner itself can be trusted, and the primary use cases.

| Document | Audience |
|----------|----------|
| [docs/VISION.md](docs/VISION.md) | **Start here** — what it is, the competitive gap, security model, use cases |
| [docs/PLATFORM_GUIDE.md](docs/PLATFORM_GUIDE.md) | Full operational pipeline: inventory → scan → SIEM → IR → scorecard |
| [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) | Installation, CLI, pytest plugin, GitHub Action |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Three-engine model, transport, probe isolation, report pipeline |
| [docs/SECURITY.md](docs/SECURITY.md) | Scanner security model; controls against malicious targets |
| [docs/THREAT_CATALOG.md](docs/THREAT_CATALOG.md) | T1–T12 reference; attack patterns; remediation |
| [docs/THREAT_MAPPING.md](docs/THREAT_MAPPING.md) | CoSAI T1–T12 / NIST AI RMF / OWASP MCP Top 10 / CWE |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | Threat definition JSON schema; adding new probes |
| [docs/CATALOG_SIGNING_FAQ.md](docs/CATALOG_SIGNING_FAQ.md) | Threat definition signing & trust model; key rotation; enterprise overrides |
| [docs/architecture-decisions.md](docs/architecture-decisions.md) | Full architecture panel findings |
| [docs/workplan.md](docs/workplan.md) | Implementation roadmap (P0–P13, all complete) |

## Why not the existing tools?

| Tool | Gap |
|------|-----|
| MCP-Bastion / MCPProxy-go | Runtime proxies for production traffic monitoring — complement, not competitor; ~2 of 12 categories tested |
| Cisco MCP Scanner / Snyk / Enkrypt | Static analysis only — tests source code, not the running server |
| mcp-authx | T1 only |
| OWASP MCP Top 10 | Document; no runnable code |

cosai-mcp is the only tool that combines runtime black-box probing + stateful multi-turn conformance testing + a CI/CD gate spanning the CoSAI taxonomy: 9 categories scanned zero-config, plus T4/T9/T12 covered when the middleware is deployed in the target. Static analyzers and runtime proxies are complements — they test what you wrote and monitor production; cosai-mcp gates what ships.

### What this is

A **runnable reference implementation of the CoSAI/OASIS MCP Security taxonomy** plus a **signed conformance artifact**: point the scanner at any MCP server, get a SARIF report and an Ed25519-signed scorecard that proves — verifiably, without trusting a vendor — which CoSAI categories the server passes. The threat catalog is signed, the audit log is hash-chained, and reports carry a per-installation (or org/fleet) signing key fingerprint. Conformance you can verify, not a dashboard you have to believe.

## FAQ

**How is this different from MCP-Bastion or MCPProxy-go?**
Those are runtime proxies — they sit in front of a production server and monitor live traffic. cosai-mcp is a scanner — it runs before deploy, in CI. They test what's running in production; we gate what gets to production. Complements, not competitors.

**How is this different from static analysis tools (Cisco, Snyk, Enkrypt)?**
Static analyzers test what you wrote — the source code. We test what you shipped — the running server. An MCP server can pass every static check and still echo raw arguments into a shell at runtime. You need both.

**T4, T9, T12 need middleware — what's the black-box coverage story there?**
T4, T6, and T9 each have a passive manifest-scan layer that runs zero-config. T4 detects tool-description poisoning hidden in `tools/list`. T6 detects name collisions, reserved-method shadowing, and typosquatted tool names. T9 detects destructive tools missing two-stage commit (delete/drop/wipe/revoke/etc. tools without a `confirmed` param or `_preview` sibling) — the structural Totem check from the CoSAI WS4 T9 contribution. T4 adversarial mode with canary tokens additionally catches exfiltration from outside. For T9 and T12, full coverage requires the middleware in the call path — detecting that LLM judgment drove an authorization decision or that an audit log entry was missing requires being instrumented inside the server.

**Is this ready for others to use?**
1461 passing tests, Apache 2.0, installs with pip. The catalog format and taxonomy coverage are stable. Reference-implementation quality — solid enough to standardize the probe catalog schema against, not yet production-hardened for enterprise deployment at scale.

**What about non-Python MCP servers?**
The scanner speaks JSON-RPC — it's language-agnostic. Any MCP server regardless of implementation language is a valid target. The server-side middleware is Python-only today, but the scanner works against TypeScript, Go, or anything.

**Who decides what goes in the official catalog?**
Currently the project, with threat definitions Ed25519-signed by the project keypair. The public key is hardcoded in the binary — even if an attacker poisons the PyPI package, they cannot forge valid signatures without the private key. See [docs/CATALOG_SIGNING_FAQ.md](docs/CATALOG_SIGNING_FAQ.md) for details on key rotation, custom catalogs, and trust. The proposal to the CoSAI working group is that WS4 becomes the signing authority — same model as OWASP and the Top 10. Community submits, working group ratifies, signed artifacts ship.

**How do I know the threat definitions haven't been tampered with?**
Official definitions are Ed25519-signed; the scanner validates signatures at load time. The public key is hardcoded in the binary and published via Sigstore attestation. Custom threats (unsigned) require explicit `--allow-custom-catalog` flag. See [docs/CATALOG_SIGNING_FAQ.md](docs/CATALOG_SIGNING_FAQ.md) for the full security model, including enterprise key rotation via `COSAI_PUBKEY` environment variable.

## License

Apache 2.0. Contributions welcome — see [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

Target upstream: [`cosai-oasis`](https://github.com/cosai-oasis) as the official reference implementation.
