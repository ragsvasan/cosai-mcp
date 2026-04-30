# cosai-mcp

[![PyPI](https://img.shields.io/pypi/v/cosai-mcp)](https://pypi.org/project/cosai-mcp/)
[![CI](https://github.com/ragsvasan/cosai-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/ragsvasan/cosai-mcp/actions)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Open-source MCP security framework covering all 12 CoSAI threat categories (T1–T12).

**Status:** Alpha — 822 tests passing, all T1–T12 categories implemented, Apache 2.0.

```bash
# Try without installing
uvx --from cosai-mcp cosai scan http://localhost:8000

# Or install permanently
pip install cosai-mcp
cosai scan http://localhost:8000
```

---

## What it is

`cosai-mcp` is the runnable reference implementation of the [CoSAI/OASIS January 2026 MCP Security whitepaper](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md). It ships three things:

- **Exhaustive test suite** — black-box probes + stateful conformance harness covering T1–T12; point at any MCP server, get a SARIF report
- **Composable Python middleware** — drop `CoSAIStack` into FastAPI/FastMCP for runtime enforcement
- **JSON-extensible threat catalog** — add new threats by dropping a signed JSON file; no code changes

## Key capabilities

- **Three-engine architecture** — black-box prober, stateful harness, and middleware instrumentation. No single engine can cover all 12 categories; the guide explains why and which categories belong to which engine.
- **Remediation-first reports** — every finding includes an exact fix shape and a verify command, not just a description. HTML, SARIF 2.1.0, and CSV output.
- **Adaptive probe synthesis** — discovers tool schemas via `tools/list` and synthesizes type-correct payloads; eliminates schema-mismatch false negatives.
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
| T6 | Integrity/Verification | Stateful harness |
| T7 | Session Security Failures | Stateful harness |
| T8 | Network Binding Failures | Black-box prober |
| T9 | Trust Boundary Failures | Middleware (deploy in target) |
| T10 | Resource Management | Black-box prober |
| T11 | Supply Chain/Lifecycle | Black-box prober |
| T12 | Insufficient Logging | Middleware (deploy in target) |

T4, T9, T12 require the cosai-mcp middleware deployed in the target server — black-box probing cannot detect prompt injection, LLM trust violations, or audit log tampering from outside the call path. See [docs/THREAT_CATALOG.md](docs/THREAT_CATALOG.md) for the full rationale.

## Quick start

```bash
# Scan a server — all categories, all engines
cosai scan http://localhost:8000

# HTML report with remediation blocks
cosai scan http://localhost:8000 --report-html report.html

# SARIF output for GitHub security tab
cosai scan http://localhost:8000 --report-sarif findings.sarif

# Adversarial mode (read-only probes; own targets only)
cosai scan http://localhost:8000 --adversarial --i-own-this-target=localhost

# Enable stateful adversarial probes (higher risk; explicit opt-in)
cosai scan http://localhost:8000 --adversarial --i-own-this-target=localhost --allow-stateful-adversarial

# Use a built-in server profile
cosai scan http://localhost:8000 --profile fastmcp

# pytest plugin
pytest --cosai-target=http://localhost:8000 --cosai-severity=critical
```

## Documentation

| Document | Audience |
|----------|----------|
| [docs/VISION.md](docs/VISION.md) | Why this exists; use cases |
| [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) | Installation, CLI, pytest plugin, GitHub Action |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Three-engine model, transport, probe isolation, report pipeline |
| [docs/SECURITY.md](docs/SECURITY.md) | Scanner security model; controls against malicious targets |
| [docs/THREAT_CATALOG.md](docs/THREAT_CATALOG.md) | T1–T12 reference; attack patterns; remediation |
| [docs/THREAT_MAPPING.md](docs/THREAT_MAPPING.md) | ISO 27001 / NIST AI RMF / OWASP MCP Top 10 / OWASP ASI Top 10 / MITRE ATLAS / SOC 2 |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | Threat definition JSON schema; adding new probes |
| [docs/architecture-decisions.md](docs/architecture-decisions.md) | Full architecture panel findings |
| [docs/workplan.md](docs/workplan.md) | Implementation roadmap (P0–P13, all complete) |

## Why not the existing tools?

| Tool | Gap |
|------|-----|
| MCP-Bastion / MCPProxy-go | Runtime proxies for production traffic monitoring — complement, not competitor; ~2 of 12 categories tested |
| Cisco MCP Scanner / Snyk / Enkrypt | Static analysis only — tests source code, not the running server |
| mcp-authx | T1 only |
| OWASP MCP Top 10 | Document; no runnable code |

cosai-mcp is the only tool that combines runtime black-box probing + stateful multi-turn conformance testing + all 12 CoSAI categories + CI/CD gate. Static analyzers and runtime proxies are complements — they test what you wrote and monitor production; cosai-mcp gates what ships.

## FAQ

**How is this different from MCP-Bastion or MCPProxy-go?**
Those are runtime proxies — they sit in front of a production server and monitor live traffic. cosai-mcp is a scanner — it runs before deploy, in CI. They test what's running in production; we gate what gets to production. Complements, not competitors.

**How is this different from static analysis tools (Cisco, Snyk, Enkrypt)?**
Static analyzers test what you wrote — the source code. We test what you shipped — the running server. An MCP server can pass every static check and still echo raw arguments into a shell at runtime. You need both.

**T4, T9, T12 need middleware — what's the black-box coverage story there?**
For T4, adversarial mode with canary tokens catches exfiltration and prompt injection echoing from outside. For T9 and T12, we detect the absence of controls — probing whether logging endpoints exist and whether audit trails are present. But detecting that something happened requires being in the call path. That's what the middleware engine handles.

**Is this ready for others to use?**
811 passing tests, Apache 2.0, installs with pip. The catalog format and taxonomy coverage are stable. Reference-implementation quality — solid enough to standardize the probe catalog schema against, not yet production-hardened for enterprise deployment at scale.

**What about non-Python MCP servers?**
The scanner speaks JSON-RPC — it's language-agnostic. Any MCP server regardless of implementation language is a valid target. The server-side middleware is Python-only today, but the scanner works against TypeScript, Go, or anything.

**Who decides what goes in the official catalog?**
Currently the project, with threat definitions Ed25519-signed by the project keypair. This includes files under `catalog/official/adversarial/` — unsigned official adversarial files are rejected at load time. The proposal to the CoSAI working group is that WS4 becomes the signing authority — same model as OWASP and the Top 10. Community submits, working group ratifies, signed artifacts ship.

## License

Apache 2.0. Contributions welcome — see [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

Target upstream: [`cosai-oasis`](https://github.com/cosai-oasis) as the official reference implementation.
