# cosai-mcp

Open-source MCP security framework covering all 12 CoSAI threat categories (T1–T12).

**Status:** Pre-alpha — architecture panel complete, implementation in progress.

```bash
# Zero install — scan any MCP server
uvx cosai-mcp scan http://localhost:8000
```

---

## What it is

`cosai-mcp` is the runnable reference implementation of the [CoSAI/OASIS January 2026 MCP Security whitepaper](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md). It ships three things:

- **Exhaustive test suite** — black-box probes + stateful conformance harness covering T1–T12; point at any MCP server, get a SARIF report
- **Composable Python middleware** — drop `CoSAIStack` into FastAPI/FastMCP for runtime enforcement
- **JSON-extensible threat catalog** — add new threats by dropping a signed JSON file; no code changes

## Coverage matrix

| Category | Name | Engine |
|----------|------|--------|
| T1 | Improper Authentication | Black-box prober |
| T2 | Missing Access Control | Stateful harness |
| T3 | Input Validation Failures | Black-box prober |
| T4 | Data/Control Boundary | Middleware (deploy in target) |
| T5 | Inadequate Data Protection | Middleware (deploy in target) |
| T6 | Integrity/Verification | Stateful harness |
| T7 | Session Security Failures | Stateful harness |
| T8 | Network Binding Failures | Black-box prober |
| T9 | Trust Boundary Failures | Middleware (deploy in target) |
| T10 | Resource Management | Black-box prober |
| T11 | Supply Chain/Lifecycle | Black-box prober (partial) |
| T12 | Insufficient Logging | Middleware (deploy in target) |

T4, T9, T12 require the cosai-mcp middleware deployed in the target server. See [docs/THREAT_CATALOG.md](docs/THREAT_CATALOG.md) for why.

## Documentation

| Document | Audience |
|----------|----------|
| [docs/VISION.md](docs/VISION.md) | Why this exists; use cases |
| [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) | Installation, CLI, pytest plugin, GitHub Action |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Three-engine model, transport, probe isolation, report pipeline |
| [docs/SECURITY.md](docs/SECURITY.md) | Scanner security model; controls against malicious targets |
| [docs/THREAT_CATALOG.md](docs/THREAT_CATALOG.md) | T1–T12 reference; attack patterns; remediation |
| [docs/THREAT_MAPPING.md](docs/THREAT_MAPPING.md) | ISO 27001 / NIST AI RMF / OWASP / SOC 2 / EU AI Act alignment |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | Threat definition JSON schema; adding new probes |
| [docs/architecture-decisions.md](docs/architecture-decisions.md) | Full architecture panel findings (20 Sonnet + 7 Opus) |
| [docs/workplan.md](docs/workplan.md) | Implementation roadmap (P0–P9) |

## Why not the existing tools?

| Tool | Gap |
|------|-----|
| MCP-Bastion | Middleware only; ~2 of 12 categories; no test suite |
| Cisco MCP Scanner | Static analysis only; no runtime enforcement |
| mcp-authx | T1 only |
| OWASP MCP Top 10 | Document; no runnable code |

cosai-mcp covers all 12 categories, provides runnable probes, and is the only open implementation of session-bound identity (RFC 8693 + RFC 9449) and DAG execution trace logging.

## License

Apache 2.0. Contributions welcome — see [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

Target upstream: [`cosai-oasis`](https://github.com/cosai-oasis) as the official reference implementation.
