# Getting Started with cosai-mcp

cosai-mcp scans MCP servers for security vulnerabilities across all 12 CoSAI threat categories. It requires nothing installed on the target — point it at any running MCP server and get a report.

---

## Quickstart: Zero Install

```bash
uvx cosai-mcp scan http://localhost:8000
```

That's it. `uvx` downloads and runs the scanner without a permanent install. You get a report to stdout and exit code `0` (clean) or `1` (findings).

---

## Installation

```bash
pip install cosai-mcp
```

With pytest integration:

```bash
pip install cosai-mcp[pytest]
```

Python 3.11+ required.

---

## Running Your First Scan

```bash
# Scan a local MCP server
cosai-mcp scan http://localhost:8000

# Scan with SARIF report (for GitHub Security tab)
cosai-mcp scan http://localhost:8000 --report sarif --output results.sarif

# Scan with HTML report
cosai-mcp scan http://localhost:8000 --report html --output results.html

# Fail only on critical findings
cosai-mcp scan http://localhost:8000 --fail-on critical

# Scan specific threat categories only
cosai-mcp scan http://localhost:8000 --categories T1,T3,T7

# Show coverage matrix (which engine covers which category)
cosai-mcp scan http://localhost:8000 --report-coverage
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no findings at or above threshold |
| 1 | Findings at or above `--fail-on` threshold |
| 2 | Scanner error — **treated as failure in CI** |
| 3 | Target unreachable |

Exit code `2` is never clean. If the scanner crashes or encounters an internal error, CI fails.

---

## Transports

The scanner detects the right transport automatically based on the server's `initialize` response:

| Transport | When used |
|-----------|-----------|
| Streamable HTTP (MCP 2025-03-26) | Default for all modern MCP servers |
| LegacySSE (MCP 2024-11-05) | Auto-selected when server negotiates `2024-11-05` |
| stdio | Local subprocess servers — requires `--allow-stdio` |

For stdio (local MCP server binary):

```bash
cosai-mcp scan --stdio ./my-mcp-server --allow-stdio
```

---

## Pytest Integration

Add cosai-mcp probes to your existing pytest suite:

```bash
pip install cosai-mcp[pytest]
pytest --cosai-target=http://localhost:8000
```

Filter by severity:

```bash
pytest --cosai-target=http://localhost:8000 --cosai-severity=critical
```

Filter by category:

```bash
pytest --cosai-target=http://localhost:8000 --cosai-categories=T1,T3,T8
```

Findings appear inline with your existing test results. Critical findings cause the suite to fail.

---

## Python API

```python
from cosai_mcp import Scanner, ScanConfig

config = ScanConfig(
    target="http://localhost:8000",
    categories=["T1", "T3", "T7"],
    fail_on="critical",
)

results = Scanner(config).run()

for finding in results.findings:
    print(f"{finding.severity} [{finding.category}] {finding.title}")
    print(f"  Probe: {finding.probe_id}")
    print(f"  Remediation: {finding.remediation}")

print(f"Exit code: {results.exit_code}")
```

---

## GitHub Actions CI Gate

Add to your workflow to block PRs on critical MCP security findings:

```yaml
name: MCP Security Scan

on: [pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  mcp-security:
    runs-on: ubuntu-latest
    steps:
      - name: Start your MCP server
        run: ./start-mcp-server.sh &

      - name: Run cosai-mcp scan
        uses: cosai-mcp/scan-action@<commit-sha>
        with:
          target: http://localhost:8000
          fail_on: critical
          report: sarif

      - name: Upload to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: cosai-scan.sarif
```

Use a commit SHA for the Action, not a tag. Tags are mutable.

---

## Docker

```bash
docker run ghcr.io/cosai-mcp/scanner http://host.docker.internal:8000
```

Docker mode adds network isolation — the scanner cannot reach any host except the explicit target. This provides the strongest SSRF protection.

```bash
# With SARIF output
docker run -v $(pwd)/output:/output \
  ghcr.io/cosai-mcp/scanner \
  http://host.docker.internal:8000 \
  --report sarif --output /output/results.sarif
```

---

## Understanding the Report

### Coverage matrix

The report includes a coverage matrix showing which engine covered each threat category:

| Category | Engine | Coverage |
|----------|--------|----------|
| T1: Authentication | Black-box prober | Full |
| T2: Access Control | Stateful harness | Full |
| T3: Input Validation | Black-box prober | Full |
| T4: Data/Control Boundary | Middleware only | Requires middleware deployment |
| T5: Data Protection | Middleware only | Requires middleware deployment |
| T6: Integrity | Stateful harness | Full |
| T7: Session Security | Stateful harness | Full |
| T8: Network Binding | Black-box prober | Full |
| T9: Trust Boundaries | Middleware only | Requires middleware deployment |
| T10: Resource Management | Black-box prober | Full |
| T11: Supply Chain | Black-box prober (partial) | Partial — static analysis only |
| T12: Logging | Middleware only | Requires middleware deployment |

**T4, T9, T12** require the target server to have the cosai-mcp middleware installed. A black-box scanner cannot observe what flows through the LLM's reasoning loop.

### Finding severities

| Severity | Meaning |
|----------|---------|
| `critical` | Directly exploitable; immediate remediation required |
| `high` | High likelihood of exploitation in realistic conditions |
| `medium` | Exploitable under specific conditions |
| `low` | Defense-in-depth gap; lower exploitability |
| `info` | Deviation from best practice; not directly exploitable |

### Partial scans

If the scanner could not connect, crashed, or was interrupted, the report is marked `scan-incomplete`. This is distinct from `clean`. A `scan-incomplete` result does not mean the server is secure — it means the scan did not finish.

---

## Using the Middleware (T4, T9, T12)

For T4 (indirect prompt injection), T9 (LLM trust boundaries), and T12 (execution traces), deploy the middleware in your MCP server. The middleware IS the detection mechanism for these categories.

### FastAPI / FastMCP

```python
from cosai_mcp.middleware import CoSAIStack, CoSAIConfig

app.add_middleware(CoSAIStack, config=CoSAIConfig(
    # T1: Session-bound identity
    session_binding=True,
    dpop_required=True,

    # T2: Per-tool authorization
    tool_allowlist=["read_file", "search_db", "send_email"],
    confused_deputy_prevention=True,

    # T4: Data/control boundary
    prompt_injection_detection=True,

    # T10: Resource budgets
    execution_budget_seconds=30,
    max_tool_calls_per_session=100,

    # T12: Execution traces
    audit_log_path="/var/log/cosai/traces",
    audit_chain_verify=True,
))
```

With middleware deployed, run the scan again — T4, T9, T12 findings will now be detectable.

---

## Verifying Reports

Verify a signed report has not been tampered with:

```bash
cosai-mcp audit verify results.sarif
```

Verify the audit log chain:

```bash
cosai-mcp audit verify /var/log/cosai/traces/audit.log
```

Output:
```
✓ Report signature: VALID
✓ Catalog hash: matches scan record
✓ Audit chain: 1,247 entries, chain INTACT
  Signed: 2026-04-26T14:32:01Z
  Public key fingerprint: ed25519:abc123...
```

---

## Custom Threat Definitions

Add your own threat definitions without changing code:

```bash
# Enable custom catalog support
cosai-mcp scan http://localhost:8000 \
  --allow-custom-catalog \
  --custom-catalog-path ./my-org-threats/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the threat definition JSON schema and how to write effective probes.

---

## Troubleshooting

**`scan-incomplete`: handshake failed**
The target did not complete the MCP `initialize`/`initialized` lifecycle. This is itself a T1/T7 finding if the server is supposed to be MCP-compliant.

**Exit code 2: scanner error**
An internal error occurred. Run with `--debug` for the full traceback. This is always treated as a failure in CI — it never produces a clean result.

**All T4/T9/T12 findings show `middleware-only`**
These categories require cosai-mcp middleware deployed in the target server. Deploy `CoSAIStack` and re-run the scan.

**Custom catalog not loading**
Custom catalogs require `--allow-custom-catalog`. If your custom catalog uses `matches_regex`, also add `--allow-regex-in-custom`.

**`UnsafePatternError` on custom catalog**
A `matches_regex` pattern in your catalog was rejected by RE2 (likely catastrophic backtracking potential). Simplify the pattern or use `contains` instead.
