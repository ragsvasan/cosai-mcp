# Getting Started with cosai-mcp

cosai scans MCP servers for security vulnerabilities across all 12 CoSAI threat categories. It requires nothing installed on the target — point it at any running MCP server and get a report.

---

## Quickstart

```bash
# Try without a permanent install
uvx --from cosai-mcp cosai scan http://localhost:8000

# Or install permanently
pip install cosai-mcp
cosai scan http://localhost:8000
```

You get a report to stdout and exit code `0` (clean) or `1` (findings).

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
cosai scan http://localhost:8000

# Scan with SARIF report (for GitHub Security tab)
cosai scan http://localhost:8000 --report sarif --output results.sarif

# Scan with HTML report
cosai scan http://localhost:8000 --report html --output results.html

# Fail only on critical findings
cosai scan http://localhost:8000 --fail-on critical

# Scan specific threat categories only
cosai scan http://localhost:8000 --categories T1,T3,T7

# Show coverage matrix (which engine covers which category)
cosai scan http://localhost:8000 --report-coverage
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
cosai scan --stdio ./my-mcp-server --allow-stdio
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

      - name: Run cosai scan
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
| T5: Data Protection | Black-box prober | Full |
| T6: Integrity | Black-box + stateful harness | Full |
| T7: Session Security | Stateful harness | Full |
| T8: Network Binding | Black-box prober | Full |
| T9: Trust Boundaries | Middleware only | Requires middleware deployment |
| T10: Resource Management | Black-box prober | Full |
| T11: Supply Chain | Black-box prober | Full |
| T12: Logging | Middleware + black-box prober | Full (middleware) + T12-002 description transparency |

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

## Scanning Auth-Protected Servers

Most development servers run without authentication — the default scan requires no credentials.

For servers that require a Bearer token even for the MCP handshake (production servers, servers with OAuth2/OIDC), pass a token with `--auth-token`:

```bash
cosai scan http://localhost:8080 --auth-token "your-token-here"
```

Or via environment variable (recommended for CI — avoids token in shell history):

```bash
export COSAI_AUTH_TOKEN="your-token-here"
cosai scan http://localhost:8080
```

**What the token is used for:**
- Session setup (`initialize` + `initialized` + `tools/list`)
- All non-T1 probes (T2–T12)

**What it is NOT used for:**
- T1 (authentication) probes always run without the token — the T1 test IS "does the server reject unauthenticated requests?" A server that requires auth for `initialize` will correctly PASS T1. The scanner strips **both** `--auth-token` and any pre-formatted `Authorization` header before running T1 probes, so a server that only checks `Authorization: Bearer …` is also correctly exercised.

**How to generate a scan token for your server:**

The scanner needs a valid token for session setup. Most auth systems have a service-account or API-key concept:

| Auth system | How to create a scan token |
|-------------|---------------------------|
| OAuth2 / OpenID Connect | Create a service account; issue a long-lived client credential |
| API keys | Generate a read-scope API key in your admin panel |
| JWT (symmetric) | Mint a token with your signing key (add a `scanner` audience claim) |
| Custom | Ask the server for a `/api-keys` or `/tokens` endpoint |

**Rate-limited servers:**

Some servers enforce per-session call budgets (e.g. one new MCP session per second). Because each probe spawns a fresh subprocess connection, rapid probing can trigger these limits. When the server rejects the MCP `initialize` handshake (e.g. `rate_limit_exceeded`), the affected probes are automatically retried with exponential backoff before being marked **INCONCLUSIVE**.

By default the scanner retries up to **2 times** with a **1.5 s × 2^n** backoff (1.5 s, then 3 s). If all attempts fail, the probe is marked INCONCLUSIVE — it appears in the "Inconclusive — Security Property Not Verified" section in the HTML report and is omitted from SARIF output. It is not counted as a security finding.

Tune the retry behaviour with `--max-probe-retries` and `--retry-backoff`:

```bash
# More retries with a longer initial delay for aggressive rate limits
cosai scan http://localhost:8080 --auth-token "$TOKEN" \
  --max-probe-retries 4 --retry-backoff 3.0
```

Combine with `--probe-delay` (sleep between probes) to avoid triggering rate limits in the first place:

```bash
cosai scan http://localhost:8080 --auth-token "$TOKEN" \
  --probe-delay 2.5 --max-probe-retries 3
```

A probe delay of 1–3 seconds is usually sufficient. Start at 1 second and increase if you still see INCONCLUSIVE probes with "MCP handshake" in the reason text.

**Via the Python API:**

```python
results = Scanner(
    "http://localhost:8080",
    auth_token="...",
    probe_delay_seconds=2.5,
    max_probe_retries=3,
    retry_backoff_seconds=2.0,
).run()
```

**Stateful scenarios with server-specific tool names:**

Stateful scenarios (T2, T6, T7) use generic placeholder tool names (`admin_delete`, `read_file`, `echo`). If your server names its tools differently, use `--method-override` to map them:

```bash
cosai scan http://localhost:8080 --engine stateful \
  --method-override admin_delete=execute_task \
  --method-override echo=log_freeform
```

When a scenario is inconclusive due to a missing tool, the report includes the exact `--method-override` flags to add, with the closest available tool name suggested automatically. Via the Python API:

```python
results = Scanner(
    "http://localhost:8080",
    method_overrides={"admin_delete": "execute_task", "echo": "log_freeform"},
).run(categories=["T2"])
```

**Custom MCP endpoint path:**

If your server mounts MCP at a non-standard path (default is `/mcp`):

```bash
cosai scan http://localhost:8080 --mcp-path /v1/mcp
```

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
cosai audit verify results.sarif
```

Verify the audit log chain:

```bash
cosai audit verify /var/log/cosai/traces/audit.log
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
cosai scan http://localhost:8000 \
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

**Many probes show INCONCLUSIVE with "Scanner could not complete MCP handshake"**
The target server is rejecting the `initialize` request (rate limit, session budget, or transient error) before any probe payload is sent. The scanner automatically retries up to 2 times per probe with exponential backoff. If retries are exhausted, the probe is marked INCONCLUSIVE — an infrastructure failure, not a security verdict. To reduce the failure rate: add `--probe-delay 2.5` to slow probe throughput, or increase `--max-probe-retries 4 --retry-backoff 3.0` for servers with stricter rate limits. Re-run once tuned; previously inconclusive probes should produce real PASS or FINDING results.

**Stateful scenarios show INCONCLUSIVE with "tool not present on this server"**
The scenario uses a generic placeholder tool name (e.g. `admin_delete`) that does not exist on your server. The report includes the exact `--method-override` flag with the closest matching real tool name. Add it to your scan command and re-run.

**T2 probes marked INCONCLUSIVE after synthesis**
T2 (confused-deputy) probes intentionally use adversarial parameter names (e.g. `session_id`, `role`) that the server will reject. This INCONCLUSIVE result is expected — it means the server enforced its schema and rejected unknown parameters. Synthesis is deliberately suppressed for T2 to avoid replacing those adversarial names with the server's real parameters (which would produce a false positive by turning the security probe into a functional test call).
