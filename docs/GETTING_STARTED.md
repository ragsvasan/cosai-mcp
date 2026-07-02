# Getting Started with cosai-mcp

cosai scans MCP servers for security vulnerabilities across T1–T12 via three engines (9 categories zero-config, 3 via middleware deployment). Black-box probing requires nothing on the target; middleware coverage requires deploying cosai_mcp/middleware/ — point it at any running MCP server and get a report.

---

## Quickstart

```bash
# Install from source (interim — package not yet on PyPI)
git clone https://github.com/ragsvasan/cosai-mcp && cd cosai-mcp && pip install -e .

# Scan a local server (loopback/RFC1918 targets allowed by default;
# use --block-private-targets in CI to enforce a public-only policy)
cosai scan http://localhost:8000

# After the 0.1.0 PyPI release — not yet published:
#   uvx --from cosai-mcp cosai scan http://localhost:8000
#   pip install cosai-mcp
```

You get a report to stdout and exit code `0` (clean) or `1` (findings).

---

## Installation

Until the 0.1.0 PyPI release, install from source:

```bash
git clone https://github.com/ragsvasan/cosai-mcp && cd cosai-mcp && pip install -e .
```

With pytest integration (from source):

```bash
pip install -e ".[pytest]"
```

Python 3.11+ required.

After the 0.1.0 PyPI release (not yet published), `pip install cosai-mcp` and
`pip install cosai-mcp[pytest]` will work directly.

---

## Running Your First Scan

```bash
# Scan a local MCP server (loopback/RFC1918 targets allowed by default;
# use --block-private-targets to enforce a public-only policy)
cosai scan http://localhost:8000

# Scan with SARIF report (for GitHub Security tab)
cosai scan http://localhost:8000 --report-sarif results.sarif

# Scan with HTML report
cosai scan http://localhost:8000 --report-html results.html

# Fail only on critical findings
cosai scan http://localhost:8000 --fail-on critical

# Scan specific threat categories only
cosai scan http://localhost:8000 --categories T1,T3,T7

# T5: widen the secret/PII manifest scan to the broad-PII tier
# (SSN, IBAN, US phone, Luhn-validated PAN) on top of the always-on
# anchored-credential tier (AWS/GCP/Azure/GitHub/GitLab/Google/JWT)
cosai scan http://localhost:8000 --pii-strict

# T11: supply-chain check — flag discovered tools not on the approved
# allowlist, or within one edit of an approved name (typosquat).
# Without this flag, T11 is reported INCONCLUSIVE (not clean).
cosai scan http://localhost:8000 --tool-allowlist search,read_file,deploy

# Show coverage matrix (which engine covers which category)
cosai scan http://localhost:8000 --report-coverage
```

---

## Scanning a Fleet of Servers

For more than one MCP server, `--targets` scans them all with bounded
concurrency and emits **one** aggregated result instead of N separate
invocations you'd otherwise have to hand-merge:

```bash
# fleet-targets.txt — one URL per line, blank lines and '#' comments ignored
cat > fleet-targets.txt <<EOF
http://server1.internal:8000
http://server2.internal:8000
http://server3.internal:8000
EOF

cosai scan --targets fleet-targets.txt \
  --report-sarif fleet.sarif \
  --scorecard fleet-scorecard.json \
  --fleet-concurrency 10
```

This produces one merged SARIF report (one run per target — GitHub renders
multi-run SARIF natively), one aggregated scorecard JSON listing every
target's outcome and signed per-target scorecard, and a single process exit
code that is the *worst* outcome across the fleet (a scanner error on any
target outranks a real finding, which outranks one target simply being
unreachable — so a proven vulnerability on server B is never masked just
because server A was down). A target that hangs is recorded as timed out
(`--fleet-target-timeout`, default 600s) rather than blocking the whole run.

Flags with per-server semantics (`--profile`, `--adversarial`, `--baseline`,
`--method-overrides`) aren't supported with `--targets` — scan those targets
individually. Flags that apply uniformly across a fleet (`--auth-token`,
`--read-token`, `--mcp-path`, `--tool-allowlist`, `--pii-strict`,
`--expected-catalog-hash`, etc.) work as expected.

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

**Pinning the catalog for a reproducible gate.** A release gate whose
ruleset can drift between the PR run and the merge run isn't a control.
Pin it with `--expected-catalog-hash`:

```bash
# Once: capture the hash of the catalog you're reviewing/shipping
cosai scan http://localhost:8000 --no-report | grep "Catalog hash"

# In CI: refuse to scan (exit 2) if the loaded catalog has changed
cosai scan http://localhost:8000 --expected-catalog-hash "$COSAI_CATALOG_SHA"
```

The reusable `cosai-gate.yml` workflow (`.github/workflows/cosai-gate.yml`)
exposes this as an `expected_catalog_hash` input.

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

Some servers enforce per-session call budgets (e.g. one new MCP session per second). Because each probe spawns a fresh subprocess connection, rapid probing can trigger these limits, producing infrastructure errors that look like scanner failures. Use `--probe-delay` to add a sleep between probes:

```bash
cosai scan http://localhost:8080 --auth-token "$TOKEN" --probe-delay 2.5
```

A delay of 1–3 seconds is usually sufficient. Start at 1 second and increase if you still see rate-limit errors in `--debug` output.

**Via the Python API:**

```python
results = Scanner(
    "http://localhost:8080",
    auth_token="...",
    probe_delay_seconds=2.5,
).run()
```

**Custom MCP endpoint path:**

If your server mounts MCP at a non-standard path (default is `/mcp`):

```bash
cosai scan http://localhost:8080 --mcp-path /v1/mcp
```

---

## Using the Middleware (T4, T9, T12)

All 12 middleware modules are implemented and composable via `CoSAIStack`. For T4 (indirect prompt injection), T9 (LLM trust boundaries), and T12 (execution traces), deploy the middleware in your MCP server — the middleware IS the detection mechanism for these categories.

### FastAPI / FastMCP

```python
from cosai_mcp.middleware import CoSAIStack
from cosai_mcp.middleware.authz import AuthzEnforcer, ToolPolicy
from cosai_mcp.middleware.supply_chain import SupplyChainEnforcer
from cosai_mcp.middleware.session import SessionManager
from cosai_mcp.middleware.audit import AuditLogger

# Build the stack
stack = CoSAIStack(
    # T11: allowlist + typosquat prevention + Ed25519 registry signatures
    supply_chain_enforcer=SupplyChainEnforcer(
        allowlist=frozenset(["read_file", "search_db", "send_email"]),
    ),

    # T2: per-tool RBAC + confused deputy prevention
    authz_enforcer=AuthzEnforcer(),

    # T7: JWT validation (alg-pinned, JTI replay cache) + DPoP proof verification
    session_manager=SessionManager(
        expected_issuer="https://auth.example.com",
        expected_audience="mcp-server",
    ),

    # T12: append-only hash-chained audit log
    audit_logger=AuditLogger("/var/log/cosai/traces/audit.jsonl"),
)

# At startup — after tools/list (T11 + T4 tool-poisoning scan)
stack.check_manifest(tools, session_id=session_id)

# On every tools/call (T3 → T2 → T7 → T12)
stack.check_tool_call(
    tool_name=request.tool_name,
    arguments=request.arguments,
    authz_context=build_authz_context(request),
    session_id=session_id,
    jwt_token=request.headers.get("Authorization", "").removeprefix("Bearer "),
    jwt_keyset=keyset,
)

# After tool returns (T4/T9 response boundary scan)
stack.check_response(response_body, session_id=session_id)
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

### Sigstore/Fulcio keyless signer identity

The default scorecard signature (Ed25519) is verified against a trust anchor
baked into the release — it proves the scorecard wasn't tampered with, but
not *which organization* produced it. Sigstore signing adds an **additional**
signature bound to an OIDC identity, so a verifier can pin "this exact CI
workflow, this exact repo" instead of trusting any holder of the signing key.

Requires the optional `sigstore` extra and a real ambient OIDC identity token
— it only works from an environment that provides one (GitHub Actions with
`permissions: id-token: write`, GitLab CI, or an interactive OIDC login):

```bash
pip install cosai-mcp[sigstore]

cosai scan http://localhost:8000 \
  --scorecard scorecard.json \
  --sigstore-sign
# → writes scorecard.json (Ed25519-signed, as before) and
#   scorecard.json.sigstore.json (the Sigstore bundle)
```

Verify against the identity you expect signed it — `--trusted-identity` is
required; a bundle without a pinned identity proves nothing about who signed
it, so this is rejected rather than silently skipped:

```bash
cosai scorecard verify scorecard.json \
  --sigstore-bundle scorecard.json.sigstore.json \
  --trusted-identity "https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main" \
  --trusted-issuer "https://token.actions.githubusercontent.com"
```

`--sigstore-bundle`/`--trusted-identity`/`--trusted-issuer` also work on
`cosai scorecard show`, independent of `--verify` (which governs only the
Ed25519 check). Use `--sigstore-staging` on either side to test against
Sigstore's public staging instance instead of production. Not yet supported
in fleet mode (`--targets`) — sign each target's scorecard individually.

Key rotation is not applicable — this is a keyless mechanism, so there's no
long-lived private key to rotate. The operational equivalent is *trust-policy*
rotation: update which `--trusted-identity`/`--trusted-issuer` a verifier
accepts (e.g. when a CI workflow moves to a new repository).

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

## Publishing (maintainers)

Releases go to PyPI via `.github/workflows/publish.yml` using **Trusted
Publishing** (OIDC) — no PyPI API token is ever stored as a GitHub secret.
This requires a one-time setup on PyPI's side before the first release.

### One-time setup

On [pypi.org](https://pypi.org) (and separately on
[test.pypi.org](https://test.pypi.org) for the dry-run path), for the
`cosai-mcp` project, add a Trusted Publisher with:

| Field | Value |
|---|---|
| Owner | `ragsvasan` |
| Repository name | `cosai-mcp` |
| Workflow filename | `publish.yml` |
| Environment name | `pypi` (or `testpypi` on test.pypi.org) |

If the `cosai-mcp` project doesn't exist on PyPI yet, use "Publish a new
project" via Trusted Publishing — it reserves the name and links the
publisher in the same step, no separate manual upload needed first.

The `pypi` / `testpypi` GitHub Environments referenced above are
auto-created on first workflow run if they don't already exist; add
protection rules (e.g. required reviewers) under repo Settings →
Environments for an extra gate on real publishes, if desired.

### Dry run (recommended before the first real release)

Validate the entire pipeline — build, OIDC handshake, upload — against
TestPyPI without touching the real index:

Actions tab → **Publish to PyPI** → **Run workflow** → target: `testpypi`.

Then verify: `pip install --index-url https://test.pypi.org/simple/ cosai-mcp`.

### Real release

Publishing only happens on an explicit trigger — never on a routine push:

1. Bump `version` in `pyproject.toml` if this isn't the first release.
2. Create a GitHub Release (tag `vX.Y.Z`) — this is what triggers
   `publish-pypi`. (Or Actions tab → **Publish to PyPI** → **Run workflow**
   → target: `pypi`, for a re-run without cutting a new release.)
3. Once it completes, `pip install cosai-mcp` resolves the just-published
   version. Update the "not yet on PyPI" language in this file and
   README.md to the real install command.

---

## Troubleshooting

**`scan-incomplete`: handshake failed**
The target did not complete the MCP `initialize`/`initialized` lifecycle. This is itself a T1/T7 finding if the server is supposed to be MCP-compliant.

**Exit code 2: scanner error**
An internal error occurred. Run with `--debug` for the full traceback. This is always treated as a failure in CI — it never produces a clean result.

**All T4/T9/T12 findings show `middleware-only`**
These categories require cosai-mcp middleware deployed in the target server. Deploy `CoSAIStack` (see the middleware section above) — it provides detection for T4, T9, and T12 from inside the call path.

**Custom catalog not loading**
Custom catalogs require `--allow-custom-catalog`. If your custom catalog uses `matches_regex`, also add `--allow-regex-in-custom`.

**`UnsafePatternError` on custom catalog**
A `matches_regex` pattern in your catalog was rejected by RE2 (likely catastrophic backtracking potential). Simplify the pattern or use `contains` instead.

**Rate-limit errors in probe output (e.g. "429", "too many requests", "session limit")**
The target server is rejecting probe connections because they arrive too quickly. Add `--probe-delay 2.5` (or higher) to the scan command. This does not affect result accuracy — each probe still gets a fresh, isolated connection; there are just longer gaps between them.

**T2 probes marked INCONCLUSIVE after synthesis**
T2 (confused-deputy) probes intentionally use adversarial parameter names (e.g. `session_id`, `role`) that the server will reject. This INCONCLUSIVE result is expected — it means the server enforced its schema and rejected unknown parameters. Synthesis is deliberately suppressed for T2 to avoid replacing those adversarial names with the server's real parameters (which would produce a false positive by turning the security probe into a functional test call).
