# Contributing to cosai-mcp

## Ways to contribute

1. **New threat definitions** — add a JSON file to `catalog/official/` (requires PR + maintainer signing)
2. **Probe improvements** — improve coverage or reduce false positives in existing probes
3. **Bug fixes** — fix scanner, middleware, or report issues
4. **Documentation** — improve docs, add examples

---

## Adding a New Threat Definition

This is how the community extends coverage when new MCP attack vectors are discovered.

### 1. Write the JSON definition

Create `catalog/official/<category>-<sequence>.json`. Example structure:

```json
{
  "schema_version": "1.0",
  "id": "T03-007",
  "category": "T3",
  "name": "unicode_normalization_bypass",
  "title": "Path traversal via Unicode normalization",
  "description": "Unicode-encoded path separators (%2e%2e%2f) may bypass naive string validation before normalization, allowing path traversal in file tools.",
  "severity": "high",
  "cosai_ref": "T3",
  "owasp_ref": "MCP-Top10-A03",
  "cwe": ["CWE-22"],
  "probes": [
    {
      "id": "T03-007-p1",
      "transport": "http",
      "method": "tools/call",
      "description": "Unicode-encoded path traversal in file path argument",
      "payload": {
        "name": "{{tool_name}}",
        "arguments": {
          "path": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        }
      },
      "assertions": [
        {
          "target": "response.error",
          "operator": "eq",
          "value": true,
          "rationale": "Server must reject path traversal regardless of encoding"
        },
        {
          "target": "response.body",
          "operator": "not_contains",
          "value": "root:",
          "rationale": "File contents must not be returned"
        },
        {
          "target": "response.error.code",
          "operator": "error_code_in",
          "value": [-32602, -32600],
          "rationale": "Must return invalid params, not internal error"
        }
      ]
    }
  ],
  "engine": "black-box-prober",
  "remediation": "Normalize and resolve all path arguments to absolute paths before validation. Reject any path that resolves outside the allowed root directory, regardless of encoding used.",
  "references": [
    "https://owasp.org/www-community/attacks/Path_Traversal",
    "https://cosai.org/T3"
  ]
}
```

### Threat definition schema reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | ✓ | Always `"1.0"` |
| `id` | string | ✓ | Format: `T<NN>-<NNN>` (category + sequence) |
| `category` | string | ✓ | `T1` through `T12` |
| `name` | string | ✓ | snake_case identifier |
| `title` | string | ✓ | Human-readable, ≤80 chars |
| `description` | string | ✓ | What the vulnerability is; ≤500 chars |
| `severity` | enum | ✓ | `critical`, `high`, `medium`, `low`, `info` |
| `cosai_ref` | string | ✓ | `T1` through `T12` |
| `owasp_ref` | string | | `MCP-Top10-A01` etc. |
| `cwe` | array of string | | CWE identifiers |
| `probes` | array | ✓ | At least one probe |
| `engine` | enum | ✓ | `black-box-prober`, `stateful-harness`, `middleware` |
| `remediation` | string | ✓ | Concrete fix guidance; ≤1000 chars |
| `references` | array of string | | https:// URLs only |

**Probe fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | ✓ | Format: `<threat-id>-p<N>` |
| `transport` | enum | ✓ | `http`, `stdio`, `any` |
| `method` | string | ✓ | MCP method: `tools/call`, `tools/list`, `initialize` |
| `description` | string | | What this probe tests |
| `payload` | object | ✓ | JSON-RPC params (no arbitrary nesting depth > 10) |
| `assertions` | array | ✓ | At least one assertion |

**Assertion operators:**

| Operator | Target types | Description |
|----------|-------------|-------------|
| `eq` | any | Exact equality |
| `ne` | any | Not equal |
| `contains` | string | Substring present |
| `not_contains` | string | Substring absent |
| `matches_regex` | string | RE2-compatible regex (official catalog only) |
| `status_in` | HTTP status array | HTTP status code in list |
| `error_code_in` | integer array | JSON-RPC error code in list |

**Assertion targets:**

| Target | Type | Description |
|--------|------|-------------|
| `response.error` | bool | `true` if response has an error |
| `response.error.code` | integer | JSON-RPC error code |
| `response.error.message` | string | Error message text |
| `response.body` | string | Full response body as string |
| `response.status` | integer | HTTP status code |
| `response.headers.<name>` | string | HTTP response header value |

### 2. Template variables

Probe payloads support a fixed set of template variables. No other substitution is allowed.

| Variable | Value at runtime |
|----------|-----------------|
| `{{target_url}}` | The scanner's target URL |
| `{{session_id}}` | Current MCP session ID |
| `{{tool_name}}` | First tool from `tools/list` that matches the probe's intent |

Template substitution occurs on the parsed Python dict, not on the JSON string. Values containing `{{` after substitution abort the probe.

### 3. What makes a good probe

**Test one thing.** Each probe should test exactly one bypass or attack pattern. Multiple related patterns → multiple probes.

**Use `error_code_in` for injection probes.** A server that responds with `-32603` (Internal error) to an injection payload may have executed the payload and crashed. Assert `-32602` (Invalid params) to confirm the server rejected the input before processing.

**Include a negative assertion.** For data exfiltration risks, always assert `not_contains` on the response body in addition to asserting an error was returned.

**Think about false negatives.** Will the probe pass on a vulnerable server? Write a comment in the PR explaining how you verified this.

**Think about false positives.** Will the probe fail on a correctly implemented server for a reason other than the vulnerability? Rate-limiting probes should allow for 429 responses.

### 4. Write a regression test

Every new threat definition needs a regression test:

```python
# tests/probes/test_t03_validation_probes.py

def test_regression_t03_007_unicode_normalization(mock_mcp_server, scan_config):
    """T03-007: server must reject Unicode-encoded path traversal."""
    mock_mcp_server.configure_tool("read_file", response={
        "content": "root:x:0:0:root:/root:/bin/bash\n..."
    })

    results = Scanner(scan_config).run(categories=["T3"], probes=["T03-007"])

    # Vulnerable server returns file contents → FAIL
    assert results.findings[0].probe_id == "T03-007-p1"
    assert results.findings[0].status == "FAIL"

def test_regression_t03_007_unicode_normalization_patched(mock_mcp_server, scan_config):
    """T03-007: patched server rejects with -32602."""
    mock_mcp_server.configure_tool("read_file", error={
        "code": -32602,
        "message": "Invalid path"
    })

    results = Scanner(scan_config).run(categories=["T3"], probes=["T03-007"])
    assert results.findings[0].status == "PASS"
```

### 5. Submit a PR

1. Fork the repository
2. Create branch: `threat/T03-007-unicode-normalization`
3. Add the JSON file + regression test
4. Run the test suite: `pytest tests/ -v`
5. Open a PR with:
   - Description of the vulnerability and how you discovered it
   - Evidence that the probe correctly detects vulnerable servers
   - Evidence that the probe passes on correctly implemented servers

Maintainers review the definition, validate the probe logic, and sign the JSON file with the project Ed25519 key before merging. You do not need to sign it yourself.

---

## Severity Classification

Use this guide consistently:

| Severity | Criteria | Examples |
|----------|----------|---------|
| `critical` | Directly exploitable without prerequisites; high-confidence code execution, data exfiltration, or auth bypass | SQL injection that returns data, unauthenticated tool call accepted |
| `high` | Exploitable in realistic conditions with moderate prerequisites | Session fixation, confused deputy with known tool names |
| `medium` | Exploitable under specific conditions; requires attacker in a specific position | Tool shadowing requiring mid-session timing, partial path traversal |
| `low` | Defense-in-depth gap; low exploitability but deviates from best practice | Missing rate limiting on read-only tools, verbose error messages |
| `info` | Best practice deviation; not directly exploitable | No heartbeat on long-running operations, non-standard error codes |

When uncertain between two levels, choose the higher one.

---

## Code Contributions

### Setup

```bash
git clone https://github.com/cosai-mcp/cosai-mcp
cd cosai-mcp
pip install -e ".[dev]"
```

### Running tests

```bash
# Full suite
pytest tests/ -v

# Specific module
pytest tests/catalog/ -v

# With coverage
pytest tests/ --cov=cosai_mcp --cov-report=term-missing
```

### Code review gate

Per project rules (see `CLAUDE.md`): every code change follows `code → tests → review → fix → tests → (repeat) → commit`. All PRs require passing tests. Security-critical changes (transport, catalog, harness, report) require a T1 Full panel review by maintainers.

### Mock discipline

All tests that mock external calls use `unittest.mock.create_autospec(real_fn, return_value=...)`. Never bare `MagicMock` or lambdas. This ensures signature drift is caught in tests, not in production.

### Adding a regression test

Every bug fix must include a test named `test_regression_<description>` that would have caught the original bug.

---

## Security Vulnerability Reporting

**Do not open public issues for security vulnerabilities.** Use GitHub's private Security Advisory feature. Response SLA: acknowledgement within 48 hours, initial assessment within 7 days.
