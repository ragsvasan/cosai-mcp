# cosai-mcp P10–P13 — New Session Context

## What this is

Context doc for the next implementation session. Covers the four phases added to workplan.md
after the Mnemo live scan (2026-04-27). Read workplan.md P10/P11/P12 for the full spec.

---

## Why these phases exist

**Live scan result against Mnemo (2026-04-27):**
- 11 PASS
- 14 INCONCLUSIVE (schema mismatch — scanner's generic params didn't match server's tool schema)
- 2 HIGH findings (T11: unknown tool returns isError:false instead of JSON-RPC -32601)
- 0 false positives (after P10 false-positive fixes landed in this session)

The 14 INCONCLUSIVE results are honest (not bugs), but they represent wasted scan capacity.
The scanner knew the vulnerability pattern but couldn't reach the security logic to test it because
the probe payload said `{"cmd": "..."}` and the server expected `{"query": "..."}`.

P10 fixes this. P11 reduces setup friction. P12 makes findings actionable.

---

## Scan command (working as of 2026-04-27)

```bash
cd ~/CoSAI
MNEMO_TOKEN=$(cat ~/.mnemo/mcp_token)
python -m cosai_mcp.cli scan http://localhost:8080 \
  --allow-private-targets \
  --auth-token "$MNEMO_TOKEN" \
  --mcp-path "/mcp/" \
  --report-html cosai-mnemo-report.html \
  --report-csv cosai-mnemo-report.csv
```

Token is a `mnemo_` prefixed opaque token in `~/.mnemo/mcp_token`. Created in `api_tokens` table
(not `mcp_tokens` — that table is a dead end; `get_user_by_token` queries `api_tokens`).

Mnemo runs on **port 8080** (not 8000). MCP endpoint is `/mcp/` (trailing slash — redirects
without it). Both the backend (`uvicorn backend.main:app --port 8000`) and the MCP wrapper
(`uvicorn mnemo_mcp.http_app:app --port 8080`) must be running.

---

## Repo state entering P10

Branch: `main`. All 576 tests passing. Recent commits:
- `c5e25cf` — fix(false-positives): INCONCLUSIVE status + MCP content-layer error normalization
- `a4efe24` — feat(report): Mnemo-themed HTML report + CSV export
- `3d2b870` — docs: add auth-protected server scanning guide

**Key files:**
- `cosai_mcp/harness/context.py` — INCONCLUSIVE detection via `_SCHEMA_MISMATCH_KEYWORDS`
- `cosai_mcp/harness/assertions.py` — `response.error` normalizes both JSON-RPC + MCP content-layer errors
- `cosai_mcp/stateful/harness.py` — tool-manifest check before running scenarios
- `cosai_mcp/report/html.py` — Mnemo dark theme, INCONCLUSIVE badge
- `cosai_mcp/report/csv_report.py` — Excel-compatible CSV export
- `cosai_mcp/api.py` — `_run_scan()`, `Scanner` class, exit code gate
- `cosai_mcp/cli.py` — `cosai scan` CLI, `--report-html`, `--report-csv`, `--no-report`

---

## P10: Adaptive Probes — what to build

### New files
- `cosai_mcp/discovery.py` — `DiscoveredTool` dataclass + `discover_tools(target_url, config)`
- `cosai_mcp/synthesis.py` — `synthesize_probe_payload(tool, threat_pattern, catalog_payload)`

### Changed files
- `cosai_mcp/harness/context.py` — `execute_probe()` receives optional `DiscoveredTool`; retries on schema mismatch
- `cosai_mcp/api.py` — calls `discover_tools()` once before prober loop; passes to `ProbeRunner`
- `cosai_mcp/harness/runner.py` — `run_probe()` gains `discovered_tool` kwarg
- `cosai_mcp/cli.py` — `--no-adaptive` flag

### Critical constraints
- Synthesis is PURE (no I/O, no subprocess). Done in parent process before fork.
- Schemas larger than 64 KB are silently skipped (schema bombing protection).
- No `{{` allowed in synthesized payload after substitution (template escape guard — ValueError).
- Retry is ONE attempt only. Second schema mismatch → INCONCLUSIVE with `synthesis_attempted=True`.
- `--no-adaptive` flag disables all synthesis; must produce identical results to current behavior.

### Success metric
INCONCLUSIVE count on Mnemo scan drops from 14 to ≤ 3 after P10.

---

## P11: Server Profiles — what to build

### New files
- `cosai_mcp/profiles/__init__.py` — `ServerProfile` frozen dataclass
- `cosai_mcp/profiles/builtin.py` — `fastmcp`, `mnemo`, `openai-plugin`, `generic-auth`, `generic-noauth`

### New CLI commands
- `cosai profile list` — list all profiles
- `cosai profile info <name>` — show full detail
- `cosai profile validate <path>` — validate user-written profile

### Critical constraints
- User profiles loaded via `ast.literal_eval`, not `exec`/`eval`. No function execution.
- `--allow-custom-profiles` required for `.cosai/profiles/` files (off by default).
- Profile name lookup is EXACT only — no fuzzy matching (typosquatting risk).
- `mnemo` profile: `tool_name_map = {"admin_delete": "purge_records", "read_file": "search_memories", "echo": "ping"}`

---

## P12: Remediation-First Report — what to build

### New files
- `cosai_mcp/report/remediation.py` — `RemediationBlock` dataclass + static registry for T01–T11

### Changed files
- `cosai_mcp/report/html.py` — add Remediation tab per finding; "WHAT WE SENT / GOT / SPEC REQUIRES / FIX SHAPE / VERIFY"
- `cosai_mcp/report/csv_report.py` — add `remediation_spec_ref`, `remediation_fix_shape` columns
- `cosai_mcp/cli.py` — `--report-mode full|developer|executive|ci` flag

### Critical constraints
- "WHAT WE GOT" (actual server response) MUST be HTML-escaped before insertion into report.
  This is already done at ingestion in `result.py` via `_html_escape()`. Verify the pipeline
  carries through to the new remediation tab.
- Remediation content is STATIC — no LLM generation at report time.
- Missing remediation silently omits the tab. Never crashes.

---

## Locked architecture (do not re-litigate)

- Each probe runs in its own `multiprocessing.Process` — OS-level isolation
- No shared memory between probes
- Results as JSON-serialized frozen dataclasses via `Queue`
- Subprocess creates its own transport + session
- `ScanConfig.auth_token` flows through IPC via pickle (confirmed working)
- `response.error` normalizes both `{"error":{...}}` and `{"result":{"isError":true}}`
- INCONCLUSIVE is not a finding and does not trigger exit code 1

---

## Panel requirements for this session

P10 is T1 Full panel (new network call path + synthesis touches probe isolation boundary).
P11 is T2 Sonnet (profile file loading touches user-supplied input).
P12 is T2 Sonnet (report rendering touches sanitized probe response — XSS risk in new sections).

All panels include: "Is this the industry-standard approach for this problem class? Name the standard. Would this pass a SOC 2 / penetration test review?"

Adversary panel (P10 only) must include: "Can a malicious MCP server's inputSchema trigger unsafe behavior in the synthesizer? Can schema bombing exhaust memory before the 64 KB guard?"

---

## P13: Adversarial Probes — what to build

### The guardrail contract (non-negotiable)

Adversarial probes demonstrate exploitability to the server *owner*. They never extract real
data, never exfiltrate to external endpoints, never persist state. Proof of reachability via
synthetic canary values — not actual exploitation. Same contract as a responsible pen test.

### Four misuse scenarios this feature must block

1. Weaponization against non-owned targets (`cosai scan https://victim.com --adversarial`)
2. Payload library extracted and used standalone
3. Canary payload modified to point at an attacker-controlled endpoint
4. Social engineering: "run this scan against your colleague's server"

### Guardrail implementation

**Guardrail 1 — Dual opt-in (blocks 1, 4)**
Two flags required on the same command line:
```bash
cosai scan <target> \
  --adversarial \
  --i-own-this-target "I confirm I am authorized to run adversarial probes against <target>"
```
The declaration string must contain the target hostname verbatim. Checked in `enforcer.py`
before the catalog loads. Embedded in the report. Not a bypass — the full sentence is required.

**Guardrail 2 — Canary-only payloads (blocks 2)**
Per-scan, per-probe unique string: `COSAI_PROBE_{threat_id}_{scan_id[:8]}_{secrets.token_hex(4)}`
Scanner asserts on presence/absence in the server's response. No `wget`, DNS callbacks, or
out-of-band channels. All observation is in-band.

**Guardrail 3 — No external endpoints (blocks 3)**
`enforcer.py` rejects any payload URL whose hostname is not the scan target or localhost.
Runs at catalog load AND at execution time (defense in depth). P10 adaptive synthesis is
also checked before the subprocess is spawned.

**Guardrail 4 — Read-only by default (no state mutation)**
Adversarial catalog entries carry `"mode": "read-only"` or `"mode": "stateful"` (required field).
Stateful probes need a third flag: `--allow-stateful-adversarial`. Default: only read-only.

**Guardrail 5 — Report is separate and marked**
- Separate `--report-adversarial-html <path>` (not included in default `cosai-report.html`)
- Red `ADVERSARIAL SCAN — AUTHORIZED TARGETS ONLY` banner
- Canary values replaced with `[CANARY REDACTED]` in "WHAT WE SENT"
- `<meta name="robots" content="noindex, nofollow">` + `frame-ancestors 'none'`

### New files

- `cosai_mcp/adversarial/__init__.py` — `AdversarialMode` dataclass
- `cosai_mcp/adversarial/enforcer.py` — dual opt-in, external endpoint check, read-only gate
- `cosai_mcp/adversarial/canary.py` — `Canary`, `generate_canary()`, `detect_canary()`
- `catalog/official/adversarial/` — T3-ADV-001, T4-ADV-001, T5-ADV-001, T7-ADV-001, T11-ADV-001
- `cosai_mcp/report/adversarial_html.py` — adversarial report renderer

### Adversarial probes (all read-only except T5)

| ID | Category | What it proves | Mode |
|----|----------|---------------|------|
| T3-ADV-001 | Injection | Canary echoed in response → injection reached output path | read-only |
| T4-ADV-001 | Prompt injection | Canary in subsequent tool call → LLM influenced | read-only |
| T5-ADV-001 | Cross-tenant leak | Canary in session B from session A write | stateful |
| T7-ADV-001 | Session replay | Session A token accepted in session B | read-only |
| T11-ADV-001 | Typosquatting | `tooIs_list` (capital I) accepted as `tools/list` | read-only |

### Critical constraint: ordering

P13 MUST come after P10 (adaptive synthesis is reused for canary injection into real params)
and after P11 (profiles supply tool name mappings needed by T11-ADV-001).

### Panel requirement

T1 Full panel. Adversary prompt must include explicit license:
"Construct the scenario where cosai-mcp's adversarial mode is itself weaponized against a
non-consenting target. Is the dual opt-in sufficient? Can the canary mechanism be repurposed
for actual data exfiltration by a malicious catalog entry? Does this tool pass the
responsible disclosure bar — would Bugcrowd or HackerOne accept reports generated by it?"
