# cosai-mcp — Claude Code Instructions

## Project Purpose
Open-source MCP security framework: exhaustive test suite + composable middleware covering all 12 CoSAI threat categories (T1–T12). Fills the gap no existing tool covers — everything out there is either a document, a narrow point-tool, or a commercial service.

## Origin
Designed in April 2026 based on the CoSAI/OASIS January 2026 whitepaper "Security Taxonomy and Governance Framework for the Model Context Protocol". Architecture decisions are locked (see below) — do not re-litigate without explicit user instruction.

## Landscape (what already exists — do not duplicate)
| Tool | What it does | Why we differ |
|---|---|---|
| MCP-Bastion | Lightweight JSON-RPC middleware | Narrow, no test suite, no session identity |
| Cisco MCP Scanner | YARA + LLM static scan | Scan-only, no runtime enforcement |
| mcp-authx | OAuth 2.1 + PKCE | T1 only |
| OWASP MCP Top 10 / Cheat Sheet | Documents | No runnable code |
| CoSAI CodeGuard | Coding rules | Not MCP-specific |

**Our unique value:** all 12 categories, runnable black-box probes, session-bound identity reference impl, DAG execution trace logger, CI/CD gate.

---

## Locked Architecture Decisions

### 1. Standalone / Headless / Zero-MCP-Dependency
- Talks TO MCP servers, never IS one
- No MCP SDK dependency (SDK vuln cannot compromise scanner)
- Runtime deps: `httpx`, `subprocess`, `websockets`, `google-re2`, `joserfc` (or `PyJWT[crypto]`), `keyring`
- Transports: **Streamable HTTP** (primary, MCP 2025-03-26), stdio, LegacySSE (fallback for 2024-11-05 servers only) — all behind one `Transport` interface
- WebSocket is not in the MCP spec and is not implemented

### 2. JSON-Extensible Threat Catalog
New threats: drop a JSON file. Updated threats: edit JSON. Zero code changes required.

**Catalog layout:**
```
catalog/
  official/          ← Ed25519-signed by project keypair
    T01-auth.json
    T04-tool-poisoning.json
    ...
  custom/            ← user-owned; reports mark as UNTRUSTED
    my-org-threats.json
```

**JSON security model (non-negotiable):**
- No code execution in JSON — only safe string templates with fixed variable allowlist (`{{target_url}}`, `{{session_id}}`, `{{tool_name}}`)
- Template substitution occurs on the **parsed Python dict** (before `json.dumps`), not on the serialized JSON string. Validate that no substituted value contains `{{` after expansion (abort probe with ERROR).
- Every file validated against meta-schema before loading — unknown fields rejected, not ignored
- Ed25519 signatures on official catalog; harness refuses unsigned official files. **Public key hardcoded as bytes literal in `cosai_mcp/keys.py`** (not loaded from disk) + published via Sigstore/PEP 740 attestation. `COSAI_PUBKEY` env var overrides for enterprise key rotation.
- All paths resolved within `catalog/` — absolute paths rejected
- `operator` field is a closed enum: `eq`, `ne`, `contains`, `not_contains`, `matches_regex`, `status_in`, `error_code_in`
- `matches_regex` uses `google-re2` (linear time, no backtracking). All patterns validated at catalog load time — RE2 refusal = `UnsafePatternError`. `matches_regex` disabled in custom catalog files unless `--allow-regex-in-custom` is set.
- **Probe destination is not catalog-controlled.** Target host comes from CLI/scanner config only. Catalog defines payload + assertions only.
- Provenance is derived from **load path** (`catalog/official/` vs `catalog/custom/`), never from a JSON field.
- Custom catalog requires `--allow-custom-catalog` flag (off by default).
- Threat definitions are frozen dataclasses after parse — `tuple`/`MappingProxyType` for all container fields; no mutable containers.

**Threat definition schema:**
```json
{
  "schema_version": "1.0",
  "id": "T04-001",
  "category": "T4",
  "severity": "critical",
  "cosai_ref": "T4",
  "owasp_ref": "MCP-Top10-A04",
  "cwe": ["CWE-74"],
  "probes": [
    {
      "id": "T04-001-p1",
      "transport": "http",
      "method": "tools/call",
      "payload": {
        "name": "{{tool_name}}",
        "arguments": { "cmd": "; cat /etc/passwd" }
      },
      "assertions": [
        { "target": "response.error", "operator": "eq", "value": true },
        { "target": "response.body", "operator": "not_contains", "value": "root:" }
      ]
    }
  ],
  "remediation": "Enforce strict JSON schema on all tool arguments...",
  "references": ["https://cosai.org/T4"]
}
```

### 3. Probe Isolation (harness cannot be weaponized)
- Each probe runs in its own **`multiprocessing.Process`** — OS-level isolation, not coroutine/thread isolation
- Results return as JSON-serialized frozen dataclasses; no shared memory between probes
- Network allowlist enforced at **socket connect time** via custom httpx transport: `target_host` resolved to IP at scan start; any connect to a different IP is rejected (defeats DNS rebinding). `follow_redirects=False` hard-coded. `trust_env=False` (blocks HTTP_PROXY injection). RFC1918, link-local, loopback, IPv6 ULA blocked by default.
- No filesystem writes during scan (read-only catalog access)
- Result objects use `tuple`/`MappingProxyType` for all container fields — no mutable containers in frozen dataclasses
- Timeout enforced per probe via OS (SIGALRM / `multiprocessing` terminate), not Python thread-based timeout
- Probe output sanitized before report write; HTML-escaped **at ingestion** into result object, not at render time
- stdio transport: `shell=False` always, fixed argv (no template substitution into argv/env), `close_fds=True`, minimal filtered env, `start_new_session=True`, stdout/stderr size-capped at 10MB

### 4. Adoption Paths (low-friction ladder)
```bash
# Zero install
uvx cosai-mcp scan http://localhost:8000

# pytest plugin
pip install cosai-mcp[pytest]
pytest --cosai-target=http://localhost:8000 --cosai-severity=critical

# Python API
from cosai_mcp import Scanner
results = Scanner("http://localhost:8000").run(categories=["T1","T4","T7"])

# GitHub Action
uses: cosai-mcp/scan-action@v1
with: { target: ${{ env.MCP_URL }}, fail_on: critical }

# Docker
docker run ghcr.io/cosai-mcp/scanner http://localhost:8000
```

### 5. Report Security
- HTML-escape all captured response content **at ingestion** (not at render time); use `html.escape(quote=True)`
- Never render response bodies as executable content
- SARIF generated via structured builder (never string interpolation). Attacker bytes go in exactly one field: `message.text` (plain text, length-capped, control-char-stripped). `ruleId`, `suppressions`, `partialFingerprints` are scanner-generated only — never derived from response content. Output validated against SARIF 2.1.0 JSON schema before writing. Partial scans set `invocation.executionSuccessful: false`.
- HTML report: `references` rendered as text; URLs allowed only if scheme ∈ {http, https}, with `rel="noopener noreferrer"` + CSP `default-src 'none'`
- Report signed with per-installation key (stored in OS keychain via `keyring`) + scan timestamp + catalog hash; report embeds public key fingerprint for verification
- SARIF output (GitHub renders natively as security findings)

---

## Planned Project Structure
```
cosai_mcp/
  middleware/
    auth.py           # T1: Session-bound identity, dual tokens, DPoP (RFC 9449)
    authz.py          # T2: Confused deputy prevention, per-tool RBAC
    validation.py     # T3: JSON schema strict mode, injection guards
    boundary.py       # T4: Data/control separation, tool poisoning detection
    protection.py     # T5: Context leak prevention, PII scrubbing
    integrity.py      # T6: Tool signature verification, shadowing detection
    session.py        # T7: Cryptographic session binding
    network.py        # T8: Bind address validation, shadow server detection
    trust.py          # T9: LLM output untrusted, sanitize before re-feed
    resources.py      # T10: Heartbeat, budget limits, loop detection
    supply_chain.py   # T11: Tool allowlist, registry signature check
    audit.py          # T12: DAG execution trace, immutable append log
  identity/           # Session-bound identity (RFC 8693 + RFC 9449 DPoP)
  scanner/            # Static tool definition analyzer
  cli.py              # `cosai scan` + `cosai audit`
catalog/
  official/           # Signed threat definitions
  custom/             # User extensions
tests/probes/         # Black-box protocol probes — one file per T category
  conftest.py         # MCP_TARGET_URL fixture
  t01_auth_probes.py
  ...
examples/
  fastapi-mcp/
  fastmcp/
.github/workflows/
  cosai-gate.yml      # Reusable CI action
docs/
  threat-mapping.md   # CoSAI T1–T12 ↔ ISO 27001 ↔ NIST AI RMF
  patterns/
```

---

## Panel Gate — COMPLETE (2026-04-26)

T1 Full panel ran 2026-04-26. CONDITIONAL PASS. Full findings: [docs/architecture-decisions.md](docs/architecture-decisions.md).

**10 P0 blockers incorporated into locked architecture above. Do not implement anything that contradicts them.**

### Three-Engine Architecture (locked — panel mechanism-class verdict)

Black-box probing is structurally wrong for T4, T9, T12. The tool ships three engines:

| Engine | Covers | Mechanism |
|--------|--------|-----------|
| **Black-box prober** | T1, T3, T8, T10 (partial T2/T6/T11) | One-shot JSON-RPC probes |
| **Stateful conformance harness** | T2, T6, T7 | Full `initialize` + multi-turn scripted scenarios |
| **Middleware instrumentation** | T4, T9, T12 | Middleware IS the test — detection requires being in the call path |

README must include a coverage matrix mapping each T category to the engine that covers it. Never claim black-box probe coverage for T4, T9, or T12.

### MCP Session Lifecycle (locked — panel MCP-protocol finding)

Every probe MUST be preceded by:
1. `initialize` request (with `protocolVersion`, accurate `clientInfo`, minimal `capabilities`)
2. `initialized` notification
3. `tools/list` (cache manifest; T3/T4 probes iterate discovered tools)

Scanner that cannot complete handshake reports `scan-incomplete`, NOT `clean`.
Transport autodetection: if server responds with `protocolVersion: "2024-11-05"`, fall back to LegacySSE.

### Exit Codes (locked — fail-closed contract)

| Code | Meaning |
|------|---------|
| 0 | Clean — no findings at or above threshold |
| 1 | Findings at or above `--fail-on` threshold |
| 2 | Scanner internal error — **treated as failure by CI gate** |
| 3 | Target unreachable |

GitHub Action treats exit code 2 as failure regardless of `fail_on`.

---

## Open Source Strategy
- License: Apache 2.0
- Target upstream: `cosai-oasis` GitHub org (contribute as reference implementation)
- Aligns with: OWASP MCP Top 10, CoSAI T1–T12, ISO 27001:2022, NIST AI RMF 2026
- SARIF output enables GitHub native security tab integration

## CoSAI Threat Categories Reference
| ID | Name | Core Risk |
|---|---|---|
| T1 | Improper Authentication | Identity spoofing, OAuth proxying |
| T2 | Missing Access Control | Privilege escalation, multi-tenancy |
| T3 | Input Validation Failures | Command injection, path traversal |
| T4 | Data/Control Boundary | Indirect prompt injection, tool poisoning |
| T5 | Inadequate Data Protection | Exfiltration, context leakage |
| T6 | Integrity/Verification | Supply chain, tool shadowing |
| T7 | Session Security Failures | Session hijacking, MITM |
| T8 | Network Binding Failures | Shadow servers, isolation gaps |
| T9 | Trust Boundary Failures | Overreliance on LLM judgment |
| T10 | Resource Management | Denial of wallet, infinite loops |
| T11 | Supply Chain/Lifecycle | Malicious marketplace skills |
| T12 | Insufficient Logging | Invisible agent activity |
