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
- Runtime deps: `httpx`, `subprocess`, `websockets` only
- Transports: HTTP+SSE, stdio, WebSocket — all behind one `Transport` interface

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
- Every file validated against meta-schema before loading — unknown fields rejected, not ignored
- Ed25519 signatures on official catalog; harness refuses unsigned official files
- All paths resolved within `catalog/` — absolute paths rejected
- `operator` field is a closed enum: `eq`, `ne`, `contains`, `not_contains`, `matches_regex`, `status_in`
- Threat definitions are frozen dataclasses after parse — no mutation

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
- Each probe runs in its own isolated context — no shared state between probes
- Network allowlist: probes connect ONLY to `target_host`; outbound to any other host is blocked and flagged
- No filesystem writes during scan (read-only catalog access)
- Result objects are immutable
- Timeout enforced per probe (T10 defense applied to the harness itself)
- Probe output sanitized before report write (prevents second-order injection from malicious MCP responses)

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
- HTML-escape all captured response content
- Never render response bodies as executable content
- Sign report with scan timestamp + catalog hash
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

## Panel Gate — Mandatory Before First Commit

Architecture has NOT yet had its panel review. Run before any implementation:

**T1 Full panel (new security-critical architecture):**
1. Correctness + Security + MCP Protocol — Sonnet, parallel
2. Adversary — Opus, **separate pass**, explicit license: "the current design may be the wrong mechanism class entirely. Construct the failure scenario that compromises the scanner itself."

Panel prompt must include:
> "Is this the industry-standard approach for this problem class? Name the standard. Would this pass a SOC 2 / penetration test review?"

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
