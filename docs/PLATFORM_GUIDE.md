# cosai-mcp Platform Guide — End-to-End MCP Security Operations

*This document covers the full operational pipeline introduced in cosai-mcp v0.2+.
For the baseline scanner documentation, see [README.md](../README.md).*

---

## The Shift: From Scanner to Platform

The original cosai-mcp ships one capability: **runtime conformance scanning**. Point it at a running MCP server and get a SARIF report. That is still the core.

With the additions in v0.2+, cosai-mcp covers the full security operations lifecycle for MCP servers — not just detection, but inventory, real-time SIEM feed, automated incident response, and signed compliance attestation. Together these four capabilities form a complete operational loop:

```
┌──────────────────────────────────────────────────────────────────────┐
│                  MCP Security Operations Loop                        │
│                                                                      │
│  ①  VISIBILITY      cosai inventory capture                          │
│     Track A         Know exactly what tools a server exposes.        │
│                     Detect drift between deploys.                    │
│                                    │                                 │
│                                    ▼                                 │
│  ②  DETECTION       cosai scan                                       │
│     Baseline        Probe all 12 CoSAI categories. SARIF to GitHub.  │
│                                    │                                 │
│                                    ▼                                 │
│  ③  STREAMING       cosai scan --emit-to                             │
│     Track B         Stream every probe result as OCSF Detection      │
│                     Finding (class_uid 2004) to your SIEM/SOAR.     │
│                     Anomaly rules fire on rate spikes and bursts.    │
│                                    │                                 │
│                                    ▼                                 │
│  ④  RESPONSE        cosai scan --contain-on-anomaly                  │
│     Track D         On anomaly: emit OCSF Security Incident (2001)   │
│                     → auto-quarantine report → firewall commands.   │
│                     Human-in-the-loop gate for destructive actions.  │
│                                    │                                 │
│                                    ▼                                 │
│  ⑤  ATTESTATION     cosai scan --scorecard                           │
│     Track E         Signed, per-category conformance grade for       │
│                     every scan. Machine-verifiable by auditors.      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Audience Map

| Role | What they care about | Entry point |
|------|---------------------|-------------|
| **Security engineer** | CI gate, SARIF findings, remediation steps | `cosai scan` |
| **SOC analyst** | SIEM feed, anomaly alerts, incident tickets | `--emit-to`, `--contain-on-anomaly` |
| **Platform/DevSecOps** | Inventory drift alerts on every deploy | `cosai inventory capture/diff` |
| **CISO / auditor** | Signed conformance evidence across all categories | `--scorecard`, `cosai scorecard verify` |
| **MCP server author** | Integrated test suite, coverage per category | `pytest --cosai-target=...` |

---

## Track A — Tool Inventory & Drift Detection

### What it does

Captures a signed snapshot of every tool a server exposes — name, description, and input schema — and computes a content-addressed hash of the manifest. Subsequent snapshots can be diffed to detect additions, removals, or silent schema changes between deploys.

### Why it matters

Tool poisoning (T6) and supply-chain attacks (T11) often arrive as a single tool description change — a parameter renamed, a schema field added — that is invisible to code review if the change is in a JSON manifest or a dependency. Inventory drift detection makes these changes auditable and blocker-eligible in CI.

### Usage

```bash
# Capture a signed snapshot
cosai inventory capture http://localhost:8000 -o baseline.json

# Re-capture after a deploy
cosai inventory capture http://localhost:8000 -o current.json

# Diff — exits 1 if any drift detected (CI gate)
cosai inventory diff baseline.json current.json --fail-on-drift

# Verify a snapshot's Ed25519 signature
cosai inventory verify baseline.json
```

### What drift looks like

```
[DRIFT] T-added     new_tool_name        (added to server manifest)
[DRIFT] T-removed   old_tool             (removed from server manifest)
[DRIFT] T-schema    existing_tool        (input_schema changed)
[DRIFT] T-desc      existing_tool        (description changed)
```

### Trust model

Snapshots are signed with the per-installation Ed25519 key (stored in OS keychain). Cross-machine verification uses `COSAI_INVENTORY_PUBKEY` (base64-encoded public key). The scanner refuses to accept re-signed snapshots from a different key without the env var override.

---

## Track B — OCSF Telemetry to SIEM/SOAR

### What it does

After every scan, each probe result is serialised as an [OCSF Detection Finding](https://schema.ocsf.io/2.0.0/classes/detection_finding) event (class_uid 2004) and POSTed to a configurable SIEM webhook. Severity is derived from the threat catalog (`critical` → severity_id 5, `high` → 4, etc.). An in-process anomaly detector fires alerts when finding rates or critical burst counts exceed thresholds.

### Why it matters

Every commercial SIEM (Splunk, Elastic, Panther, Microsoft Sentinel) natively ingests OCSF events. A single `--emit-to` flag turns cosai-mcp into a continuous SIEM data source — no adapter, no ETL, no schema translation.

### Usage

```bash
# Emit to SIEM after scan
cosai scan http://localhost:8000 \
  --emit-to https://siem.example.com/webhook/cosai \
  --emit-auth-header "Bearer $SIEM_TOKEN" \
  --anomaly-threshold 5 \
  --critical-burst-threshold 2

# Env vars (avoid leaking tokens in shell history)
export COSAI_EMIT_TO=https://siem.example.com/webhook/cosai
export COSAI_EMIT_AUTH="Bearer $SIEM_TOKEN"
cosai scan http://localhost:8000
```

### OCSF event structure (Detection Finding — class_uid 2004)

```json
{
  "class_uid": 2004,
  "class_name": "Detection Finding",
  "category_uid": 2,
  "severity_id": 4,
  "severity": "High",
  "status_id": 1,
  "time": 1747353600000,
  "finding": {
    "uid": "T01-001-p1",
    "title": "T01-001",
    "types": ["Security Finding"],
    "rule": { "uid": "T01-001", "name": "T01-001", "category": "T1" }
  },
  "resources": [{ "uid": "http://target:8000", "name": "MCP Server" }],
  "unmapped": {
    "passed": false,
    "probe_id": "T01-001-p1",
    "threat_id": "T01-001",
    "duration_seconds": 0.42
  }
}
```

### Anomaly rules

| Rule | Trigger |
|------|---------|
| `HIGH_FINDING_RATE` | > N non-passing probes in rolling window (default 5 min) |
| `CRITICAL_BURST` | > N critical findings in rolling window |
| `SEVERITY_ESCALATION` | Critical finding when baseline expectation is medium or lower |

Anomaly alerts are printed to stderr with `[ANOMALY]` prefix. They do not alter the exit code.

---

## Track D — Automated IR Containment

### What it does

When `--contain-on-anomaly` is set and anomaly thresholds are exceeded, the scanner:

1. Builds an `IncidentRecord` capturing all findings, anomaly rules triggered, worst-case severity, and recommended containment actions
2. Emits an [OCSF Security Incident](https://schema.ocsf.io/2.0.0/classes/security_incident) event (class_uid 2001) to the SIEM — this triggers automated SOAR playbooks in Splunk SOAR, Palo Alto XSOAR, etc.
3. Writes a signed JSON quarantine report to disk
4. Optionally generates firewall block commands (printed for human approval; never auto-executed)
5. Optionally sends a best-effort session kill signal to the MCP server

### Why it matters

The gap between "alert fired" and "server contained" is where attackers operate. By emitting a structured OCSF Security Incident, cosai-mcp triggers existing SOAR playbooks — without requiring any vendor agent on an MCP server.

### Usage

```bash
# Scan + auto-contain on anomaly
cosai scan http://localhost:8000 \
  --contain-on-anomaly \
  --anomaly-threshold 3 \
  --emit-to https://siem.example.com/webhook \
  --ir-report ./incidents/$(date +%s).json

# Manual containment from an incident file (after human review)
cosai ir contain ./incidents/1234567890.json \
  --emit-to https://siem.example.com/webhook \
  --block-egress

# Print an incident summary
cosai ir status ./incidents/1234567890.json
```

### Containment actions

| Action | What happens |
|--------|-------------|
| `session_kill` | Best-effort HTTP close to MCP server URL |
| `emit_incident` | POST OCSF Security Incident (2001) to SIEM webhook |
| `quarantine_report` | Write signed JSON incident report to disk |
| `block_egress` | Generate `iptables`/`pfctl` commands for human execution |

**Firewall commands are never auto-executed.** They are printed and written to the incident report for operator review. This is intentional: automatic network changes in production are a blast-radius risk. The SOAR playbook (triggered by the OCSF event) owns automation beyond this.

### OCSF Security Incident (class_uid 2001)

```json
{
  "class_uid": 2001,
  "class_name": "Security Incident",
  "severity_id": 5,
  "verdict_id": 1,
  "verdict": "True Positive",
  "finding_info": {
    "uid": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "title": "MCP Server Security Incident: http://victim:8000",
    "related_events": [{ "uid": "T01-001-p1" }, { "uid": "T01-002-p1" }]
  }
}
```

---

## Track E — Signed Conformance Scorecard

### What it does

After every scan, produces a per-category conformance grade for all 12 CoSAI categories, signs the scorecard with the per-installation Ed25519 key, and writes it as a machine-verifiable JSON artifact. The signature covers all fields deterministically — any post-hoc modification invalidates the signature.

### Why it matters

Compliance audits require *evidence*, not just reports. A signed scorecard is an attestation — the scanner cryptographically asserts that a specific server, at a specific time, with a specific threat catalog, achieved a specific conformance level. Auditors can verify the signature offline without trusting the reporting party.

This maps directly to CoSAI T1–T12 conformance and the NIST AI RMF (2026 Critical Infrastructure Profile).

### Usage

```bash
# Produce a signed scorecard
cosai scan http://localhost:8000 --scorecard scorecard.json

# Verify signature (auditor-side, no internet required)
COSAI_SCORECARD_PUBKEY="<base64-pubkey>" cosai scorecard verify scorecard.json

# Human-readable summary
cosai scorecard show scorecard.json --verify
```

### Scorecard format

```json
{
  "scan_id": "7c4e9f2a-...",
  "target_url": "http://localhost:8000",
  "scan_timestamp": "2026-05-16T09:00:00Z",
  "catalog_hash": "sha256:abc123...",
  "tool_version": "0.2.0",
  "conformance_level": "partial_conformance",
  "categories": [
    { "category": "T1", "grade": "pass", "probe_count": 8, "finding_count": 0, "critical_count": 0 },
    { "category": "T2", "grade": "fail", "probe_count": 4, "finding_count": 2, "critical_count": 1 },
    ...
  ],
  "public_key": "4a3b...",
  "signature": "9f2e..."
}
```

### Conformance levels

| Level | Condition |
|-------|-----------|
| `full_conformance` | All tested categories pass (WARN counts as pass) |
| `partial_conformance` | ≤ 3 failing categories, no critical findings |
| `non_conformant` | Any critical finding, or > 3 failing categories |
| `insufficient_coverage` | > 4 categories not tested |

### Trust model

Same architecture as Track A inventory signing:
- Per-installation key generated on first use, stored in OS keychain via `keyring`
- `COSAI_SCORECARD_PUBKEY` env var for cross-machine verification by auditors
- Scorecards signed by a different key are rejected unless the env var explicitly authorises that key

---

## Full Pipeline Example (GitHub Actions)

```yaml
jobs:
  mcp-security:
    runs-on: ubuntu-latest
    services:
      mcp-server:
        image: ${{ env.MCP_IMAGE }}
        ports: ["8000:8000"]

    steps:
      - name: Install cosai-mcp
        run: pip install cosai-mcp

      # ① Capture inventory baseline (first run) or diff (subsequent runs)
      - name: Inventory capture
        run: |
          cosai inventory capture http://localhost:8000 -o current-inventory.json
          if [ -f baseline-inventory.json ]; then
            cosai inventory diff baseline-inventory.json current-inventory.json \
              --fail-on-drift
          fi

      # ② Scan + stream to SIEM + auto-contain on anomaly + signed scorecard
      - name: Conformance scan
        env:
          COSAI_EMIT_TO: ${{ secrets.SIEM_WEBHOOK_URL }}
          COSAI_EMIT_AUTH: Bearer ${{ secrets.SIEM_TOKEN }}
        run: |
          cosai scan http://localhost:8000 \
            --fail-on critical \
            --report-sarif findings.sarif \
            --scorecard scorecard.json \
            --contain-on-anomaly \
            --anomaly-threshold 5

      # ③ Upload SARIF to GitHub Security tab
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: findings.sarif

      # ④ Archive scorecard as compliance evidence
      - name: Archive scorecard
        uses: actions/upload-artifact@v4
        with:
          name: conformance-scorecard
          path: scorecard.json
```

---

## Comparison: Scanner vs. Platform

| Capability | cosai-mcp v0.1 | cosai-mcp v0.2+ |
|-----------|:--------------:|:---------------:|
| Runtime black-box probing | ✅ | ✅ |
| Stateful conformance harness | ✅ | ✅ |
| All 12 CoSAI categories | ✅ | ✅ |
| CI/CD gate (exit codes) | ✅ | ✅ |
| SARIF → GitHub security tab | ✅ | ✅ |
| Tool inventory + drift detection | ❌ | ✅ Track A |
| Non-bypassable HITL gate | ❌ | ✅ Track C |
| OCSF telemetry → SIEM | ❌ | ✅ Track B |
| OCSF anomaly detection | ❌ | ✅ Track B |
| Automated IR containment | ❌ | ✅ Track D |
| OCSF Security Incident (2001) | ❌ | ✅ Track D |
| Signed conformance scorecard | ❌ | ✅ Track E |
| Per-category grade attestation | ❌ | ✅ Track E |

---

## What cosai-mcp Still Does Not Do

These are genuine gaps — not future plans, just things outside scope by design:

- **No static code analysis.** Use Cisco MCP Scanner or Enkrypt AI on source.
- **No production traffic monitoring.** Use MCPProxy-go or MCP-Bastion for runtime.
- **No LLM-semantic judgment.** Every probe is deterministic and CI-reproducible.
- **Firewall changes are never auto-applied.** Block commands are generated for human approval. Automated network changes belong in your SOAR playbook, triggered by the OCSF Security Incident event.
- **Session kill is best-effort.** MCP has no standard "kill session" method. The signal is sent; hard isolation requires the firewall block.
