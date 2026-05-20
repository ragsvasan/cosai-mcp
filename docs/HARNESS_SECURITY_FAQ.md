# Harness Security & Threat Definition — FAQ

Two questions come up at almost every demo: *how does the threat catalog work without being a code-execution surface?* and *how do we make sure a malicious MCP server can't turn the scanner against itself?* This document answers both in Q&A form. For signing specifically, see [CATALOG_SIGNING_FAQ.md](CATALOG_SIGNING_FAQ.md).

---

## Threat Definition Format

**Q: How do you define a new threat — do you write code?**

No. Drop a JSON file in `catalog/official/` or `catalog/custom/`. The harness loads it, validates it, and runs it. No code changes, no recompile.

Each file declares the threat ID, CoSAI/OWASP/CWE references, severity, and a list of probes. A probe is a JSON-RPC payload plus a set of assertions. The catalog is pure data.

**Q: What does a threat definition actually look like?**

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

**Q: Can a catalog file contain arbitrary code or expressions?**

No. Template substitution is the only dynamic feature, and the variable allowlist is closed: `{{target_url}}`, `{{session_id}}`, `{{tool_name}}`. Nothing else is substituted.

Substitution operates on the parsed Python dict — not on the raw JSON string. This prevents JSON structural injection (a substituted value that breaks out of the string and becomes a new JSON key). After substitution, the harness checks whether any field still contains `{{` — if so, the probe is aborted with `TemplateInjectionError`.

The `operator` field is a closed enum: `eq`, `ne`, `contains`, `not_contains`, `matches_regex`, `status_in`, `error_code_in`. There is no `eval` operator, no expression language.

**Q: What about `matches_regex` — can't an attacker cause ReDoS with a crafted pattern?**

Patterns are compiled with `google-re2`, which has linear-time guarantees and no backtracking. RE2 compiles every pattern at catalog load time. If RE2 refuses a pattern, we throw `UnsafePatternError` and reject the entire catalog file — not just the probe. Additionally, `matches_regex` is disabled in custom catalog files unless `--allow-regex-in-custom` is passed explicitly.

**Q: Where does the probe's target URL come from — can the catalog redirect probes?**

Never from the catalog. The target host is set only at the CLI or scanner config level. A catalog file specifies the payload shape and assertions — that's all. There is no URL field in probe definitions. This is a deliberate trust boundary: a compromised catalog file cannot exfiltrate session tokens by redirecting probes to an attacker endpoint.

**Q: Can a custom catalog file claim to be official?**

No. Provenance is derived from the filesystem load path, not from any field inside the JSON. A file in `catalog/custom/` is stamped `UNTRUSTED` in every report regardless of what it says about itself. Provenance cannot be self-asserted.

**Q: Can threat definitions be modified after load?**

No. They are converted to frozen dataclasses immediately after parsing. All container fields are converted to `tuple` and `MappingProxyType`. Attempting to mutate any field raises `AttributeError`. A post-load integrity walk asserts that no mutable containers remain anywhere in the definition tree.

---

## Harness Poisoning Prevention

**Q: The scanner processes attacker-controlled responses. How does a malicious server not compromise the scanner itself?**

Three independent layers.

**Layer 1 — Process isolation.** Every probe runs in its own `multiprocessing.Process`. This is OS-level isolation — not threads, not coroutines. A response that exploits Python module-level state, SSL session cache, or the httpx connection pool can only affect the probe process, not the harness. Results come back as JSON-serialized frozen dataclasses; no shared memory, no IPC beyond the serialized result.

**Layer 2 — Fail-closed crash semantics.** Any unexpected probe exit — exception, OOM, segfault, OS SIGKILL — maps to `ProbeStatus.ERROR`, not `PASS`. The harness cannot be tricked into reporting clean by crashing a probe.

**Layer 3 — Network allowlist at the socket level.** The target hostname resolves to an IP once at scan start. Any subsequent connect attempt to a different IP is rejected. RFC1918, link-local, loopback, and IPv6 ULA are blocked by default. `follow_redirects=False` and `trust_env=False` are hard-coded. This prevents a server that issues an HTTP 307 to `169.254.169.254` (AWS IMDS) from pivoting the scanner into a cloud credential exfiltration.

**Q: What's the DNS rebinding risk and how do you handle it?**

Classic attack: scanner resolves `evil.example.com` to a public IP, connects, passes the allowlist check. The attacker flips DNS mid-session to an RFC1918 address. Subsequent probe connections go internal.

Our defense: the target hostname resolves to an IP once at scan start. The custom httpx transport pins that IP. Any connect to a different IP is rejected, mid-session DNS changes notwithstanding.

Hard guarantee caveat: the IP-pinning path is best-effort in the Python-only runner. A hard guarantee requires Docker with `--network=none` plus an explicit IP rule. Both modes are documented; neither overstates its guarantee.

**Q: Can a malicious server response inject content into the SARIF report and suppress findings on GitHub?**

No. SARIF is generated exclusively via a structured builder — zero string interpolation. Attacker-controlled bytes land in exactly one field: `result.message.text`, which is typed as plain text, capped at 4096 characters, and control-character-stripped. `ruleId`, `suppressions`, and `partialFingerprints` are scanner-generated from catalog metadata only. A server cannot inject a `"suppressions"` array that GitHub would interpret to silence real findings. SARIF output is also validated against the SARIF 2.1.0 JSON schema before writing to disk.

**Q: What about response content leaking into HTML reports?**

All captured response content is HTML-escaped at ingestion into the result object — not at render time. By the time any report writer touches the data, it's already inert. `html.escape(quote=True)` is applied once, at the boundary.

**Q: Timeouts — can a hanging server stall the harness?**

No. Timeouts are enforced at the OS level via `multiprocessing.Process.terminate()` + `SIGKILL`. Python thread-based timeouts (`threading.Timer`) can be silently swallowed if the GIL is held. OS-level termination cannot be blocked from within the probe. A probe that hangs is killed by the OS; the harness records it as a timeout result and moves on.

**Q: What if the scan can't finish — does a partial scan report clean?**

Never. The CI exit code contract makes this impossible:

| Code | Meaning |
|------|---------|
| 0 | Clean — no findings at or above threshold |
| 1 | Findings at or above `--fail-on` threshold |
| 2 | Scanner internal error |
| 3 | Target unreachable |

Exit code 2 is treated as a build failure by the GitHub Action, regardless of `--fail-on`. A scan that cannot complete the MCP handshake (`initialize` → `initialized` → `tools/list`) reports `scan-incomplete`, not `clean`. There is no code path that infers clean from an error state.

**Q: Can the scanner be weaponized via stdio to achieve code execution in CI?**

No. The stdio transport is hardened:

- `shell=False` always — no subprocess.Popen with a shell string
- `close_fds=True` — child does not inherit scanner file descriptors (audit log, keyring)
- `start_new_session=True` — child cannot signal the scanner process group
- `env=` is an explicit minimal allowlist (`PATH`, `COSAI_*` only) — no `*_TOKEN`, `*_KEY`, cloud credentials
- stdout/stderr size-capped at 10 MB — a malicious server cannot OOM the harness via stderr flood
- Template substitution never touches `argv` or `env`

stdio mode is also disabled by default in CI (`--ci` flag). It requires explicit `--allow-stdio`.

**Q: The scanner runs in CI with broad permissions. Does it scrub its environment?**

Yes. At process start, the scanner strips all environment variables matching `*_TOKEN`, `*_KEY`, `AWS_*`, `GOOGLE_*`, `GCP_*` before launching any subprocess. Retained: `PATH`, `COSAI_*`, `HOME`, `TMPDIR`. The GitHub Action sets `permissions: contents: read, security-events: write` only — no `id-token: write`, no `packages: write`.

---

## Quick Reference

| Attack | Defense |
|--------|---------|
| Catalog template code execution | Closed variable allowlist + `TemplateInjectionError` on `{{` post-substitution |
| ReDoS via regex pattern | `google-re2` (linear time); compile at load; reject file on RE2 refusal |
| Catalog redirects probes to exfiltration URL | Target host is CLI-only; no URL field in probe definitions |
| Custom catalog claims official provenance | Provenance = load path; JSON field ignored |
| Malicious server poisons subsequent probes | Each probe in its own `multiprocessing.Process` |
| Crash probe to infer PASS | Any unexpected exit → `ProbeStatus.ERROR` (fail-closed) |
| DNS rebinding mid-session | IP pinned at scan start; different IP rejected at socket level |
| HTTP 307 redirect to IMDS | `follow_redirects=False` hard-coded |
| SARIF suppression injection | Structured builder; attacker bytes in `message.text` only |
| Partial scan reports clean | Exit code 2 = CI failure; `scan-incomplete` is not `clean` |
| stdio argv injection → code execution | `shell=False`; fixed argv; template vars never touch argv/env |
| CI credential exfiltration via subprocess | Env scrubbed at start; child gets minimal allowlist only |

---

## See Also

- [CATALOG_SIGNING_FAQ.md](CATALOG_SIGNING_FAQ.md) — Ed25519 signing, key hardcoding, enterprise key rotation
- [SECURITY.md](SECURITY.md) — full technical specification of every control
- [THREAT_CATALOG.md](THREAT_CATALOG.md) — probe format, modifier fields, coverage matrix
