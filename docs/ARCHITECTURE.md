# cosai-mcp — Architecture

## Overview

cosai-mcp is a security testing framework for MCP servers. It is not an MCP server itself. It speaks the MCP protocol as a client, sends adversarial probes, and reports findings. The architecture is designed so that a malicious MCP target cannot compromise the scanner.

## Three-Engine Model

A single probe mechanism cannot cover all 12 CoSAI threat categories. The tool ships three engines with distinct mechanisms, and the README coverage matrix documents honestly which engine covers which category.

```
┌─────────────────────────────────────────────────────────────┐
│                    cosai-mcp Scanner                        │
│                                                             │
│  ┌─────────────────┐  ┌──────────────────┐  ┌───────────┐  │
│  │  Black-box      │  │  Stateful        │  │Middleware │  │
│  │  Prober         │  │  Conformance     │  │Instrument │  │
│  │                 │  │  Harness         │  │           │  │
│  │  T1, T3, T8,    │  │  T2, T6, T7      │  │T4, T9,    │  │
│  │  T10            │  │  (multi-turn)    │  │T12        │  │
│  └────────┬────────┘  └────────┬─────────┘  └─────┬─────┘  │
│           │                   │                   │         │
│  ┌────────▼───────────────────▼───────────────────▼──────┐  │
│  │                  MCPSession                           │  │
│  │  initialize → initialized → tools/list → probe calls │  │
│  └───────────────────────────┬───────────────────────────┘  │
│                              │                              │
│  ┌───────────────────────────▼───────────────────────────┐  │
│  │                  Transport Layer                      │  │
│  │  StreamableHTTP (primary) │ LegacySSE │ stdio        │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    Target MCP Server
```

### Why three engines?

**Black-box probing** (one-shot JSON-RPC calls) is valid for T1, T3, T8, T10 — categories where the server's response to a single malformed or adversarial request is the finding. It cannot detect categories that require stateful sequences or LLM-in-the-loop observation.

**Stateful conformance harness** (full `initialize` + multi-turn scripted scenarios) is required for T2, T6, T7, where the attack requires a specific ordering of legitimate and attacker-controlled turns. Session fixation (T7) cannot be detected in a single request. Tool shadowing (T6) requires observing a baseline `tools/list` and then a re-fetch.

**Middleware instrumentation** (the middleware IS the test) is the only mechanism for T4, T9, T12. These categories require being in the call path — observing what content flows through the agent's reasoning loop, not just what the server returns. A black-box scanner is on the wrong side of the boundary.

---

## MCP Session Lifecycle

Every probe, regardless of engine, is preceded by the mandatory MCP handshake:

```
Scanner                          Target
   │                               │
   │  initialize(protocolVersion,  │
   │    clientInfo, capabilities)  │
   │──────────────────────────────▶│
   │                               │
   │  ◀─ initialize result ────────│
   │     (negotiated version,      │
   │      server capabilities)     │
   │                               │
   │  initialized (notification)   │
   │──────────────────────────────▶│
   │                               │
   │  tools/list                   │
   │──────────────────────────────▶│
   │                               │
   │  ◀─ tool manifest ────────────│
   │     (cached for session)      │
   │                               │
   │  [probes begin]               │
```

If the handshake fails, the scanner reports `scan-incomplete` — not `clean`. There is no ambiguous success state.

**Protocol version negotiation:** the scanner supports `2025-03-26` (Streamable HTTP, primary) and `2024-11-05` (LegacySSE, backward compat). If the server's `initialize` response declares `2024-11-05`, the scanner falls back to LegacySSE transport automatically.

---

## Transport Layer

```
cosai_mcp/transport/
  base.py              Transport ABC: connect, send, recv, close
  streamable_http.py   Primary (MCP 2025-03-26)
  legacy_sse.py        Backward compat (MCP 2024-11-05)
  stdio.py             Subprocess-based for local servers
```

**Streamable HTTP** (primary): single endpoint, returns direct JSON or `text/event-stream` depending on request. Handles `Mcp-Session-Id` header. A custom `httpcore.AsyncNetworkBackend` (`_PinnedNetworkBackend`) enforces the network allowlist at TCP connect time — routing sockets to the pre-resolved IP without altering the URL or TLS SNI hostname, so SNI-based virtual hosting (e.g. GCP, Cloudflare) is compatible.

**LegacySSE**: HTTP POST to send + SSE stream to receive. Used only when server negotiates `2024-11-05`.

**stdio**: subprocess-based for testing local servers without a network listener. Hardened — see Security section.

WebSocket is not in the MCP specification and is not implemented.

---

## Probe Isolation

Each probe runs in its own `multiprocessing.Process`. Not a thread. Not a coroutine. An OS process.

```
ProbeRunner
  │
  ├── Process(probe_1) → ProbeResult (JSON-serialized frozen dataclass)
  ├── Process(probe_2) → ProbeResult
  └── Process(probe_N) → ProbeResult
       │
       No shared memory
       OS-level timeout via multiprocessing terminate (not thread timeout)
       Crash/OOM/segfault → ProbeStatus.ERROR (fail-closed)
```

**Why `multiprocessing.Process`?** Python threads share the GIL, module-level singletons, httpx connection pools, ssl.SSLContext caches, and OS-level file descriptor tables. A malicious server response that exploits any shared state could contaminate subsequent probes. Process isolation eliminates all of these channels.

**Fail-closed:** if a probe process crashes, OOMs, or exits with any unexpected code, the result is `ERROR` — not `PASS`. There is no condition under which an error maps to a clean finding.

---

## Threat Catalog

```
catalog/
  official/          Ed25519-signed by project keypair
    T01-001.json
    T01-001.json.sig
    ...
  custom/            User-owned; reports mark as UNTRUSTED
    (user files here)
```

Threat definitions are JSON files validated against a strict meta-schema. New threats can be added by dropping a JSON file — no code changes required. See [CONTRIBUTING.md](CONTRIBUTING.md) for the schema and signing process.

The catalog loader:
1. Validates JSON against meta-schema (unknown fields rejected, not ignored)
2. Verifies Ed25519 signature against the hardcoded public key in `cosai_mcp/keys.py`
3. Converts all container fields to immutable types (`tuple`, `MappingProxyType`)
4. Validates all `matches_regex` patterns with `google-re2` at load time
5. Freezes all definitions — no mutation after load

Custom catalogs require `--allow-custom-catalog` (off by default). `matches_regex` in custom catalogs requires `--allow-regex-in-custom`.

---

## Adaptive Probe Synthesis

When a probe returns INCONCLUSIVE (schema mismatch — the server rejected the payload because it did not match the tool's expected schema), the scanner synthesizes a schema-aware payload using the tool manifest from `tools/list` and retries once. This eliminates false negatives caused by static catalog payloads that predate the target server's schema.

**T2 synthesis suppression (non-negotiable):**

Synthesis is disabled for T2 (confused-deputy / missing access control) probes. T2 probes test security by using adversarial parameter *names* — e.g. `session_id`, `role`, `privilege_level` — that the tool schema does not expect. When the server rejects these, that INCONCLUSIVE result is the expected outcome: the schema check fires before the authorization check is reached.

If synthesis were applied to a T2 probe, it would replace the adversarial parameter names with the tool's real parameters, turning the security probe into a functional call that would succeed — producing a false positive (the probe would "pass" by confirming that a legitimate call works, not that the authorization check fires).

T2 INCONCLUSIVE results are expected and should be interpreted as: the server enforces schema validation. The confused-deputy test requires the middleware engine or manual testing with a server that exposes a permissive schema.

**`error_code_in` MCP-layer fallback:**

The `error_code_in` assertion operator checks `response.error.code` (JSON-RPC protocol error) against an allowlist of expected codes. Some servers return errors via the MCP content layer (`result.isError: true`) instead of JSON-RPC protocol errors — in this case, `error.code` does not exist.

When `error_code_in` is evaluated and `response.error_code` is `None` but `response.error` is `True` (the server DID signal an error via `isError: true`), the assertion passes. The server correctly indicated an error; the specific JSON-RPC code cannot be verified, but error presence is sufficient. This prevents false failures against well-behaved servers that follow the MCP content-layer error convention.

---

## Network Allowlist

The scanner must not be weaponized for SSRF. A malicious target returning a 302 to `169.254.169.254` (AWS IMDS) must not be followed.

Controls enforced at socket connect time via `_PinnedNetworkBackend` (a custom `httpcore.AsyncNetworkBackend`):

- `follow_redirects=False` — hard-coded, non-overridable
- `trust_env=False` — HTTP_PROXY injection blocked
- Target IP resolved once at scan start; `_PinnedNetworkBackend.connect_tcp()` routes every socket to that IP directly, so the kernel never re-resolves the hostname. Any mid-session DNS change is caught by a re-resolution check in `_PinnedAsyncTransport.handle_async_request()` before each request.
- IP routing happens at the TCP layer only — the URL and TLS SNI hostname are left unchanged, which is required for correct operation against SNI-based virtual hosting (GCP, Cloudflare, AWS ALB, etc.)
- RFC1918, link-local, loopback, IPv6 ULA blocked by default
- Docker path adds `--network=none` except for the explicit target IP

The hard guarantee (DNS rebinding impossible) requires Docker. The Python-only path provides best-effort protection via IP pinning.

---

## Report Pipeline

```
MCP Response (attacker-controlled bytes)
     │
     │ html.escape(quote=True) at ingestion
     ▼
ProbeResult.evidence (escaped string)
ProbeResult._raw_unsafe (internal, never serialized to output)
     │
     ├──▶ SARIF builder (structured, never string interpolation)
     │      message.text ← evidence (plain text, length-capped, control-char-stripped)
     │      ruleId ← scanner catalog ID only
     │      suppressions ← scanner-generated only
     │      Validated against SARIF 2.1.0 JSON schema before write
     │
     └──▶ HTML builder
            All content from escaped evidence
            CSP: default-src 'none'
            References: text only; https:// URLs get rel="noopener noreferrer"
```

HTML escaping happens **at ingestion** into `ProbeResult`, not at render time. By the time content reaches any renderer, it is already escaped. This eliminates the class of bugs where content passes through multiple code paths before escaping is applied.

---

## Audit Log (T12)

The audit log is a hash-chained append-only file:

```json
{"seq": 1, "data": {...}, "prev_hash": "sha256:0000...0000", "entry_hash": "sha256:abc..."}
{"seq": 2, "data": {...}, "prev_hash": "sha256:abc...", "entry_hash": "sha256:def..."}
```

Each entry's `entry_hash` covers the entry content + `prev_hash`. Tampering with any entry breaks the chain at the next entry. `cosai audit verify` walks the chain and reports `CHAIN_BROKEN` at the first invalid entry.

File-level immutability (beyond O_APPEND) requires OS controls (`chattr +a`) outside the scanner's scope — documented explicitly.

---

## Exit Codes

| Code | Meaning | CI gate behavior |
|------|---------|-----------------|
| 0 | Clean — no findings at or above threshold | Pass |
| 1 | Findings at or above `--fail-on` threshold | Fail |
| 2 | Scanner internal error | **Fail** (fail-closed) |
| 3 | Target unreachable | Fail |

Exit code 2 is treated as failure by the GitHub Action regardless of `fail_on`. A scanner crash never produces a clean result.

Partial scans (exit 2 or 3) set `invocation.executionSuccessful: false` in SARIF output, preventing GitHub from treating a partial upload as a complete clean scan.

---

## Supply Chain

The scanner's own supply chain is hardened against the attacks it tests for:

- **Ed25519 public key** hardcoded as bytes literal in `cosai_mcp/keys.py` — not loaded from disk, cannot be replaced by a catalog substitution attack
- **PyPI attestation** via Sigstore/PEP 740 — verifiable at install time
- **GitHub Action** examples reference commit SHA, not mutable version tags
- **Reproducible builds** + SLSA L3 provenance (Phase 9)
- **Runtime environment** scrubbed at process start: `*_TOKEN`, `*_KEY`, cloud credential env vars stripped before any subprocess runs

---

## Module Map

```
cosai_mcp/
  keys.py              Ed25519 public key (bytes literal)
  config.py            ScanConfig, engine selection, flag parsing (probe_delay_seconds, auth_header)
  exceptions.py        SignatureVerificationError, UnsafePatternError, etc.
  session.py           MCPSession: handshake, tools/list, probe dispatch
  api.py               Scanner class (Python API)
  cli.py               cosai scan + cosai audit commands
  pytest_plugin.py     --cosai-target, --cosai-severity fixtures

  transport/
    base.py            Transport ABC
    streamable_http.py Primary HTTP transport + network allowlist
    legacy_sse.py      2024-11-05 backward compat
    stdio.py           Subprocess transport (hardened)

  catalog/
    schema.py          JSON meta-schema + validator
    loader.py          CatalogLoader: sig verify + schema validate + freeze
    models.py          Frozen dataclasses (ThreatDefinition, Probe, Assertion)
    template.py        Safe template substitution (dict-first, RE2)

  harness/
    runner.py          ProbeRunner: multiprocessing dispatch, fail-closed
    result.py          ProbeResult frozen dataclass
    assertions.py      Assertion evaluator (all operators + error_code_in)
    context.py         ProbeContext: session + IP + config per process
    mock_server.py     Test-only MCP server for unit tests

  stateful/
    harness.py         StatefulHarness: multi-turn scenario engine
    scenarios/         T2, T6, T7 scenario definitions

  middleware/
    auth.py            T1: DPoP (RFC 9449), ephemeral key pair
    authz.py           T2: per-tool RBAC, confused deputy prevention
    validation.py      T3: JSON schema strict mode on inbound responses
    boundary.py        T4: data/control boundary, prompt injection strip
    protection.py      T5: PII scrubbing (RE2 only)
    integrity.py       T6: tool manifest baseline diff
    session.py         T7: session binding checks
    network.py         T8: bind address validation
    trust.py           T9: untrusted response pipeline, sanitization
    resources.py       T10: heartbeat, budget counter, loop detection
    supply_chain.py    T11: tool name allowlist, typosquat detection
    audit.py           T12: hash-chained append log

  identity/
    (RFC 8693 token exchange + RFC 9449 DPoP reference impl)

  report/
    sarif.py           SARIF 2.1.0 structured builder
    html.py            HTML report (CSP hardened)
    sign.py            Per-installation report signing (keyring)
    verify.py          Report + audit chain verification

  scanner/
    (static tool definition analyzer — offline, no target needed)
```
