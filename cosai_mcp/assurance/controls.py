"""CoSAI MCP Security v2.0 §3.3.2 — control requirements by assurance level.

Frozen, in-package transcription of the four-level matrix (L1 Sandbox, L2
Internal, L3 Production, L4 Regulated) across eight dimensions. Requirement
text is paraphrased; see the CoSAI paper for normative wording.

Deliberately NOT a JSON catalog (Mnemo dec_64a81342b1): this table defines
what a level *means*, so it must not be operator-extensible.

``probe_threats`` link scanner evidence to a control: a conclusive finding on
any linked ID fails it (disproof).  Only ``verify_with`` probes — which assert a
*positive* control signal such as a specific rejection code — can PROVE a
control, and only up to ``blackbox_max_level``.  Negative assertions ("the
response did not leak X") and reachability checks never prove a control: a
tool that ignores its arguments passes them without any defence existing.
"""
from __future__ import annotations

import types

from cosai_mcp.assurance.models import Control, Requirement, Strength

PROFILE_VERSION = "cosai-mcp-security-v2.0"

M = Strength.MUST
S = Strength.SHOULD

DIMENSIONS: tuple[str, ...] = (
    "Identity and Authentication",
    "Authorization and Delegation",
    "Transport and Network Security",
    "Isolation and Sandboxing",
    "Logging and Observability",
    "Supply Chain and Lifecycle",
    "Tool Definition, Input, and Output Integrity",
    "State and Discovery Security",
)
_ID, _AZ, _TN, _IS, _LO, _SC, _TI, _SD = DIMENSIONS


def _c(
    control_id: str,
    dimension: str,
    title: str,
    mcp_t: tuple[str, ...],
    levels: dict[int, tuple[Strength, str]],
    probes: tuple[str, ...] = (),
    blackbox_max_level: int = 0,
    verify_with: tuple[str, ...] = (),
    optional: tuple[str, ...] = (),
) -> Control:
    return Control(
        control_id=control_id,
        dimension=dimension,
        title=title,
        levels=types.MappingProxyType(
            {lvl: Requirement(st, text) for lvl, (st, text) in levels.items()}
        ),
        mcp_t=mcp_t,
        probe_threats=probes,
        blackbox_max_level=blackbox_max_level,
        verify_with=verify_with,
        optional_probes=optional,
    )


_AUTH_PROBES = ("T01-001", "T01-002", "T01-004", "T01-006")
_SSRF_PROBES = ("T08-001", "T08-004", "T08-005", "T08-006", "T08-007", "T08-008", "T08-009")
_INPUT_PROBES = ("T03-001", "T03-002", "T03-003", "T03-004", "T03-005", "T03-006", "T03-007")
_LIMIT_PROBES = ("T10-001", "T10-002", "T10-003", "T10-004", "T10-005")

CONTROLS: tuple[Control, ...] = (
    # --- Identity and Authentication (MCP-T1, MCP-T2) ---------------------
    _c("ID-01", _ID, "MCP client-server authentication", ("MCP-T1",), {
        2: (M, "OAuth 2.1 with PKCE for all remote server connections"),
        3: (M, "OAuth 2.1 + PKCE, short-lived credentials, Client ID Metadata Documents"),
        4: (M, "OAuth 2.1 + PKCE, short-lived, enterprise-managed authorization"),
    }, probes=_AUTH_PROBES),
    _c("ID-02", _ID, "Authorization issuer validation", ("MCP-T1",), {
        2: (M, "Validate issuer metadata during authorization server discovery"),
        3: (M, "Validate RFC 9207 iss; bind registration state to issuing AS"),
        4: (M, "Issuer binding enforced centrally with alerts on issuer mismatch"),
    }),
    _c("ID-03", _ID, "Agent identity", ("MCP-T1",), {
        2: (S, "Agents registered in a local inventory with unique identifiers"),
        3: (M, "Standardized workload identity (e.g. SPIFFE SVIDs) tied to code version"),
        4: (M, "Workload identity with attestation of the execution environment"),
    }),
    _c("ID-04", _ID, "User identity propagation", ("MCP-T1", "MCP-T2"), {
        2: (S, "Preserve subject identity to downstream authorization"),
        3: (M, "Token exchange with distinct actor and subject claims"),
        4: (M, "Token exchange with delegation chain preserved for audit"),
    }),
    _c("ID-05", _ID, "Credential storage", ("MCP-T1",), {
        2: (M, "OS keychain or secrets manager"),
        3: (M, "Secrets manager with automated rotation"),
        4: (M, "Hardware-backed/isolated keystores for long-lived keys"),
    }),
    _c("ID-06", _ID, "Credential lifetime", ("MCP-T1",), {
        2: (S, "Bounded lifetime, scheduled rotation"),
        3: (M, "Short-lived tokens; refresh tokens rotated and stored confidentially"),
        4: (M, "Short-lived sender-constrained credentials bounded by task risk"),
    }, probes=("T01-003",)),
    # --- Authorization and Delegation (MCP-T2, MCP-T9) --------------------
    _c("AZ-01", _AZ, "Tool-level authorization", ("MCP-T2", "MCP-T9"), {
        2: (S, "Tool allowlists per agent role"),
        3: (M, "ABAC/PBAC plus TBAC parameter-level constraints before execution"),
        4: (M, "TBAC with continuous evaluation and automated credential revocation"),
    }, probes=("T02-001", "T02-005", "T07-002", "T07-003", "T2-SC-001", "T2-SC-002")),
    _c("AZ-02", _AZ, "Scope management", ("MCP-T2",), {
        2: (S, "Scoped permissions per server connection"),
        3: (M, "Least-privilege scopes; incremental consent via WWW-Authenticate"),
        4: (M, "Rich Authorization Requests (RFC 9396) for sensitive operations"),
    }, probes=("T02-005",)),
    _c("AZ-03", _AZ, "Delegation depth", ("MCP-T2",), {
        2: (S, "Defined maximum depth for agent chains"),
        3: (M, "Enforced depth limits with TTL and audience restrictions"),
        4: (M, "Depth limits, audience restrictions, sender-constrained tokens per hop"),
    }),
    _c("AZ-04", _AZ, "Token binding (sender-constrained tokens)", ("MCP-T1", "MCP-T2"), {
        3: (M, "DPoP or mTLS sender-constrained tokens for delegated sensitive ops"),
        4: (M, "Sender-constrained tokens with hardware-attested keys where supported"),
    }, probes=("T01-003",)),
    _c("AZ-05", _AZ, "Scope narrowing on delegation", ("MCP-T2",), {
        2: (S, "Scope narrows at each hop"),
        3: (M, "Scope narrows at each hop; never exceeds delegating principal"),
        4: (M, "Scope narrowing cryptographically bound to the transaction path"),
    }),
    _c("AZ-06", _AZ, "Audience restriction", ("MCP-T1",), {
        2: (S, "aud claim validation on received tokens"),
        3: (M, "RFC 8707 resource indicators; reject audience mismatch"),
        4: (M, "Resource indicators enforced globally with RFC 9728 discovery"),
    }, optional=("T01-008",)),
    _c("AZ-07", _AZ, "No token passthrough", ("MCP-T1", "MCP-T2"), {
        2: (M, "Never forward tokens issued for the MCP server to upstream APIs"),
        3: (M, "Downstream auth only via RFC 8693 token exchange"),
        4: (M, "Token exchange with sender-constrained bindings downstream"),
    }),
    _c("AZ-08", _AZ, "Human-in-the-loop", ("MCP-T2", "MCP-T9"), {
        1: (S, "Warning on untrusted tools"),
        2: (M, "Explicit confirmation for destructive or state-mutating actions"),
        3: (M, "Central approval policies with step-up for high-impact actions"),
        4: (M, "Multi-party approval for irreversible or high-value operations"),
    }, probes=("T02-003", "T09")),
    # --- Transport and Network Security (MCP-T7, MCP-T8, MCP-T10) --------
    _c("TN-01", _TN, "Transport encryption", ("MCP-T7",), {
        2: (M, "TLS for all remote connections"),
        3: (M, "TLS 1.3; mTLS for server-to-server; certificate validation"),
        4: (M, "mTLS governed by workload identity federation"),
    }, probes=("T08-002",)),
    _c("TN-02", _TN, "Network binding", ("MCP-T8",), {
        1: (M, "HTTP transport binds to 127.0.0.1 only; never 0.0.0.0"),
        2: (M, "Explicit internal interface binding behind authenticated ingress"),
        3: (M, "Network segmentation between MCP components"),
        4: (M, "Dedicated segments, default-deny egress via proxy with logging"),
    }, probes=("T08-003",)),  # reachability only — can never prove loopback binding
    _c("TN-03", _TN, "Origin and CSRF protection", ("MCP-T7", "MCP-T8"), {
        1: (M, "Validate Origin and Host headers on HTTP transport"),
        2: (M, "Origin, Host validation and CSRF protection on all HTTP endpoints"),
        3: (M, "Strict origin policies; authentication for all remote access"),
        4: (M, "Strict origin policies, request signing, DNS pinning"),
    }, probes=("T07-001",)),
    _c("TN-04", _TN, "Protocol request metadata validation", ("MCP-T7",), {
        2: (M, "Validate MCP-Protocol-Version, Mcp-Method, Mcp-Name (Streamable HTTP)"),
        3: (M, "Reject header/body mismatches before auth, routing, caching, execution"),
        4: (M, "Gateway enforcement with alerts on HeaderMismatch and bad versions"),
    }, probes=("T07-004", "T07-005"), blackbox_max_level=3,
       verify_with=("T07-004", "T07-005")),
    _c("TN-05", _TN, "Payload limits", ("MCP-T10",), {
        2: (M, "Defined payload size and basic recursion depth limits"),
        3: (M, "Payload/depth limits with per-client/principal/tenant rate limits"),
        4: (M, "Limits with anomaly-based throttling and tenant-aware cost controls"),
    }, probes=_LIMIT_PROBES),  # T10 probes accept ANY error (auth/rate-limit too): disprove only
    _c("TN-06", _TN, "Message integrity", ("MCP-T7",), {
        2: (S, "Payload hashing and strict content-length validation"),
        3: (M, "Application-layer signatures over the full JSON-RPC body"),
        4: (M, "Signatures with unique nonces and time-window replay protection"),
    }),
    _c("TN-07", _TN, "Local HTTP exposure", ("MCP-T8",), {
        1: (M, "If HTTP: validate Origin, bind localhost; prefer stdio/UDS"),
    }, probes=("T08-003", "T07-001")),
    # --- Isolation and Sandboxing (MCP-T5, MCP-T8, MCP-T9) ---------------
    _c("IS-01", _IS, "Execution isolation", ("MCP-T8", "MCP-T9"), {
        # L1 cell: SHOULD restricted context + MUST NOT touch production
        # credentials/data — the MUST clause governs the gate.
        1: (M, "MUST NOT access production credentials or live data "
               "(SHOULD: restricted local user context)"),
        2: (M, "Application sandboxing or containers with resource limits"),
        3: (M, "Strong container isolation (gVisor/Kata); no shared runtime"),
        4: (M, "Strong tenant isolation with attested workload identity"),
    }),
    _c("IS-02", _IS, "Data isolation", ("MCP-T5",), {
        1: (M, "Synthetic/mock data only (else reclassify as Level 2+)"),
        2: (M, "Per-user data separation"),
        3: (M, "Per-tenant isolation with encryption"),
        4: (M, "Per-tenant encryption with tenant-specific keys"),
    }),
    _c("IS-03", _IS, "Context isolation", ("MCP-T5",), {
        2: (S, "Scope cached tool outputs and context to user and workflow"),
        3: (M, "Context scoped to user, tenant, task, and agent boundary"),
        4: (M, "Cross-tenant context sharing prohibited"),
    }, probes=("T05-001", "T05-002", "T05")),
    _c("IS-04", _IS, "Snapshot and rollback", ("MCP-T9",), {
        1: (S, "Environment supports snapshot/rewind for experimentation"),
        3: (S, "Rollback capability for MCP server updates"),
        4: (M, "Rollback, staged rollouts, canary deployments"),
    }),
    # --- Logging and Observability (MCP-T12) -----------------------------
    _c("LO-01", _LO, "Action logging", ("MCP-T12",), {
        2: (M, "Structured logs of tool, caller, decision, target, outcome (redacted)"),
        3: (M, "Comprehensive logging incl. auth/cache decisions and header mismatches"),
        4: (M, "Immutable, tamper-evident logging of all interactions"),
    }),
    _c("LO-02", _LO, "Delegation chain logging", ("MCP-T12",), {
        2: (S, "Correlation IDs linking related events"),
        3: (M, "Full delegation-chain reconstruction with scope/audience per hop"),
        4: (M, "Reconstruction with policy version and attestation state per hop"),
    }),
    _c("LO-03", _LO, "Distributed tracing", ("MCP-T12",), {
        2: (S, "Propagate correlation IDs across host, client, server"),
        3: (M, "W3C Trace Context in _meta; bounded allowlisted baggage"),
        4: (M, "Trace context correlated with identity, policy, runtime telemetry"),
    }),
    _c("LO-04", _LO, "Log schema", ("MCP-T12",), {
        2: (S, "Structured format mapped to OCSF or CEF"),
        3: (M, "OCSF/CEF with agentic extension fields"),
        4: (M, "Mandatory agentic fields correlated in SIEM"),
    }),
    _c("LO-05", _LO, "Monitoring and alerting", ("MCP-T12",), {
        2: (S, "Centralized log aggregation"),
        3: (M, "SIEM integration and anomaly detection on agent behavior"),
        4: (M, "Continuous monitoring with automated containment hooks"),
    }),
    # --- Supply Chain and Lifecycle (MCP-T6, MCP-T11) --------------------
    _c("SC-01", _SC, "Server provenance", ("MCP-T6", "MCP-T11"), {
        1: (S, "Warn when running unverified servers"),
        2: (S, "Provenance checks for tool definitions and server packages"),
        3: (M, "Code-signing verification before installation; SBOM tracking"),
        4: (M, "Signing, SBOM, reproducible builds, binary authorization"),
    }),
    _c("SC-02", _SC, "Server inventory", ("MCP-T11",), {
        2: (S, "Documented inventory with owner and trust status"),
        3: (M, "Centralized inventory with version/owner/purpose metadata"),
        4: (M, "Automated discovery and alerting on unregistered servers"),
    }),
    _c("SC-03", _SC, "Extension inventory", ("MCP-T11",), {
        2: (S, "Approved extensions by reverse-DNS identifier and version"),
        3: (M, "Extension IDs, versions, maintainers, capabilities tracked"),
        4: (M, "Policy enforcement with block-by-default for unapproved extensions"),
    }),
    _c("SC-04", _SC, "Update management", ("MCP-T11",), {
        2: (S, "Version tracking"),
        3: (M, "Dependency pinning with hash verification, vulnerability scanning"),
        4: (M, "Pinning, automated scanning, staged rollout, forced CVE upgrades"),
    }),
    _c("SC-05", _SC, "Decommissioning", ("MCP-T11",), {
        2: (S, "Documented removal process"),
        3: (M, "Complete removal of deprecated servers; credential revocation"),
        4: (M, "Automated lifecycle policies; downstream delegation revocation"),
    }),
    # --- Tool Definition, Input, and Output Integrity (MCP-T3, MCP-T4) ---
    _c("TI-01", _TI, "Tool schema integrity", ("MCP-T3", "MCP-T4", "MCP-T6"), {
        1: (S, "Review tool descriptions and schemas before use"),
        2: (S, "Pin trusted tool definitions and alert on changes"),
        3: (M, "Cryptographically pin approved definitions; re-approve changes"),
        4: (M, "Signed tool-definition manifests; unsigned rejected at runtime"),
    }, probes=("T06-001", "T06-002", "T06", "T04", "T11-001", "T11", "T6-SC-001")),
    _c("TI-02", _TI, "Schema validation", ("MCP-T3",), {
        1: (S, "Validate obvious dangerous inputs"),
        2: (M, "Validate against JSON Schema; reject undeclared parameters"),
        3: (M, "Bounded JSON Schema 2020-12 validation; no external $ref deref"),
        4: (M, "Signed schema manifests and bounded validation budgets"),
    }, probes=("T03",)),
    _c("TI-03", _TI, "Input validation", ("MCP-T3",), {
        1: (S, "Validate obvious dangerous inputs"),
        2: (M, "Sanitize file paths against directory traversal"),
        3: (M, "Strict schemas; validate paths, URLs, commands, x-mcp-header params"),
        4: (M, "Policy-aware validation with per-tool allowlists and deep inspection"),
    }, probes=_INPUT_PROBES),  # negative (no-leak) assertions: disprove only
    _c("TI-04", _TI, "Output handling", ("MCP-T4",), {
        1: (S, "Treat tool output as untrusted"),
        2: (M, "Sanitize tool outputs before returning them to the model"),
        3: (M, "Classify and sanitize output against injection, SSRF, commands"),
        4: (M, "Content classification and policy enforcement on outputs"),
    }, probes=("T05-001", "T05-002")),
    _c("TI-05", _TI, "Cacheable result handling", ("MCP-T5", "MCP-T7"), {
        2: (S, "Honor ttlMs/cacheScope; default private/no-store"),
        3: (M, "Prevent cross-user/tenant caching; revalidate pinned definitions"),
        4: (M, "Centralized cache policy with tenant-isolated keys"),
    }, optional=("T05-003",)),
    _c("TI-06", _TI, "SSRF and traversal defense", ("MCP-T3", "MCP-T8"), {
        2: (M, "Restrict URL schemes to HTTPS; sanitize file paths"),
        3: (M, "Deny loopback, link-local, and cloud metadata destinations"),
        4: (M, "All egress through strict allowlists at inspected proxies"),
    }, probes=(*_SSRF_PROBES, "T03-002")),  # negative (no-leak) assertions
    # --- State and Discovery Security (MCP-T1, MCP-T6, MCP-T7) ------------
    _c("SD-01", _SD, "Explicit state handle integrity", ("MCP-T7",), {
        2: (M, "Handles are CSPRNG, opaque, principal-scoped; auth on every request"),
        3: (M, "Tenant-bound, expiring, revocable handles; revocation cancels tasks"),
        4: (M, "Continuous re-evaluation and automated revocation on anomaly"),
    }, probes=("T7-SC-001", "T7-SC-002"), optional=("T07-007",)),
    _c("SD-02", _SD, "Request metadata trust", ("MCP-T1",), {
        2: (M, "_meta identity/capability claims never used alone for authorization"),
        3: (M, "Reject _meta claims conflicting with the authenticated principal"),
        4: (M, "Gateway reconciliation of _meta claims with workload identity"),
    }, optional=("T01-007",)),
    _c("SD-03", _SD, "Client-held state integrity", ("MCP-T7",), {
        2: (M, "Sealed state (e.g. requestState) HMAC/AEAD-protected; reject on failure"),
        3: (M, "Principal, expiry, and request ID sealed inside the payload"),
        4: (M, "Centrally managed rotated sealing keys; failures alerted"),
    }),
    _c("SD-04", _SD, "Server and authorization discovery", ("MCP-T1", "MCP-T6"), {
        2: (S, "Support server/discover and RFC 9728 Protected Resource Metadata"),
        3: (M, "Implement server/discover and Protected Resource Metadata"),
        4: (M, "Discovery and OIDC validation with centralized policy"),
    }, probes=("T01",)),  # passive RFC 9728 PRM check (cosai_mcp.wellknown)
    _c("SD-05", _SD, "Elicitation security", ("MCP-T4", "MCP-T9"), {
        2: (S, "Treat elicitation as untrusted; no credentials via form mode"),
        3: (M, "Input-required flows isolated from privileged tool invocation"),
        4: (M, "Elicited content fully validated before influencing execution"),
    }),
    _c("SD-06", _SD, "Deprecated feature migration", ("MCP-T6", "MCP-T11"), {
        2: (S, "Avoid new dependencies on Roots, Sampling, protocol Logging"),
        3: (M, "Migrate Roots, Sampling, Logging to supported replacements"),
        4: (M, "Deprecated usage inventoried, exception-approved, time-boxed"),
    }, probes=("T11-002", "T07-006")),
    _c("SD-07", _SD, "Refresh tokens", ("MCP-T1",), {
        # L2 cell: MUST protect as confidential + SHOULD rotate.
        2: (M, "If issued, MUST be protected as confidential credentials "
               "(SHOULD be rotated)"),
        3: (M, "Rotated, stored securely, not a substitute for runtime authorization"),
        4: (M, "Rotation enforced; revocation propagated within SLA"),
    }),
)

CONTROLS_BY_ID: types.MappingProxyType = types.MappingProxyType(
    {c.control_id: c for c in CONTROLS}
)
