"""Python API — Scanner class, ScanResult, scrub_env, COVERAGE_MATRIX."""
from __future__ import annotations

import dataclasses
import datetime
import hashlib
import os
import re
import socket
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cosai_mcp.adversarial import AdversarialMode
from cosai_mcp.catalog.loader import CatalogLoader
from cosai_mcp.catalog.models import Severity, ThreatDefinition
from cosai_mcp.config import ScanConfig
from cosai_mcp.exceptions import ScannerInternalError, TargetUnreachableError
from cosai_mcp.harness.result import ProbeResult
from cosai_mcp.harness.runner import ProbeRunner
from cosai_mcp.profiles.models import ServerProfile
from cosai_mcp.stateful.harness import ScenarioResult, StatefulHarness
from cosai_mcp.stateful.scenarios import (
    t2_confused_deputy,
    t2_privilege_escalation_chain,
    t6_tool_shadowing_mid_session,
    t7_session_revocation,
    t7_session_token_binding,
)

# ---------------------------------------------------------------------------
# Coverage matrix — locked by three-engine architecture decision
# ---------------------------------------------------------------------------

COVERAGE_MATRIX: dict[str, str] = {
    "T1":  "black-box-prober",
    "T2":  "black-box-partial+stateful",
    "T3":  "black-box-prober",
    "T4":  "middleware-only+manifest",
    "T5":  "black-box-partial",
    "T6":  "black-box-partial+stateful",
    "T7":  "stateful",
    "T8":  "black-box-prober",
    "T9":  "middleware-only+manifest",
    "T10": "black-box-prober",
    "T11": "black-box-partial",
    "T12": "middleware-only",
}

# Categories only detectable via middleware instrumentation — cannot be probed
MIDDLEWARE_ONLY_CATEGORIES: frozenset[str] = frozenset({"T4", "T9", "T12"})

# Categories that test authentication enforcement — probes must run WITHOUT
# the configured auth token so they exercise the unauthenticated code path.
# The session setup (initialize/tools/list) still uses auth when provided.
AUTH_PROBE_CATEGORIES: frozenset[str] = frozenset({"T1"})

# ---------------------------------------------------------------------------
# Env scrubbing — strip secrets before subprocess spawn
#
# Design: scrub_env() returns a copy and never mutates the source dict.
# _apply_env_scrub() mutates os.environ in-place and is ONLY called from the
# CLI entry point (a short-lived process).  Library callers (Scanner.run())
# must NOT call _apply_env_scrub(); they receive the scrubbed env via
# ScanConfig.subprocess_env — passed explicitly to subprocesses, never by
# mutating the host process environment.
# ---------------------------------------------------------------------------

_SCRUB_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in [
        r".*_TOKEN$",
        r".*_KEY$",
        r".*_SECRET$",
        r".*_PASSWORD$",
        r".*_CREDENTIAL.*",
        r"AWS_.*",
        r"GOOGLE_APPLICATION_CREDENTIALS",
        r"GCP_.*",
        r"AZURE_.*",
        r"GH_.*",
        r"GITHUB_.*",
        # Connection-string variables that embed credentials (FIX [3])
        r"DATABASE_URL$",
        r"MONGODB_URI$",
        r"MONGO_URI$",
        r"REDIS_URL$",
        r"CELERY_BROKER_URL$",
        r"SMTP_.*",
        r"MAIL_PASSWORD$",
    ]
)


# cosai-mcp's OWN configuration variables. These are not target-bound
# credentials — they configure the scanner itself and several (notably the
# WP6 fleet signing key) are required IN-PROCESS for report/scorecard signing.
# They are never forwarded into a probe subprocess regardless (probes get a
# minimal filtered env), so exempting them from the secret-pattern scrub does
# not widen the subprocess attack surface. Without this exemption,
# COSAI_REPORT_SIGNING_KEY matches ``.*_KEY$`` and the fleet key is silently
# stripped before signing — defeating WP6 entirely in the CLI path.
_SCRUB_ALLOWLIST: frozenset[str] = frozenset({
    "COSAI_REPORT_SIGNING_KEY",
})


def scrub_env(env: dict[str, str] | None = None) -> dict[str, str]:
    """Return a copy of ``env`` with sensitive vars removed.

    If ``env`` is None, reads ``os.environ`` at call time into a fresh dict.
    Never mutates the source mapping. cosai-mcp's own config vars
    (``_SCRUB_ALLOWLIST``) are preserved — they are scanner configuration,
    not target secrets.
    """
    source = env if env is not None else dict(os.environ)
    return {
        k: v for k, v in source.items()
        if k in _SCRUB_ALLOWLIST or not any(p.match(k) for p in _SCRUB_PATTERNS)
    }


def _apply_env_scrub() -> None:
    """Mutate ``os.environ`` in-place — CLI-only, called once at process start.

    Must NOT be called from library code (Scanner.run(), _run_scan()).
    Library paths should pass scrub_env() output to subprocess constructors.
    """
    for key in list(os.environ.keys()):
        if key in _SCRUB_ALLOWLIST:
            continue  # cosai's own config — needed in-process (e.g. WP6 key)
        if any(p.match(key) for p in _SCRUB_PATTERNS):
            del os.environ[key]


# ---------------------------------------------------------------------------
# Rate-limit backoff helper
# ---------------------------------------------------------------------------

_RETRY_AFTER_RE: re.Pattern[str] = re.compile(
    r"retry_after['\"]?\s*:\s*(\d+(?:\.\d+)?)", re.IGNORECASE
)


def _extract_retry_after(results: list) -> float | None:
    """Return retry_after seconds from the first -32029 result, or None.

    Checks both result.error (subprocess-level rejection during initialize) and
    result.response_body (server returned -32029 as a JSON-RPC error response).
    Both fields are HTML-escaped at ingestion, so unescape before matching.
    The -32029 digit check itself is safe on the escaped form (digits/minus
    are never HTML-escaped).
    """
    import html as _html_mod
    for r in results:
        for raw in (getattr(r, "error", None), getattr(r, "response_body", None)):
            if raw and "-32029" in raw:
                m = _RETRY_AFTER_RE.search(_html_mod.unescape(raw))
                if m:
                    return float(m.group(1))
        if getattr(r, "status_code", None) == 429:
            return None  # HTTP 429 without retry_after — caller uses probe_delay
    return None


# ---------------------------------------------------------------------------
# Pre-scan tool discovery (P10 — replaces _get_first_tool_name)
# ---------------------------------------------------------------------------

def _run_discovery(
    target_url: str,
    config: ScanConfig,
) -> tuple[str, tuple]:
    """Run tool discovery and return (first_tool_name, discovered_tools_tuple).

    Uses discover_tools() from cosai_mcp.discovery to get the full schema
    snapshot.  Falls back to ("ping", ()) on any failure so the scan proceeds
    with static catalog payloads (identical to pre-P10 behavior).

    Returns
    -------
    first_tool_name:
        The name of the first discovered tool, or "ping" when none found.
    discovered_tools:
        Tuple of DiscoveredTool objects (may be empty on failure).
    """
    from cosai_mcp.discovery import DiscoveredTool, discover_tools

    discovered: tuple[DiscoveredTool, ...] = discover_tools(target_url, config)
    first_name = discovered[0].name if discovered else "ping"
    return first_name, discovered


def _adversarial_safety_dict(threat: ThreatDefinition) -> dict[str, Any]:
    """Return the executable subset of a threat for adversarial safety checks.

    Reference URLs and remediation text are intentionally excluded: the enforcer
    is meant to inspect probe material that can influence requests, not metadata.
    """
    from cosai_mcp.harness.context import _to_json_safe

    return {
        "id": threat.id,
        "mode": threat.mode,
        "probes": [
            {
                "id": probe.id,
                "transport": probe.transport,
                "method": probe.method,
                "payload": _to_json_safe(probe.payload),
            }
            for probe in threat.probes
        ],
    }


# ---------------------------------------------------------------------------
# URL / connectivity helpers
# ---------------------------------------------------------------------------

def _parse_target(target: str) -> tuple[str, int, str]:
    """Parse ``target`` URL and return ``(host, port, normalised_url)``.

    Raises ``ValueError`` if the URL is missing scheme or hostname.
    """
    parsed = urlparse(target)
    if not parsed.scheme or not parsed.hostname:
        raise ValueError(f"Invalid target URL — must include scheme and host: {target!r}")
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port, target


def check_reachable(host: str, port: int, timeout: float = 5.0) -> None:
    """Attempt a TCP connection to ``host:port``.

    Raises ``TargetUnreachableError`` on failure.  This is the only network
    access the CLI makes before starting the full scan; it gives exit-code 3
    a clean, early signal path.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except (TimeoutError, OSError) as exc:
        raise TargetUnreachableError(
            f"Cannot reach {host}:{port} — {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Catalog helper
# ---------------------------------------------------------------------------

CATALOG_ROOT: Path = Path(__file__).parent.parent / "catalog"


def _canonical_threat(t: ThreatDefinition) -> dict[str, Any]:
    """Return a JSON-serialisable canonical view of a ThreatDefinition.

    Covers *every* security-relevant field — payloads, assertions, severity,
    remediation, provenance, mode — not just the id.  This is what binds a
    signed report to the exact catalog content that produced it (H-2): any
    modification to an assertion, payload, or severity changes the hash even
    when the threat id string is unchanged.
    """
    import types as _types
    from enum import Enum as _Enum

    def _plain(v: Any) -> Any:
        # Normalise frozen containers / enums into deterministic plain types.
        if isinstance(v, (_types.MappingProxyType, dict)):
            return {str(k): _plain(val) for k, val in sorted(v.items())}
        if isinstance(v, (tuple, list)):
            return [_plain(x) for x in v]
        if isinstance(v, _Enum):
            return v.value
        return v

    def _assertion(a: Any) -> dict[str, Any]:
        # compiled_pattern is a derived re2 object — `value` already captures
        # the pattern source, so hashing `value` covers regex tampering.
        return {
            "target": a.target,
            "operator": _plain(a.operator),
            "value": _plain(a.value),
        }

    def _probe(p: Any) -> dict[str, Any]:
        return {
            "id": p.id,
            "transport": p.transport,
            "method": p.method,
            "payload": _plain(p.payload),
            "assertions": [_assertion(a) for a in p.assertions],
            # Corroboration (schema 1.1) is security-relevant — it decides
            # whether a signal becomes a finding — so it MUST bind the hash.
            "corroboration": [_assertion(a) for a in p.corroboration],
            "probe_token": p.probe_token,
            "probe_count": p.probe_count,
            "probe_headers": _plain(p.probe_headers) if p.probe_headers else None,
        }

    return {
        "schema_version": t.schema_version,
        "id": t.id,
        "category": t.category,
        "severity": _plain(t.severity),
        "cosai_ref": t.cosai_ref,
        "owasp_ref": t.owasp_ref,
        "cwe": list(t.cwe),
        "probes": [_probe(p) for p in t.probes],
        "remediation": t.remediation,
        "references": list(t.references),
        "provenance": _plain(t.provenance),
        "mode": t.mode,
        "confidence": _plain(t.confidence),
    }


def _catalog_hash(threats: list[ThreatDefinition]) -> str:
    """SHA-256 over the canonical content of every loaded threat definition.

    Binds a signed report to the exact catalog content (payloads, assertions,
    severities, remediation, provenance, mode) — not merely the set of threat
    ids.  A sabotaged catalog whose ids are unchanged now produces a *different*
    hash, restoring the tamper-evidence contract locked in CLAUDE.md (H-2).
    """
    import json as _json

    canonical = sorted(
        (_canonical_threat(t) for t in threats),
        key=lambda d: (d["id"], d["provenance"]),
    )
    blob = _json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(blob).hexdigest()


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScanResult:
    """Immutable result of a complete cosai-mcp scan.

    ``exit_code`` follows the locked semantics:
        0  clean — no findings at or above threshold
        1  findings at or above ``fail_on`` threshold
        2  scanner internal error (scan-incomplete counts as 2)
        3  target unreachable (set by caller, not by this dataclass)
    """
    target_url: str
    threats: tuple[ThreatDefinition, ...]
    probe_results: tuple[ProbeResult, ...]
    scenario_results: tuple[ScenarioResult, ...]
    scan_timestamp: str
    catalog_hash: str
    exit_code: int

    @property
    def has_findings(self) -> bool:
        # WP2: a baseline-accepted (suppressed) finding is, by definition,
        # known and accepted — it must not drive report-trigger / IR decisions
        # any more than it drives the exit code.  It is still present in
        # probe_results so report builders that iterate directly still list it.
        failed_probes = any(
            not r.passed and not r.suppressed
            for r in self.probe_results
            if r.error is None
        )
        failed_scenarios = any(
            not r.passed and r.status == "complete" for r in self.scenario_results
        )
        return failed_probes or failed_scenarios

    @property
    def is_incomplete(self) -> bool:
        return any(r.status == "scan-incomplete" for r in self.scenario_results)


# ---------------------------------------------------------------------------
# Exit-code determination — implements fail_on severity threshold (FIX [5])
# ---------------------------------------------------------------------------

# Higher value = higher severity (threshold comparison: finding_rank >= threshold)
_SEVERITY_RANK: dict[str, int] = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


def _determine_exit_code(
    probe_results: list[ProbeResult],
    scenario_results: list[ScenarioResult],
    fail_on: str,
    threat_severity: dict[str, Severity] | None = None,
) -> int:
    """Return 0, 1, or 2 based on scan results, respecting the fail_on threshold.

    ``threat_severity`` maps threat_id → Severity for threshold filtering.
    When not provided, all failed probes count as findings (conservative).

    Exit code 3 (unreachable) is set by the caller before ``_run_scan`` is invoked.
    """
    # scan-incomplete is always exit 2 — scanner could not verify the target
    if any(r.status == "scan-incomplete" for r in scenario_results):
        return 2

    # Probe errors (scanner crash in subprocess) → exit 2.
    # Timeouts and server-side rate-limit rejections are operational, not crashes —
    # the scanner ran correctly; the probe simply couldn't complete.  Exclude them
    # so a slow or rate-limiting server doesn't suppress real findings under exit 2.
    _OPERATIONAL_ERROR_MARKERS = ("timed out", "-32029")

    def _is_crash(r: ProbeResult) -> bool:
        if r.error is None:
            return False
        return not any(m in r.error for m in _OPERATIONAL_ERROR_MARKERS)

    if any(_is_crash(r) for r in probe_results):
        return 2

    threshold = _SEVERITY_RANK.get(fail_on.lower(), _SEVERITY_RANK["critical"])

    if threat_severity is not None:
        def _above_threshold(r: ProbeResult) -> bool:
            sev = threat_severity.get(r.threat_id)
            if sev is None:
                return True  # unknown severity: conservative, count it
            return _SEVERITY_RANK.get(sev.value, 0) >= threshold

        failed_probes = any(
            not r.passed
            and r.error is None
            and r.inconclusive_reason is None  # inconclusive ≠ finding
            and not r.suppressed              # WP2: baseline-accepted ≠ gating
            and _above_threshold(r)
            for r in probe_results
        )

        # Nothing verified: no clean pass exists above threshold AND every
        # non-passing probe above threshold errored (timed out / crashed).
        # Inconclusive probes are excluded — "couldn't test this condition" is
        # different from "scanner could not run". A single passed=True probe
        # above threshold (clean verdict) prevents exit 2.
        has_clean = any(
            r.passed and not r.suppressed and _above_threshold(r)
            for r in probe_results
        )
        if not has_clean:
            qualifying = [
                r for r in probe_results
                if not r.suppressed and not r.passed and _above_threshold(r)
            ]
            if qualifying and all(r.error is not None for r in qualifying):
                return 2
    else:
        failed_probes = any(
            not r.passed
            and r.error is None
            and r.inconclusive_reason is None  # inconclusive ≠ finding
            and not r.suppressed              # WP2: baseline-accepted ≠ gating
            for r in probe_results
        )

        has_clean = any(r.passed and not r.suppressed for r in probe_results)
        if not has_clean:
            qualifying = [r for r in probe_results if not r.suppressed and not r.passed]
            if qualifying and all(r.error is not None for r in qualifying):
                return 2

    # inconclusive scenarios don't trigger exit 1 — they weren't tested
    failed_scenarios = any(
        not r.passed and r.status not in ("inconclusive",)
        for r in scenario_results
    )

    if failed_probes or failed_scenarios:
        return 1

    return 0


# ---------------------------------------------------------------------------
# Core scan orchestration
# ---------------------------------------------------------------------------

def _run_scan(
    *,
    target: str,
    categories: list[str] | None,
    engine: str,
    allow_custom_catalog: bool,
    probe_timeout_seconds: float,
    catalog_root: Path,
    fail_on: str = "critical",
    allow_private_targets: bool = True,
    auth_token: str | None = None,
    read_token: str | None = None,
    mcp_path: str = "/mcp",
    adaptive: bool = True,
    profile: ServerProfile | None = None,
    adversarial_mode: AdversarialMode | None = None,
    probe_delay_seconds: float = 0.0,
    baseline_path: Path | None = None,
    pii_strict: bool = False,
    stateful_method_overrides: dict[str, str] | None = None,
) -> ScanResult:
    """Orchestrate a complete scan and return a ``ScanResult``.

    Caller is responsible for:
    - Catching ``TargetUnreachableError`` before this call (check_reachable)
    - Mapping ``ScanResult.exit_code`` to the process exit code
    - Env scrubbing: CLI callers should call ``_apply_env_scrub()`` once at
      process start BEFORE calling this function.  Library callers must NOT
      call ``_apply_env_scrub()`` — the scrubbed env is passed to subprocesses
      via ScanConfig.

    Any unhandled exception from this function should be mapped to exit code 2.
    """
    host, port, target_url = _parse_target(target)
    scan_timestamp = datetime.datetime.now(datetime.UTC).isoformat()

    # NOTE: _apply_env_scrub() is intentionally NOT called here (FIX [2]).
    # CLI callers call it once at process start; library callers must not mutate os.environ.

    # Apply profile overrides — profile wins over individual flags when set
    effective_mcp_path = (profile.mcp_path if profile else None) or mcp_path
    effective_auth_token = auth_token  # --auth-token always wins; profile only formats it
    effective_auth_header: str | None = None
    if effective_auth_token and profile and profile.auth_header_format:
        effective_auth_header = profile.auth_header_format.replace("{token}", effective_auth_token)

    config = ScanConfig(
        target_host=host,
        target_port=port,
        allow_private_targets=allow_private_targets,
        probe_timeout_seconds=probe_timeout_seconds,
        auth_token=effective_auth_token,
        read_token=read_token,
        mcp_path=effective_mcp_path,
        auth_header=effective_auth_header,
        probe_delay_seconds=probe_delay_seconds,
        pii_strict=pii_strict,
        stateful_method_overrides=stateful_method_overrides,
    )

    # Generate a unique scan ID for this run (used for canary traceability)
    scan_id = str(uuid.uuid4())

    # Validate adversarial dual opt-in before loading catalog; stamp scan_id
    adv_base = adversarial_mode or AdversarialMode()
    adv = dataclasses.replace(adv_base, scan_id=scan_id) if adv_base.enabled else adv_base
    if adv.enabled:
        adv.validate(target_url)

    # Load + filter catalog
    loader = CatalogLoader(
        catalog_root=catalog_root,
        allow_custom=allow_custom_catalog,
        allow_adversarial=adv.enabled,
    )
    all_threats = loader.load_all()

    effective_categories = _normalise_categories(categories)
    if effective_categories is not None:
        threats = [t for t in all_threats if t.category.upper() in effective_categories]
    else:
        threats = all_threats

    if adv.enabled:
        from cosai_mcp.adversarial.enforcer import check_no_external_endpoints

        for threat in threats:
            if "-ADV-" in threat.id.upper():
                check_no_external_endpoints(
                    _adversarial_safety_dict(threat),
                    target_url,
                    allow_stateful=adv.allow_stateful,
                )

    # Profile: filter out categories that don't apply to this server type
    if profile and profile.skip_categories:
        threats = [t for t in threats if t.category.upper() not in profile.skip_categories]
        if not threats:
            import warnings
            warnings.warn(
                f"Profile {profile.name!r} skip_categories filtered out all threats — "
                "the scan will run no probes and exit 0 (clean) with no evidence. "
                "Check your --categories filter or profile configuration.",
                stacklevel=3,
            )

    catalog_hash_ = _catalog_hash(threats)
    threat_severity = {t.id: t.severity for t in threats}

    # --- Prober engine ---
    probe_results: list[ProbeResult] = []
    if engine in ("prober", "all"):
        # P10: discover tool schemas once; use for adaptive payload synthesis.
        # discover_tools() is a superset of the old _get_first_tool_name() —
        # returns (first_tool_name, all_discovered_tools).  Falls back to
        # ("ping", ()) on failure so the scan proceeds identically to pre-P10.
        real_tool_name, discovered_tools = _run_discovery(target_url, config)

        # T4: passive manifest scan — no probe sent, uses already-fetched manifest.
        # Runs whenever T4 is in scope (no category filter, or T4 explicitly requested).
        if effective_categories is None or "T4" in effective_categories:
            probe_results.extend(_scan_manifest_t4(tuple(discovered_tools) if discovered_tools else ()))  # noqa: E501

        # T9: passive Totem manifest scan — flags destructive tools missing two-stage commit.
        # Runs whenever T9 is in scope (no category filter, or T9 explicitly requested).
        if effective_categories is None or "T9" in effective_categories:
            probe_results.extend(_scan_manifest_t9(tuple(discovered_tools) if discovered_tools else ()))  # noqa: E501

        # T5: passive manifest secret/PII scan — credentials or PII embedded in
        # tool names/descriptions are a data-protection leak (and a poisoning
        # delivery vector).  --pii-strict widens to the broad-PII tier.
        if effective_categories is None or "T5" in effective_categories:
            probe_results.extend(
                _scan_manifest_t5(
                    tuple(discovered_tools) if discovered_tools else (),
                    pii_strict=config.pii_strict,
                )
            )

        # T6: passive manifest integrity scan — tool-name collisions and tool
        # names within Levenshtein 1 of a reserved MCP method or another tool
        # (typosquat / shadowing).  Replaces the old T06-001/002 black-box probes
        # that only asserted tools/list succeeds (audit COV-02).
        if effective_categories is None or "T6" in effective_categories:
            probe_results.extend(_scan_manifest_t6(tuple(discovered_tools) if discovered_tools else ()))  # noqa: E501

        # Profile: remap discovered tool name through tool_name_map if present.
        # This ensures probes use the real server tool name instead of the
        # catalog placeholder ("ping") when the server uses a different name.
        if profile and profile.tool_name_map:
            real_tool_name = profile.apply_tool_name(real_tool_name)

        # For auth-testing categories (T1), probes must run without the auth
        # token — the test IS "does the server reject unauthenticated requests?"
        # Both auth_token and auth_header must be cleared: auth_header carries
        # the pre-formatted "Bearer <tok>" value set by profile, and takes
        # precedence over auth_token in the transport's _build_headers().
        no_auth_config = dataclasses.replace(config, auth_token=None, auth_header=None)

        ProbeRunner(config=config, target_url=target_url)
        for threat in threats:
            if threat.category.upper() in MIDDLEWARE_ONLY_CATEGORIES:
                continue  # middleware-only — not probeable from outside
            variables = {
                "target_url": target_url,
                "session_id": "cosai-scan",
                "tool_name": real_tool_name,
            }
            # T1 probes test auth enforcement — send them without the auth token.
            # pass_on_auth_reject=True: if the server rejects the unauthenticated
            # initialize, that IS correct behavior (auth enforced) → probe PASSES.
            is_auth_category = threat.category.upper() in AUTH_PROBE_CATEGORIES
            probe_config = no_auth_config if is_auth_category else config
            probe_runner = ProbeRunner(config=probe_config, target_url=target_url)

            # Find the DiscoveredTool matching the tool under test.
            # adaptive=False (--no-adaptive) disables synthesis entirely.
            active_discovered_tool = None
            if adaptive and discovered_tools:
                # Match by tool name; fall back to first tool when no exact match
                # (covers probes that substitute {{tool_name}} at runtime).
                active_discovered_tool = next(
                    (t for t in discovered_tools if t.name == real_tool_name),
                    discovered_tools[0] if discovered_tools else None,
                )

            # For adversarial threats, generate a per-threat canary and inject it.
            # After the probe runs, detect whether the canary appeared in the response.
            is_adversarial_threat = adv.enabled and "-ADV-" in threat.id.upper()
            if is_adversarial_threat:
                canary = adv.make_canary(threat.id)
                variables["canary"] = canary.value
            else:
                canary = None

            raw_results = probe_runner.run_threat(
                threat,
                variables=variables,
                pass_on_auth_reject=is_auth_category,
                discovered_tool=active_discovered_tool,
            )

            # Honour retry_after from any -32029 rate-limit response so
            # subsequent probes don't immediately hit the active rate limiter.
            # Falls back to probe_delay_seconds when no rate-limit was seen.
            retry_after = _extract_retry_after(raw_results)
            delay = retry_after if retry_after is not None else config.probe_delay_seconds
            if delay > 0:
                time.sleep(delay)

            if is_adversarial_threat and canary is not None:
                import html as _html_mod

                from cosai_mcp.adversarial.canary import detect_canary as _detect
                annotated: list[ProbeResult] = []
                for r in raw_results:
                    raw_body = _html_mod.unescape(r.response_body)
                    hit = _detect(raw_body, canary)
                    annotated.append(dataclasses.replace(r, canary_detected=hit) if hit else r)
                probe_results.extend(annotated)
            else:
                probe_results.extend(raw_results)

    # --- Stateful engine ---
    scenario_results: list[ScenarioResult] = []
    if engine in ("stateful", "all"):
        run_all = effective_categories is None
        _stateful_scenarios = [
            (frozenset({"T2"}), t2_privilege_escalation_chain),
            (frozenset({"T2"}), t2_confused_deputy),
            (frozenset({"T6"}), t6_tool_shadowing_mid_session),
            (frozenset({"T7"}), t7_session_token_binding),
            (frozenset({"T7"}), t7_session_revocation),
        ]
        profile_skip = profile.skip_categories if profile else frozenset()
        harness = StatefulHarness(
            config=config,
            method_overrides=config.stateful_method_overrides,
        )
        for cats, factory in _stateful_scenarios:
            if cats & profile_skip:
                continue  # profile declares this category not applicable
            if run_all or cats & (effective_categories or set()):
                scenario = factory()
                result = harness.run_scenario(scenario, target_url)
                scenario_results.append(result)

    # --- WP2: apply .cosai-baseline suppression (inside the scan path) ---
    # Loaded fail-closed: a malformed baseline raises ValueError, which the
    # CLI/Scanner map to exit code 2 — a broken baseline must NEVER be silently
    # treated as "suppress nothing" or "suppress everything".  Suppressed
    # findings remain in probe_results (flagged) so reports still list them;
    # only the exit-code computation excludes them.
    if baseline_path is not None:
        from cosai_mcp.baseline import Baseline, apply_baseline

        baseline = Baseline.load(baseline_path)
        probe_results = apply_baseline(probe_results, baseline)

    return ScanResult(
        target_url=target_url,
        threats=tuple(threats),
        probe_results=tuple(probe_results),
        scenario_results=tuple(scenario_results),
        scan_timestamp=scan_timestamp,
        catalog_hash=catalog_hash_,
        exit_code=_determine_exit_code(
            probe_results, scenario_results, fail_on, threat_severity
        ),
    )


def _scan_manifest_t4(
    discovered_tools: tuple,
) -> list[ProbeResult]:
    """Scan the tools/list manifest for T4 tool-poisoning patterns.

    Runs ToolPoisoningDetector on every tool returned by the target server and
    converts each finding into a ProbeResult so it surfaces in ScanResult and
    report output.  This is passive analysis (no probe sent) — it uses the
    manifest already fetched during discovery.

    Called from _run_scan after _run_discovery, inside the prober block.
    """
    import json as _json

    from cosai_mcp.harness.result import ProbeResult as _ProbeResult
    from cosai_mcp.middleware.boundary import ToolPoisoningDetector

    if not discovered_tools:
        return []

    # Deep-convert MappingProxyType → regular dict via JSON round-trip so that
    # ToolPoisoningDetector's isinstance(prop_def, dict) check works on nested schemas.
    tool_dicts: list[dict] = []
    for t in discovered_tools:
        try:
            schema = _json.loads(_json.dumps(dict(t.input_schema)))
        except (TypeError, ValueError):
            schema = {}
        tool_dicts.append({"name": t.name, "description": t.description, "inputSchema": schema})

    scan = ToolPoisoningDetector().scan(tool_dicts)
    results: list[ProbeResult] = []
    for i, finding in enumerate(scan.findings):
        results.append(_ProbeResult(
            probe_id=f"T04-manifest-p{i + 1}",
            threat_id="T04",
            passed=False,
            status_code=None,
            response_body=finding.excerpt,
            error=None,
            assertions=(),
            duration_seconds=0.0,
            inconclusive_reason=None,
        ))
    return results


def _scan_manifest_t9(
    discovered_tools: tuple,
) -> list[ProbeResult]:
    """Scan tools/list manifest for T9 Totem violations.

    Flags destructive tools missing two-stage commit.

    A tool is flagged when:
      - Its NAME (split on _ / - / space) contains a clearly-destructive verb, AND
      - It lacks a confirmed/dry_run/preview boolean parameter AND has no sibling
        plan/preview/dry-run tool in the manifest.

    Name-only matching (no description scanning) keeps false-positive rate low.
    Ambiguous verbs (run, execute, send, trigger) are intentionally excluded; only
    verbs that are unambiguously irreversible (delete, wipe, purge, etc.) are used.

    This is the passive structural check for TKA Totem compliance: no probabilistic
    component should hold commit authority over irreversible state without an explicit
    human confirmation step.
    """
    from cosai_mcp.harness.result import ProbeResult as _ProbeResult

    if not discovered_tools:
        return []

    # Clearly-destructive verbs only — ambiguous verbs (run, execute, send, publish,
    # trigger) excluded to keep false-positive rate low. A tool named "send_email"
    # may be write-only but is not unambiguously irreversible.
    _DESTRUCTIVE_VERBS: frozenset[str] = frozenset({
        "delete", "remove", "drop", "destroy", "wipe", "purge", "reset",
        "revoke", "terminate", "shutdown", "cancel", "truncate", "flush", "erase",
        "uninstall", "deactivate", "deregister",
    })

    _CONFIRM_PARAMS: frozenset[str] = frozenset({
        "confirmed", "confirm", "dry_run", "dryrun", "preview", "plan_only",
    })

    tool_names: frozenset[str] = frozenset(t.name for t in discovered_tools)
    results: list[ProbeResult] = []

    for i, tool in enumerate(discovered_tools):
        name_parts = re.split(r"[_\-\s/]", tool.name.lower())

        # Skip tools that ARE the preview/plan/dry-run variant — they are governance artifacts
        _PLAN_MARKERS = frozenset({"preview", "plan", "dry", "dryrun", "simulate", "check"})
        if any(part in _PLAN_MARKERS for part in name_parts):
            continue

        is_destructive = any(part in _DESTRUCTIVE_VERBS for part in name_parts)

        if not is_destructive:
            continue

        # Use the pre-computed boolean_params from discovery (avoids MappingProxyType issues)
        has_confirm_param = any(p.lower() in _CONFIRM_PARAMS for p in tool.boolean_params)

        sibling_candidates = [
            f"{tool.name}_preview", f"preview_{tool.name}",
            f"{tool.name}_plan", f"plan_{tool.name}",
            f"{tool.name}_dry_run",
        ]
        has_sibling = any(s in tool_names for s in sibling_candidates)

        if not has_confirm_param and not has_sibling:
            excerpt = (
                f"Tool '{tool.name}' performs destructive operations but "
                f"lacks a two-stage commit pattern (no confirmed/dry_run parameter "
                f"and no preview/plan sibling tool). "
                f"Remediation: add a confirmed: boolean parameter or expose a "
                f"'{tool.name}_preview' tool that returns a description without executing."
            )
            results.append(_ProbeResult(
                probe_id=f"T09-manifest-p{i + 1}",
                threat_id="T09",
                passed=False,
                status_code=None,
                response_body=excerpt,
                error=None,
                assertions=(),
                duration_seconds=0.0,
                inconclusive_reason=None,
            ))

    return results


# Reserved MCP method names a tool must never shadow or typosquat (T6).
# Compared case-insensitively against tool names via Levenshtein distance.
_RESERVED_MCP_METHODS: frozenset[str] = frozenset({
    "initialize", "ping", "tools/list", "tools/call",
    "resources/list", "resources/read", "resources/templates/list",
    "resources/subscribe", "resources/unsubscribe",
    "prompts/list", "prompts/get", "completion/complete",
    "logging/setlevel", "roots/list", "sampling/createmessage",
    "notifications/initialized", "notifications/cancelled",
})


def _scan_manifest_t5(
    discovered_tools: tuple,
    pii_strict: bool = False,
) -> list[ProbeResult]:
    """Passive T5 secret/PII scan over the discovered tools/list manifest.

    Tool names and descriptions are attacker-influenced content already fetched
    during discovery.  A credential or PII string embedded there is a T5 data-
    protection leak (and a tool-poisoning delivery vector).  ``PIIScrubber``
    redacts the value, so the report shows ``[REDACTED:<type>]`` — never the raw
    secret.

    To stay low-false-positive, only unambiguous credential types are reported by
    default; ``pii_strict`` additionally reports the broad-PII tier (SSN, IBAN,
    US phone, Luhn-corroborated PAN).  Example emails / documentation hostnames in
    descriptions are intentionally NOT flagged here.

    Passive — no probe sent.  Mirrors ``_scan_manifest_t4/t6/t9``.  Called from
    ``_run_scan`` whenever T5 is in scope.
    """
    from cosai_mcp.harness.result import make_probe_result
    from cosai_mcp.middleware.protection import (
        CREDENTIAL_TYPES,
        STRICT_PII_TYPES,
        PIIScrubber,
    )

    if not discovered_tools:
        return []

    # Reportable types for the MANIFEST scan = unambiguous credentials (+ strict
    # PII when enabled).  The scrubber also matches context-leak patterns
    # (internal_hostname, stack_trace) and email, but those are deliberately NOT
    # reported here: tool descriptions routinely mention internal hostnames and
    # example emails in legitimate documentation, so flagging them on the manifest
    # would be high-false-positive.  Those patterns are the RESPONSE-BODY context-
    # leak surface — detected by PIIScrubber when the T5 middleware is deployed in
    # the call path (see middleware/protection.py), not by this passive scan.
    reportable = CREDENTIAL_TYPES | (STRICT_PII_TYPES if pii_strict else frozenset())
    scrubber = PIIScrubber(pii_strict=pii_strict)
    results: list[ProbeResult] = []
    idx = 0
    for tool in discovered_tools:
        blob = f"{tool.name}\n{tool.description}"
        scrub = scrubber.scrub(blob)
        flagged = [f for f in scrub.findings if f.pii_type in reportable]
        if not flagged:
            continue
        idx += 1
        pii_types = sorted({f.pii_type for f in flagged})
        excerpt = (
            f"Tool '{tool.name}' manifest entry leaks {len(flagged)} secret/PII "
            f"value(s) [{', '.join(pii_types)}]. Redacted: {scrub.text}"
        )
        # make_probe_result HTML-escapes _body at ingestion (locked report rule).
        results.append(make_probe_result(
            probe_id=f"T05-manifest-p{idx}",
            threat_id="T05",
            passed=False,
            assertions=(),
            response={"_body": excerpt},
        ))
    return results


def _scan_manifest_t6(discovered_tools: tuple) -> list[ProbeResult]:
    """Passive T6 integrity scan over the discovered tools/list manifest.

    Replaces the vacuous T06-001/002 black-box probes (which only asserted that
    tools/list succeeds) with the real detection the coverage matrix claims
    (audit COV-02):
      1. Name COLLISION — two tools share an identical name (definite shadowing).
      2. RESERVED-method shadow — a tool name is within Levenshtein 1 of (or
         equals) a standard MCP method name (e.g. ``tools_call`` vs ``tools/call``).
      3. Near-collision — two distinct tool names within Levenshtein 1 of each
         other (typosquat / shadowing within the manifest).

    Each finding is a failing ProbeResult.  When the manifest is non-empty and
    nothing is flagged, one passing ProbeResult is emitted so a clean T6 grades
    PASS (the scan ran and found no integrity issue) rather than NOT_TESTED.
    """
    from cosai_mcp.harness.result import ProbeResult as _ProbeResult
    from cosai_mcp.middleware.integrity import fold_homoglyphs, levenshtein

    if not discovered_tools:
        return []

    names: list[str] = [t.name for t in discovered_tools]
    # Homoglyph-folded, lower-cased view used for shadow/near-collision distance
    # so a mixed-script squat (Cyrillic "rеad_file") is not invisible to the scan.
    _folded: dict[str, str] = {n: fold_homoglyphs(n).lower() for n in set(names)}
    results: list[ProbeResult] = []

    def _finding(idx: int, excerpt: str) -> ProbeResult:
        return _ProbeResult(
            probe_id=f"T06-manifest-p{idx}",
            threat_id="T06",
            passed=False,
            status_code=None,
            response_body=excerpt,
            error=None,
            assertions=(),
            duration_seconds=0.0,
            inconclusive_reason=None,
        )

    finding_idx = 0

    # 1. Exact-name collisions.
    seen: dict[str, int] = {}
    for name in names:
        seen[name] = seen.get(name, 0) + 1
    for name, count in seen.items():
        if count > 1:
            finding_idx += 1
            results.append(_finding(
                finding_idx,
                f"Tool name collision: '{name}' appears {count} times in the "
                f"manifest. Duplicate tool names allow one definition to shadow "
                f"another (T6). Tool names must be unique within a server.",
            ))

    # 2. Reserved-method shadowing (equal or Levenshtein ≤ 1), homoglyph-folded.
    for name in sorted(set(names)):
        lname = _folded[name]
        for method in _RESERVED_MCP_METHODS:
            d = levenshtein(lname, method)
            if d <= 1:
                finding_idx += 1
                kind = "matches" if d == 0 else "is within edit-distance 1 of"
                results.append(_finding(
                    finding_idx,
                    f"Tool '{name}' {kind} the reserved MCP method '{method}'. "
                    f"A tool whose name shadows a protocol method can intercept "
                    f"or impersonate that method (T6 shadowing).",
                ))
                break

    # 3. Near-collisions between distinct tool names (typosquat within manifest).
    #    Suppress benign pluralisation pairs (e.g. get_user / get_users), the
    #    dominant false positive — a trailing-'s' difference between two names is
    #    almost always an intentional singular/plural enumeration variant, not a
    #    typosquat.
    def _is_plural_variant(a: str, b: str) -> bool:
        lo, hi = sorted((a.lower(), b.lower()), key=len)
        return hi == lo + "s"

    unique = sorted(set(names))
    for i in range(len(unique)):
        for j in range(i + 1, len(unique)):
            # Compare homoglyph-folded forms: distance 0 means the two distinct
            # raw names are identical once look-alike characters are folded (a
            # homoglyph clone — the strongest squat signal); distance 1 is a
            # classic single-edit typosquat.
            d = levenshtein(_folded[unique[i]], _folded[unique[j]])
            if d <= 1 and not _is_plural_variant(unique[i], unique[j]):
                finding_idx += 1
                if d == 0:
                    detail = (
                        f"Tool names '{unique[i]}' and '{unique[j]}' are identical "
                        f"after folding look-alike (homoglyph) characters. One "
                        f"impersonates the other (T6 homoglyph squat)."
                    )
                else:
                    detail = (
                        f"Tool names '{unique[i]}' and '{unique[j]}' differ by a "
                        f"single edit (Levenshtein 1). One may be a typosquat or "
                        f"shadow of the other (T6). Verify both are intentional and "
                        f"distinct."
                    )
                results.append(_finding(finding_idx, detail))

    if not results:
        # Manifest scanned, no integrity issue — emit a clean PASS marker so the
        # category grades PASS, not NOT_TESTED.
        results.append(_ProbeResult(
            probe_id="T06-manifest-clean",
            threat_id="T06",
            passed=True,
            status_code=None,
            response_body=(
                f"Manifest integrity scan: {len(names)} tool(s) enumerated; no "
                f"name collisions, reserved-method shadows, or near-duplicate "
                f"names detected."
            ),
            error=None,
            assertions=(),
            duration_seconds=0.0,
            inconclusive_reason=None,
        ))

    return results


def _normalise_categories(categories: list[str] | None) -> frozenset[str] | None:
    """Return normalised category set, or None if all categories are requested."""
    if not categories:
        return None
    upper = frozenset(c.upper() for c in categories)
    if upper == {"ALL"}:
        return None
    return upper


# ---------------------------------------------------------------------------
# Public Scanner class
# ---------------------------------------------------------------------------

class Scanner:
    """Python API for programmatic cosai-mcp usage.

    Example::

        from cosai_mcp import Scanner
        results = Scanner("http://localhost:8000").run(categories=["T1", "T4"])

    Or with an explicit configuration object::

        from cosai_mcp import Scanner, ScanConfig
        results = Scanner(
            ScanConfig(target="http://localhost:8000", categories=["T1"], fail_on="high")
        ).run()

    Raises:
        ValueError: invalid target URL (missing scheme or hostname)
        TargetUnreachableError: TCP connect to target failed
        ScannerInternalError: unexpected error in the scan engine
    """

    def __init__(
        self,
        target: str | ScanConfig,
        categories: list[str] | None = None,
        engine: str = "all",
        allow_custom_catalog: bool = False,
        probe_timeout_seconds: float = 30.0,
        catalog_root: Path | None = None,
        allow_private_targets: bool = True,
        auth_token: str | None = None,
        mcp_path: str = "/mcp",
        adaptive: bool = True,
        profile: ServerProfile | None = None,
        adversarial_mode: AdversarialMode | None = None,
        probe_delay_seconds: float = 0.0,
        baseline_path: Path | None = None,
        fail_on: str = "critical",
        pii_strict: bool = False,
        stateful_method_overrides: dict[str, str] | None = None,
    ) -> None:
        # Accept either a full target URL string (original form) or a ScanConfig
        # (documented public form).  When a ScanConfig is passed, its fields
        # populate the corresponding instance attributes; explicit keyword
        # arguments are ignored in favour of the config's values.
        if isinstance(target, ScanConfig):
            cfg = target
            self.target = cfg.target or f"http://{cfg.target_host}:{cfg.target_port}"
            self.categories = cfg.categories
            self.fail_on = cfg.fail_on
            self.probe_timeout_seconds = cfg.probe_timeout_seconds
            self.allow_private_targets = cfg.allow_private_targets
            self.auth_token = cfg.auth_token
            self.mcp_path = cfg.mcp_path
            self.probe_delay_seconds = cfg.probe_delay_seconds
            self.engine = engine
            self.allow_custom_catalog = allow_custom_catalog
            self.catalog_root = catalog_root or CATALOG_ROOT
            self.adaptive = adaptive
            self.profile = profile
            self.adversarial_mode = adversarial_mode
            self.baseline_path = baseline_path
            self.pii_strict = cfg.pii_strict
            self.stateful_method_overrides = cfg.stateful_method_overrides
            return

        self.target = target
        self.fail_on = fail_on
        self.categories = categories
        self.engine = engine
        self.allow_custom_catalog = allow_custom_catalog
        self.probe_timeout_seconds = probe_timeout_seconds
        self.catalog_root = catalog_root or CATALOG_ROOT
        self.allow_private_targets = allow_private_targets
        self.auth_token = auth_token
        self.mcp_path = mcp_path
        self.adaptive = adaptive
        self.profile = profile
        self.adversarial_mode = adversarial_mode
        self.probe_delay_seconds = probe_delay_seconds
        self.baseline_path = baseline_path
        self.pii_strict = pii_strict
        self.stateful_method_overrides = stateful_method_overrides

    def run(self, categories: list[str] | None = None) -> ScanResult:
        """Run a complete scan and return a :class:`ScanResult`.

        ``categories`` overrides the instance-level setting for this call.

        Raises:
            ValueError: target URL is malformed
            TargetUnreachableError: TCP connect failed
            ScannerInternalError: unexpected internal error
        """
        effective_categories = categories if categories is not None else self.categories
        try:
            return _run_scan(
                target=self.target,
                categories=effective_categories,
                engine=self.engine,
                allow_custom_catalog=self.allow_custom_catalog,
                probe_timeout_seconds=self.probe_timeout_seconds,
                catalog_root=self.catalog_root,
                fail_on=self.fail_on,
                allow_private_targets=self.allow_private_targets,
                auth_token=self.auth_token,
                mcp_path=self.mcp_path,
                adaptive=self.adaptive,
                profile=self.profile,
                adversarial_mode=self.adversarial_mode,
                probe_delay_seconds=self.probe_delay_seconds,
                baseline_path=self.baseline_path,
                pii_strict=self.pii_strict,
                stateful_method_overrides=self.stateful_method_overrides,
            )
        except (ValueError, TargetUnreachableError):
            raise  # let typed exceptions propagate as-is
        except Exception as exc:
            raise ScannerInternalError(
                f"Unexpected scan engine error: {exc}"
            ) from exc
