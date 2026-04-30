"""Python API — Scanner class, ScanResult, scrub_env, COVERAGE_MATRIX."""
from __future__ import annotations

import dataclasses
import datetime
import hashlib
import os
import re
import socket
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
    t7_session_token_binding,
)

# ---------------------------------------------------------------------------
# Coverage matrix — locked by three-engine architecture decision
# ---------------------------------------------------------------------------

COVERAGE_MATRIX: dict[str, str] = {
    "T1":  "black-box-prober",
    "T2":  "black-box-partial+stateful",
    "T3":  "black-box-prober",
    "T4":  "middleware-only",
    "T5":  "black-box-partial",
    "T6":  "black-box-partial+stateful",
    "T7":  "stateful",
    "T8":  "black-box-prober",
    "T9":  "middleware-only",
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


def scrub_env(env: dict[str, str] | None = None) -> dict[str, str]:
    """Return a copy of ``env`` with sensitive vars removed.

    If ``env`` is None, reads ``os.environ`` at call time into a fresh dict.
    Never mutates the source mapping.
    """
    source = env if env is not None else dict(os.environ)
    return {k: v for k, v in source.items() if not any(p.match(k) for p in _SCRUB_PATTERNS)}


def _apply_env_scrub() -> None:
    """Mutate ``os.environ`` in-place — CLI-only, called once at process start.

    Must NOT be called from library code (Scanner.run(), _run_scan()).
    Library paths should pass scrub_env() output to subprocess constructors.
    """
    for key in list(os.environ.keys()):
        if any(p.match(key) for p in _SCRUB_PATTERNS):
            del os.environ[key]


# ---------------------------------------------------------------------------
# Pre-scan tool discovery (P10 — replaces _get_first_tool_name)
# ---------------------------------------------------------------------------

def _run_discovery(
    target_url: str,
    config: ScanConfig,
) -> tuple[str, object]:
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
    from cosai_mcp.discovery import discover_tools, DiscoveredTool

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
    except (OSError, socket.timeout) as exc:
        raise TargetUnreachableError(
            f"Cannot reach {host}:{port} — {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Catalog helper
# ---------------------------------------------------------------------------

CATALOG_ROOT: Path = Path(__file__).parent.parent / "catalog"


def _catalog_hash(threats: list[ThreatDefinition]) -> str:
    """SHA-256 fingerprint of the loaded threat IDs (sorted for determinism)."""
    ids = sorted(t.id for t in threats)
    return hashlib.sha256("|".join(ids).encode()).hexdigest()


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
        failed_probes = any(not r.passed for r in self.probe_results if r.error is None)
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

    # Probe errors (scanner crash in subprocess) → exit 2
    if any(r.error is not None for r in probe_results):
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
            and _above_threshold(r)
            for r in probe_results
        )
    else:
        failed_probes = any(
            not r.passed
            and r.error is None
            and r.inconclusive_reason is None  # inconclusive ≠ finding
            for r in probe_results
        )

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
    mcp_path: str = "/mcp",
    adaptive: bool = True,
    profile: ServerProfile | None = None,
    adversarial_mode: AdversarialMode | None = None,
    probe_delay_seconds: float = 0.0,
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
    scan_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

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
        mcp_path=effective_mcp_path,
        auth_header=effective_auth_header,
        probe_delay_seconds=probe_delay_seconds,
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

        runner = ProbeRunner(config=config, target_url=target_url)
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

            if config.probe_delay_seconds > 0:
                import time as _time
                _time.sleep(config.probe_delay_seconds)

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
        ]
        profile_skip = profile.skip_categories if profile else frozenset()
        harness = StatefulHarness(config=config)
        for cats, factory in _stateful_scenarios:
            if cats & profile_skip:
                continue  # profile declares this category not applicable
            if run_all or cats & (effective_categories or set()):
                scenario = factory()
                result = harness.run_scenario(scenario, target_url)
                scenario_results.append(result)

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

    Raises:
        ValueError: invalid target URL (missing scheme or hostname)
        TargetUnreachableError: TCP connect to target failed
        ScannerInternalError: unexpected error in the scan engine
    """

    def __init__(
        self,
        target: str,
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
    ) -> None:
        self.target = target
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
                fail_on="critical",
                allow_private_targets=self.allow_private_targets,
                auth_token=self.auth_token,
                mcp_path=self.mcp_path,
                adaptive=self.adaptive,
                profile=self.profile,
                adversarial_mode=self.adversarial_mode,
                probe_delay_seconds=self.probe_delay_seconds,
            )
        except (ValueError, TargetUnreachableError):
            raise  # let typed exceptions propagate as-is
        except Exception as exc:
            raise ScannerInternalError(
                f"Unexpected scan engine error: {exc}"
            ) from exc
