"""cosai CLI — `cosai scan` and `cosai audit verify`."""
from __future__ import annotations

import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import click

from cosai_mcp.adversarial import AdversarialMode
from cosai_mcp.api import (
    CATALOG_ROOT,
    COVERAGE_MATRIX,
    MIDDLEWARE_ONLY_CATEGORIES,
    ScanResult,
    _apply_env_scrub,
    _parse_target,
    _run_scan,
    check_reachable,
)
from cosai_mcp.exceptions import TargetUnreachableError
from cosai_mcp.profiles import BUILTIN_PROFILES, resolve_profile
from cosai_mcp.profiles.models import ServerProfile
from cosai_mcp.report.sign import OrgSigningKeyError
from cosai_mcp.report.verify import VerifyStatus, verify_audit_log

# ---------------------------------------------------------------------------
# Top-level CLI group
# ---------------------------------------------------------------------------

class _AdvancedHelpCommand(click.Command):
    """A command whose ``hidden=True`` options are revealed by ``--help-advanced``.

    Keeps the default ``--help`` output to the ~8 core flags while every
    advanced flag stays fully functional (no removal — the locked adoption
    paths and CI integrations depend on them). ``--help-advanced`` prints the
    complete option list.
    """

    #: ctx.meta key carrying the per-invocation "show advanced" signal.
    #: Stored on the Context (NOT the Command) so it can never leak between
    #: invocations — Click reuses the same Command instance in-process, so
    #: instance/class state would make a later plain --help render advanced.
    _META_KEY = "cosai.show_advanced_help"

    def format_options(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        show_advanced = bool(ctx.meta.get(self._META_KEY, False))
        opts = []
        for param in self.get_params(ctx):
            if not isinstance(param, click.Option):
                continue
            rec = param.get_help_record(ctx)
            if rec is None and show_advanced and param.hidden:
                # Hidden option — surfaced only under --help-advanced.
                param.hidden = False
                try:
                    rec = param.get_help_record(ctx)
                finally:
                    param.hidden = True
            if rec is None:
                continue
            opts.append(rec)
        if opts:
            with formatter.section("Options"):
                formatter.write_dl(opts)
        if not show_advanced:
            formatter.write_paragraph()
            formatter.write_text(
                "Run with --help-advanced to see all options "
                "(reporting, adversarial mode, profiles, IR/SIEM, timeouts)."
            )


def _parse_tool_allowlist(raw: str | None) -> tuple[str, ...] | None:
    """Parse the comma-separated --tool-allowlist value into a tuple of names."""
    if raw is None:
        return None
    names = [n.strip() for n in raw.split(",") if n.strip()]
    if not names:
        return None
    seen: dict[str, None] = {}
    for n in names:
        seen.setdefault(n, None)
    return tuple(seen)


def _help_advanced_cb(ctx: click.Context, param: click.Parameter, value: bool) -> None:
    if not value or ctx.resilient_parsing:
        return
    # Per-invocation signal on ctx.meta (never on the Command instance, which
    # Click reuses in-process — instance state would leak into a later
    # plain --help and wrongly reveal hidden options).
    ctx.meta[_AdvancedHelpCommand._META_KEY] = True
    click.echo(ctx.command.get_help(ctx))
    ctx.exit()


def _parse_method_overrides(raw: str | None) -> dict[str, str] | None:
    """Parse a ``placeholder=real`` comma-separated list into a mapping.

    Mirrors the tolerant parsing used elsewhere in the CLI: each comma-separated
    item is stripped; blank items are skipped; each item is split on the FIRST
    ``=`` only (tool/method names may contain ``/``, e.g.
    ``session/terminate=session/delete``); items with no ``=`` are ignored as
    malformed. Later duplicate keys win. Returns ``None`` when nothing usable
    remains so the scan path keeps its no-override default.
    """
    if not raw:
        return None
    out: dict[str, str] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item or "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or not value:
            continue
        out[key] = value
    return out or None


@click.group()
def main() -> None:
    """cosai-mcp: MCP security scanner for the CoSAI threat taxonomy.

    9 categories scanned zero-config; T4/T9/T12 require the cosai-mcp
    middleware deployed in the target.
    """


# ---------------------------------------------------------------------------
# cosai scan
# ---------------------------------------------------------------------------

@main.command(cls=_AdvancedHelpCommand)
@click.option(
    "--help-advanced",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=_help_advanced_cb,
    help="Show every option (advanced reporting, adversarial, IR/SIEM, tuning).",
)
@click.argument("target", required=False, default=None)
@click.option("--targets", "targets_path", type=click.Path(exists=True, dir_okay=False),
              default=None, hidden=True,
              help="Path to a plain-text target list (one MCP server URL per line; "
                   "blank lines and '#' comments ignored) — scan every target with "
                   "bounded concurrency and emit one aggregated exit code, one "
                   "merged SARIF report, and one roll-up scorecard. Mutually "
                   "exclusive with TARGET. Only the core scan options (categories, "
                   "engine, fail-on, catalog-root, allow-private-targets, "
                   "probe-timeout, pii-strict, expected-catalog-hash) apply in "
                   "fleet mode.")
@click.option("--fleet-concurrency", type=int, default=5, show_default=True, hidden=True,
              help="Max targets scanned in parallel in fleet mode (--targets).")
@click.option("--fleet-target-timeout", type=float, default=600.0, show_default=True,
              hidden=True,
              help="Max seconds to wait on any single target in fleet mode before "
                   "recording it as timed out and moving on — bounds the whole "
                   "fleet run against one hung/hostile target.")
@click.option(
    "--categories",
    default="all",
    show_default=True,
    help="Comma-separated T-categories to scan (e.g. T1,T3) or 'all'.",
)
@click.option(
    "--engine",
    type=click.Choice(["prober", "stateful", "all"], case_sensitive=False),
    default="all",
    show_default=True,
    help="Scan engine to use.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    default="high",
    show_default=True,
    help="Minimum severity that causes exit code 1. Defaults to 'high' so HIGH "
         "auth/session findings fail the gate (matches the reusable "
         "cosai-gate.yml default); pass --fail-on=critical to gate only on "
         "critical.",
)
@click.option("--baseline", "baseline_path", type=click.Path(exists=True, dir_okay=False),
              default=None,
              help="Path to a .cosai-baseline file of accepted-finding "
                   "fingerprints. Matched findings are excluded from the exit "
                   "code but still listed in every report. A malformed baseline "
                   "fails the scan (exit 2) — never silently ignored.")
@click.option("--allow-custom-catalog", is_flag=True, default=False, hidden=True,
              help="Load threat definitions from catalog/custom/ in addition to official/.")
@click.option("--report-sarif", type=click.Path(), default=None,
              help="Write SARIF 2.1.0 report to this file path.")
@click.option("--report-html", type=click.Path(), default=None,
              help="Write HTML report to this file path. "
                   "Defaults to cosai-report.html in the current directory.")
@click.option("--no-report", is_flag=True, default=False, hidden=True,
              help="Suppress the default cosai-report.html output.")
@click.option(
    "--report-mode",
    type=click.Choice(["full", "developer", "executive", "ci"], case_sensitive=False),
    default="full",
    show_default=True,
    help=(
        "Report detail level. "
        "full: findings + collapsible remediation tabs (default). "
        "developer: same as full with remediation expanded by default. "
        "executive: summary grid only, no per-finding code or detail. "
        "ci: suppress HTML output (plain text summary only)."
    ),
)
@click.option("--report-csv", type=click.Path(), default=None, hidden=True,
              help="Write CSV findings report to this file path (Excel-compatible).")
@click.option("--report-coverage", is_flag=True, default=False, hidden=True,
              help="Print coverage matrix showing which engine covers each category.")
@click.option("--probe-timeout", type=float, default=30.0, show_default=True, hidden=True,
              help="Per-probe timeout in seconds.")
@click.option("--probe-delay", type=float, default=0.0, show_default=True, hidden=True,
              help="Seconds to sleep between probes. Use when the target server "
                   "enforces rate limits on new MCP sessions.")
@click.option("--allow-private-targets/--block-private-targets", default=True, hidden=True,
              help="Allow scanning RFC1918/loopback targets (default: allowed for dev use). "
                   "Use --block-private-targets in CI to enforce public-target-only policy.")
@click.option("--catalog-root", type=click.Path(exists=True, file_okay=False), default=None, hidden=True,  # noqa: E501
              help="Override catalog root directory (default: ./catalog).")
@click.option("--auth-token", default=None, envvar="COSAI_AUTH_TOKEN", hidden=True,
              help="Bearer token for servers that require auth on the MCP handshake.")
@click.option("--read-token", default=None, envvar="COSAI_READ_TOKEN", hidden=True,
              help="Read-scoped Bearer token used by scope-enforcement probes "
                   "(T02-005): the scanner calls write-capable tools with this "
                   "token and asserts the server rejects them. Without it those "
                   "probes are reported INCONCLUSIVE.")
@click.option("--mcp-path", default="/mcp", show_default=True, hidden=True,
              help="URL path of the MCP endpoint (override if server uses a custom path).")
@click.option("--no-adaptive", is_flag=True, default=False, hidden=True,
              help="Disable adaptive probe synthesis. Forces static catalog payloads — "
                   "use for hermetic tests or when server schema is adversarially crafted.")
@click.option("--pii-strict", is_flag=True, default=False, hidden=True,
              help="Widen the T5 secret/PII manifest scan to the broad-PII tier "
                   "(SSN, IBAN, US phone, Luhn-validated PAN) on top of the always-on "
                   "anchored-credential tier. Off by default to keep scans fast.")
@click.option("--profile", default=None,
              help="Server profile name (e.g. mnemo, fastmcp). Optional — omit for a "
                   "generic scan. Sets mcp_path, auth header format, tool name map, "
                   "and skip_categories automatically.")
@click.option("--allow-custom-profiles", is_flag=True, default=False, hidden=True,
              help="Load profile from .cosai/profiles/<name>.py or ~/.cosai/profiles/<name>.py "
                   "in addition to built-in profiles.")
@click.option("--adversarial", is_flag=True, default=False, hidden=True,
              help="Enable adversarial probe mode (canary-only payloads). "
                   "Requires --i-own-this-target. "
                   "ONLY use against targets you own and have authorization to test.")
@click.option("--i-own-this-target", "i_own_this_target", default=None, hidden=True,
              help="Ownership declaration for adversarial mode. "
                   "Must contain the target hostname verbatim. "
                   "Example: --i-own-this-target=myserver.example.com")
@click.option("--allow-stateful-adversarial", is_flag=True, default=False, hidden=True,
              help="Allow stateful adversarial probes that modify server state. "
                   "Only effective with --adversarial.")
@click.option("--report-adversarial-html", type=click.Path(), default=None, hidden=True,
              help="Write the adversarial probe report to this path "
                   "(default: cosai-adversarial-report.html when --adversarial is set).")
@click.option("--skip-reachability", is_flag=True, default=False, hidden=True,
              help="Skip the initial TCP reachability check (testing only).")
@click.option(
    "--emit-to",
    default=None,
    envvar="COSAI_EMIT_TO",
    hidden=True,
    help=(
        "SIEM/SOAR webhook URL.  When set, every probe result is emitted as an "
        "OCSF Detection Finding (class_uid 2004) to this endpoint via HTTP POST. "
        "Failures to deliver are logged as warnings but do not affect exit code."
    ),
)
@click.option(
    "--emit-auth-header",
    default=None,
    envvar="COSAI_EMIT_AUTH",
    hidden=True,
    help=(
        "Authorization header value for the SIEM webhook "
        "(e.g. 'Bearer <token>'). Also read from COSAI_EMIT_AUTH env var."
    ),
)
@click.option(
    "--anomaly-threshold",
    type=int,
    default=10,
    show_default=True,
    hidden=True,
    help="Max findings in the rolling window before an anomaly alert is emitted.",
)
@click.option(
    "--critical-burst-threshold",
    type=int,
    default=3,
    show_default=True,
    hidden=True,
    help="Max critical findings in the rolling window before a burst alert fires.",
)
@click.option("--contain-on-anomaly", is_flag=True, default=False, hidden=True,
              help="Trigger IR containment automatically when anomaly thresholds are exceeded.")
@click.option("--ir-report", type=click.Path(), default=None, hidden=True,
              help="Write a JSON incident report to this path when findings are detected.")
@click.option("--scorecard", "scorecard_path", type=click.Path(), default=None, hidden=True,
              help="Write a signed conformance scorecard JSON to this path.")
@click.option("--no-sign-scorecard", is_flag=True, default=False, hidden=True,
              help="Produce an unsigned scorecard (skip Ed25519 signing).")
@click.option("--sigstore-sign", is_flag=True, default=False, hidden=True,
              help="Additionally sign the scorecard with Sigstore keyless signing "
                   "(ENT-P0-2), writing a <scorecard>.sigstore.json sidecar bundle. "
                   "Requires the optional 'sigstore' package (pip install "
                   "cosai-mcp[sigstore]) and a real ambient OIDC identity (GitHub "
                   "Actions with permissions: id-token: write, GitLab CI, or an "
                   "interactive OIDC login) — fails loudly (exit 2) if either is "
                   "missing, never silently skips. Does not replace the existing "
                   "Ed25519 signature; both are written.")
@click.option("--sigstore-staging", is_flag=True, default=False, hidden=True,
              help="Use Sigstore's public staging instance instead of production "
                   "(testing only) — applies to --sigstore-sign.")
@click.option("--experimental", is_flag=True, default=False, hidden=True,
              help="Enable experimental Tracks B/D (SIEM/OCSF telemetry "
                   "emission and IR containment). These are NOT part of the "
                   "default scan surface and may change or be removed.")
@click.option("--method-overrides", default=None, hidden=True,
              help="Comma-separated placeholder=real map for the stateful "
                   "conformance harness, e.g. "
                   "'admin_delete=purge,session/terminate=session/delete'. "
                   "Remaps scenario tool/method names onto the equivalent tools "
                   "this server actually exposes, so T2/T6/T7 scenarios run "
                   "instead of reporting INCONCLUSIVE. Split on the first '=' "
                   "only (names may contain '/'); malformed items are ignored.")
@click.option("--tool-allowlist", "tool_allowlist", default=None, hidden=True,
              help="Comma-separated list of operator-approved tool names for T11 "
                   "supply-chain checks. When set, any discovered tool not on this "
                   "list (unexpected) or within Levenshtein distance 1 (typosquat) "
                   "is flagged. Without it, T11 reports INCONCLUSIVE.")
@click.option("--expected-catalog-hash", "expected_catalog_hash", default=None, hidden=True,
              help="SHA-256 hex digest the loaded threat catalog must match (see "
                   "'Catalog hash:' in scan output). Pins a release gate to an exact, "
                   "reviewed catalog: a mismatch refuses to scan (exit 2) before any "
                   "probe runs, instead of silently running against a changed ruleset.")
@click.option("--protocol-era", "protocol_era",
              type=click.Choice(["auto", "modern", "legacy"]), default="auto",
              show_default=True, hidden=True,
              help="MCP protocol era to speak. 'auto' probes the 2026-07-28 stateless "
                   "server/discover first and falls back to the legacy initialize "
                   "handshake; 'modern' / 'legacy' pin one era.")
def scan(
    target: str | None,
    targets_path: str | None,
    fleet_concurrency: int,
    fleet_target_timeout: float,
    categories: str,
    engine: str,
    fail_on: str,
    baseline_path: str | None,
    allow_custom_catalog: bool,
    report_sarif: str | None,
    report_html: str | None,
    no_report: bool,
    report_mode: str,
    report_csv: str | None,
    report_coverage: bool,
    probe_timeout: float,
    probe_delay: float,
    allow_private_targets: bool,
    catalog_root: str | None,
    auth_token: str | None,
    read_token: str | None,
    mcp_path: str,
    no_adaptive: bool,
    pii_strict: bool,
    profile: str | None,
    allow_custom_profiles: bool,
    adversarial: bool,
    i_own_this_target: str | None,
    allow_stateful_adversarial: bool,
    report_adversarial_html: str | None,
    skip_reachability: bool,
    contain_on_anomaly: bool,
    ir_report: str | None,
    emit_to: str | None,
    emit_auth_header: str | None,
    anomaly_threshold: int,
    critical_burst_threshold: int,
    scorecard_path: str | None,
    no_sign_scorecard: bool,
    sigstore_sign: bool,
    sigstore_staging: bool,
    experimental: bool,
    method_overrides: str | None,
    tool_allowlist: str | None,
    expected_catalog_hash: str | None,
    protocol_era: str,
) -> None:
    """Scan a target MCP server for CoSAI threat categories T1–T12.

    TARGET is the base URL of the MCP server, e.g. http://localhost:8000.

    Exit codes:
        0  Clean — no findings at or above --fail-on threshold.
        1  Findings detected at or above --fail-on threshold.
        2  Scanner internal error (fail-closed; treated as failure by CI).
        3  Target unreachable.
    """
    # -- WP3: Tracks B/D are experimental and OFF the default scan surface --
    # Using any SIEM/OCSF (Track B) or IR-containment (Track D) flag without
    # --experimental fails closed (exit 2) rather than silently ignoring the
    # flag: a user who passed --emit-to / --ir-report and got NO emission
    # would wrongly believe their SIEM was wired.
    _experimental_flags_used = [
        name for name, used in (
            ("--emit-to", bool(emit_to)),
            ("--emit-auth-header", bool(emit_auth_header)),
            ("--contain-on-anomaly", bool(contain_on_anomaly)),
            ("--ir-report", bool(ir_report)),
        ) if used
    ]
    if _experimental_flags_used and not experimental:
        click.echo(
            "[ERROR] "
            + ", ".join(_experimental_flags_used)
            + " require --experimental (Tracks B/D: SIEM/OCSF telemetry and "
            "IR containment are experimental and not part of the default "
            "scan surface).",
            err=True,
        )
        sys.exit(2)
    # Scrub sensitive env vars from this process before spawning subprocesses.
    # CLI-only: one-time mutation of os.environ at process start is acceptable
    # because this process exits when the scan completes (FIX [2]).
    _apply_env_scrub()

    if report_coverage:
        _print_coverage_matrix()

    cat_list = [c.strip() for c in categories.split(",") if c.strip()] if categories != "all" else None  # noqa: E501
    effective_catalog_root = Path(catalog_root) if catalog_root else CATALOG_ROOT

    # -- Validate --expected-catalog-hash before it ever reaches _run_scan --
    # An empty string (e.g. an unset CI variable interpolated as "") must not
    # fall through to the generic "expected ''" mismatch message — that's an
    # operator/CI mistake, not a real pin, and deserves its own clear error.
    if expected_catalog_hash is not None and expected_catalog_hash.strip() == "":
        click.echo(
            "[ERROR] --expected-catalog-hash was passed an empty value. "
            "Omit the flag entirely to scan unpinned, or pass the real "
            "64-character catalog hash to pin a release gate.",
            err=True,
        )
        sys.exit(2)

    # -- ENT-P0-2: --sigstore-sign / --sigstore-staging only make sense
    # bound to a scorecard artifact — signing "nothing" silently is not an
    # option this project offers. --
    if sigstore_sign and not scorecard_path:
        click.echo(
            "[ERROR] --sigstore-sign requires --scorecard <path> — there is "
            "no scorecard artifact to sign otherwise.",
            err=True,
        )
        sys.exit(2)
    if sigstore_staging and not sigstore_sign:
        click.echo(
            "[ERROR] --sigstore-staging requires --sigstore-sign.",
            err=True,
        )
        sys.exit(2)

    # -- ENT-P0-4: fleet mode branches off before any single-target-only
    # logic (profiles, adversarial mode, the single-target reachability
    # check) — each target gets its own reachability check inside
    # run_fleet_scan, isolated per-target. --
    if targets_path:
        if target:
            click.echo(
                "[ERROR] Pass either TARGET or --targets <file>, not both.", err=True
            )
            sys.exit(2)
        # Panel-review finding (ENT-P0-4): these flags have per-server
        # semantics that don't generalize across a fleet of DIFFERENT
        # targets (a profile/baseline/method-override tuned for one server,
        # an ownership declaration naming one hostname) — silently dropping
        # them produced a false-green (e.g. --auth-token ignored, every
        # target scanned unauthenticated with no warning). Fail loudly
        # instead of guessing what the operator meant.
        _fleet_unsupported = [
            name for name, used in (
                ("--profile", bool(profile)),
                ("--adversarial", adversarial),
                ("--i-own-this-target", bool(i_own_this_target)),
                ("--allow-stateful-adversarial", allow_stateful_adversarial),
                ("--baseline", bool(baseline_path)),
                ("--method-overrides", bool(method_overrides)),
                # Fleet targets are era-detected individually; a single pinned
                # era would silently be ignored (defense FIX 1).
                ("--protocol-era", protocol_era != "auto"),
            ) if used
        ]
        if _fleet_unsupported:
            click.echo(
                "[ERROR] " + ", ".join(_fleet_unsupported) + " are not supported "
                "with --targets (fleet mode) — these options have per-server "
                "semantics that don't generalize across a fleet of different "
                "targets. Scan each such target individually instead.",
                err=True,
            )
            sys.exit(2)
        # --sigstore-sign signs a single Scorecard object (see
        # scorecard/sigstore_signing.py); the aggregated fleet scorecard
        # (build_fleet_scorecard) wraps N per-target scorecards in a
        # different shape and has no defined Sigstore signing semantics yet
        # — reject rather than silently sign nothing, or invent behavior.
        if sigstore_sign:
            click.echo(
                "[ERROR] --sigstore-sign is not yet supported with --targets "
                "(fleet mode) — Sigstore signing applies to a single "
                "scorecard artifact. Scan each target individually instead.",
                err=True,
            )
            sys.exit(2)
        _run_fleet_scan_and_exit(
            targets_path=Path(targets_path),
            max_concurrency=fleet_concurrency,
            per_target_timeout=fleet_target_timeout,
            categories=cat_list,
            engine=engine,
            allow_custom_catalog=allow_custom_catalog,
            probe_timeout_seconds=probe_timeout,
            catalog_root=effective_catalog_root,
            fail_on=fail_on,
            allow_private_targets=allow_private_targets,
            pii_strict=pii_strict,
            expected_catalog_hash=expected_catalog_hash,
            auth_token=auth_token,
            read_token=read_token,
            mcp_path=mcp_path,
            probe_delay_seconds=probe_delay,
            adaptive=not no_adaptive,
            tool_allowlist=_parse_tool_allowlist(tool_allowlist),
            skip_reachability=skip_reachability,
            report_sarif=report_sarif,
            scorecard_path=scorecard_path,
            no_sign_scorecard=no_sign_scorecard,
        )
        return

    if not target:
        click.echo(
            "[ERROR] Missing argument TARGET (or pass --targets <file> for a fleet scan).",
            err=True,
        )
        sys.exit(2)

    # -- Resolve server profile (exit 2 on unknown name or bad custom file) --
    resolved_profile: ServerProfile | None = None
    if profile:
        try:
            resolved_profile = resolve_profile(
                profile,
                allow_custom=allow_custom_profiles,
                project_root=Path.cwd(),
            )
        except ValueError as exc:
            click.echo(f"[ERROR] Profile error: {exc}", err=True)
            sys.exit(2)

    # -- Build adversarial mode config (validation deferred to _run_scan) --
    adv_mode: AdversarialMode | None = None
    if adversarial:
        adv_mode = AdversarialMode(
            enabled=True,
            ownership_declaration=i_own_this_target,
            allow_stateful=allow_stateful_adversarial,
            scan_id="",  # populated by _run_scan via scan_id uuid
        )

    # -- Reachability check (exit 3 path) --
    if not skip_reachability:
        try:
            host, port, _ = _parse_target(target)
            check_reachable(host, port)
        except TargetUnreachableError as exc:
            click.echo(f"[ERROR] Target unreachable: {exc}", err=True)
            sys.exit(3)
        except ValueError as exc:
            click.echo(f"[ERROR] Invalid target URL: {exc}", err=True)
            sys.exit(2)

    if allow_custom_catalog:
        click.echo(
            "[WARNING] --allow-custom-catalog is set: custom catalog files are loaded "
            "without Ed25519 signature verification and will be marked UNTRUSTED in reports.",
            err=True,
        )

    # -- Run scan (exit 2 on scanner internal error) --
    try:
        result = _run_scan(
            target=target,
            categories=cat_list,
            engine=engine,
            allow_custom_catalog=allow_custom_catalog,
            probe_timeout_seconds=probe_timeout,
            catalog_root=effective_catalog_root,
            fail_on=fail_on,
            allow_private_targets=allow_private_targets,
            auth_token=auth_token,
            read_token=read_token,
            mcp_path=mcp_path,
            adaptive=not no_adaptive,
            profile=resolved_profile,
            adversarial_mode=adv_mode,
            probe_delay_seconds=probe_delay,
            baseline_path=Path(baseline_path) if baseline_path else None,
            pii_strict=pii_strict,
            stateful_method_overrides=_parse_method_overrides(method_overrides),
            tool_allowlist=_parse_tool_allowlist(tool_allowlist),
            expected_catalog_hash=expected_catalog_hash,
            protocol_era=protocol_era,
        )
    except ValueError as exc:
        # Includes adversarial dual opt-in failures, a malformed
        # .cosai-baseline, and a --expected-catalog-hash mismatch
        # (fail-closed: none of these must be silently ignored).
        click.echo(f"[ERROR] {exc}", err=True)
        sys.exit(2)
    except TargetUnreachableError as exc:
        click.echo(f"[ERROR] Target unreachable during scan: {exc}", err=True)
        sys.exit(3)
    except Exception as exc:  # noqa: BLE001
        click.echo(f"[ERROR] Scanner internal error: {exc}", err=True)
        sys.exit(2)

    # -- Emit summary --
    _print_scan_summary(result, fail_on=fail_on)

    # -- SIEM/SOAR telemetry emission (Track B — experimental, WP3) --
    if emit_to and experimental:
        _emit_scan_telemetry(
            result=result,
            target=target,
            emit_to=emit_to,
            emit_auth_header=emit_auth_header,
            anomaly_threshold=anomaly_threshold,
            critical_burst_threshold=critical_burst_threshold,
        )

    # -- Write reports — exit 2 on failure when path is explicitly provided (FIX [7]) --
    if report_sarif:
        try:
            _write_sarif_report(result, Path(report_sarif))
            click.echo(f"SARIF report written to {report_sarif}")
        except Exception as exc:  # noqa: BLE001
            click.echo(f"[ERROR] Failed to write SARIF report: {exc}", err=True)
            sys.exit(2)

    # Default: write cosai-report.html unless --no-report, --report-mode ci, or
    # explicit --report-html given. ci mode suppresses HTML (plain-text summary only).
    effective_html_path = (
        None
        if (no_report or report_mode.lower() == "ci")
        else (report_html or "cosai-report.html")
    )
    if effective_html_path:
        try:
            _write_html_report(result, Path(effective_html_path), report_mode=report_mode)
            click.echo(f"HTML report written to {effective_html_path}")
        except Exception as exc:  # noqa: BLE001
            click.echo(f"[ERROR] Failed to write HTML report: {exc}", err=True)
            sys.exit(2)

    if report_csv:

        try:
            _write_csv_report(result, Path(report_csv))
            click.echo(f"CSV report written to {report_csv}")
        except Exception as exc:  # noqa: BLE001
            click.echo(f"[ERROR] Failed to write CSV report: {exc}", err=True)
            sys.exit(2)

    # -- Adversarial HTML report (only if --adversarial was used) --
    if adversarial and not no_report and report_mode.lower() != "ci":
        adv_html_path = report_adversarial_html or "cosai-adversarial-report.html"
        try:
            _write_adversarial_html_report(
                result,
                Path(adv_html_path),
                target_url=target,
                ownership_declaration=i_own_this_target or "",
            )
            click.echo(
                f"Adversarial report written to {adv_html_path} "
                "(RESTRICTED — contains probe payloads)"
            )
        except Exception as exc:  # noqa: BLE001
            click.echo(f"[ERROR] Failed to write adversarial HTML report: {exc}", err=True)
            sys.exit(2)

    # -- IR containment (Track D — experimental, WP3; best-effort; must not
    #    change exit_code) --
    if experimental and (contain_on_anomaly or ir_report or emit_to):
        try:
            _run_ir_containment(
                result=result,
                target=target,
                contain_on_anomaly=contain_on_anomaly,
                ir_report_path=ir_report,
                emit_to=emit_to,
                emit_auth_header=emit_auth_header,
                anomaly_threshold=anomaly_threshold,
                critical_burst_threshold=critical_burst_threshold,
                allow_private=allow_private_targets,
            )
        except Exception as exc:  # noqa: BLE001
            click.echo(f"[IR] Containment error (scan result unchanged): {type(exc).__name__}", err=True)  # noqa: E501

    # -- Scorecard (exits 2 on write failure — explicitly configured path must succeed) --
    if scorecard_path:
        try:
            from cosai_mcp.scorecard.builder import build_scorecard
            scorecard = build_scorecard(result, signed=not no_sign_scorecard)
            Path(scorecard_path).write_text(
                __import__("json").dumps(scorecard.to_dict(), indent=2),
                encoding="utf-8",
            )
            signed_tag = "" if no_sign_scorecard else " (signed)"
            click.echo(
                f"Scorecard{signed_tag}: {scorecard.conformance_level.value} "
                f"→ {scorecard_path}"
            )

            # -- ENT-P0-2: Sigstore keyless signing — an ADDITIONAL bundle
            # alongside the Ed25519 signature above, never a replacement.
            # Must fail loudly (exit 2), matching the Ed25519 write-failure
            # path immediately above: a user who passed --sigstore-sign and
            # got no bundle would otherwise wrongly believe it was signed. --
            if sigstore_sign:
                from cosai_mcp.scorecard.sigstore_signing import sign_scorecard_sigstore

                try:
                    bundle = sign_scorecard_sigstore(scorecard, staging=sigstore_staging)
                except Exception as exc:  # noqa: BLE001
                    click.echo(f"[ERROR] Sigstore signing failed: {exc}", err=True)
                    sys.exit(2)
                sigstore_bundle_path = f"{scorecard_path}.sigstore.json"
                Path(sigstore_bundle_path).write_text(
                    __import__("json").dumps(bundle, indent=2), encoding="utf-8"
                )
                click.echo(f"Sigstore bundle: {sigstore_bundle_path}")
        except Exception as exc:  # noqa: BLE001
            click.echo(f"[ERROR] Failed to write scorecard: {exc}", err=True)
            sys.exit(2)

    sys.exit(result.exit_code)


# ---------------------------------------------------------------------------
# cosai scorecard
# ---------------------------------------------------------------------------

@main.group()
def scorecard() -> None:
    """Verify and inspect signed conformance scorecards."""


def _print_compliance_mapping(sc: Any) -> None:
    """Print each category's CoSAI + OWASP MCP Top 10 + NIST AI RMF mapping.

    ENT-P0-3: the mapping printed here is read from the SIGNED payload
    (verified above, when called from `scorecard verify`) — not
    re-derived from docs/THREAT_MAPPING.md — so what's on screen is what
    was actually attested to.
    """
    click.echo("\n  Compliance mapping (CoSAI -> OWASP MCP Top 10 / NIST AI RMF):")
    for cat in sc.categories:
        mapping = cat.compliance_mapping
        if mapping is None:
            click.echo(f"    {cat.category:<5} (no compliance mapping in this scorecard)")
            continue
        nist = ", ".join(mapping.nist_ai_rmf)
        click.echo(f"    {cat.category:<5} {mapping.owasp_mcp_top10:<32} NIST AI RMF: {nist}")


def _check_scorecard_catalog_pin(sc: Any, expected_catalog_hash: str | None) -> None:
    """Raise SystemExit(1) if *sc* wasn't produced by the pinned catalog.

    Adversary-pass EXPLOIT 2 (ENT-P0-1 review): a valid Ed25519 signature
    only proves the scorecard wasn't tampered with after signing — it says
    nothing about which catalog produced it. A release gate that consumes a
    signed-scorecard artifact (scan job -> separate verify job) must be able
    to pin the same reproducibility guarantee ``cosai scan
    --expected-catalog-hash`` gives a live scan.
    """
    if expected_catalog_hash is not None and sc.catalog_hash != expected_catalog_hash:
        click.echo(
            f"[INVALID] Catalog hash mismatch: scorecard was produced with "
            f"catalog {sc.catalog_hash!r}, expected {expected_catalog_hash!r}. "
            "A valid signature does not guarantee the pinned catalog ran.",
            err=True,
        )
        sys.exit(1)


def _verify_sigstore_bundle_or_exit(
    sc: Any,
    sigstore_bundle: str | None,
    trusted_identity: str | None,
    trusted_issuer: str | None,
    sigstore_staging: bool,
) -> None:
    """Verify *sc* against a Sigstore bundle file (ENT-P0-2), if one was given.

    Triggered by --sigstore-bundle's own presence — not gated behind
    --verify — because passing a bundle path is itself an explicit request
    to check it; silently skipping an explicit ask is worse than the
    (redundant) extra work.

    Fail-closed: --sigstore-bundle without --trusted-identity is rejected.
    A Sigstore signature proves someone with *a* Fulcio-issued certificate
    signed the payload — without pinning the expected identity, that is
    "signed by anyone," which authenticates nothing (the same reasoning
    that makes Ed25519 verify_scorecard() refuse a bare signature check
    with no trusted public key).
    """
    if not sigstore_bundle:
        return
    if not trusted_identity:
        click.echo(
            "[ERROR] --sigstore-bundle requires --trusted-identity — a "
            "Sigstore signature from an unspecified identity proves nothing "
            "about who signed it.",
            err=True,
        )
        sys.exit(2)

    import json as _json

    from cosai_mcp.scorecard.sigstore_signing import (
        SigstoreUnavailableError,
        SigstoreVerificationError,
        verify_scorecard_sigstore,
    )

    try:
        bundle_dict = _json.loads(Path(sigstore_bundle).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        click.echo(f"[ERROR] Cannot read Sigstore bundle: {exc}", err=True)
        sys.exit(2)

    try:
        verify_scorecard_sigstore(
            sc, bundle_dict,
            identity=trusted_identity, issuer=trusted_issuer, staging=sigstore_staging,
        )
    except SigstoreUnavailableError as exc:
        click.echo(f"[ERROR] {exc}", err=True)
        sys.exit(2)
    except SigstoreVerificationError as exc:
        click.echo(f"[INVALID] Sigstore verification failed: {exc}", err=True)
        sys.exit(1)

    click.echo(f"[OK] Sigstore signature valid — identity: {trusted_identity}")


_SIGSTORE_VERIFY_OPTIONS = [
    click.option(
        "--sigstore-bundle", "sigstore_bundle",
        type=click.Path(exists=True, dir_okay=False), default=None,
        help="Path to a Sigstore bundle JSON (written alongside the scorecard "
             "by `cosai scan --sigstore-sign`, as <scorecard>.sigstore.json). "
             "Verifies an ADDITIONAL signature bound to an organizational "
             "OIDC identity, on top of the Ed25519 signature. Requires "
             "--trusted-identity.",
    ),
    click.option(
        "--trusted-identity", "trusted_identity", default=None,
        help="Expected Sigstore signer identity (e.g. the GitHub Actions "
             "workflow identity URI that ran the scan). Required with "
             "--sigstore-bundle.",
    ),
    click.option(
        "--trusted-issuer", "trusted_issuer", default=None,
        help="Expected OIDC issuer URL for the Sigstore identity (e.g. "
             "https://token.actions.githubusercontent.com). Optional "
             "additional pin alongside --trusted-identity.",
    ),
    click.option(
        "--sigstore-staging", "sigstore_staging", is_flag=True, default=False,
        help="Verify against Sigstore's public staging instance instead of "
             "production (testing only).",
    ),
]


def _apply_options(
    options: Sequence[Callable[[Callable[..., Any]], Callable[..., Any]]],
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        for opt in reversed(options):
            fn = opt(fn)
        return fn
    return decorator


@scorecard.command("verify")
@click.argument("scorecard_file", type=click.Path(exists=True))
@click.option("--expected-catalog-hash", "expected_catalog_hash", default=None,
              help="SHA-256 hex digest the scorecard's catalog_hash must match. "
                   "A valid signature alone does not prove the pinned, reviewed "
                   "catalog produced this scorecard.")
@_apply_options(_SIGSTORE_VERIFY_OPTIONS)
def scorecard_verify(
    scorecard_file: str,
    expected_catalog_hash: str | None,
    sigstore_bundle: str | None,
    trusted_identity: str | None,
    trusted_issuer: str | None,
    sigstore_staging: bool,
) -> None:
    """Verify the Ed25519 signature on a scorecard JSON file.

    Exit codes:
        0  Valid — signature verified against the trusted installation key
           (and catalog_hash matches --expected-catalog-hash, and the
           Sigstore bundle matches --trusted-identity, if given).
        1  Invalid — signature does not verify, public key mismatch,
           catalog_hash mismatch, or Sigstore identity mismatch.
        2  File/bundle cannot be read, not a valid scorecard, or
           --sigstore-bundle given without --trusted-identity.
    """
    import json as _json

    from cosai_mcp.scorecard.models import Scorecard
    from cosai_mcp.scorecard.signing import ScorecardVerificationError, verify_scorecard

    try:
        raw = _json.loads(Path(scorecard_file).read_text(encoding="utf-8"))
        sc = Scorecard.from_dict(raw)
    except (KeyError, ValueError, OSError) as exc:
        click.echo(f"[ERROR] Cannot read scorecard: {exc}", err=True)
        sys.exit(2)

    # Adversary-pass EXPLOIT 1 (ENT-P0-2 review): the Sigstore check must run
    # and pass BEFORE any "valid" output is printed. Printing the Ed25519
    # [OK] line first meant a subsequent Sigstore failure left a misleading
    # "[OK] ... valid" line on stdout above the real (possibly crashing)
    # verdict — a log-scraper that only checks for "[OK]" would be fooled.
    try:
        verify_scorecard(sc)
        _check_scorecard_catalog_pin(sc, expected_catalog_hash)
    except ScorecardVerificationError as exc:
        click.echo(f"[INVALID] {exc}", err=True)
        sys.exit(1)

    _verify_sigstore_bundle_or_exit(
        sc, sigstore_bundle, trusted_identity, trusted_issuer, sigstore_staging
    )

    click.echo(f"[OK] Scorecard signature valid — conformance: {sc.conformance_level.value}")
    _print_compliance_mapping(sc)


@scorecard.command("show")
@click.argument("scorecard_file", type=click.Path(exists=True))
@click.option("--verify", "do_verify", is_flag=True, default=False,
              help="Verify signature before printing.")
@click.option("--expected-catalog-hash", "expected_catalog_hash", default=None,
              help="SHA-256 hex digest the scorecard's catalog_hash must match "
                   "(only checked when --verify is also set).")
@_apply_options(_SIGSTORE_VERIFY_OPTIONS)
def scorecard_show(
    scorecard_file: str,
    do_verify: bool,
    expected_catalog_hash: str | None,
    sigstore_bundle: str | None,
    trusted_identity: str | None,
    trusted_issuer: str | None,
    sigstore_staging: bool,
) -> None:
    """Print a human-readable summary of a conformance scorecard.

    Exit codes:
        0  Scorecard printed (and verified if --verify or --sigstore-bundle
           was set).
        1  Signature verification failed (--verify) or Sigstore identity
           mismatch (--sigstore-bundle).
        2  Invalid/unreadable scorecard or bundle file, or --sigstore-bundle
           given without --trusted-identity.
    """
    import json as _json

    from cosai_mcp.scorecard.models import Grade, Scorecard
    from cosai_mcp.scorecard.signing import ScorecardVerificationError, verify_scorecard

    try:
        raw = _json.loads(Path(scorecard_file).read_text(encoding="utf-8"))
        sc = Scorecard.from_dict(raw)
    except (KeyError, ValueError, OSError) as exc:
        click.echo(f"[ERROR] Cannot read scorecard: {exc}", err=True)
        sys.exit(2)

    if do_verify:
        try:
            verify_scorecard(sc)
        except ScorecardVerificationError as exc:
            click.echo(f"[INVALID] Signature verification failed: {exc}", err=True)
            sys.exit(1)
        _check_scorecard_catalog_pin(sc, expected_catalog_hash)

    _verify_sigstore_bundle_or_exit(
        sc, sigstore_bundle, trusted_identity, trusted_issuer, sigstore_staging
    )

    _GRADE_ICON = {
        Grade.PASS: "✓",
        Grade.WARN: "⚠",
        Grade.FAIL: "✗",
        Grade.NOT_TESTED: "–",
    }

    click.echo("\nConformance Scorecard")
    click.echo(f"  Target     : {sc.target_url}")
    click.echo(f"  Timestamp  : {sc.scan_timestamp}")
    click.echo(f"  Conformance: {sc.conformance_level.value}")
    click.echo(f"  Signed     : {'yes — ' + sc.public_key[:16] + '…' if sc.is_signed else 'no'}")
    click.echo(f"\n  {'Category':<6} {'Grade':<6} {'Findings':<10} {'Critical':<10} Engine")
    click.echo("  " + "-" * 60)
    for cat in sc.categories:
        icon = _GRADE_ICON.get(cat.grade, "?")
        click.echo(
            f"  {cat.category:<6} {icon} {cat.grade.value:<4}  "
            f"{cat.finding_count:<10} {cat.critical_count:<10} {cat.coverage_engine}"
        )
    _print_compliance_mapping(sc)
    click.echo()


# ---------------------------------------------------------------------------
# cosai audit
# ---------------------------------------------------------------------------

@main.group()
def audit() -> None:
    """Audit and verify cosai-mcp scan artifacts."""


@audit.command("verify")
@click.argument("report", type=click.Path())
@click.option("--expected-head", default=None, envvar="COSAI_AUDIT_HEAD",
              help="Externally-anchored tip chain_hash. Without it, a "
                   "wholesale rewrite of the log from genesis cannot be "
                   "detected — only mid-file edits and reordering are caught.")
def audit_verify(report: str, expected_head: str | None) -> None:
    """Verify the hash-chained integrity of an audit log.

    REPORT is the path to the JSON Lines audit log written by a previous scan.

    Exit codes:
        0  Chain intact.
        1  Chain broken (tamper detected).
        2  File not found or empty log.
    """
    result = verify_audit_log(report, expected_head=expected_head)
    if expected_head is None and result.status == VerifyStatus.OK:
        click.echo(
            "[WARN] No --expected-head anchor supplied — a wholesale rewrite "
            "of the log from genesis would NOT be detected. Persist and pass "
            "the last known chain head for full tamper-evidence.",
            err=True,
        )

    if result.status == VerifyStatus.OK:
        click.echo(f"Audit log OK — {result.entries_verified} entries verified.")
        sys.exit(0)
    elif result.status == VerifyStatus.CHAIN_BROKEN:
        click.echo(
            f"[FAIL] Audit chain broken at entry {result.broken_at_line}: "
            f"{result.error_message}",
            err=True,
        )
        sys.exit(1)
    elif result.status == VerifyStatus.FILE_NOT_FOUND:
        click.echo(f"[ERROR] Audit log not found: {report}", err=True)
        sys.exit(2)
    else:  # EMPTY
        click.echo(f"[WARN] Audit log is empty: {report}", err=True)
        sys.exit(2)


# ---------------------------------------------------------------------------
# cosai profile
# ---------------------------------------------------------------------------

@main.group()
def profile() -> None:
    """Manage server profiles for zero-config scanning."""


@profile.command("list")
def profile_list() -> None:
    """List all available built-in server profiles."""
    click.echo("\nBuilt-in server profiles:\n")
    click.echo(f"  {'NAME':<20} {'SKIP':<14} DESCRIPTION")
    click.echo("  " + "-" * 70)
    for _name, p in sorted(BUILTIN_PROFILES.items()):
        skip = ",".join(sorted(p.skip_categories)) or "—"
        click.echo(f"  {p.name:<20} {skip:<14} {p.description}")
    click.echo()
    click.echo("Use 'cosai profile info <name>' for full details.")


@profile.command("info")
@click.argument("name")
@click.option("--allow-custom-profiles", is_flag=True, default=False,
              help="Search .cosai/profiles/ and ~/.cosai/profiles/ in addition to built-ins.")
def profile_info(name: str, allow_custom_profiles: bool) -> None:
    """Show full detail for a server profile."""
    try:
        p = resolve_profile(name, allow_custom=allow_custom_profiles, project_root=Path.cwd())
    except ValueError as exc:
        click.echo(f"[ERROR] {exc}", err=True)
        sys.exit(2)

    click.echo(f"\nProfile: {p.name}")
    click.echo(f"  Description  : {p.description}")
    click.echo(f"  MCP path     : {p.mcp_path}")
    click.echo(f"  Auth format  : {p.auth_header_format or '(none)'}")
    skip = ", ".join(sorted(p.skip_categories)) or "(none)"
    click.echo(f"  Skip cats    : {skip}")
    if p.tool_name_map:
        click.echo("  Tool name map:")
        for placeholder, real in sorted(p.tool_name_map.items()):
            click.echo(f"    {placeholder} → {real}")
    else:
        click.echo("  Tool name map: (empty — uses adaptive discovery)")
    click.echo(f"  Notes        : {p.notes}")
    click.echo()


@profile.command("validate")
@click.argument("path", type=click.Path(exists=True))
def profile_validate(path: str) -> None:
    """Validate a user-written profile file.

    PATH is the .py file to validate.  The file must contain exactly one
    assignment: ``profile = {...}`` where the value is a plain Python dict.

    Exit codes:
        0  Valid.
        1  Invalid — error message describes the problem.
    """
    from cosai_mcp.profiles.loader import _parse_user_profile

    try:
        p = _parse_user_profile(Path(path))
        click.echo(f"[OK] Profile {p.name!r} is valid.")
        sys.exit(0)
    except (ValueError, OSError) as exc:
        click.echo(f"[INVALID] {exc}", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# cosai inventory
# ---------------------------------------------------------------------------

@main.group()
def inventory() -> None:
    """Capture and compare MCP server tool inventories."""


@inventory.command("capture")
@click.argument("target")
@click.option(
    "--output",
    "-o",
    default=None,
    help="Path to write the signed JSON artifact. Prints to stdout if omitted.",
)
@click.option(
    "--no-sign",
    is_flag=True,
    default=False,
    help="Skip signing and emit raw inventory JSON (not recommended for production).",
)
@click.option("--timeout", default=10.0, show_default=True, help="HTTP timeout in seconds.")
@click.option(
    "--allow-private-targets/--block-private-targets",
    "allow_private",
    default=True,
    help="Allow capturing from RFC1918/loopback targets (default: allowed for "
         "dev/loopback use, matching `cosai scan`). Use --block-private-targets "
         "in CI to enforce a public-target-only policy.",
)
def inventory_capture(
    target: str, output: str | None, no_sign: bool, timeout: float, allow_private: bool
) -> None:
    """Capture a tool manifest from TARGET and emit a signed inventory artifact.

    TARGET is an MCP server URL (e.g. http://localhost:8000).

    Exit codes:
        0  Inventory captured (and signed, unless --no-sign).
        2  Capture failed (unreachable server, handshake error, or a private
           target while --block-private-targets is set).
    """
    from cosai_mcp.inventory.signing import sign_inventory
    from cosai_mcp.inventory.snapshot import capture as _capture

    try:
        inv = _capture(target, timeout=timeout, allow_private_targets=allow_private)
    except Exception as exc:
        click.echo(f"[ERROR] Inventory capture failed: {exc}", err=True)
        sys.exit(2)

    if no_sign:
        payload = inv.to_dict()
    else:
        try:
            payload = sign_inventory(inv)
        except Exception as exc:
            click.echo(f"[ERROR] Signing failed: {exc}", err=True)
            sys.exit(2)

    text = json.dumps(payload, indent=2)
    if output:
        Path(output).write_text(text, encoding="utf-8")
        click.echo(
            f"Inventory written to {output} "
            f"({'unsigned' if no_sign else 'signed'}, "
            f"{len(inv.tools)} tool(s), hash={inv.content_hash[:16]}...)"
        )
    else:
        click.echo(text)


@inventory.command("verify")
@click.argument("artifact", type=click.Path(exists=True))
def inventory_verify(artifact: str) -> None:
    """Verify the Ed25519 signature on a signed inventory artifact.

    ARTIFACT is a path to a file written by `cosai inventory capture`.

    Exit codes:
        0  Signature valid.
        1  Signature invalid or artifact tampered.
        2  File unreadable or malformed JSON.
    """
    from cosai_mcp.exceptions import SignatureVerificationError
    from cosai_mcp.inventory.signing import verify_inventory

    try:
        data = json.loads(Path(artifact).read_text(encoding="utf-8"))
    except Exception as exc:
        click.echo(f"[ERROR] Cannot read artifact: {exc}", err=True)
        sys.exit(2)

    try:
        inv = verify_inventory(data)
        click.echo(
            f"Signature VALID — {inv.server_name} {inv.server_version}, "
            f"{len(inv.tools)} tool(s), captured {inv.captured_at}"
        )
    except SignatureVerificationError as exc:
        click.echo(f"[FAIL] {exc}", err=True)
        sys.exit(1)


@inventory.command("diff")
@click.argument("baseline", type=click.Path(exists=True))
@click.argument("current", type=click.Path(exists=True))
@click.option(
    "--fail-on-drift",
    is_flag=True,
    default=False,
    help="Exit 1 if any drift is detected (CI gate mode).",
)
@click.option(
    "--skip-verify-signatures",
    is_flag=True,
    default=False,
    help=(
        "Skip Ed25519 signature verification on signed artifacts. "
        "NOT recommended for production or CI drift gates."
    ),
)
def inventory_diff(
    baseline: str, current: str, fail_on_drift: bool, skip_verify_signatures: bool
) -> None:
    """Compare two inventory artifacts and report drift.

    BASELINE and CURRENT are paths to JSON artifacts (signed or unsigned).
    Signed artifacts (produced by `cosai inventory capture`) are verified by
    default.  Use --skip-verify-signatures only if the signer and verifier
    have different installation keys and COSAI_INVENTORY_PUBKEY is not set.

    Exit codes:
        0  No drift detected (or --fail-on-drift not set).
        1  Drift detected and --fail-on-drift is set.
        2  File unreadable, malformed JSON, or signature invalid.
    """
    from cosai_mcp.exceptions import SignatureVerificationError
    from cosai_mcp.inventory.drift import detect_drift
    from cosai_mcp.inventory.signing import verify_inventory
    from cosai_mcp.inventory.snapshot import ToolInventory

    def _load(path: str) -> ToolInventory:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        is_signed = "inventory" in data and "signature" in data
        if is_signed:
            if skip_verify_signatures:
                click.echo(
                    f"[WARN] {path}: signed artifact loaded without signature "
                    "verification (--skip-verify-signatures). Integrity not guaranteed.",
                    err=True,
                )
                return ToolInventory.from_dict(data["inventory"])
            # Verify by default — signed artifact must pass trust-anchor check.
            return verify_inventory(data)
        return ToolInventory.from_dict(data)

    try:
        base_inv = _load(baseline)
        curr_inv = _load(current)
    except SignatureVerificationError as exc:
        click.echo(f"[FAIL] Signature verification failed: {exc}", err=True)
        sys.exit(2)
    except Exception as exc:
        click.echo(f"[ERROR] Cannot load artifact: {exc}", err=True)
        sys.exit(2)

    report = detect_drift(base_inv, curr_inv)

    if not report.has_drift:
        click.echo(f"No drift detected. ({len(base_inv.tools)} tool(s) unchanged)")
        sys.exit(0)

    click.echo(f"Drift detected: {report.summary()}")
    for entry in report.entries:
        kind = entry.kind.value.upper()
        if entry.before is not None and entry.after is not None:
            click.echo(f"  [{kind}] {entry.tool_name}")
            click.echo(f"    before: {entry.before[:120]}")
            click.echo(f"    after:  {entry.after[:120]}")
        elif entry.after is not None:
            click.echo(f"  [{kind}] {entry.tool_name}: {str(entry.after)[:120]}")
        else:
            click.echo(f"  [{kind}] {entry.tool_name}: {str(entry.before)[:120]}")

    if fail_on_drift:
        sys.exit(1)


# ---------------------------------------------------------------------------
# Telemetry helper
# ---------------------------------------------------------------------------

def _emit_scan_telemetry(
    result: ScanResult,
    target: str,
    emit_to: str,
    emit_auth_header: str | None,
    anomaly_threshold: int,
    critical_burst_threshold: int,
) -> None:
    """Emit all probe results as OCSF events and report anomalies to stderr."""
    from urllib.parse import urlparse, urlunparse

    from cosai_mcp.telemetry.anomaly import AnomalyDetector
    from cosai_mcp.telemetry.emitter import HttpEmitter
    from cosai_mcp.telemetry.ocsf import build_detection_finding

    # Build probe_id → severity string from the threat catalog on the result
    probe_severity: dict[str, str] = {}
    for threat in result.threats:
        sev_str = threat.severity.value if hasattr(threat.severity, "value") else str(threat.severity)  # noqa: E501
        for probe_def in threat.probes:
            probe_severity[probe_def.id] = sev_str

    emitter = HttpEmitter(emit_to, auth_header=emit_auth_header)
    detector = AnomalyDetector(
        high_finding_rate_threshold=anomaly_threshold,
        critical_burst_threshold=critical_burst_threshold,
    )

    emitted = 0
    failed = 0
    for probe in result.probe_results:
        severity = probe_severity.get(probe.probe_id, "medium")
        event = build_detection_finding(
            probe_id=probe.probe_id,
            threat_id=probe.threat_id,
            passed=probe.passed,
            target=target,
            duration_seconds=probe.duration_seconds,
            severity=severity,
        ).to_dict()

        emit_result = emitter.emit(event)
        if emit_result.success:
            emitted += 1
        else:
            failed += 1

        alerts = detector.ingest(event)
        for alert in alerts:
            click.echo(f"[ANOMALY] {alert.rule.value}: {alert.message}", err=True)

    # Redact any userinfo (credentials) from the URL before printing
    parsed = urlparse(emit_to)
    safe_emit = urlunparse(parsed._replace(
        netloc=(parsed.hostname or "") + (f":{parsed.port}" if parsed.port else "")
    ))
    click.echo(
        f"Telemetry: {emitted} event(s) emitted to {safe_emit}"
        + (f", {failed} failed (see warnings)" if failed else "")
    )

    if detector.alerts:
        click.echo(
            f"Anomaly detection: {len(detector.alerts)} alert(s) fired.",
            err=True,
        )


# ---------------------------------------------------------------------------
# IR containment helper
# ---------------------------------------------------------------------------

def _run_ir_containment(
    result: ScanResult,
    target: str,
    contain_on_anomaly: bool,
    ir_report_path: str | None,
    emit_to: str | None,
    emit_auth_header: str | None,
    anomaly_threshold: int,
    critical_burst_threshold: int,
    allow_private: bool = False,
) -> None:
    """Build an IncidentRecord from the scan result and run containment actions.

    Fires when: (a) any findings exist AND ``--ir-report`` or ``--emit-to`` is set,
    OR (b) ``--contain-on-anomaly`` is set and thresholds are exceeded.
    Never raises — all errors are caught and logged to stderr.
    """
    from urllib.parse import urlparse, urlunparse

    from cosai_mcp.ir.containment import perform_containment
    from cosai_mcp.ir.incident import ContainmentAction, build_incident

    # Build probe_id → severity string from the threat catalog on the result
    probe_severity: dict[str, str] = {}
    for threat in result.threats:
        sev = threat.severity.value if hasattr(threat.severity, "value") else str(threat.severity)
        for probe_def in threat.probes:
            probe_severity[probe_def.id] = sev

    # Collect non-passing probes as findings (error probes are inconclusive — skip).
    # WP2: a baseline-accepted (suppressed) finding is, by definition, known and
    # accepted — it must not drive automated IR containment / incident emission
    # any more than it drives the exit code or ScanResult.has_findings.
    findings = [
        {
            "probe_id": p.probe_id,
            "threat_id": p.threat_id,
            "severity": probe_severity.get(p.probe_id, "medium"),
        }
        for p in result.probe_results
        if not p.passed and p.error is None and not p.suppressed
    ]

    if not findings:
        return  # Nothing to report

    # Determine if anomaly thresholds are exceeded
    anomaly_rules: list[str] = []
    if contain_on_anomaly:
        if len(findings) > anomaly_threshold:
            anomaly_rules.append("high_finding_rate")
        critical_count = sum(1 for f in findings if f.get("severity") == "critical")
        if critical_count > critical_burst_threshold:
            anomaly_rules.append("critical_burst")

        if not anomaly_rules:
            # Thresholds not exceeded — only write report/emit if explicitly requested
            if not ir_report_path and not emit_to:
                return

    incident = build_incident(
        target_url=target,
        scan_timestamp=result.scan_timestamp,
        findings=findings,
        anomaly_rules=anomaly_rules,
        probe_severity=probe_severity,
    )

    # Determine which actions to run
    actions: list[ContainmentAction] = []
    if anomaly_rules and contain_on_anomaly:
        # Full recommended containment on threshold breach
        actions = list(incident.recommended_actions)
    else:
        # Non-anomaly path: only emit/report if explicitly configured
        if emit_to:
            actions.append(ContainmentAction.EMIT_INCIDENT)
        if ir_report_path:
            actions.append(ContainmentAction.QUARANTINE_REPORT)

    if not actions:
        return

    from pathlib import Path as _Path

    containment_results = perform_containment(
        incident,
        actions=actions,
        emit_endpoint=emit_to,
        emit_auth_header=emit_auth_header,
        report_path=_Path(ir_report_path) if ir_report_path else None,
        allow_private=allow_private,
    )

    # Redact credentials from emit URL before printing
    if emit_to:
        parsed = urlparse(emit_to)
        urlunparse(parsed._replace(
            netloc=(parsed.hostname or "") + (f":{parsed.port}" if parsed.port else "")
        ))

    click.echo(
        f"[IR] Incident {incident.incident_id} "
        f"severity={incident.severity.value} "
        f"findings={len(findings)}"
        + (f" anomalies={','.join(anomaly_rules)}" if anomaly_rules else "")
    )
    for cr in containment_results:
        status = "ok" if cr.success else "FAILED"
        first_line = cr.detail.splitlines()[0] if cr.detail else ""
        click.echo(f"  [{status}] {cr.action.value}: {first_line}")
        # Print block commands on subsequent lines (they're multi-line)
        if cr.action.value == "block_egress" and cr.success:
            for line in cr.detail.splitlines()[1:]:
                click.echo(f"         {line}")


# ---------------------------------------------------------------------------
# cosai ir
# ---------------------------------------------------------------------------

@main.group()
def ir() -> None:
    """Incident response containment for compromised MCP servers."""


@ir.command("contain")
@click.argument("incident_file", type=click.Path(exists=True))
@click.option("--emit-to", default=None, envvar="COSAI_EMIT_TO",
              help="SIEM/SOAR webhook URL to emit OCSF Security Incident.")
@click.option("--emit-auth-header", default=None, envvar="COSAI_EMIT_AUTH",
              help="Authorization header value for the --emit-to endpoint.")
@click.option("--block-egress", is_flag=True, default=False,
              help="Generate firewall block commands for the incident target.")
@click.option("--session-kill", "do_session_kill", is_flag=True, default=False,
              help="Attempt a best-effort protocol-level close of the MCP connection.")
@click.option("--all-actions", is_flag=True, default=False,
              help="Execute all actions in the incident's recommended_actions list.")
@click.option("--allow-private", is_flag=True, default=False,
              help="Permit containment HTTP to private/loopback/link-local "
                   "addresses (internal MCP servers). Off by default — "
                   "containment to non-public targets is rejected to prevent "
                   "SSRF via a crafted incident artifact.")
def ir_contain(
    incident_file: str,
    emit_to: str | None,
    emit_auth_header: str | None,
    block_egress: bool,
    do_session_kill: bool,
    all_actions: bool,
    allow_private: bool,
) -> None:
    """Execute IR containment actions from an incident JSON report.

    INCIDENT_FILE is a JSON report produced by ``cosai scan --ir-report``.

    Exit codes:
        0  All requested actions succeeded.
        1  One or more actions failed.
        2  Invalid incident file.
    """
    import json as _json

    from cosai_mcp.ir.containment import perform_containment
    from cosai_mcp.ir.incident import ContainmentAction, IncidentRecord

    try:
        raw = _json.loads(Path(incident_file).read_text(encoding="utf-8"))
        # Support both bare incident dict and the wrapped quarantine report format
        incident_dict = raw.get("incident", raw)
        incident = IncidentRecord.from_dict(incident_dict)
    except (KeyError, ValueError, OSError) as exc:
        click.echo(f"[ERROR] Invalid incident file: {exc}", err=True)
        sys.exit(2)

    if all_actions:
        actions = list(incident.recommended_actions)
    else:
        actions = []
        if emit_to:
            actions.append(ContainmentAction.EMIT_INCIDENT)
        if block_egress:
            actions.append(ContainmentAction.BLOCK_EGRESS)
        if do_session_kill:
            actions.append(ContainmentAction.SESSION_KILL)
        if not actions:
            # Default: emit + quarantine report to current dir
            if emit_to:
                actions.append(ContainmentAction.EMIT_INCIDENT)
            actions.append(ContainmentAction.QUARANTINE_REPORT)

    results = perform_containment(
        incident,
        actions=actions,
        emit_endpoint=emit_to,
        emit_auth_header=emit_auth_header,
        allow_private=allow_private,
    )

    any_failure = False
    for r in results:
        status = "ok" if r.success else "FAILED"
        click.echo(f"[{status}] {r.action.value}: {r.detail.splitlines()[0]}")
        if r.action.value == "block_egress" and r.success:
            for line in r.detail.splitlines()[1:]:
                click.echo(f"       {line}")
        if not r.success:
            any_failure = True

    sys.exit(1 if any_failure else 0)


@ir.command("status")
@click.argument("incident_file", type=click.Path(exists=True))
def ir_status(incident_file: str) -> None:
    """Print a human-readable summary of an incident JSON report.

    Exit codes:
        0  Valid incident file printed.
        2  Invalid or unreadable incident file.
    """
    import json as _json

    from cosai_mcp.ir.incident import IncidentRecord

    try:
        raw = _json.loads(Path(incident_file).read_text(encoding="utf-8"))
        incident_dict = raw.get("incident", raw)
        incident = IncidentRecord.from_dict(incident_dict)
    except (KeyError, ValueError, OSError) as exc:
        click.echo(f"[ERROR] Invalid incident file: {exc}", err=True)
        sys.exit(2)

    click.echo(f"Incident ID  : {incident.incident_id}")
    click.echo(f"Target       : {incident.target_url}")
    click.echo(f"Severity     : {incident.severity.value}")
    click.echo(f"Timestamp    : {incident.scan_timestamp}")
    click.echo(f"Findings     : {len(incident.findings)}")
    if incident.anomaly_rules:
        click.echo(f"Anomaly rules: {', '.join(incident.anomaly_rules)}")
    click.echo(f"Rec. actions : {', '.join(a.value for a in incident.recommended_actions)}")
    if incident.findings:
        click.echo("\nFindings:")
        for f in incident.findings:
            click.echo(f"  [{f.severity}] {f.probe_id} / {f.threat_id}")


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _print_coverage_matrix() -> None:
    """Print the engine-coverage matrix to stdout."""
    click.echo("\nCoverage Matrix — cosai-mcp engine coverage per category:")
    click.echo(f"{'Category':<10} {'Engine Coverage'}")
    click.echo("-" * 45)
    for cat in sorted(COVERAGE_MATRIX.keys(), key=lambda x: int(x[1:].lstrip("0") or "0")):
        coverage = COVERAGE_MATRIX[cat]
        note = "  ← not probeable from outside" if cat in MIDDLEWARE_ONLY_CATEGORIES else ""
        click.echo(f"{cat:<10} {coverage}{note}")
    click.echo()


def _print_scan_summary(result: ScanResult, fail_on: str = "critical") -> None:
    total_probes = len(result.probe_results)
    failed_probes = sum(1 for r in result.probe_results if not r.passed and not r.inconclusive_reason)  # noqa: E501
    total_scenarios = len(result.scenario_results)
    failed_scenarios = sum(1 for r in result.scenario_results if not r.passed and not r.inconclusive_reason)  # noqa: E501

    click.echo(f"\nTarget: {result.target_url}")
    click.echo(f"Timestamp: {result.scan_timestamp}")
    click.echo(f"Catalog hash: {result.catalog_hash[:16]}…")
    click.echo(
        f"Probes: {failed_probes}/{total_probes} failed   "
        f"Scenarios: {failed_scenarios}/{total_scenarios} failed"
    )

    total_non_inconclusive_findings = (
        sum(1 for r in result.probe_results if not r.passed and r.error is None and not r.inconclusive_reason and not r.suppressed)  # noqa: E501
        + sum(1 for r in result.scenario_results if not r.passed and r.status not in ("scan-incomplete", "inconclusive"))  # noqa: E501
    )
    inconclusive_count = (
        sum(1 for r in result.probe_results if r.inconclusive_reason)
        + sum(1 for r in result.scenario_results if r.status == "inconclusive")
    )
    suppressed_count = sum(1 for r in result.probe_results if r.suppressed)
    if suppressed_count:
        click.echo(
            f"Baseline: {suppressed_count} accepted finding(s) suppressed "
            "(excluded from exit code; still listed in reports)."
        )
    if result.exit_code == 0:
        if total_non_inconclusive_findings > 0:
            click.echo(
                f"[CLEAN] No findings at or above {fail_on!r} severity. "
                f"({total_non_inconclusive_findings} finding(s) below threshold; "
                f"{inconclusive_count} inconclusive.)"
            )
        else:
            inconc_note = f" ({inconclusive_count} inconclusive.)" if inconclusive_count else ""
            click.echo(f"[CLEAN] No findings.{inconc_note}")
    elif result.exit_code == 1:
        click.echo(f"[FINDINGS] {failed_probes + failed_scenarios} issue(s) at or above {fail_on!r} severity.")  # noqa: E501
    else:
        click.echo("[ERROR] Scan completed with internal errors — treat as failure.", err=True)


# ---------------------------------------------------------------------------
# Manifest-scan stubs — metadata for T04/T09 passive findings that have no
# catalog entry (catalog requires signing; manifest scans are code-driven).
# ---------------------------------------------------------------------------

def _make_manifest_stubs() -> tuple[dict, dict]:
    """Build (sarif_stubs, html_stubs) for passive manifest-scan findings.

    Both dicts are keyed by bare category code (e.g. "T09") because that is what
    the passive scans (_scan_manifest_t3_schema/t4/t5/t6/t9/t11) write into
    ProbeResult.threat_id. A category missing here is silently dropped from the
    SARIF/HTML report, so every passive-scan category MUST have a stub.
    """
    from cosai_mcp.catalog.models import Severity

    sarif: dict = {
        "T03": {
            # Distinct rule id: T03-001 is the command-injection catalog rule.
            "rule_id": "T03-100",
            "name": "T3 Input Validation — Unsafe Tool inputSchema",
            "severity": Severity.MEDIUM,
            "remediation": (
                "Tool inputSchema must not reference external $ref URIs (clients "
                "must not dereference them), must use spec-valid x-mcp-header "
                "annotations (HTTP-token name, unique, string/integer/boolean, "
                "reachable via 'properties' only), and must stay within bounded "
                "depth and subschema count. Ref: CoSAI MCP Security v2.0 §3.2.3, "
                "MCP 2026-07-28 JSON Schema usage, CWE-20."
            ),
            "owasp_ref": "MCP03:2025; MCP05:2025; MCP06:2025",
            "cwe": ("CWE-20", "CWE-918"),
        },
        "T05": {
            "rule_id": "T05-001",
            "name": "T5 Data Protection — Secret/PII in Tool Manifest",
            "severity": Severity.HIGH,
            "remediation": (
                "Tool names and descriptions must not embed credentials or PII. "
                "Remove any API key, token, or personal data from the manifest; "
                "inject secrets via environment/secrets-manager at runtime, never "
                "in tool definitions. Ref: CoSAI T5, CWE-312."
            ),
            "owasp_ref": "MCP10:2025",
            "cwe": ("CWE-312", "CWE-200"),
        },
        "T06": {
            "rule_id": "T06-001",
            "name": "T6 Integrity — Manifest Tool-Name Collision/Shadowing",
            "severity": Severity.HIGH,
            "remediation": (
                "Tool names must be unique and must not collide with, shadow, or "
                "typosquat (Levenshtein 1 of) a reserved MCP method or another "
                "tool. Enforce a unique, signed tool allowlist. Ref: CoSAI T6, CWE-345."
            ),
            "owasp_ref": "MCP03:2025; MCP04:2025",
            "cwe": ("CWE-345",),
        },
        "T09": {
            "rule_id": "T09-001",
            "name": "T9 Totem Violation — Missing Two-Stage Commit",
            "severity": Severity.HIGH,
            "remediation": (
                "Destructive tools must implement a two-stage commit pattern: "
                "add a `confirmed: boolean` parameter (when False, return a "
                "description of what would happen without executing), or expose "
                "a `<tool>_preview` sibling tool. No irreversible action should "
                "execute without explicit confirmation. Ref: TKA Totem layer, CoSAI T9."
            ),
            "owasp_ref": "MCP02:2025",
            "cwe": ("CWE-284",),
        },
        "T04": {
            "rule_id": "T04-001",
            "name": "T4 Tool Poisoning — Manifest Anomaly",
            "severity": Severity.HIGH,
            "remediation": (
                "Tool descriptions must not contain instructions that redirect LLM "
                "behavior or embed system-prompt-style directives. Use concise, "
                "functional descriptions that describe what the tool does, not what "
                "the LLM should do. Ref: CoSAI T4, MCP tool poisoning."
            ),
            "owasp_ref": "MCP03:2025; MCP06:2025",
            "cwe": ("CWE-74",),
        },
        "T11": {
            "rule_id": "T11-001",
            "name": "T11 Supply Chain — Unexpected/Typosquatted Tool",
            "severity": Severity.HIGH,
            "remediation": (
                "A discovered tool is not on the operator allowlist, or is within "
                "one edit of an approved name (typosquat). Confirm the tool is "
                "approved and signed, or remove it from the server. Maintain an "
                "explicit approved-tool allowlist. Ref: CoSAI T11, CWE-1357."
            ),
            "owasp_ref": "MCP04:2025",
            "cwe": ("CWE-1357", "CWE-494"),
        },
    }
    html: dict = {
        k: {**v, "references": ()} for k, v in sarif.items()
    }
    return sarif, html


_MANIFEST_STUBS_SARIF, _MANIFEST_STUBS_HTML = _make_manifest_stubs()


def _build_sarif_dict(result: ScanResult) -> dict[str, Any]:
    """Build the SARIF 2.1.0 document dict for one ScanResult (single run).

    Extracted from _write_sarif_report so fleet mode (ENT-P0-4) can build
    one dict per target and merge their "runs" arrays into one document,
    reusing the same rule/result population logic — never a second,
    parallel implementation of it.
    """
    from cosai_mcp.report.sarif import SarifBuilder, ScanContext

    ctx = ScanContext(
        target_url=result.target_url,
        scan_timestamp=result.scan_timestamp,
        catalog_hash=result.catalog_hash,
        execution_successful=(result.exit_code != 2),
        exit_code=result.exit_code,
    )
    builder = SarifBuilder(ctx)

    # Map probe_id → threat for metadata lookup
    threat_by_id = {t.id: t for t in result.threats}

    for probe_result in result.probe_results:
        threat = threat_by_id.get(probe_result.threat_id)
        if threat is None:
            # Manifest-scan results carry a bare category code (e.g. "T09", "T04")
            # that has no catalog entry. Use the stub so findings appear in the report.
            stub = _MANIFEST_STUBS_SARIF.get(probe_result.threat_id)
            if stub is None:
                continue
            builder.add_result(
                result=probe_result,
                severity=stub["severity"],
                rule_id=stub["rule_id"],
                rule_name=stub["name"],
                rule_description=stub["remediation"],
                owasp_ref=stub.get("owasp_ref", ""),
                cwe=stub.get("cwe", ()),
                confidence="medium",
            )
            continue
        builder.add_result(
            result=probe_result,
            severity=threat.severity,
            rule_id=threat.id,
            rule_name=getattr(threat, "name", threat.id),
            rule_description=getattr(threat, "remediation", "")[:512],
            owasp_ref=threat.owasp_ref,
            cwe=threat.cwe,
            confidence=getattr(getattr(threat, "confidence", None), "value", "medium")
            if getattr(threat, "confidence", None) is not None
            else "medium",
        )

    return builder.build()


def _run_fleet_scan_and_exit(
    *,
    targets_path: Path,
    max_concurrency: int,
    per_target_timeout: float,
    categories: list[str] | None,
    engine: str,
    allow_custom_catalog: bool,
    probe_timeout_seconds: float,
    catalog_root: Path,
    fail_on: str,
    allow_private_targets: bool,
    pii_strict: bool,
    expected_catalog_hash: str | None,
    auth_token: str | None,
    read_token: str | None,
    mcp_path: str,
    probe_delay_seconds: float,
    adaptive: bool,
    tool_allowlist: tuple[str, ...] | None,
    skip_reachability: bool,
    report_sarif: str | None,
    scorecard_path: str | None,
    no_sign_scorecard: bool,
) -> None:
    """ENT-P0-4: run a fleet scan, write the merged SARIF / aggregated
    scorecard, and exit with the aggregate exit code. Never returns."""
    from cosai_mcp.fleet import (
        build_fleet_scorecard,
        merge_sarif,
        parse_targets_file,
        run_fleet_scan,
    )
    from cosai_mcp.report.sarif import _validate_sarif_structure

    try:
        targets = parse_targets_file(targets_path)
    except ValueError as exc:
        click.echo(f"[ERROR] {exc}", err=True)
        sys.exit(2)

    # Panel-review finding (ENT-P0-4): ThreadPoolExecutor silently clamps
    # max_workers<1 to 1 without any signal — a banner printing the
    # requested value would lie about what's actually in effect. Reject
    # instead, matching this project's fail-closed convention for other
    # malformed operator input (e.g. --expected-catalog-hash "").
    if max_concurrency < 1:
        click.echo(
            f"[ERROR] --fleet-concurrency must be >= 1 (got {max_concurrency}).",
            err=True,
        )
        sys.exit(2)

    click.echo(f"Fleet scan: {len(targets)} target(s), max concurrency {max_concurrency}")

    fleet_result = run_fleet_scan(
        targets,
        max_concurrency=max_concurrency,
        per_target_timeout=per_target_timeout,
        categories=categories,
        engine=engine,
        allow_custom_catalog=allow_custom_catalog,
        probe_timeout_seconds=probe_timeout_seconds,
        catalog_root=catalog_root,
        fail_on=fail_on,
        allow_private_targets=allow_private_targets,
        pii_strict=pii_strict,
        expected_catalog_hash=expected_catalog_hash,
        auth_token=auth_token,
        read_token=read_token,
        mcp_path=mcp_path,
        probe_delay_seconds=probe_delay_seconds,
        adaptive=adaptive,
        tool_allowlist=tool_allowlist,
        skip_reachability=skip_reachability,
    )

    _STATUS_LABEL = {0: "CLEAN", 1: "FINDINGS", 2: "ERROR", 3: "UNREACHABLE"}
    for outcome in fleet_result.targets:
        status = _STATUS_LABEL.get(outcome.exit_code, "?")
        detail = f" — {outcome.error}" if outcome.error else ""
        click.echo(f"  [{status:<11}] {outcome.target_url}{detail}")

    if report_sarif:
        sarif_docs = [
            _build_sarif_dict(outcome.result)
            for outcome in fleet_result.targets
            if outcome.result is not None
        ]
        if sarif_docs:
            merged = merge_sarif(sarif_docs)
            _validate_sarif_structure(merged)
            Path(report_sarif).write_text(
                json.dumps(merged, indent=2, ensure_ascii=True), encoding="utf-8"
            )
            click.echo(f"Merged SARIF report written to {report_sarif}")
        else:
            click.echo(
                "[WARN] No target completed a scan — no SARIF report written.", err=True
            )

    if scorecard_path:
        fleet_scorecard = build_fleet_scorecard(fleet_result, signed=not no_sign_scorecard)
        Path(scorecard_path).write_text(json.dumps(fleet_scorecard, indent=2), encoding="utf-8")
        click.echo(f"Aggregated scorecard written to {scorecard_path}")

    click.echo(f"\nFleet exit code: {fleet_result.exit_code}")
    sys.exit(fleet_result.exit_code)


def _write_sarif_report(result: ScanResult, path: Path) -> None:
    from cosai_mcp.report.sarif import _validate_sarif_structure

    doc = _build_sarif_dict(result)
    _validate_sarif_structure(doc)
    sarif_json = json.dumps(doc, indent=2, ensure_ascii=True)
    path.write_text(sarif_json, encoding="utf-8")

    # Attempt to sign the report (best-effort; failure is a warning not an error)
    try:
        from cosai_mcp.report.sign import ReportSigner
        signer = ReportSigner()
        sig = signer.sign(
            sarif_json=sarif_json,
            scan_timestamp=result.scan_timestamp,
            catalog_hash=result.catalog_hash,
        )
        sig_path = path.with_suffix(".sig.json")
        sig_path.write_text(json.dumps(sig.to_dict(), indent=2), encoding="utf-8")
    except OrgSigningKeyError as exc:
        # A misconfigured fleet org key must be LOUD — a fleet that believes
        # it is emitting comparable signed reports but is silently emitting
        # none is exactly the failure WP6 must not introduce.
        click.echo(f"[WARN] Report not signed — {exc}", err=True)
    except Exception:  # noqa: BLE001, S110
        pass  # signing unavailable (no keyring / no key) — continue without signature


def _write_csv_report(result: ScanResult, path: Path) -> None:
    from cosai_mcp.report.csv_report import write_csv_report
    write_csv_report(result, path)


def _write_html_report(result: ScanResult, path: Path, report_mode: str = "full") -> None:
    import json as _json
    from collections import defaultdict

    from cosai_mcp.report.html import (
        HtmlReportBuilder,
        HtmlReportSection,
        HtmlScenarioSection,
        ProbeContext,
        ScenarioStep,
    )

    builder = HtmlReportBuilder(
        target_url=result.target_url,
        scan_timestamp=result.scan_timestamp,
        report_mode=report_mode,
    )

    # EFF-03: render a coverage matrix for ALL 12 categories so NOT-TESTED ones
    # (middleware-only or all-inconclusive) are visible and distinct from PASS,
    # matching the signed scorecard JSON.  Best-effort — a scorecard failure must
    # never block the HTML report.
    try:
        from cosai_mcp.scorecard.builder import build_scorecard
        _sc = build_scorecard(result, signed=False)
        builder.set_coverage([c.to_dict() for c in _sc.categories])
    except Exception:  # noqa: BLE001, S110
        pass

    # Build probe_context lookup: probe_id → ProbeContext
    # Uses the threat catalog to describe what each probe actually sends.
    from cosai_mcp.harness.context import _to_json_safe

    probe_context_by_id: dict[str, ProbeContext] = {}
    for threat in result.threats:
        for probe in threat.probes:
            # Recursively convert MappingProxyType so json.dumps works
            payload = _to_json_safe(probe.payload)
            try:
                payload_str = _json.dumps(payload, indent=None, separators=(", ", ": "))
                if len(payload_str) > 120:
                    payload_str = payload_str[:117] + "…"
            except Exception:
                payload_str = str(payload)[:120]

            assertion_descs = []
            for a in probe.assertions:
                val_str = (
                    ", ".join(str(v) for v in a.value)
                    if isinstance(a.value, tuple)
                    else str(a.value)
                )
                assertion_descs.append(
                    f"{a.target} must {a.operator} {val_str}"
                )

            probe_context_by_id[probe.id] = ProbeContext(
                method=probe.method,
                payload_summary=f"{probe.method} → {payload_str}",
                assertion_descriptions=assertion_descs,
            )

    # Group probe results by threat_id (preserving catalog order)
    results_by_threat: dict[str, list] = defaultdict(list)
    for r in result.probe_results:
        results_by_threat[r.threat_id].append(r)

    threat_by_id = {t.id: t for t in result.threats}

    for threat_id, probe_results in sorted(results_by_threat.items()):
        threat = threat_by_id.get(threat_id)  # type: ignore[assignment]
        if threat is None:
            # Manifest-scan results carry a bare category code — use stub metadata.
            stub = _MANIFEST_STUBS_HTML.get(threat_id)
            if stub is None:
                continue
            threat = stub
            passed = all(r.passed for r in probe_results)
            section = HtmlReportSection(
                threat_id=stub["rule_id"],
                category=threat_id,
                severity=stub["severity"],
                passed=passed,
                probe_results=probe_results,
                remediation=stub["remediation"],
                references=stub.get("references", ()),
                probe_contexts=[None] * len(probe_results),
            )
            builder.add_section(section)
            continue
        passed = all(r.passed for r in probe_results)

        # Attach ProbeContext per result (parallel list, same order)
        contexts = [probe_context_by_id.get(r.probe_id) for r in probe_results]

        section = HtmlReportSection(
            threat_id=threat.id,
            category=threat.category,
            severity=threat.severity,
            passed=passed,
            probe_results=probe_results,
            remediation=getattr(threat, "remediation", ""),
            references=getattr(threat, "references", ()),
            probe_contexts=[c for c in contexts if c is not None] or None,
        )
        builder.add_section(section)

    # Wire scenario results
    for sr in result.scenario_results:
        steps: list[ScenarioStep] = []
        for step_r in sr.step_results:
            # Build a response summary from the raw response dict or failures
            if step_r.failures:
                resp_parts = []
                for f in step_r.failures:
                    resp_parts.append(
                        f"{f.target}: expected {f.operator} {f.expected!r}, got {f.actual!r}"
                    )
                resp_summary = "; ".join(resp_parts)
            elif step_r.error:
                resp_summary = step_r.error
            elif step_r.response:
                try:
                    raw = _json.dumps(step_r.response, separators=(", ", ": "))
                    resp_summary = raw[:200] + ("…" if len(raw) > 200 else "")
                except Exception:
                    resp_summary = str(step_r.response)[:200]
            else:
                resp_summary = ""

            steps.append(ScenarioStep(
                index=step_r.step_index,
                description=step_r.description,
                passed=step_r.passed,
                response_summary=resp_summary,
            ))

        # Use first threat category for display
        category = sr.threat_categories[0] if sr.threat_categories else ""
        builder.add_scenario(HtmlScenarioSection(
            scenario_id=sr.scenario_id,
            scenario_name=sr.scenario_name,
            category=category,
            passed=sr.passed,
            steps=steps,
            inconclusive_reason=sr.inconclusive_reason,
        ))

    path.write_text(builder.build(), encoding="utf-8")


def _write_adversarial_html_report(
    result: ScanResult,
    path: Path,
    target_url: str,
    ownership_declaration: str,
) -> None:
    from cosai_mcp.catalog.models import Severity
    from cosai_mcp.report.adversarial_html import AdversarialFinding, AdversarialHtmlReport

    report = AdversarialHtmlReport(
        target_url=target_url,
        scan_timestamp=result.scan_timestamp,
        scan_id=getattr(result, "scan_id", ""),
        ownership_declaration=ownership_declaration,
    )

    # Surface adversarial probe results — those with "-ADV-" in the probe ID
    for probe_result in result.probe_results:
        if "-ADV-" not in probe_result.probe_id.upper():
            continue

        # Find the matching threat for severity and category info
        threat = next(
            (t for t in result.threats if any(p.id == probe_result.probe_id for p in t.probes)),
            None,
        )
        severity = threat.severity if threat else Severity.HIGH
        category = threat.category if threat else "?"

        # response_body is pre-escaped by make_probe_result (ingestion-time HTML escape).
        # Pass through directly; adversarial_html.py's _render_finding adds defense-in-depth.
        report.add_finding(AdversarialFinding(
            probe_id=probe_result.probe_id,
            threat_id=probe_result.threat_id,
            category=category,
            severity=severity,
            passed=probe_result.passed,
            canary_detected=probe_result.canary_detected,
            payload_sent="(see probe catalog)",
            response_body=probe_result.response_body or "",
            error=probe_result.error,
        ))

    html_content = report.build()
    path.write_text(html_content, encoding="utf-8")

    # Sign the adversarial report (best-effort; same mechanism as SARIF signing)
    try:
        from cosai_mcp.report.sign import ReportSigner
        signer = ReportSigner()
        sig = signer.sign(
            sarif_json=html_content,   # ReportSigner hashes any report content string
            scan_timestamp=result.scan_timestamp,
            catalog_hash=result.catalog_hash,
        )
        sig_path = path.with_suffix(".sig.json")
        sig_path.write_text(json.dumps(sig.to_dict(), indent=2), encoding="utf-8")
    except OrgSigningKeyError as exc:
        click.echo(f"[WARN] Adversarial report not signed — {exc}", err=True)
    except Exception:  # noqa: BLE001, S110
        pass  # signing unavailable (no keyring / no key) — continue without signature


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
