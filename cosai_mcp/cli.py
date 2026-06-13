"""cosai CLI — `cosai scan` and `cosai audit verify`."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from cosai_mcp.adversarial import AdversarialMode
from cosai_mcp.api import (
    CATALOG_ROOT,
    COVERAGE_MATRIX,
    MIDDLEWARE_ONLY_CATEGORIES,
    ScanResult,
    Scanner,
    _apply_env_scrub,
    _run_scan,
    check_reachable,
    _parse_target,
)
from cosai_mcp.exceptions import ScannerInternalError, TargetUnreachableError
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


def _help_advanced_cb(ctx: click.Context, param: click.Parameter, value: bool):
    if not value or ctx.resilient_parsing:
        return
    # Per-invocation signal on ctx.meta (never on the Command instance, which
    # Click reuses in-process — instance state would leak into a later
    # plain --help and wrongly reveal hidden options).
    ctx.meta[_AdvancedHelpCommand._META_KEY] = True
    click.echo(ctx.command.get_help(ctx))
    ctx.exit()


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
@click.argument("target")
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
@click.option("--catalog-root", type=click.Path(exists=True, file_okay=False), default=None, hidden=True,
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
@click.option("--experimental", is_flag=True, default=False, hidden=True,
              help="Enable experimental Tracks B/D (SIEM/OCSF telemetry "
                   "emission and IR containment). These are NOT part of the "
                   "default scan surface and may change or be removed.")
def scan(
    target: str,
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
    experimental: bool,
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

    cat_list = [c.strip() for c in categories.split(",") if c.strip()] if categories != "all" else None
    effective_catalog_root = Path(catalog_root) if catalog_root else CATALOG_ROOT

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
        )
    except ValueError as exc:
        # Includes adversarial dual opt-in failures AND a malformed
        # .cosai-baseline (fail-closed: a broken baseline must not be ignored).
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
            click.echo(f"[IR] Containment error (scan result unchanged): {type(exc).__name__}", err=True)

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


@scorecard.command("verify")
@click.argument("scorecard_file", type=click.Path(exists=True))
def scorecard_verify(scorecard_file: str) -> None:
    """Verify the Ed25519 signature on a scorecard JSON file.

    Exit codes:
        0  Valid — signature verified against the trusted installation key.
        1  Invalid — signature does not verify or public key mismatch.
        2  File cannot be read or is not a valid scorecard.
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

    try:
        verify_scorecard(sc)
        click.echo(f"[OK] Scorecard signature valid — conformance: {sc.conformance_level.value}")
    except ScorecardVerificationError as exc:
        click.echo(f"[INVALID] {exc}", err=True)
        sys.exit(1)


@scorecard.command("show")
@click.argument("scorecard_file", type=click.Path(exists=True))
@click.option("--verify", "do_verify", is_flag=True, default=False,
              help="Verify signature before printing.")
def scorecard_show(scorecard_file: str, do_verify: bool) -> None:
    """Print a human-readable summary of a conformance scorecard.

    Exit codes:
        0  Scorecard printed (and verified if --verify was set).
        1  Signature verification failed (only with --verify).
        2  Invalid or unreadable scorecard file.
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

    _GRADE_ICON = {
        Grade.PASS: "✓",
        Grade.WARN: "⚠",
        Grade.FAIL: "✗",
        Grade.NOT_TESTED: "–",
    }

    click.echo(f"\nConformance Scorecard")
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
    for name, p in sorted(BUILTIN_PROFILES.items()):
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
    "--allow-private",
    is_flag=True,
    default=False,
    help="Allow capturing from RFC1918/loopback targets (for internal MCP servers).",
)
def inventory_capture(
    target: str, output: str | None, no_sign: bool, timeout: float, allow_private: bool
) -> None:
    """Capture a tool manifest from TARGET and emit a signed inventory artifact.

    TARGET is an MCP server URL (e.g. http://localhost:8000).

    Exit codes:
        0  Inventory captured (and signed, unless --no-sign).
        2  Capture failed (unreachable server, handshake error, private target).
    """
    from cosai_mcp.inventory.snapshot import capture as _capture
    from cosai_mcp.inventory.signing import sign_inventory

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
    from cosai_mcp.inventory.signing import verify_inventory
    from cosai_mcp.exceptions import SignatureVerificationError

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
    from cosai_mcp.inventory.snapshot import ToolInventory
    from cosai_mcp.inventory.signing import verify_inventory
    from cosai_mcp.inventory.drift import detect_drift
    from cosai_mcp.exceptions import SignatureVerificationError

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
            click.echo(f"  [{kind}] {entry.tool_name}: {entry.after[:120]}")
        else:
            click.echo(f"  [{kind}] {entry.tool_name}: {entry.before[:120]}")

    if fail_on_drift:
        sys.exit(1)


# ---------------------------------------------------------------------------
# Telemetry helper
# ---------------------------------------------------------------------------

def _emit_scan_telemetry(
    result: "ScanResult",
    target: str,
    emit_to: str,
    emit_auth_header: str | None,
    anomaly_threshold: int,
    critical_burst_threshold: int,
) -> None:
    """Emit all probe results as OCSF events and report anomalies to stderr."""
    from urllib.parse import urlparse, urlunparse

    from cosai_mcp.telemetry.emitter import HttpEmitter
    from cosai_mcp.telemetry.ocsf import build_detection_finding
    from cosai_mcp.telemetry.anomaly import AnomalyDetector

    # Build probe_id → severity string from the threat catalog on the result
    probe_severity: dict[str, str] = {}
    for threat in result.threats:
        sev_str = threat.severity.value if hasattr(threat.severity, "value") else str(threat.severity)
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
        netloc=parsed.hostname + (f":{parsed.port}" if parsed.port else "")
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
    result: "ScanResult",
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

    from cosai_mcp.ir.incident import build_incident, ContainmentAction
    from cosai_mcp.ir.containment import perform_containment

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
    safe_emit = emit_to
    if emit_to:
        parsed = urlparse(emit_to)
        safe_emit = urlunparse(parsed._replace(
            netloc=parsed.hostname + (f":{parsed.port}" if parsed.port else "")
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
    from cosai_mcp.ir.incident import IncidentRecord, ContainmentAction
    from cosai_mcp.ir.containment import perform_containment

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
    failed_probes = sum(1 for r in result.probe_results if not r.passed and not r.inconclusive_reason)
    total_scenarios = len(result.scenario_results)
    failed_scenarios = sum(1 for r in result.scenario_results if not r.passed and not r.inconclusive_reason)

    click.echo(f"\nTarget: {result.target_url}")
    click.echo(f"Timestamp: {result.scan_timestamp}")
    click.echo(f"Catalog hash: {result.catalog_hash[:16]}…")
    click.echo(
        f"Probes: {failed_probes}/{total_probes} failed   "
        f"Scenarios: {failed_scenarios}/{total_scenarios} failed"
    )

    total_non_inconclusive_findings = (
        sum(1 for r in result.probe_results if not r.passed and r.error is None and not r.inconclusive_reason and not r.suppressed)
        + sum(1 for r in result.scenario_results if not r.passed and r.status not in ("scan-incomplete", "inconclusive"))
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
        click.echo(f"[FINDINGS] {failed_probes + failed_scenarios} issue(s) at or above {fail_on!r} severity.")
    else:
        click.echo("[ERROR] Scan completed with internal errors — treat as failure.", err=True)


# ---------------------------------------------------------------------------
# Manifest-scan stubs — metadata for T04/T09 passive findings that have no
# catalog entry (catalog requires signing; manifest scans are code-driven).
# ---------------------------------------------------------------------------

def _make_manifest_stubs() -> tuple[dict, dict]:
    """Build (sarif_stubs, html_stubs) for T04 and T09 manifest findings.

    Both dicts are keyed by bare category code (e.g. "T09") because that is
    what _scan_manifest_t4 and _scan_manifest_t9 write into ProbeResult.threat_id.
    """
    from cosai_mcp.catalog.models import Severity

    sarif: dict = {
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
            "owasp_ref": "MCP-Top10-A09",
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
            "owasp_ref": "MCP-Top10-A04",
            "cwe": ("CWE-74",),
        },
    }
    html: dict = {
        k: {**v, "references": ()} for k, v in sarif.items()
    }
    return sarif, html


_MANIFEST_STUBS_SARIF, _MANIFEST_STUBS_HTML = _make_manifest_stubs()


def _write_sarif_report(result: ScanResult, path: Path) -> None:
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
            confidence=getattr(threat, "confidence", None).value
            if getattr(threat, "confidence", None) is not None
            else "medium",
        )

    sarif_json = builder.build_json()
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
    except Exception:  # noqa: BLE001
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
    except Exception:  # noqa: BLE001
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
        threat = threat_by_id.get(threat_id)
        if threat is None:
            # Manifest-scan results carry a bare category code — use stub metadata.
            stub = _MANIFEST_STUBS_HTML.get(threat_id)
            if stub is None:
                continue
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
            probe_contexts=contexts,
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
    import html as _html
    from cosai_mcp.catalog.models import Severity
    from cosai_mcp.report.adversarial_html import AdversarialHtmlReport, AdversarialFinding

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
    except Exception:  # noqa: BLE001
        pass  # signing unavailable (no keyring / no key) — continue without signature


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
