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
from cosai_mcp.report.verify import VerifyStatus, verify_audit_log


# ---------------------------------------------------------------------------
# Top-level CLI group
# ---------------------------------------------------------------------------

@click.group()
def main() -> None:
    """cosai-mcp: MCP security scanner covering all 12 CoSAI threat categories."""


# ---------------------------------------------------------------------------
# cosai scan
# ---------------------------------------------------------------------------

@main.command()
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
    default="critical",
    show_default=True,
    help="Minimum severity that causes exit code 1.",
)
@click.option("--allow-custom-catalog", is_flag=True, default=False,
              help="Load threat definitions from catalog/custom/ in addition to official/.")
@click.option("--report-sarif", type=click.Path(), default=None,
              help="Write SARIF 2.1.0 report to this file path.")
@click.option("--report-html", type=click.Path(), default=None,
              help="Write HTML report to this file path. "
                   "Defaults to cosai-report.html in the current directory.")
@click.option("--no-report", is_flag=True, default=False,
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
@click.option("--report-csv", type=click.Path(), default=None,
              help="Write CSV findings report to this file path (Excel-compatible).")
@click.option("--report-coverage", is_flag=True, default=False,
              help="Print coverage matrix showing which engine covers each category.")
@click.option("--probe-timeout", type=float, default=30.0, show_default=True,
              help="Per-probe timeout in seconds.")
@click.option("--probe-delay", type=float, default=0.0, show_default=True,
              help="Seconds to sleep between probes. Use when the target server "
                   "enforces rate limits on new MCP sessions.")
@click.option("--allow-private-targets/--block-private-targets", default=True,
              help="Allow scanning RFC1918/loopback targets (default: allowed for dev use). "
                   "Use --block-private-targets in CI to enforce public-target-only policy.")
@click.option("--catalog-root", type=click.Path(exists=True, file_okay=False), default=None,
              help="Override catalog root directory (default: ./catalog).")
@click.option("--auth-token", default=None, envvar="COSAI_AUTH_TOKEN",
              help="Bearer token for servers that require auth on the MCP handshake.")
@click.option("--mcp-path", default="/mcp", show_default=True,
              help="URL path of the MCP endpoint (override if server uses a custom path).")
@click.option("--no-adaptive", is_flag=True, default=False,
              help="Disable adaptive probe synthesis. Forces static catalog payloads — "
                   "use for hermetic tests or when server schema is adversarially crafted.")
@click.option("--profile", default=None,
              help="Server profile name (e.g. mnemo, fastmcp). Sets mcp_path, auth header "
                   "format, tool name map, and skip_categories automatically.")
@click.option("--allow-custom-profiles", is_flag=True, default=False,
              help="Load profile from .cosai/profiles/<name>.py or ~/.cosai/profiles/<name>.py "
                   "in addition to built-in profiles.")
@click.option("--adversarial", is_flag=True, default=False,
              help="Enable adversarial probe mode (canary-only payloads). "
                   "Requires --i-own-this-target. "
                   "ONLY use against targets you own and have authorization to test.")
@click.option("--i-own-this-target", "i_own_this_target", default=None,
              help="Ownership declaration for adversarial mode. "
                   "Must contain the target hostname verbatim. "
                   "Example: --i-own-this-target=myserver.example.com")
@click.option("--allow-stateful-adversarial", is_flag=True, default=False,
              help="Allow stateful adversarial probes that modify server state. "
                   "Only effective with --adversarial.")
@click.option("--report-adversarial-html", type=click.Path(), default=None,
              help="Write the adversarial probe report to this path "
                   "(default: cosai-adversarial-report.html when --adversarial is set).")
@click.option("--skip-reachability", is_flag=True, default=False, hidden=True,
              help="Skip the initial TCP reachability check (testing only).")
@click.option(
    "--emit-to",
    default=None,
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
    help="Max findings in the rolling window before an anomaly alert is emitted.",
)
@click.option(
    "--critical-burst-threshold",
    type=int,
    default=3,
    show_default=True,
    help="Max critical findings in the rolling window before a burst alert fires.",
)
def scan(
    target: str,
    categories: str,
    engine: str,
    fail_on: str,
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
    mcp_path: str,
    no_adaptive: bool,
    profile: str | None,
    allow_custom_profiles: bool,
    adversarial: bool,
    i_own_this_target: str | None,
    allow_stateful_adversarial: bool,
    report_adversarial_html: str | None,
    skip_reachability: bool,
    emit_to: str | None,
    emit_auth_header: str | None,
    anomaly_threshold: int,
    critical_burst_threshold: int,
) -> None:
    """Scan a target MCP server for CoSAI threat categories T1–T12.

    TARGET is the base URL of the MCP server, e.g. http://localhost:8000.

    Exit codes:
        0  Clean — no findings at or above --fail-on threshold.
        1  Findings detected at or above --fail-on threshold.
        2  Scanner internal error (fail-closed; treated as failure by CI).
        3  Target unreachable.
    """
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
            mcp_path=mcp_path,
            adaptive=not no_adaptive,
            profile=resolved_profile,
            adversarial_mode=adv_mode,
            probe_delay_seconds=probe_delay,
        )
    except ValueError as exc:
        # Includes adversarial dual opt-in failures
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

    # -- SIEM/SOAR telemetry emission --
    if emit_to:
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

    sys.exit(result.exit_code)


# ---------------------------------------------------------------------------
# cosai audit
# ---------------------------------------------------------------------------

@main.group()
def audit() -> None:
    """Audit and verify cosai-mcp scan artifacts."""


@audit.command("verify")
@click.argument("report", type=click.Path())
def audit_verify(report: str) -> None:
    """Verify the hash-chained integrity of an audit log.

    REPORT is the path to the JSON Lines audit log written by a previous scan.

    Exit codes:
        0  Chain intact.
        1  Chain broken (tamper detected).
        2  File not found or empty log.
    """
    result = verify_audit_log(report)

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
    failed_probes = sum(1 for r in result.probe_results if not r.passed)
    total_scenarios = len(result.scenario_results)
    failed_scenarios = sum(1 for r in result.scenario_results if not r.passed)

    click.echo(f"\nTarget: {result.target_url}")
    click.echo(f"Timestamp: {result.scan_timestamp}")
    click.echo(f"Catalog hash: {result.catalog_hash[:16]}…")
    click.echo(
        f"Probes: {failed_probes}/{total_probes} failed   "
        f"Scenarios: {failed_scenarios}/{total_scenarios} failed"
    )

    total_non_inconclusive_findings = (
        sum(1 for r in result.probe_results if not r.passed and r.error is None and not r.inconclusive_reason)
        + sum(1 for r in result.scenario_results if not r.passed and r.status not in ("scan-incomplete", "inconclusive"))
    )
    inconclusive_count = (
        sum(1 for r in result.probe_results if r.inconclusive_reason)
        + sum(1 for r in result.scenario_results if r.status == "inconclusive")
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
            continue
        builder.add_result(
            result=probe_result,
            severity=threat.severity,
            rule_id=threat.id,
            rule_name=getattr(threat, "name", threat.id),
            rule_description=getattr(threat, "remediation", "")[:512],
            owasp_ref=threat.owasp_ref,
            cwe=threat.cwe,
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
    except Exception:  # noqa: BLE001
        pass  # signing unavailable (no keyring / no key) — continue without signature


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
