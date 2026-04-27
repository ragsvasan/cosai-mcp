"""cosai CLI — `cosai scan` and `cosai audit verify`."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

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
              help="Write HTML report to this file path.")
@click.option("--report-coverage", is_flag=True, default=False,
              help="Print coverage matrix showing which engine covers each category.")
@click.option("--probe-timeout", type=float, default=30.0, show_default=True,
              help="Per-probe timeout in seconds.")
@click.option("--allow-private-targets", is_flag=True, default=False,
              help="Allow scanning RFC1918/loopback/link-local targets (dev servers).")
@click.option("--catalog-root", type=click.Path(exists=True, file_okay=False), default=None,
              help="Override catalog root directory (default: ./catalog).")
@click.option("--auth-token", default=None, envvar="COSAI_AUTH_TOKEN",
              help="Bearer token for servers that require auth on the MCP handshake.")
@click.option("--mcp-path", default="/mcp", show_default=True,
              help="URL path of the MCP endpoint (override if server uses a custom path).")
@click.option("--skip-reachability", is_flag=True, default=False, hidden=True,
              help="Skip the initial TCP reachability check (testing only).")
def scan(
    target: str,
    categories: str,
    engine: str,
    fail_on: str,
    allow_custom_catalog: bool,
    report_sarif: str | None,
    report_html: str | None,
    report_coverage: bool,
    probe_timeout: float,
    allow_private_targets: bool,
    catalog_root: str | None,
    auth_token: str | None,
    mcp_path: str,
    skip_reachability: bool,
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
        )
    except TargetUnreachableError as exc:
        click.echo(f"[ERROR] Target unreachable during scan: {exc}", err=True)
        sys.exit(3)
    except Exception as exc:  # noqa: BLE001
        click.echo(f"[ERROR] Scanner internal error: {exc}", err=True)
        sys.exit(2)

    # -- Emit summary --
    _print_scan_summary(result)

    # -- Write reports — exit 2 on failure when path is explicitly provided (FIX [7]) --
    if report_sarif:
        try:
            _write_sarif_report(result, Path(report_sarif))
            click.echo(f"SARIF report written to {report_sarif}")
        except Exception as exc:  # noqa: BLE001
            click.echo(f"[ERROR] Failed to write SARIF report: {exc}", err=True)
            sys.exit(2)

    if report_html:
        try:
            _write_html_report(result, Path(report_html))
            click.echo(f"HTML report written to {report_html}")
        except Exception as exc:  # noqa: BLE001
            click.echo(f"[ERROR] Failed to write HTML report: {exc}", err=True)
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


def _print_scan_summary(result: ScanResult) -> None:
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

    if result.exit_code == 0:
        click.echo("[CLEAN] No findings.")
    elif result.exit_code == 1:
        click.echo(f"[FINDINGS] {failed_probes + failed_scenarios} issue(s) detected.")
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


def _write_html_report(result: ScanResult, path: Path) -> None:
    from cosai_mcp.report.html import HtmlReportBuilder, HtmlReportSection

    builder = HtmlReportBuilder(
        target_url=result.target_url,
        scan_timestamp=result.scan_timestamp,
    )

    # Group probe results by threat_id
    from collections import defaultdict
    results_by_threat: dict[str, list] = defaultdict(list)
    for r in result.probe_results:
        results_by_threat[r.threat_id].append(r)

    threat_by_id = {t.id: t for t in result.threats}

    for threat_id, probe_results in sorted(results_by_threat.items()):
        threat = threat_by_id.get(threat_id)
        if threat is None:
            continue
        passed = all(r.passed for r in probe_results)
        section = HtmlReportSection(
            threat_id=threat.id,
            category=threat.category,
            severity=threat.severity,
            passed=passed,
            probe_results=probe_results,
            remediation=getattr(threat, "remediation", ""),
            references=getattr(threat, "references", ()),
        )
        builder.add_section(section)

    path.write_text(builder.build(), encoding="utf-8")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
