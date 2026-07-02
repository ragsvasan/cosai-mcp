"""Fleet scanning — bounded-concurrency multi-target scan with one
aggregated verdict.

ENT-P0-4 (docs/ENTERPRISE_REQUIREMENTS_2026-07-01.md): "no enterprise runs
one MCP server; a per-server-only tool doesn't fit a release gate." This
module runs `_run_scan` against N targets with bounded concurrency,
isolates a per-target failure (unreachable, scanner error) so it never
masks another target's real findings, and merges the per-target SARIF and
scorecard artifacts into one file each.

Targets file format is plain text (one URL per line, blank lines and '#'
comments ignored) — not YAML. Adding pyyaml as a new core runtime
dependency would extend the locked minimal-dependency list in CLAUDE.md
("Standalone / Headless / Zero-MCP-Dependency": httpx, subprocess,
websockets, google-re2, joserfc, keyring), which is not this feature's
call to make unilaterally; the acceptance criterion's substance (one file,
N targets, one aggregated verdict) does not require YAML specifically.
"""
from __future__ import annotations

import concurrent.futures
import dataclasses
import html
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cosai_mcp.exceptions import TargetUnreachableError

# Default wall-clock bound per target so one hung target (e.g. a hostile
# server that accepts the TCP connect and stalls mid-handshake in a way no
# individual probe's own SIGALRM/multiprocessing timeout covers) cannot
# block the whole fleet run indefinitely — panel-review finding (ENT-P0-4):
# ThreadPoolExecutor's default shutdown(wait=True) blocks until every
# submitted future completes, defeating the "one bad target doesn't block
# the others" guarantee at the whole-fleet level even though per-target
# TargetOutcome isolation was already correct.
_DEFAULT_PER_TARGET_TIMEOUT_SECONDS = 600.0


def _sanitize_error(text: str | BaseException) -> str:
    """Sanitize an exception message before it reaches a report artifact.

    Panel-review finding (ENT-P0-4): `TargetOutcome.error` is `str(exc)` on
    exceptions raised while scanning a TARGET SERVER — the call graph
    (DNS resolution, TLS negotiation, HTTP, JSON-RPC parsing) means the
    text can embed target-influenced bytes (e.g. a crafted TLS certificate
    CN, a JSON-decode-error snippet of the response body, an HTTP reason
    phrase). Every other target-influenced string in this codebase is
    sanitized at ingestion (CLAUDE.md "Report Security": "HTML-escape all
    captured response content at ingestion") before it can reach a written
    artifact — this reuses the same control-char-strip + length-cap
    (_sanitize_message, already used for SARIF message.text) and adds the
    HTML-escape CLAUDE.md requires, so the fleet scorecard's error field
    and the stdout status line share one sanitized value.
    """
    from cosai_mcp.report.sarif import _sanitize_message

    return html.escape(_sanitize_message(str(text)), quote=True)

# Aggregate exit-code precedence, worst to best. A scanner error (2) always
# dominates (matches the single-target locked contract: exit 2 is a failure
# regardless of --fail-on). A real finding (1) must outrank a DIFFERENT
# target simply being unreachable (3) — the acceptance criterion's core
# requirement is that one down host doesn't mask another host's findings.
_EXIT_PRECEDENCE: dict[int, int] = {2: 0, 1: 1, 3: 2, 0: 3}


@dataclasses.dataclass(frozen=True)
class TargetOutcome:
    """Result of scanning one target within a fleet run."""

    target_url: str
    exit_code: int
    result: Any = None  # ScanResult | None — Any avoids an api.py import cycle
    error: str | None = None


@dataclasses.dataclass(frozen=True)
class FleetResult:
    """Aggregated result of a fleet scan — one verdict over N targets."""

    targets: tuple[TargetOutcome, ...]
    exit_code: int


def parse_targets_file(path: Path) -> list[str]:
    """Parse a plain-text target list: one URL per line.

    Blank lines and lines starting with '#' (after stripping) are ignored.
    Raises ValueError on an empty result or a line missing a URL scheme —
    fail closed, matching this project's convention for malformed
    operator-supplied input (see baseline.py's fail-closed .cosai-baseline
    parsing).
    """
    from cosai_mcp.api import _parse_target

    targets: list[str] = []
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        _parse_target(line)  # raises ValueError with the offending URL on failure
        targets.append(line)

    if not targets:
        raise ValueError(f"{path}: no targets found (file is empty or all-comments)")
    return targets


def _aggregate_exit_code(codes: list[int]) -> int:
    """Return the worst exit code per _EXIT_PRECEDENCE. Empty input is clean."""
    if not codes:
        return 0
    return min(codes, key=lambda c: _EXIT_PRECEDENCE.get(c, 0))


def _default_scan_one(
    target: str, *, skip_reachability: bool = False, **run_scan_kwargs: Any
) -> TargetOutcome:
    """Reachability-check then scan a single target, isolating every
    failure mode into a TargetOutcome instead of letting it propagate and
    abort the fleet (per-target isolation is the whole point of this
    function — see run_fleet_scan's docstring).

    skip_reachability mirrors the single-target CLI's --skip-reachability
    escape hatch (panel-review finding: it was previously silently dropped
    in fleet mode, force-failing every target whose MCP endpoint doesn't
    accept a bare TCP connect the same way the operator explicitly opted
    out of for single-target scans).
    """
    from cosai_mcp.api import _parse_target, _run_scan, check_reachable

    if not skip_reachability:
        try:
            host, port, _ = _parse_target(target)
            check_reachable(host, port)
        except TargetUnreachableError as exc:
            return TargetOutcome(target_url=target, exit_code=3, error=_sanitize_error(exc))
        except ValueError as exc:
            return TargetOutcome(target_url=target, exit_code=2, error=_sanitize_error(exc))

    try:
        result = _run_scan(target=target, **run_scan_kwargs)
        return TargetOutcome(target_url=target, exit_code=result.exit_code, result=result)
    except TargetUnreachableError as exc:
        return TargetOutcome(target_url=target, exit_code=3, error=_sanitize_error(exc))
    except ValueError as exc:
        return TargetOutcome(target_url=target, exit_code=2, error=_sanitize_error(exc))
    except Exception as exc:  # noqa: BLE001 — isolate any scanner-internal crash per-target
        return TargetOutcome(target_url=target, exit_code=2, error=_sanitize_error(exc))


def run_fleet_scan(
    targets: list[str],
    *,
    max_concurrency: int = 5,
    per_target_timeout: float = _DEFAULT_PER_TARGET_TIMEOUT_SECONDS,
    scan_fn: Callable[..., TargetOutcome] = _default_scan_one,
    **run_scan_kwargs: Any,
) -> FleetResult:
    """Scan every target in *targets* with at most *max_concurrency* scans
    in flight at once.

    A failure scanning one target (unreachable, malformed URL, scanner
    crash) is isolated to that target's TargetOutcome — it never stops or
    masks the other targets' scans. Results are returned in the same order
    as *targets* (input order), not completion order, so fleet output is
    deterministic regardless of which target happens to finish first.

    per_target_timeout bounds how long this function waits on the slowest
    outstanding target before giving up on it and returning (panel-review
    finding: without this, a single target that hangs — e.g. a hostile
    server that accepts the TCP connect and stalls mid-handshake in a way
    no individual probe's own timeout covers — blocks the ENTIRE fleet run
    indefinitely, since ThreadPoolExecutor's default shutdown() waits for
    every submitted future). A target still running when the timeout is
    reached is recorded as a timed-out TargetOutcome; the underlying
    thread may continue running in the background (Python cannot forcibly
    kill a thread), but this function's caller is never blocked on it.
    """
    outcomes_by_target: dict[str, TargetOutcome] = {}
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, max_concurrency))
    try:
        future_to_target = {
            pool.submit(scan_fn, target, **run_scan_kwargs): target for target in targets
        }
        try:
            for future in concurrent.futures.as_completed(
                future_to_target, timeout=per_target_timeout
            ):
                target = future_to_target[future]
                # scan_fn's contract is "always return a TargetOutcome,
                # never raise" (see _default_scan_one) — this is a
                # defense-in-depth safety net for a custom scan_fn that
                # doesn't follow it, using the same exit-code precedence
                # _default_scan_one uses internally so behavior is
                # identical either way.
                try:
                    outcomes_by_target[target] = future.result()
                except TargetUnreachableError as exc:
                    outcomes_by_target[target] = TargetOutcome(
                        target_url=target, exit_code=3, error=_sanitize_error(exc)
                    )
                except Exception as exc:  # noqa: BLE001
                    outcomes_by_target[target] = TargetOutcome(
                        target_url=target, exit_code=2, error=_sanitize_error(exc)
                    )
        except concurrent.futures.TimeoutError:
            pass  # any target still outstanding is handled below
    finally:
        # wait=False: never block process exit on a still-running thread —
        # Python cannot forcibly kill it, but this call must not wait for
        # it either (see docstring).
        pool.shutdown(wait=False)

    for target in targets:
        if target not in outcomes_by_target:
            outcomes_by_target[target] = TargetOutcome(
                target_url=target,
                exit_code=2,
                error=_sanitize_error(
                    f"Fleet scan timed out waiting for this target "
                    f"after {per_target_timeout}s"
                ),
            )

    ordered = tuple(outcomes_by_target[t] for t in targets)
    exit_code = _aggregate_exit_code([o.exit_code for o in ordered])
    return FleetResult(targets=ordered, exit_code=exit_code)


def merge_sarif(sarif_docs: list[dict]) -> dict:
    """Combine N single-target SARIF 2.1.0 documents into one document with
    N runs — GitHub's SARIF viewer renders multi-run documents natively.
    """
    if not sarif_docs:
        raise ValueError("merge_sarif requires at least one SARIF document")

    merged_runs: list[dict] = []
    for doc in sarif_docs:
        merged_runs.extend(doc.get("runs", []))

    first = sarif_docs[0]
    return {
        "$schema": first.get("$schema", "https://json.schemastore.org/sarif-2.1.0.json"),
        "version": first.get("version", "2.1.0"),
        "runs": merged_runs,
    }


def build_fleet_scorecard(fleet_result: FleetResult, *, signed: bool = True) -> dict[str, Any]:
    """Build the one-file aggregated scorecard for a fleet run.

    Each target's own Scorecard remains individually Ed25519-signed (its
    tamper-evidence is per-target, unchanged from single-target scanning);
    this wrapper is the "one aggregated scorecard" artifact the acceptance
    criterion asks for, listing every target's outcome and — when a scan
    actually completed — its full signed Scorecard payload.
    """
    from cosai_mcp.scorecard.builder import build_scorecard

    target_entries: list[dict[str, Any]] = []
    for outcome in fleet_result.targets:
        entry: dict[str, Any] = {
            "target_url": outcome.target_url,
            "exit_code": outcome.exit_code,
            "error": outcome.error,
            "scorecard": None,
        }
        if outcome.result is not None:
            entry["scorecard"] = build_scorecard(outcome.result, signed=signed).to_dict()
        target_entries.append(entry)

    return {
        "fleet_exit_code": fleet_result.exit_code,
        "target_count": len(fleet_result.targets),
        "targets": target_entries,
    }
