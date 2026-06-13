"""Scorecard builder — derive per-category conformance grades from ScanResult."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cosai_mcp.scorecard.models import (
    CategoryResult,
    ConformanceLevel,
    Grade,
    Scorecard,
    _ENGINE_COVERAGE,
)

from cosai_mcp.report.sign import OrgSigningKeyError

if TYPE_CHECKING:
    from cosai_mcp.api import ScanResult

try:
    from importlib.metadata import version as _pkg_version
    _TOOL_VERSION = _pkg_version("cosai-mcp")
except Exception:
    _TOOL_VERSION = "0.0.0"

# Severity rank — higher = more severe
_SEV_RANK: dict[str, int] = {
    "info": 0, "informational": 0,
    "low": 1, "medium": 2, "high": 3, "critical": 4,
}

# Number of NOT_TESTED categories that triggers INSUFFICIENT_COVERAGE
_MAX_NOT_TESTED = 4


def _grade_category(
    probe_count: int,
    finding_count: int,
    critical_count: int,
    high_count: int,
    pass_count: int = 0,
) -> Grade:
    if probe_count == 0:
        return Grade.NOT_TESTED
    # Probes ran but NOTHING was conclusively verified: every probe was either
    # inconclusive (boundary rejection / method-not-found) or errored.  This is
    # NOT a pass — the category was not verified secure (audit COV-06 / §2).
    if pass_count == 0 and finding_count == 0:
        return Grade.NOT_TESTED
    if finding_count == 0:
        return Grade.PASS
    if critical_count > 0 or high_count > 0:
        return Grade.FAIL
    return Grade.WARN  # findings exist but none are high/critical


def _determine_conformance(categories: list[CategoryResult]) -> ConformanceLevel:
    not_tested = sum(1 for c in categories if c.grade == Grade.NOT_TESTED)
    fails = [c for c in categories if c.grade == Grade.FAIL]
    critical_fails = sum(c.critical_count for c in fails)

    if not_tested > _MAX_NOT_TESTED:
        return ConformanceLevel.INSUFFICIENT_COVERAGE
    if not fails:
        return ConformanceLevel.FULL_CONFORMANCE
    if critical_fails > 0 or len(fails) > 3:
        return ConformanceLevel.NON_CONFORMANT
    return ConformanceLevel.PARTIAL_CONFORMANCE


def build_scorecard(
    result: "ScanResult",
    signed: bool = True,
) -> Scorecard:
    """Build a conformance scorecard from a completed scan result.

    Parameters
    ----------
    result:
        The immutable ScanResult from ``_run_scan()``.
    signed:
        If True, sign the scorecard with the per-installation Ed25519 key.
        Pass False to produce an unsigned scorecard (e.g. for testing).
    """
    # Build probe_id → (threat_id, severity) from the catalog on the result
    probe_meta: dict[str, dict[str, str]] = {}
    for threat in result.threats:
        sev = threat.severity.value if hasattr(threat.severity, "value") else str(threat.severity)
        cat = threat.category if isinstance(threat.category, str) else str(threat.category)
        for probe_def in threat.probes:
            probe_meta[probe_def.id] = {"severity": sev, "category": cat}

    # Aggregate per-category stats from probe results
    cat_stats: dict[str, dict[str, int]] = {}
    for pr in result.probe_results:
        meta = probe_meta.get(pr.probe_id, {})
        cat = meta.get("category", "T?")
        if cat not in cat_stats:
            cat_stats[cat] = {
                "probe_count": 0, "finding_count": 0,
                "critical_count": 0, "high_count": 0,
                "pass_count": 0, "inconclusive_count": 0,
            }
        cat_stats[cat]["probe_count"] += 1
        if pr.inconclusive_reason is not None:
            # Ran, but the security property could not be verified — neither a
            # pass nor a finding (audit COV-06).
            cat_stats[cat]["inconclusive_count"] += 1
        elif pr.passed:
            cat_stats[cat]["pass_count"] += 1
        elif pr.error is None:
            cat_stats[cat]["finding_count"] += 1
            sev = meta.get("severity", "medium")
            if _SEV_RANK.get(sev, 0) >= _SEV_RANK["critical"]:
                cat_stats[cat]["critical_count"] += 1
            elif _SEV_RANK.get(sev, 0) >= _SEV_RANK["high"]:
                cat_stats[cat]["high_count"] += 1

    # Build CategoryResult for each known T-category (T1–T12)
    all_categories = [f"T{i}" for i in range(1, 13)]
    cat_results: list[CategoryResult] = []
    for cat in all_categories:
        stats = cat_stats.get(cat, {"probe_count": 0, "finding_count": 0,
                                    "critical_count": 0, "high_count": 0,
                                    "pass_count": 0, "inconclusive_count": 0})
        grade = _grade_category(
            probe_count=stats["probe_count"],
            finding_count=stats["finding_count"],
            critical_count=stats["critical_count"],
            high_count=stats["high_count"],
            pass_count=stats.get("pass_count", 0),
        )
        cat_results.append(CategoryResult(
            category=cat,
            grade=grade,
            probe_count=stats["probe_count"],
            finding_count=stats["finding_count"],
            critical_count=stats["critical_count"],
            high_count=stats["high_count"],
            coverage_engine=_ENGINE_COVERAGE.get(cat, "unknown"),
            inconclusive_count=stats.get("inconclusive_count", 0),
        ))

    conformance = _determine_conformance(cat_results)

    scan_id = getattr(result, "scan_id", "") or ""

    unsigned = Scorecard(
        scan_id=str(scan_id),
        target_url=result.target_url,
        scan_timestamp=result.scan_timestamp,
        catalog_hash=result.catalog_hash,
        tool_version=_TOOL_VERSION,
        categories=tuple(cat_results),
        conformance_level=conformance,
        public_key="",
        signature="",
    )

    if not signed:
        return unsigned

    # Sign the scorecard
    try:
        from cosai_mcp.scorecard.signing import sign_scorecard
        return sign_scorecard(unsigned)
    except OrgSigningKeyError:
        # A misconfigured fleet org key must NOT silently produce an unsigned
        # scorecard — a fleet that believes it is emitting comparable signed
        # scorecards but is silently emitting unsigned ones is exactly the
        # failure WP6 forbids. Propagate so the CLI fails closed (exit 2).
        raise
    except Exception:
        # Best-effort signing — return unsigned if keyring unavailable
        return unsigned
