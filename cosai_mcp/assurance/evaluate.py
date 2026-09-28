"""Evaluate scan evidence against a claimed CoSAI assurance level.

Verdict rules (Mnemo dec_8575e56c7c — fail-closed, never over-claim), in order:
  FAIL        any linked catalog probe, passive scan, or stateful scenario
              produced a conclusive finding (baseline-suppressed findings still
              count — accepting a risk is not meeting the control)
  UNVERIFIED  a linked catalog probe or stateful scenario did not run or
              produced no conclusive result (evidence cannot stand in for a
              test that could have disproved the control)
  ATTESTED    operator evidence recorded for the control
  PASS        the control has ``verify_with`` positive-signal probes, the
              claimed level is <= ``blackbox_max_level``, and EVERY probe
              result of EVERY ``verify_with`` threat passed conclusively
  UNVERIFIED  anything else (with the reason)

Level result: NOT_MET if any MUST FAILED; MET if every MUST is PASS (fully
scanner-verified); MET_WITH_ATTESTATION if every MUST is PASS or ATTESTED
with at least one ATTESTED; otherwise INDETERMINATE.  SHOULD controls are
reported but never gate.
"""
from __future__ import annotations

import re
import types
from collections.abc import Iterable, Mapping
from typing import Any

from cosai_mcp.assurance.controls import CONTROLS, PROFILE_VERSION
from cosai_mcp.assurance.models import (
    AssuranceReport,
    Control,
    ControlVerdict,
    EvidenceItem,
    LevelResult,
    Strength,
    Verdict,
)

# Passive manifest scans emit bare category IDs ("T06") and only when the
# manifest is non-empty, so their ABSENCE is not proof a test was skipped —
# but a present, inconclusive passive result is.
_PASSIVE_ID = re.compile(r"^T\d{2}$")


def _outcomes(
    ids: set[str], probe_results: list[Any], scenario_results: list[Any],
) -> tuple[set[str], dict[str, list[str]], set[str], set[str]]:
    """Return (conclusive_ids, failed{id: [probe_ids]}, fully_passed_ids, seen_ids).

    ``conclusive_ids``: IDs with at least one conclusive result — an ID whose
    every result was inconclusive/errored (e.g. era "not applicable", missing
    --read-token, scenario without method overrides) did not effectively run.
    ``fully_passed_ids``: IDs where EVERY result is conclusive and passed —
    one inconclusive probe under a threat means that threat is not proven.
    """
    conclusive: set[str] = set()
    failed: dict[str, list[str]] = {}
    seen_unproven: set[str] = set()
    seen: set[str] = set()
    for r in probe_results:
        if r.threat_id not in ids:
            continue
        seen.add(r.threat_id)
        if r.error is not None or r.inconclusive_reason:
            seen_unproven.add(r.threat_id)
            continue
        conclusive.add(r.threat_id)
        if not r.passed:
            failed.setdefault(r.threat_id, []).append(r.probe_id)
    for s in scenario_results:
        if s.scenario_id not in ids:
            continue
        seen.add(s.scenario_id)
        if s.status != "complete":
            seen_unproven.add(s.scenario_id)
            continue
        conclusive.add(s.scenario_id)
        if not s.passed:
            failed.setdefault(s.scenario_id, []).append(s.scenario_id)
    passed = seen - seen_unproven - set(failed)
    return conclusive, failed, passed, seen


def _control_verdict(
    control: Control,
    level: int,
    probe_results: list[Any],
    scenario_results: list[Any],
    evidence: Mapping[str, EvidenceItem],
    required_optional: frozenset[str] = frozenset(),
) -> ControlVerdict:
    skipped_note = ""

    def _mk(
        strength: Strength | None, verdict: Verdict, reason: str,
        linked: tuple[str, ...] = (), sha: str | None = None,
    ) -> ControlVerdict:
        return ControlVerdict(
            control_id=control.control_id, dimension=control.dimension,
            title=control.title, strength=strength, verdict=verdict,
            reason=reason + skipped_note,
            linked_results=linked, evidence_sha256=sha,
        )

    req = control.requirement(level)
    if req is None:
        return _mk(None, Verdict.NOT_REQUIRED, f"Not required at Level {level}.")

    linked = set(control.probe_threats) | set(control.verify_with)
    ran, failed, passed, seen = _outcomes(
        linked | set(control.optional_probes), probe_results, scenario_results
    )
    item = evidence.get(control.control_id)
    sha = item.sha256 if item else None

    if failed:
        probe_ids = tuple(pid for ids in failed.values() for pid in ids)
        return _mk(req.strength, Verdict.FAIL,
                   f"Scanner finding(s) contradict: {req.text}.", probe_ids, sha)

    # Optional disproof links become REQUIRED when the target exposes their
    # surface (e.g. modern-only probes on a modern target), so an era pin or
    # category filter cannot manufacture "not applicable" (batch-2 EXPLOIT 7).
    promoted = set(control.optional_probes) & required_optional
    required_to_run = {i for i in linked if not _PASSIVE_ID.match(i)} | promoted
    skipped = sorted(set(control.optional_probes) - ran - promoted)
    if skipped:
        skipped_note = (f" Optional disproof test(s) not conclusively run in this scan: "
                        f"{', '.join(skipped)}.")
    # A passive scan that is ABSENT (empty manifest) is exempt, but one that is
    # PRESENT and says it could not run (e.g. T11 without --tool-allowlist) is a
    # skipped disproving test like any other (round-3 EXPLOIT 1).
    passive_unproven = {i for i in linked if _PASSIVE_ID.match(i) and i in seen} - ran
    not_run = sorted((required_to_run - ran) | passive_unproven)
    if not_run:
        return _mk(req.strength, Verdict.UNVERIFIED,
                   f"Unverified: linked test(s) did not run or produced no conclusive "
                   f"result in this scan ({', '.join(not_run)}) — evidence cannot "
                   f"stand in for a test that could disprove it. Requirement: {req.text}.",
                   tuple(sorted(passed)), sha)

    if item is not None:
        return _mk(req.strength, Verdict.ATTESTED,
                   f"Operator evidence recorded ({item.artifact}); not verified by "
                   f"the scanner. Requirement: {req.text}.", tuple(sorted(passed)), sha)

    verifiers = set(control.verify_with)
    if verifiers and level <= control.blackbox_max_level and verifiers <= passed:
        return _mk(req.strength, Verdict.PASS,
                   f"Verified by positive-signal probes: {req.text}.",
                   tuple(sorted(verifiers)))

    if not verifiers:
        why = ("no black-box probe can prove this control (linked probes can only "
               "disprove it) — supply evidence (--evidence)"
               if control.probe_threats else
               "organisational/runtime control — supply evidence (--evidence)")
    elif level > control.blackbox_max_level:
        why = (f"black-box probes verify only up to Level {control.blackbox_max_level} "
               "— supply evidence (--evidence)")
    else:
        why = ("positive-signal probe(s) inconclusive: "
               + ", ".join(sorted(verifiers - passed)))
    return _mk(req.strength, Verdict.UNVERIFIED,
               f"Unverified: {why}. Requirement: {req.text}.", tuple(sorted(passed)))


def evaluate_assurance(
    claimed_level: int,
    probe_results: Iterable[Any],
    scenario_results: Iterable[Any] = (),
    evidence: Mapping[str, EvidenceItem] | None = None,
    scope: Mapping[str, Any] | None = None,
    required_optional: frozenset[str] = frozenset(),
) -> AssuranceReport:
    """Evaluate every control at ``claimed_level`` (1–4).

    ``required_optional``: optional-link IDs that must run for this target
    (e.g. modern-only probes when the target speaks MCP 2026-07-28).
    """
    if claimed_level not in (1, 2, 3, 4):
        raise ValueError(f"assurance level must be 1–4, got {claimed_level!r}")
    probes = list(probe_results)
    scenarios = list(scenario_results)
    ev = evidence or {}
    verdicts = tuple(
        _control_verdict(c, claimed_level, probes, scenarios, ev, required_optional)
        for c in CONTROLS
    )
    musts = [v for v in verdicts if v.strength is Strength.MUST]
    if any(v.verdict is Verdict.FAIL for v in musts):
        result = LevelResult.NOT_MET
    elif all(v.verdict is Verdict.PASS for v in musts):
        result = LevelResult.MET
    elif all(v.verdict in (Verdict.PASS, Verdict.ATTESTED) for v in musts):
        result = LevelResult.MET_WITH_ATTESTATION
    else:
        result = LevelResult.INDETERMINATE
    return AssuranceReport(
        claimed_level=claimed_level,
        result=result,
        profile_version=PROFILE_VERSION,
        controls=verdicts,
        scope=types.MappingProxyType(dict(scope or {})),
    )
