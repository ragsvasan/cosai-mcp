"""Frozen models for CoSAI MCP Security v2.0 Security Assurance Profiles (§3.3)."""
from __future__ import annotations

import types
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Strength(StrEnum):
    MUST = "must"
    SHOULD = "should"


class Verdict(StrEnum):
    PASS = "pass"                  # noqa: S105 — black-box probes verified the requirement
    FAIL = "fail"                  # a linked probe/scenario produced a conclusive finding
    ATTESTED = "attested"          # operator-supplied evidence recorded (not verified)
    UNVERIFIED = "unverified"      # could not be verified by this scan
    NOT_REQUIRED = "not_required"  # no requirement at the claimed level


class LevelResult(StrEnum):
    MET = "met"                                    # every MUST scanner-verified (PASS)
    MET_WITH_ATTESTATION = "met_with_attestation"  # every MUST PASS or ATTESTED, ≥1 ATTESTED
    NOT_MET = "not_met"                            # at least one MUST FAILED
    INDETERMINATE = "indeterminate"                # no MUST failed, some MUST unverified


@dataclass(frozen=True)
class Requirement:
    strength: Strength
    text: str


@dataclass(frozen=True)
class Control:
    """One row of the v2.0 §3.3.2 control matrix.

    ``levels`` maps 1..4 → Requirement (absent = not required at that level).
    ``probe_threats`` are catalog threat IDs, passive-scan category IDs
    (e.g. ``"T06"``) or stateful scenario IDs whose conclusive failure is
    evidence the control is NOT met (they can only DISPROVE).
    ``verify_with`` is the subset of catalog probes that assert a *positive*
    control signal (a specific rejection error code / HTTP status) and can
    therefore PROVE the requirement — every one must pass conclusively, up
    to ``blackbox_max_level`` (0 = never provable black-box).
    """

    control_id: str
    dimension: str
    title: str
    levels: types.MappingProxyType  # MappingProxyType[int, Requirement]
    mcp_t: tuple[str, ...]
    probe_threats: tuple[str, ...] = ()
    blackbox_max_level: int = 0
    verify_with: tuple[str, ...] = ()
    # Disproof-only links that are NOT required to run: a conclusive finding
    # still FAILS the control, but an absent/inconclusive result does not
    # block attestation. For probes whose surface is optional on the target
    # (2026-07-28-only features, the Tasks extension).
    optional_probes: tuple[str, ...] = ()

    def requirement(self, level: int) -> Requirement | None:
        req: Requirement | None = self.levels.get(level)
        return req


@dataclass(frozen=True)
class EvidenceItem:
    control_id: str
    artifact: str   # display path: control-char-stripped, capped, HTML-escaped
    sha256: str
    note: str = ""  # control-char-stripped, length-capped, HTML-escaped


@dataclass(frozen=True)
class EvidenceManifest:
    target: str     # target URL the evidence was prepared for (bound to the scan)
    items: types.MappingProxyType  # MappingProxyType[str, EvidenceItem]


@dataclass(frozen=True)
class ControlVerdict:
    control_id: str
    dimension: str
    title: str
    strength: Strength | None
    verdict: Verdict
    reason: str
    linked_results: tuple[str, ...] = ()
    evidence_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "dimension": self.dimension,
            "title": self.title,
            "strength": self.strength.value if self.strength else None,
            "verdict": self.verdict.value,
            "reason": self.reason,
            "linked_results": list(self.linked_results),
            "evidence_sha256": self.evidence_sha256,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ControlVerdict:
        strength = d.get("strength")
        return cls(
            control_id=str(d["control_id"]),
            dimension=str(d.get("dimension", "")),
            title=str(d.get("title", "")),
            strength=Strength(strength) if strength else None,
            verdict=Verdict(d["verdict"]),
            reason=str(d.get("reason", "")),
            linked_results=tuple(str(x) for x in d.get("linked_results", ())),
            evidence_sha256=(
                str(d["evidence_sha256"]) if d.get("evidence_sha256") else None
            ),
        )


@dataclass(frozen=True)
class AssuranceReport:
    """Verdict for a claimed CoSAI assurance level — embedded in the scorecard."""

    claimed_level: int
    result: LevelResult
    profile_version: str
    controls: tuple[ControlVerdict, ...] = field(default=())
    # Effective scan scope the verdict was computed over (signed with it), so
    # a verifier can see the claim came from a full, unfiltered scan.
    scope: types.MappingProxyType = field(
        default_factory=lambda: types.MappingProxyType({})
    )

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for c in self.controls:
            if c.strength is Strength.MUST:
                out[c.verdict.value] = out.get(c.verdict.value, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        must = [c for c in self.controls if c.strength is Strength.MUST]
        return {
            "claimed_level": self.claimed_level,
            "result": self.result.value,
            "profile_version": self.profile_version,
            "must_counts": {
                v.value: sum(1 for c in must if c.verdict is v)
                for v in (Verdict.PASS, Verdict.ATTESTED, Verdict.FAIL, Verdict.UNVERIFIED)
            },
            "scope": dict(self.scope),
            "controls": [c.to_dict() for c in self.controls],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AssuranceReport:
        return cls(
            claimed_level=int(d["claimed_level"]),
            result=LevelResult(d["result"]),
            profile_version=str(d.get("profile_version", "")),
            controls=tuple(ControlVerdict.from_dict(c) for c in d.get("controls", ())),
            scope=types.MappingProxyType(dict(d.get("scope") or {})),
        )
