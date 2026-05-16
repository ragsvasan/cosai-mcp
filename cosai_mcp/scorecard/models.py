"""Scorecard data models — frozen dataclasses for per-category conformance grades."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Grade(str, Enum):
    PASS = "pass"
    WARN = "warn"           # findings below "high" severity only
    FAIL = "fail"           # any high or critical finding
    NOT_TESTED = "not_tested"  # zero probes executed


class ConformanceLevel(str, Enum):
    FULL_CONFORMANCE = "full_conformance"
    PARTIAL_CONFORMANCE = "partial_conformance"
    NON_CONFORMANT = "non_conformant"
    INSUFFICIENT_COVERAGE = "insufficient_coverage"  # too many NOT_TESTED categories


# OCSF-aligned coverage labels (mirrors CLAUDE.md three-engine architecture)
_ENGINE_COVERAGE: dict[str, str] = {
    "T1": "black_box_prober",
    "T2": "stateful_harness",
    "T3": "black_box_prober",
    "T4": "middleware_instrumentation",
    "T5": "middleware_instrumentation",
    "T6": "stateful_harness",
    "T7": "stateful_harness",
    "T8": "black_box_prober",
    "T9": "middleware_instrumentation",
    "T10": "black_box_prober",
    "T11": "black_box_prober",
    "T12": "middleware_instrumentation",
}


@dataclass(frozen=True)
class CategoryResult:
    """Conformance result for a single CoSAI threat category."""

    category: str              # "T1" … "T12"
    grade: Grade
    probe_count: int           # probes executed (0 = not tested)
    finding_count: int         # non-passing probes
    critical_count: int        # findings with severity ≥ critical
    high_count: int            # findings with severity = high (not critical)
    coverage_engine: str       # which engine covers this category

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "grade": self.grade.value,
            "probe_count": self.probe_count,
            "finding_count": self.finding_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "coverage_engine": self.coverage_engine,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CategoryResult":
        return cls(
            category=str(d["category"]),
            grade=Grade(d["grade"]),
            probe_count=int(d["probe_count"]),
            finding_count=int(d["finding_count"]),
            critical_count=int(d.get("critical_count", 0)),
            high_count=int(d.get("high_count", 0)),
            coverage_engine=str(d.get("coverage_engine", "unknown")),
        )


@dataclass(frozen=True)
class Scorecard:
    """Signed conformance scorecard for a completed cosai-mcp scan.

    The ``signature`` field contains the hex-encoded Ed25519 signature over
    the canonical JSON of all other fields (sorted keys, no whitespace).
    The ``public_key`` field contains the hex-encoded Ed25519 public key of
    the signer (per-installation key from OS keychain).
    """

    scan_id: str
    target_url: str
    scan_timestamp: str
    catalog_hash: str
    tool_version: str
    categories: tuple[CategoryResult, ...]
    conformance_level: ConformanceLevel
    # Signing fields (empty string if unsigned)
    public_key: str   # hex-encoded Ed25519 public key
    signature: str    # hex-encoded Ed25519 signature

    @property
    def is_signed(self) -> bool:
        return bool(self.signature and self.public_key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "scan_timestamp": self.scan_timestamp,
            "catalog_hash": self.catalog_hash,
            "tool_version": self.tool_version,
            "categories": [c.to_dict() for c in self.categories],
            "conformance_level": self.conformance_level.value,
            "public_key": self.public_key,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Scorecard":
        return cls(
            scan_id=str(d["scan_id"]),
            target_url=str(d["target_url"]),
            scan_timestamp=str(d["scan_timestamp"]),
            catalog_hash=str(d["catalog_hash"]),
            tool_version=str(d.get("tool_version", "")),
            categories=tuple(CategoryResult.from_dict(c) for c in d.get("categories", [])),
            conformance_level=ConformanceLevel(d["conformance_level"]),
            public_key=str(d.get("public_key", "")),
            signature=str(d.get("signature", "")),
        )
