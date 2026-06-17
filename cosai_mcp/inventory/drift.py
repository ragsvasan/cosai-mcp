"""Drift detection: compare two ToolInventory snapshots.

``detect_drift()`` returns a ``DriftReport`` that classifies every change
as ADDED, REMOVED, DESCRIPTION_CHANGED, or SCHEMA_CHANGED.  An empty report
means the manifests are identical.  The drift gate in CI should fail when
``DriftReport.has_drift`` is True (configurable by kind).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from cosai_mcp.inventory.snapshot import ToolInventory, ToolRecord


class DriftKind(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    DESCRIPTION_CHANGED = "description_changed"
    SCHEMA_CHANGED = "schema_changed"


@dataclass(frozen=True)
class DriftEntry:
    kind: DriftKind
    tool_name: str
    before: str | None  # serialised representation of the old value, or None
    after: str | None   # serialised representation of the new value, or None


@dataclass(frozen=True)
class DriftReport:
    baseline_target: str
    current_target: str
    baseline_captured_at: str
    current_captured_at: str
    entries: tuple[DriftEntry, ...]

    @property
    def has_drift(self) -> bool:
        return bool(self.entries)

    @property
    def added(self) -> tuple[DriftEntry, ...]:
        return tuple(e for e in self.entries if e.kind == DriftKind.ADDED)

    @property
    def removed(self) -> tuple[DriftEntry, ...]:
        return tuple(e for e in self.entries if e.kind == DriftKind.REMOVED)

    @property
    def changed(self) -> tuple[DriftEntry, ...]:
        return tuple(
            e for e in self.entries
            if e.kind in (DriftKind.DESCRIPTION_CHANGED, DriftKind.SCHEMA_CHANGED)
        )

    def summary(self) -> str:
        if not self.has_drift:
            return "No drift detected."
        parts = []
        if self.added:
            parts.append(f"{len(self.added)} tool(s) added")
        if self.removed:
            parts.append(f"{len(self.removed)} tool(s) removed")
        if self.changed:
            parts.append(f"{len(self.changed)} tool(s) changed")
        return "; ".join(parts) + "."


def detect_drift(baseline: ToolInventory, current: ToolInventory) -> DriftReport:
    """Compare ``current`` against ``baseline`` and return a DriftReport.

    Tools are matched by name.  Changes to description or inputSchema within
    the same-named tool are reported as separate DriftEntry items.
    """
    base_map: dict[str, ToolRecord] = {t.name: t for t in baseline.tools}
    curr_map: dict[str, ToolRecord] = {t.name: t for t in current.tools}

    entries: list[DriftEntry] = []

    for name in sorted(curr_map.keys() - base_map.keys()):
        rec = curr_map[name]
        entries.append(DriftEntry(
            kind=DriftKind.ADDED,
            tool_name=name,
            before=None,
            after=rec.description or "<no description>",
        ))

    for name in sorted(base_map.keys() - curr_map.keys()):
        rec = base_map[name]
        entries.append(DriftEntry(
            kind=DriftKind.REMOVED,
            tool_name=name,
            before=rec.description or "<no description>",
            after=None,
        ))

    for name in sorted(base_map.keys() & curr_map.keys()):
        old = base_map[name]
        new = curr_map[name]
        if old.description != new.description:
            entries.append(DriftEntry(
                kind=DriftKind.DESCRIPTION_CHANGED,
                tool_name=name,
                before=old.description,
                after=new.description,
            ))
        if old.input_schema != new.input_schema:
            entries.append(DriftEntry(
                kind=DriftKind.SCHEMA_CHANGED,
                tool_name=name,
                before=old.input_schema,
                after=new.input_schema,
            ))

    return DriftReport(
        baseline_target=baseline.target,
        current_target=current.target,
        baseline_captured_at=baseline.captured_at,
        current_captured_at=current.captured_at,
        entries=tuple(entries),
    )
