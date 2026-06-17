"""Anomaly detection over emitted OCSF events.

``AnomalyDetector`` consumes OCSF event dicts emitted by cosai-mcp and fires
``AnomalyAlert`` when configured thresholds are exceeded.

Built-in rules:
* HIGH_FINDING_RATE   — more than N findings in a rolling window
* CRITICAL_BURST      — more than N critical findings in a rolling window
* SEVERITY_ESCALATION — any critical finding when baseline shows only low/medium

These are intentionally simple (threshold + window) — they are CI/CD gate
rules, not ML anomaly detection.  The AnomalyDetector is stateless across
scans; state is held in memory within a single scan session.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class AnomalyRule(StrEnum):
    HIGH_FINDING_RATE = "high_finding_rate"
    CRITICAL_BURST = "critical_burst"
    SEVERITY_ESCALATION = "severity_escalation"


@dataclass(frozen=True)
class AnomalyAlert:
    rule: AnomalyRule
    message: str
    event_count: int
    window_seconds: float
    triggered_at_ms: int  # Unix epoch milliseconds


@dataclass
class AnomalyDetector:
    """Stateful detector that tracks OCSF events and fires anomaly alerts.

    Parameters
    ----------
    high_finding_rate_threshold:
        Max findings (non-passing) in ``window_seconds`` before FINDING_RATE fires.
    critical_burst_threshold:
        Max critical findings in ``window_seconds`` before CRITICAL_BURST fires.
    severity_escalation_baseline:
        Expected max severity level. If any event exceeds this, escalation fires.
        Accepts OCSF severity_id integers (1=info, 2=low, 3=medium, 4=high, 5=critical).
    window_seconds:
        Rolling window duration for rate-based rules.
    """

    high_finding_rate_threshold: int = 10
    critical_burst_threshold: int = 3
    severity_escalation_baseline: int = 3  # medium
    window_seconds: float = 300.0  # 5 minutes

    _events: list[dict[str, Any]] = field(default_factory=list, repr=False)
    _alerts: list[AnomalyAlert] = field(default_factory=list, repr=False)

    def ingest(self, event: dict[str, Any]) -> list[AnomalyAlert]:
        """Add one OCSF event and return any new alerts it triggers."""
        now_ms = int(time.time() * 1000)
        self._events.append({**event, "_ingested_at_ms": now_ms})
        self._evict_stale(now_ms)

        new_alerts: list[AnomalyAlert] = []
        new_alerts.extend(self._check_high_finding_rate(now_ms))
        new_alerts.extend(self._check_critical_burst(now_ms))
        new_alerts.extend(self._check_severity_escalation(event, now_ms))
        self._alerts.extend(new_alerts)
        return new_alerts

    def ingest_batch(self, events: list[dict[str, Any]]) -> list[AnomalyAlert]:
        """Ingest multiple events and return all triggered alerts."""
        alerts: list[AnomalyAlert] = []
        for e in events:
            alerts.extend(self.ingest(e))
        return alerts

    @property
    def alerts(self) -> list[AnomalyAlert]:
        """All alerts fired since construction."""
        return list(self._alerts)

    def reset(self) -> None:
        """Clear all ingested events and alerts (start fresh)."""
        self._events.clear()
        self._alerts.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evict_stale(self, now_ms: int) -> None:
        cutoff = now_ms - int(self.window_seconds * 1000)
        self._events = [e for e in self._events if e.get("_ingested_at_ms", 0) >= cutoff]

    def _window_events(self) -> list[dict[str, Any]]:
        return self._events  # already evicted by _evict_stale

    def _is_finding(self, event: dict[str, Any]) -> bool:
        """Return True if the event represents a failed probe (a real finding)."""
        unmapped = event.get("unmapped", {})
        return not unmapped.get("passed", True)

    def _severity_id(self, event: dict[str, Any]) -> int:
        return int(event.get("severity_id", 99))

    def _check_high_finding_rate(self, now_ms: int) -> list[AnomalyAlert]:
        findings = [e for e in self._window_events() if self._is_finding(e)]
        count = len(findings)
        if count > self.high_finding_rate_threshold:
            # Only alert once per threshold crossing (not on every subsequent event)
            # by checking if the last alert for this rule was already fired at this count
            last = next(
                (a for a in reversed(self._alerts) if a.rule == AnomalyRule.HIGH_FINDING_RATE),
                None,
            )
            if last is None or last.event_count < count:
                return [AnomalyAlert(
                    rule=AnomalyRule.HIGH_FINDING_RATE,
                    message=(
                        f"High finding rate: {count} findings in "
                        f"{self.window_seconds}s window "
                        f"(threshold={self.high_finding_rate_threshold})"
                    ),
                    event_count=count,
                    window_seconds=self.window_seconds,
                    triggered_at_ms=now_ms,
                )]
        return []

    def _check_critical_burst(self, now_ms: int) -> list[AnomalyAlert]:
        criticals = [
            e for e in self._window_events()
            if self._is_finding(e) and self._severity_id(e) >= 5  # critical
        ]
        count = len(criticals)
        if count > self.critical_burst_threshold:
            last = next(
                (a for a in reversed(self._alerts) if a.rule == AnomalyRule.CRITICAL_BURST),
                None,
            )
            if last is None or last.event_count < count:
                return [AnomalyAlert(
                    rule=AnomalyRule.CRITICAL_BURST,
                    message=(
                        f"Critical finding burst: {count} critical findings in "
                        f"{self.window_seconds}s window "
                        f"(threshold={self.critical_burst_threshold})"
                    ),
                    event_count=count,
                    window_seconds=self.window_seconds,
                    triggered_at_ms=now_ms,
                )]
        return []

    def _check_severity_escalation(
        self, event: dict[str, Any], now_ms: int
    ) -> list[AnomalyAlert]:
        if not self._is_finding(event):
            return []
        sev = self._severity_id(event)
        if sev > self.severity_escalation_baseline:
            sev_name = event.get("severity", str(sev))
            return [AnomalyAlert(
                rule=AnomalyRule.SEVERITY_ESCALATION,
                message=(
                    f"Severity escalation: {sev_name} (id={sev}) finding exceeds "
                    f"baseline threshold (id={self.severity_escalation_baseline}). "
                    f"probe={event.get('unmapped', {}).get('probe_id', '?')}"
                ),
                event_count=1,
                window_seconds=0.0,
                triggered_at_ms=now_ms,
            )]
        return []
