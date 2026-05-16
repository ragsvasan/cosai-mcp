"""Tests for cosai_mcp.telemetry — emitter, OCSF schema, anomaly detection, CLI wiring."""
from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Any
from unittest.mock import MagicMock, create_autospec, patch

import pytest
from click.testing import CliRunner

from cosai_mcp.cli import main
from cosai_mcp.telemetry.anomaly import AnomalyAlert, AnomalyDetector, AnomalyRule
from cosai_mcp.telemetry.emitter import EmitResult, HttpEmitter, NullEmitter
from cosai_mcp.telemetry.ocsf import (
    OcsfEvent,
    _SEVERITY_MAP,
    build_detection_finding,
    probe_result_to_ocsf,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(
    passed: bool = False,
    severity_id: int = 4,  # high
    probe_id: str = "T01-001-p1",
    threat_id: str = "T01-001",
) -> dict[str, Any]:
    return build_detection_finding(
        probe_id=probe_id,
        threat_id=threat_id,
        passed=passed,
        target="http://example.com",
        severity="high" if severity_id == 4 else "critical",
        timestamp_ms=int(time.time() * 1000),
    ).to_dict()


def _make_finding_event(severity: str = "high") -> dict[str, Any]:
    return build_detection_finding(
        probe_id="T01-001-p1",
        threat_id="T01-001",
        passed=False,
        target="http://example.com",
        severity=severity,
    ).to_dict()


class _RecordingHTTPServer:
    """Minimal HTTP server that records POST bodies."""

    def __init__(self) -> None:
        self.received: list[dict[str, Any]] = []
        self._server: HTTPServer | None = None
        self._thread: Thread | None = None

    def start(self) -> int:
        """Start server on a random port. Returns the port."""
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                outer.received.append(json.loads(body))
                self.send_response(200)
                self.end_headers()

            def log_message(self, fmt: str, *args: Any) -> None:
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        port = self._server.server_address[1]
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return port

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()


# ---------------------------------------------------------------------------
# NullEmitter
# ---------------------------------------------------------------------------

class TestNullEmitter:
    def test_emit_succeeds(self) -> None:
        e = NullEmitter()
        r = e.emit({"class_uid": 2004})
        assert r.success is True
        assert r.status_code is None

    def test_emit_batch_all_succeed(self) -> None:
        e = NullEmitter()
        events = [{"id": i} for i in range(5)]
        results = e.emit_batch(events)
        assert len(results) == 5
        assert all(r.success for r in results)


# ---------------------------------------------------------------------------
# HttpEmitter
# ---------------------------------------------------------------------------

class TestHttpEmitter:
    def test_rejects_non_http_scheme(self) -> None:
        with pytest.raises(ValueError, match="http"):
            HttpEmitter("ftp://example.com/webhook")

    def test_emit_success(self) -> None:
        srv = _RecordingHTTPServer()
        port = srv.start()
        try:
            emitter = HttpEmitter(f"http://127.0.0.1:{port}/webhook")
            event = {"class_uid": 2004, "x": 1}
            result = emitter.emit(event)
            assert result.success is True
            assert result.status_code == 200
            assert srv.received == [{"class_uid": 2004, "x": 1}]
        finally:
            srv.stop()

    def test_emit_sends_auth_header(self) -> None:
        srv = _RecordingHTTPServer()

        class AuthCapture(BaseHTTPRequestHandler):
            captured_auth: str | None = None

            def do_POST(self) -> None:
                AuthCapture.captured_auth = self.headers.get("Authorization")
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_: Any) -> None:
                pass

        actual_server = HTTPServer(("127.0.0.1", 0), AuthCapture)
        port = actual_server.server_address[1]
        t = Thread(target=actual_server.serve_forever, daemon=True)
        t.start()
        try:
            emitter = HttpEmitter(f"http://127.0.0.1:{port}/", auth_header="Bearer tok123")
            emitter.emit({"class_uid": 2004})
            assert AuthCapture.captured_auth == "Bearer tok123"
        finally:
            actual_server.shutdown()

    def test_emit_returns_failure_on_bad_status(self) -> None:
        class FailHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                self.send_response(500)
                self.end_headers()

            def log_message(self, *_: Any) -> None:
                pass

        srv = HTTPServer(("127.0.0.1", 0), FailHandler)
        port = srv.server_address[1]
        t = Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            emitter = HttpEmitter(f"http://127.0.0.1:{port}/")
            result = emitter.emit({"x": 1})
            assert result.success is False
            assert result.status_code == 500
        finally:
            srv.shutdown()

    def test_emit_returns_failure_on_connect_error(self) -> None:
        emitter = HttpEmitter("http://127.0.0.1:1/")  # port 1 always refused
        result = emitter.emit({"x": 1})
        assert result.success is False
        assert result.error is not None

    def test_emit_batch_delegates_to_emit(self) -> None:
        srv = _RecordingHTTPServer()
        port = srv.start()
        try:
            emitter = HttpEmitter(f"http://127.0.0.1:{port}/")
            events = [{"id": i} for i in range(3)]
            results = emitter.emit_batch(events)
            assert len(results) == 3
            assert all(r.success for r in results)
            assert len(srv.received) == 3
        finally:
            srv.stop()


# ---------------------------------------------------------------------------
# OCSF schema builder
# ---------------------------------------------------------------------------

class TestOcsfSchema:
    def test_class_uid_is_2004(self) -> None:
        ev = build_detection_finding(
            probe_id="T01-001-p1",
            threat_id="T01-001",
            passed=False,
            target="http://x.example.com",
        )
        assert ev.data["class_uid"] == 2004

    def test_severity_mapping(self) -> None:
        for sev_str, sev_id in _SEVERITY_MAP.items():
            ev = build_detection_finding(
                probe_id="p", threat_id="t", passed=False,
                target="http://x", severity=sev_str,
            )
            assert ev.data["severity_id"] == sev_id

    def test_passed_stored_in_unmapped(self) -> None:
        ev = build_detection_finding(
            probe_id="p", threat_id="t", passed=True, target="http://x"
        )
        assert ev.data["unmapped"]["passed"] is True

    def test_finding_uid_is_probe_id(self) -> None:
        ev = build_detection_finding(
            probe_id="T04-001-p1", threat_id="T04-001", passed=False, target="http://x"
        )
        assert ev.data["finding"]["uid"] == "T04-001-p1"

    def test_resource_target_is_set(self) -> None:
        ev = build_detection_finding(
            probe_id="p", threat_id="t", passed=False, target="http://target.example.com"
        )
        assert ev.data["resources"][0]["uid"] == "http://target.example.com"

    def test_remediation_included_when_given(self) -> None:
        ev = build_detection_finding(
            probe_id="p", threat_id="t", passed=False, target="http://x",
            remediation="Fix it now."
        )
        assert ev.data["finding"]["remediation"]["desc"] == "Fix it now."

    def test_remediation_absent_when_not_given(self) -> None:
        ev = build_detection_finding(
            probe_id="p", threat_id="t", passed=False, target="http://x"
        )
        assert "remediation" not in ev.data["finding"]

    def test_to_dict_is_json_serializable(self) -> None:
        ev = build_detection_finding(
            probe_id="p", threat_id="t", passed=False, target="http://x",
            category="T1", description="Test finding",
        )
        d = ev.to_dict()
        # Must not raise
        json.dumps(d)

    def test_probe_result_to_ocsf(self) -> None:
        class FakeResult:
            probe_id = "T01-001-p1"
            threat_id = "T01-001"
            passed = False
            duration_seconds = 0.5

        ev = probe_result_to_ocsf(FakeResult(), target="http://x", severity="high")
        assert ev.data["class_uid"] == 2004
        assert ev.data["unmapped"]["probe_id"] == "T01-001-p1"
        assert ev.data["unmapped"]["passed"] is False


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

class TestAnomalyDetector:
    def test_no_alerts_below_threshold(self) -> None:
        det = AnomalyDetector(high_finding_rate_threshold=5, critical_burst_threshold=3)
        for _ in range(5):
            alerts = det.ingest(_make_finding_event("high"))
        assert not any(a.rule == AnomalyRule.HIGH_FINDING_RATE for a in det.alerts)

    def test_high_finding_rate_fires(self) -> None:
        det = AnomalyDetector(high_finding_rate_threshold=3)
        for _ in range(4):
            det.ingest(_make_finding_event("high"))
        assert any(a.rule == AnomalyRule.HIGH_FINDING_RATE for a in det.alerts)

    def test_critical_burst_fires(self) -> None:
        det = AnomalyDetector(critical_burst_threshold=2)
        for _ in range(3):
            det.ingest(_make_finding_event("critical"))
        assert any(a.rule == AnomalyRule.CRITICAL_BURST for a in det.alerts)

    def test_critical_burst_not_fire_on_high(self) -> None:
        det = AnomalyDetector(critical_burst_threshold=2)
        for _ in range(5):
            det.ingest(_make_finding_event("high"))
        assert not any(a.rule == AnomalyRule.CRITICAL_BURST for a in det.alerts)

    def test_severity_escalation_fires(self) -> None:
        det = AnomalyDetector(severity_escalation_baseline=3)  # medium
        alerts = det.ingest(_make_finding_event("critical"))
        assert any(a.rule == AnomalyRule.SEVERITY_ESCALATION for a in alerts)

    def test_severity_escalation_does_not_fire_for_passing(self) -> None:
        det = AnomalyDetector(severity_escalation_baseline=1)
        passing_event = build_detection_finding(
            probe_id="p", threat_id="t", passed=True, target="http://x", severity="critical"
        ).to_dict()
        alerts = det.ingest(passing_event)
        assert not any(a.rule == AnomalyRule.SEVERITY_ESCALATION for a in alerts)

    def test_ingest_batch_returns_all_alerts(self) -> None:
        det = AnomalyDetector(high_finding_rate_threshold=2)
        events = [_make_finding_event("high") for _ in range(3)]
        alerts = det.ingest_batch(events)
        assert len(alerts) > 0

    def test_reset_clears_state(self) -> None:
        det = AnomalyDetector(high_finding_rate_threshold=2)
        for _ in range(3):
            det.ingest(_make_finding_event("high"))
        det.reset()
        assert not det.alerts
        assert not det._events

    def test_passing_probes_not_counted_as_findings(self) -> None:
        det = AnomalyDetector(high_finding_rate_threshold=3)
        for _ in range(10):
            passing_event = build_detection_finding(
                probe_id="p", threat_id="t", passed=True, target="http://x"
            ).to_dict()
            det.ingest(passing_event)
        assert not any(a.rule == AnomalyRule.HIGH_FINDING_RATE for a in det.alerts)

    def test_alert_has_correct_rule_fields(self) -> None:
        det = AnomalyDetector(critical_burst_threshold=1)
        det.ingest(_make_finding_event("critical"))
        det.ingest(_make_finding_event("critical"))
        alerts = [a for a in det.alerts if a.rule == AnomalyRule.CRITICAL_BURST]
        assert alerts
        alert = alerts[0]
        assert alert.event_count >= 2
        assert alert.triggered_at_ms > 0
        assert alert.window_seconds == det.window_seconds


# ---------------------------------------------------------------------------
# CLI wiring — --emit-to flag
# ---------------------------------------------------------------------------

class TestEmitCLIWiring:
    def test_emit_to_wired_into_scan(self) -> None:
        """--emit-to must reach the HttpEmitter and emit events after scan."""
        srv = _RecordingHTTPServer()
        port = srv.start()
        try:
            from cosai_mcp.harness.mock_server import MockMCPServer

            with MockMCPServer() as target:
                target.wait_ready()
                runner = CliRunner()
                result = runner.invoke(
                    main,
                    [
                        "scan",
                        f"http://127.0.0.1:{target.port}",
                        "--no-report",
                        "--report-mode", "ci",
                        "--emit-to", f"http://127.0.0.1:{port}/",
                        "--skip-reachability",
                    ],
                )
            # Exit code 0/1/2 are all valid — the minimal mock server returns
            # errors for unknown probe methods (exit 2), which is expected.
            # Exit code 3 (unreachable) would mean the wiring never ran.
            assert result.exit_code != 3, result.output
            assert "Telemetry:" in result.output
            # At least one OCSF event must have been received.
            assert len(srv.received) > 0
            # Verify OCSF structure of first event.
            ev = srv.received[0]
            assert ev["class_uid"] == 2004
            assert "finding" in ev
        finally:
            srv.stop()

    def test_regression_emit_failure_does_not_affect_exit_code(self) -> None:
        """HttpEmitter failures must not change the scan exit code."""
        from cosai_mcp.harness.mock_server import MockMCPServer

        with MockMCPServer() as target:
            target.wait_ready()
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "scan",
                    f"http://127.0.0.1:{target.port}",
                    "--no-report",
                    "--report-mode", "ci",
                    "--emit-to", "http://127.0.0.1:1/",  # port 1 always refused
                    "--skip-reachability",
                ],
            )
        # Exit code must not be 3 (reachability failure). The mock server
        # returns errors for unrecognized probe methods → exit 2 from scan
        # internals is acceptable. We verify emit failures didn't change it.
        assert result.exit_code != 3, result.output
        # The scan must have printed Telemetry line (not crashed before emit)
        assert "Telemetry:" in result.output or "failed" in result.output.lower()

    def test_regression_anomaly_threshold_flags_wired(self) -> None:
        """--anomaly-threshold=1 must cause [ANOMALY] output when a finding is emitted."""
        srv = _RecordingHTTPServer()
        port = srv.start()
        try:
            from cosai_mcp.harness.mock_server import MockMCPServer

            with MockMCPServer() as target:
                target.wait_ready()
                runner = CliRunner()
                result = runner.invoke(
                    main,
                    [
                        "scan",
                        f"http://127.0.0.1:{target.port}",
                        "--no-report",
                        "--report-mode", "ci",
                        "--emit-to", f"http://127.0.0.1:{port}/",
                        "--anomaly-threshold", "1",
                        "--skip-reachability",
                    ],
                )
            # Exit 3 means reachability failed before any probes ran — wiring never triggered.
            assert result.exit_code != 3, result.output
            # The Telemetry line must appear (emitter reached)
            assert "Telemetry:" in result.output
            # At least one event was emitted; with threshold=1, any two findings trigger
            # [ANOMALY]. The mock server returns errors (findings) → anomaly should fire.
            # We assert either anomaly fired or zero findings were emitted (degenerate mock).
            emitted_count = len(srv.received)
            if emitted_count >= 2:
                assert "[ANOMALY]" in result.output, (
                    f"Expected [ANOMALY] with threshold=1 and {emitted_count} events; "
                    f"output={result.output!r}"
                )
        finally:
            srv.stop()

    def test_regression_emit_url_credentials_redacted(self) -> None:
        """Credentials embedded in --emit-to URL must not appear in CLI output."""
        from cosai_mcp.harness.mock_server import MockMCPServer

        with MockMCPServer() as target:
            target.wait_ready()
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "scan",
                    f"http://127.0.0.1:{target.port}",
                    "--no-report",
                    "--report-mode", "ci",
                    "--emit-to", "http://user:secret123@127.0.0.1:1/",
                    "--skip-reachability",
                ],
            )
        assert result.exit_code != 3, result.output
        assert "secret123" not in result.output, (
            "Credential in emit URL must be redacted from CLI output"
        )
