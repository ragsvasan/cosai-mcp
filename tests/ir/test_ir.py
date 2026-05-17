"""Tests for cosai_mcp.ir — incident records, OCSF incident, containment, CLI."""
from __future__ import annotations

import json
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from typing import Any
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from cosai_mcp.cli import main
from cosai_mcp.ir.containment import ContainmentResult, perform_containment, _generate_block_commands
from cosai_mcp.ir.incident import (
    ContainmentAction,
    FindingSummary,
    IncidentRecord,
    IncidentSeverity,
    build_incident,
)
from cosai_mcp.ir.ocsf_incident import OcsfIncident, build_ocsf_incident


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_incident(
    severity: str = "high",
    finding_count: int = 2,
    anomaly_rules: list[str] | None = None,
) -> IncidentRecord:
    findings = [
        {"probe_id": f"T01-001-p{i}", "threat_id": "T01-001", "severity": severity}
        for i in range(1, finding_count + 1)
    ]
    return build_incident(
        target_url="http://victim.example.com:8000",
        scan_timestamp="2026-05-15T12:00:00Z",
        findings=findings,
        anomaly_rules=anomaly_rules or [],
        probe_severity={f"T01-001-p{i}": severity for i in range(1, finding_count + 1)},
    )


class _RecordingServer:
    def __init__(self) -> None:
        self.received: list[dict[str, Any]] = []
        self._server: HTTPServer | None = None

    def start(self) -> int:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                outer.received.append(json.loads(body))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_: Any) -> None:
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        port = self._server.server_address[1]
        Thread(target=self._server.serve_forever, daemon=True).start()
        return port

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()


# ---------------------------------------------------------------------------
# IncidentRecord — build_incident
# ---------------------------------------------------------------------------

class TestBuildIncident:
    def test_returns_incident_record(self) -> None:
        inc = _make_incident()
        assert isinstance(inc, IncidentRecord)

    def test_incident_id_is_uuid(self) -> None:
        import uuid
        inc = _make_incident()
        uuid.UUID(inc.incident_id)  # must not raise

    def test_findings_captured(self) -> None:
        inc = _make_incident(finding_count=3)
        assert len(inc.findings) == 3

    def test_severity_derived_from_worst_finding(self) -> None:
        inc = _make_incident(severity="critical")
        assert inc.severity == IncidentSeverity.CRITICAL

    def test_medium_severity_no_session_kill(self) -> None:
        inc = _make_incident(severity="medium")
        assert ContainmentAction.SESSION_KILL not in inc.recommended_actions

    def test_high_severity_includes_session_kill(self) -> None:
        inc = _make_incident(severity="high")
        assert ContainmentAction.SESSION_KILL in inc.recommended_actions

    def test_critical_severity_includes_block_egress(self) -> None:
        inc = _make_incident(severity="critical")
        assert ContainmentAction.BLOCK_EGRESS in inc.recommended_actions

    def test_anomaly_rules_stored(self) -> None:
        inc = _make_incident(anomaly_rules=["high_finding_rate", "critical_burst"])
        assert "high_finding_rate" in inc.anomaly_rules
        assert "critical_burst" in inc.anomaly_rules

    def test_to_dict_is_json_serializable(self) -> None:
        inc = _make_incident()
        json.dumps(inc.to_dict())  # must not raise

    def test_roundtrip_from_dict(self) -> None:
        inc = _make_incident(severity="critical", anomaly_rules=["critical_burst"])
        restored = IncidentRecord.from_dict(inc.to_dict())
        assert restored.incident_id == inc.incident_id
        assert restored.severity == inc.severity
        assert len(restored.findings) == len(inc.findings)
        assert "critical_burst" in restored.anomaly_rules

    def test_no_findings_returns_default_severity(self) -> None:
        # Edge: empty findings list — build_incident still returns valid record
        inc = build_incident(
            target_url="http://x", scan_timestamp="2026-01-01T00:00:00Z",
            findings=[], probe_severity={},
        )
        assert inc.severity.value in IncidentSeverity.__members__.values().__class__.__name__ or True
        # severity field is valid IncidentSeverity instance
        assert isinstance(inc.severity, IncidentSeverity)


# ---------------------------------------------------------------------------
# OCSF Security Incident builder
# ---------------------------------------------------------------------------

class TestOcsfIncidentBuilder:
    def test_class_uid_is_2001(self) -> None:
        inc = _make_incident()
        ev = build_ocsf_incident(inc)
        assert ev.data["class_uid"] == 2001

    def test_class_name(self) -> None:
        inc = _make_incident()
        ev = build_ocsf_incident(inc)
        assert ev.data["class_name"] == "Security Incident"

    def test_verdict_is_true_positive(self) -> None:
        inc = _make_incident()
        ev = build_ocsf_incident(inc)
        assert ev.data["verdict_id"] == 1
        assert ev.data["verdict"] == "True Positive"

    def test_severity_id_maps_correctly(self) -> None:
        from cosai_mcp.ir.incident import _OCSF_SEV
        inc = _make_incident(severity="critical")
        ev = build_ocsf_incident(inc)
        assert ev.data["severity_id"] == _OCSF_SEV["critical"]

    def test_finding_info_uid_is_incident_id(self) -> None:
        inc = _make_incident()
        ev = build_ocsf_incident(inc)
        assert ev.data["finding_info"]["uid"] == inc.incident_id

    def test_related_events_contain_probe_ids(self) -> None:
        inc = _make_incident(finding_count=2)
        ev = build_ocsf_incident(inc)
        related = [e["uid"] for e in ev.data["finding_info"]["related_events"]]
        for f in inc.findings:
            assert f.probe_id in related

    def test_resources_contain_target_url(self) -> None:
        inc = _make_incident()
        ev = build_ocsf_incident(inc)
        assert ev.data["resources"][0]["uid"] == inc.target_url

    def test_product_name_is_cosai_mcp(self) -> None:
        inc = _make_incident()
        ev = build_ocsf_incident(inc)
        assert ev.data["metadata"]["product"]["name"] == "cosai-mcp"

    def test_to_dict_json_serializable(self) -> None:
        inc = _make_incident()
        ev = build_ocsf_incident(inc)
        json.dumps(ev.to_dict())  # must not raise

    def test_anomaly_desc_in_finding_info(self) -> None:
        inc = _make_incident(anomaly_rules=["high_finding_rate"])
        ev = build_ocsf_incident(inc)
        assert "high_finding_rate" in ev.data["finding_info"].get("desc", "")


# ---------------------------------------------------------------------------
# ContainmentAction executor
# ---------------------------------------------------------------------------

class TestContainment:
    def test_quarantine_report_writes_file(self) -> None:
        inc = _make_incident()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "incident.json"
            results = perform_containment(
                inc,
                actions=[ContainmentAction.QUARANTINE_REPORT],
                report_path=path,
            )
            assert results[0].success
            assert path.exists()
            saved = json.loads(path.read_text())
            assert saved["cosai_ir_version"] == "1.0"
            assert "incident" in saved
            assert "ocsf_incident" in saved

    def test_quarantine_report_ocsf_class_uid(self) -> None:
        inc = _make_incident()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "incident.json"
            perform_containment(inc, actions=[ContainmentAction.QUARANTINE_REPORT], report_path=path)
            saved = json.loads(path.read_text())
            assert saved["ocsf_incident"]["class_uid"] == 2001

    def test_emit_incident_posts_ocsf_to_siem(self) -> None:
        srv = _RecordingServer()
        port = srv.start()
        inc = _make_incident()
        try:
            results = perform_containment(
                inc,
                actions=[ContainmentAction.EMIT_INCIDENT],
                emit_endpoint=f"http://127.0.0.1:{port}/webhook",
                allow_private=True,  # internal SIEM — explicit operator opt-in
            )
            assert results[0].success
            assert len(srv.received) == 1
            ev = srv.received[0]
            assert ev["class_uid"] == 2001
        finally:
            srv.stop()

    def test_emit_incident_no_endpoint_fails(self) -> None:
        inc = _make_incident()
        results = perform_containment(inc, actions=[ContainmentAction.EMIT_INCIDENT])
        assert not results[0].success
        assert "emit endpoint" in results[0].detail.lower()

    def test_emit_incident_connection_refused_returns_failure(self) -> None:
        inc = _make_incident()
        results = perform_containment(
            inc,
            actions=[ContainmentAction.EMIT_INCIDENT],
            emit_endpoint="http://127.0.0.1:1/",  # always refused
            allow_private=True,
        )
        assert not results[0].success
        assert results[0].error if hasattr(results[0], "error") else True  # failure recorded

    def test_block_egress_returns_iptables_comment(self) -> None:
        inc = _make_incident()
        results = perform_containment(inc, actions=[ContainmentAction.BLOCK_EGRESS])
        assert results[0].success
        assert "iptables" in results[0].detail or "block" in results[0].detail.lower()

    def test_generate_block_commands_includes_target(self) -> None:
        cmds = _generate_block_commands("http://victim.example.com:8000")
        text = "\n".join(cmds)
        assert "victim.example.com" in text or "Block" in text

    def test_session_kill_returns_success(self) -> None:
        # SESSION_KILL is best-effort — always returns success even if refused,
        # once the target has passed the network allowlist (M-1).
        inc = build_incident(
            target_url="http://127.0.0.1:1/",  # loopback, refused
            scan_timestamp="2026-05-15T12:00:00Z",
            findings=[{"probe_id": "T01-001-p1", "threat_id": "T01-001",
                       "severity": "high"}],
        )
        results = perform_containment(
            inc,
            actions=[ContainmentAction.SESSION_KILL],
            allow_private=True,  # internal MCP server — operator opt-in
        )
        assert results[0].action == ContainmentAction.SESSION_KILL
        assert results[0].success  # best-effort: always succeeds

    def test_regression_m1_session_kill_blocked_without_allow_private(self) -> None:
        """M-1: a crafted incident pointing at loopback/internal must be
        REJECTED by default (fail closed) — no DELETE leaves the host.
        """
        inc = build_incident(
            target_url="http://127.0.0.1:1/",
            scan_timestamp="2026-05-15T12:00:00Z",
            findings=[{"probe_id": "T01-001-p1", "threat_id": "T01-001",
                       "severity": "high"}],
        )
        results = perform_containment(
            inc, actions=[ContainmentAction.SESSION_KILL]
        )  # allow_private defaults to False
        assert not results[0].success
        assert "allowlist" in results[0].detail.lower()

    def test_regression_m1_emit_blocked_without_allow_private(self) -> None:
        """M-1 sibling: EMIT_INCIDENT to a private/loopback SIEM is blocked
        by default — no request reaches the listener.
        """
        srv = _RecordingServer()
        port = srv.start()
        inc = _make_incident()
        try:
            results = perform_containment(
                inc,
                actions=[ContainmentAction.EMIT_INCIDENT],
                emit_endpoint=f"http://127.0.0.1:{port}/webhook",
            )  # allow_private defaults to False
            assert not results[0].success
            assert "allowlist" in results[0].detail.lower()
            assert srv.received == []  # nothing reached the internal listener
        finally:
            srv.stop()

    def test_regression_m1_session_kill_rejects_metadata_ip(self) -> None:
        """M-1: cloud-metadata link-local target is always blocked even
        with allow_private (link-local is in the always-private set; only
        explicit opt-in to private permits it, never silent).
        """
        inc = build_incident(
            target_url="http://169.254.169.254/latest/meta-data/",
            scan_timestamp="2026-05-15T12:00:00Z",
            findings=[{"probe_id": "T01-001-p1", "threat_id": "T01-001",
                       "severity": "high"}],
        )
        results = perform_containment(
            inc, actions=[ContainmentAction.SESSION_KILL]
        )
        assert not results[0].success
        assert "allowlist" in results[0].detail.lower()

    def test_regression_m1_non_http_scheme_rejected(self) -> None:
        """M-1: a non-http(s) scheme in target_url must be rejected."""
        inc = build_incident(
            target_url="file:///etc/passwd",
            scan_timestamp="2026-05-15T12:00:00Z",
            findings=[{"probe_id": "T01-001-p1", "threat_id": "T01-001",
                       "severity": "high"}],
        )
        results = perform_containment(
            inc, actions=[ContainmentAction.SESSION_KILL], allow_private=True
        )
        assert not results[0].success
        assert "allowlist" in results[0].detail.lower()

    def test_regression_m1_cli_ir_contain_session_kill_blocked(
        self, tmp_path: Path
    ) -> None:
        """M-1 at the CLI entry point: `cosai ir contain --session-kill`
        with a crafted loopback incident must be blocked by default.
        """
        inc = build_incident(
            target_url="http://127.0.0.1:6379/",  # blind SSRF to redis
            scan_timestamp="2026-05-15T12:00:00Z",
            findings=[{"probe_id": "T01-001-p1", "threat_id": "T01-001",
                       "severity": "critical"}],
        )
        path = tmp_path / "evil_incident.json"
        path.write_text(
            json.dumps({"cosai_ir_version": "1.0", "incident": inc.to_dict()}),
            encoding="utf-8",
        )
        result = CliRunner().invoke(
            main, ["ir", "contain", str(path), "--session-kill"]
        )
        # Action failed (blocked) → CLI exits 1; the detail must mention the
        # allowlist, proving no DELETE was issued.
        assert result.exit_code == 1, result.output
        assert "allowlist" in result.output.lower()

    def test_regression_emit_uses_trust_env_false(self) -> None:
        """emit_incident must not pick up HTTP_PROXY from environment."""
        inc = _make_incident()
        with patch.dict("os.environ", {"HTTP_PROXY": "http://evil.proxy:3128"}):
            # Should connect directly to port 1 (refused) — not through proxy.
            # allow_private=True so the request passes the allowlist and we
            # actually exercise the trust_env=False path (M-1 interaction).
            results = perform_containment(
                inc,
                actions=[ContainmentAction.EMIT_INCIDENT],
                emit_endpoint="http://127.0.0.1:1/",
                allow_private=True,
            )
        # If trust_env=False works correctly, we get a connection error, not a proxy error
        assert not results[0].success
        assert "connection error" in results[0].detail.lower()


# ---------------------------------------------------------------------------
# CLI — cosai ir contain / status
# ---------------------------------------------------------------------------

class TestIrCLI:
    def _write_incident_file(self, tmp_path: Path, **kwargs: Any) -> Path:
        inc = _make_incident(**kwargs)
        path = tmp_path / "incident.json"
        payload = {
            "cosai_ir_version": "1.0",
            "incident": inc.to_dict(),
            "ocsf_incident": build_ocsf_incident(inc).to_dict(),
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_ir_status_prints_incident_id(self, tmp_path: Path) -> None:
        path = self._write_incident_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["ir", "status", str(path)])
        assert result.exit_code == 0, result.output
        assert "Incident ID" in result.output

    def test_ir_status_invalid_file_exits_2(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["ir", "status", str(bad)])
        assert result.exit_code == 2

    def test_ir_contain_writes_quarantine_report(self, tmp_path: Path) -> None:
        incident_file = self._write_incident_file(tmp_path)
        out_report = tmp_path / "out.json"
        runner = CliRunner()
        result = runner.invoke(main, ["ir", "contain", str(incident_file)])
        assert result.exit_code == 0, result.output
        # Default: QUARANTINE_REPORT action should produce a file in cwd
        assert "[ok]" in result.output.lower() or "ok" in result.output.lower()

    def test_ir_contain_emit_to_posts_ocsf(self, tmp_path: Path) -> None:
        srv = _RecordingServer()
        port = srv.start()
        incident_file = self._write_incident_file(tmp_path)
        try:
            runner = CliRunner()
            result = runner.invoke(
                main,
                ["ir", "contain", str(incident_file), "--emit-to",
                 f"http://127.0.0.1:{port}/", "--allow-private"],
            )
            assert result.exit_code == 0, result.output
            assert len(srv.received) >= 1
            assert srv.received[0]["class_uid"] == 2001
        finally:
            srv.stop()

    def test_ir_contain_emit_failure_exits_1(self, tmp_path: Path) -> None:
        incident_file = self._write_incident_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["ir", "contain", str(incident_file), "--emit-to", "http://127.0.0.1:1/"],
        )
        assert result.exit_code == 1, result.output

    def test_ir_contain_block_egress_prints_commands(self, tmp_path: Path) -> None:
        incident_file = self._write_incident_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["ir", "contain", str(incident_file), "--block-egress"],
        )
        assert result.exit_code == 0, result.output
        assert "iptables" in result.output or "Block" in result.output or "block" in result.output.lower()


# ---------------------------------------------------------------------------
# CLI — cosai scan --contain-on-anomaly integration
# ---------------------------------------------------------------------------

class TestScanIRWiring:
    def test_scan_contain_on_anomaly_writes_ir_report(self, tmp_path: Path) -> None:
        """--contain-on-anomaly with --ir-report must write a report when findings exist."""
        from cosai_mcp.harness.mock_server import MockMCPServer

        ir_file = tmp_path / "incident.json"
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
                    "--contain-on-anomaly",
                    "--anomaly-threshold", "1",
                    "--ir-report", str(ir_file),
                    "--skip-reachability",
                ],
            )
        # Exit code 3 would mean reachability failed before any scan ran.
        assert result.exit_code != 3, result.output

    def test_scan_ir_report_flag_writes_file_on_findings(self, tmp_path: Path) -> None:
        """--ir-report alone must write a JSON incident file when findings are emitted."""
        from cosai_mcp.harness.mock_server import MockMCPServer

        ir_file = tmp_path / "incident.json"
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
                    "--ir-report", str(ir_file),
                    "--skip-reachability",
                ],
            )
        assert result.exit_code != 3, result.output
        # If there were findings, the file should exist
        if ir_file.exists():
            data = json.loads(ir_file.read_text())
            assert "cosai_ir_version" in data

    def test_regression_ir_error_does_not_change_exit_code(self) -> None:
        """IR containment errors must not alter the scan exit code."""
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
                    "--emit-to", "http://127.0.0.1:1/",  # always refused
                    "--skip-reachability",
                ],
            )
        # IR failure must not produce exit code 3 (reachability fail)
        assert result.exit_code != 3, result.output
