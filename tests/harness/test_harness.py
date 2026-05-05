"""Test suite for cosai-mcp probe harness: result, assertions, context, runner, mock server.

Run: pytest tests/harness/ -v
"""
from __future__ import annotations

import html
import json
import threading
import types
from typing import Any
from unittest.mock import AsyncMock, MagicMock, create_autospec, patch

import pytest

from cosai_mcp.catalog.models import Assertion, Operator, Probe, Provenance, Severity, ThreatDefinition
from cosai_mcp.config import ScanConfig
from cosai_mcp.harness.assertions import evaluate_assertion, _extract_target
from cosai_mcp.harness.context import ProbeContext
from cosai_mcp.harness.mock_server import MockMCPServer
from cosai_mcp.harness.result import AssertionResult, ProbeResult, make_probe_result, _html_escape
from cosai_mcp.harness.runner import (
    ProbeRunner,
    _probe_from_dict,
    _probe_to_dict,
    _result_from_dict,
    _threat_from_dict,
    _threat_to_dict,
    _validate_raw_result,
)
from cosai_mcp.session import MCPSession
from cosai_mcp.transport.base import Transport


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _config() -> ScanConfig:
    return ScanConfig(target_host="127.0.0.1", target_port=0, allow_private_targets=True)


def _make_assertion(
    target: str = "response.error",
    operator: Operator = Operator.EQ,
    value: object = True,
) -> Assertion:
    return Assertion(target=target, operator=operator, value=value)


def _make_probe(
    probe_id: str = "T01-001-p1",
    method: str = "tools/call",
    payload: dict | None = None,
    assertions: list[Assertion] | None = None,
) -> Probe:
    return Probe(
        id=probe_id,
        transport="http",
        method=method,
        payload=types.MappingProxyType(payload or {"name": "echo", "arguments": {}}),
        assertions=tuple(assertions or [_make_assertion()]),
    )


def _make_threat(threat_id: str = "T01-001") -> ThreatDefinition:
    return ThreatDefinition(
        schema_version="1.0",
        id=threat_id,
        category="T1",
        severity=Severity.CRITICAL,
        cosai_ref="T1",
        owasp_ref="MCP-Top10-A01",
        cwe=("CWE-287",),
        probes=(_make_probe(),),
        remediation="Enforce authentication.",
        references=("https://cosai.org/T1",),
        provenance=Provenance.OFFICIAL,
    )


def _error_response() -> dict[str, Any]:
    """Error JSON-RPC response with _body pre-populated (as context.py does)."""
    resp: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": "1",
        "error": {"code": -32600, "message": "Unauthorized"},
    }
    resp["_body"] = json.dumps(resp["error"], ensure_ascii=False)
    return resp


def _ok_response() -> dict[str, Any]:
    """OK JSON-RPC response with _body pre-populated (as context.py does)."""
    resp: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": "1",
        "result": {"content": [{"type": "text", "text": "ok"}]},
    }
    resp["_body"] = json.dumps(resp["result"], ensure_ascii=False)
    return resp


# ===========================================================================
# AssertionResult and make_probe_result
# ===========================================================================

class TestProbeResult:

    def test_make_probe_result_html_escapes_body(self):
        """Response body with HTML-injectable content must be escaped."""
        response = {"_body": "<script>alert('xss')</script>", "_status_code": 200}
        result = make_probe_result(
            probe_id="T01-001-p1",
            threat_id="T01-001",
            passed=True,
            assertions=(),
            response=response,
        )
        assert "<script>" not in result.response_body
        assert "&lt;script&gt;" in result.response_body

    def test_make_probe_result_immutable(self):
        """ProbeResult is a frozen dataclass — no field mutation allowed."""
        result = make_probe_result(
            probe_id="T01-001-p1",
            threat_id="T01-001",
            passed=True,
            assertions=(),
        )
        with pytest.raises((AttributeError, TypeError)):
            result.passed = False  # type: ignore[misc]

    def test_make_probe_result_status_code(self):
        """Status code from response is captured in result."""
        response = {"_status_code": 401, "_body": ""}
        result = make_probe_result(
            probe_id="p1",
            threat_id="T01",
            passed=False,
            assertions=(),
            response=response,
        )
        assert result.status_code == 401

    def test_probe_result_to_dict_roundtrip(self):
        """to_dict() contains all essential fields."""
        result = make_probe_result(
            probe_id="T01-001-p1",
            threat_id="T01-001",
            passed=True,
            assertions=(
                AssertionResult(
                    target="response.error",
                    operator="eq",
                    expected="True",
                    actual="True",
                    passed=True,
                    message="passed",
                ),
            ),
            duration_seconds=0.5,
        )
        d = result.to_dict()
        assert d["probe_id"] == "T01-001-p1"
        assert d["passed"] is True
        assert d["duration_seconds"] == 0.5
        assert len(d["assertions"]) == 1

    def test_html_escape_none(self):
        """_html_escape(None) returns empty string."""
        assert _html_escape(None) == ""

    def test_html_escape_ampersand(self):
        """& is escaped to &amp;."""
        assert _html_escape("a & b") == "a &amp; b"


# ===========================================================================
# evaluate_assertion and _extract_target
# ===========================================================================

class TestAssertions:

    def test_eq_true_on_error_response(self):
        """response.error == True when 'error' key present."""
        assertion = _make_assertion("response.error", Operator.EQ, True)
        result = evaluate_assertion(assertion, _error_response())
        assert result.passed is True

    def test_eq_false_on_ok_response(self):
        """response.error == True fails on ok response."""
        assertion = _make_assertion("response.error", Operator.EQ, True)
        result = evaluate_assertion(assertion, _ok_response())
        assert result.passed is False

    def test_ne_operator(self):
        """response.error != False passes on error response."""
        assertion = _make_assertion("response.error", Operator.NE, False)
        result = evaluate_assertion(assertion, _error_response())
        assert result.passed is True

    def test_contains_operator_in_body(self):
        """response.body contains 'Unauthorized' for error response."""
        assertion = _make_assertion("response.body", Operator.CONTAINS, "Unauthorized")
        result = evaluate_assertion(assertion, _error_response())
        assert result.passed is True

    def test_not_contains_operator(self):
        """response.body not_contains 'root:' for non-exfiltration response."""
        assertion = _make_assertion("response.body", Operator.NOT_CONTAINS, "root:")
        result = evaluate_assertion(assertion, _ok_response())
        assert result.passed is True

    def test_status_in_operator(self):
        """response.status_code in (400, 401, 403) passes for 401."""
        response = {**_error_response(), "_status_code": 401}
        assertion = _make_assertion("response.status_code", Operator.STATUS_IN, (400, 401, 403))
        result = evaluate_assertion(assertion, response)
        assert result.passed is True

    def test_status_in_operator_fails(self):
        """response.status_code in (400, 401) fails for 200."""
        response = {**_ok_response(), "_status_code": 200}
        assertion = _make_assertion("response.status_code", Operator.STATUS_IN, (400, 401))
        result = evaluate_assertion(assertion, response)
        assert result.passed is False

    def test_error_code_in_operator(self):
        """response.error_code in (-32600, -32601) passes for -32600."""
        assertion = _make_assertion("response.error_code", Operator.ERROR_CODE_IN, (-32600, -32601))
        result = evaluate_assertion(assertion, _error_response())
        assert result.passed is True

    def test_extract_target_error_code(self):
        """_extract_target returns error.code from error response."""
        code = _extract_target(_error_response(), "response.error_code")
        assert code == -32600

    def test_extract_target_body_from_result(self):
        """_extract_target response.body returns JSON of result."""
        body = _extract_target(_ok_response(), "response.body")
        assert "content" in body

    def test_extract_target_body_from_error(self):
        """_extract_target response.body returns JSON of error when no result."""
        body = _extract_target(_error_response(), "response.body")
        assert "Unauthorized" in body

    def test_extract_target_generic_dotted_path(self):
        """Generic dotted path walks into nested dicts."""
        response = {"result": {"content": [{"type": "text", "text": "hello"}]}}
        value = _extract_target(response, "response.result.content")
        assert isinstance(value, list)

    def test_assertion_result_never_raises(self):
        """evaluate_assertion catches all exceptions internally."""
        broken = _make_assertion("response.error", Operator.EQ, object())
        result = evaluate_assertion(broken, {"error": True})
        # Must return an AssertionResult (may have passed=False and error message)
        assert isinstance(result, AssertionResult)

    def test_assertion_result_message_on_failure(self):
        """Failed assertion includes descriptive message."""
        assertion = _make_assertion("response.error", Operator.EQ, True)
        result = evaluate_assertion(assertion, _ok_response())
        assert result.passed is False
        assert result.message  # non-empty

    def test_error_code_in_mcp_content_layer_passes(self):
        """error_code_in passes when server uses MCP isError:true instead of JSON-RPC error.

        Regression: when a server returns result.isError:true (MCP content-layer
        error) the JSON-RPC error.code is absent.  The assertion used to fail with
        'got None'; now it passes because the server IS correctly indicating an error.
        """
        mcp_error_response: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": "1",
            "result": {"content": [{"type": "text", "text": "Unknown tool: foo"}], "isError": True},
            "_body": '{"content": [{"type": "text", "text": "Unknown tool: foo"}], "isError": true}',
        }
        assertion = _make_assertion(
            "response.error_code", Operator.ERROR_CODE_IN, (-32601, -32602, -32603)
        )
        result = evaluate_assertion(assertion, mcp_error_response)
        assert result.passed is True, (
            "error_code_in should pass when server correctly rejects via MCP "
            "content-layer error (isError:true) even though no JSON-RPC error.code exists"
        )

    def test_error_code_in_none_without_is_error_fails(self):
        """error_code_in fails when error_code is None and no MCP-layer error either."""
        ok_with_no_code: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": "1",
            "result": {"content": [{"type": "text", "text": "success"}], "isError": False},
            "_body": "",
        }
        assertion = _make_assertion(
            "response.error_code", Operator.ERROR_CODE_IN, (-32601, -32602)
        )
        result = evaluate_assertion(assertion, ok_with_no_code)
        assert result.passed is False, "error_code_in must fail when no error is present at all"


# ===========================================================================
# ProbeContext
# ===========================================================================

class TestProbeContext:

    @pytest.mark.asyncio
    async def test_execute_probe_tools_call_pass(self):
        """tools/call returns error → probe with response.error==True passes."""
        config = _config()
        mock_transport = create_autospec(Transport, instance=True)
        mock_transport.send = AsyncMock(return_value=_error_response())
        mock_transport.send_notification = AsyncMock()
        mock_transport.close = AsyncMock()

        # Fake a READY session without running the full handshake
        session = MCPSession(mock_transport, config)
        session._status = type(session._status).READY

        probe = _make_probe(
            assertions=[_make_assertion("response.error", Operator.EQ, True)]
        )
        threat = _make_threat()
        ctx = ProbeContext(session, config, "http://127.0.0.1:9999")
        result = await ctx.execute_probe(probe, threat, {"tool_name": "echo"})

        assert result.passed is True
        assert result.probe_id == probe.id

    @pytest.mark.asyncio
    async def test_execute_probe_tools_call_fail(self):
        """tools/call returns ok → probe asserting error fails."""
        config = _config()
        mock_transport = create_autospec(Transport, instance=True)
        mock_transport.send = AsyncMock(return_value=_ok_response())
        mock_transport.send_notification = AsyncMock()
        mock_transport.close = AsyncMock()

        session = MCPSession(mock_transport, config)
        session._status = type(session._status).READY

        probe = _make_probe(
            assertions=[_make_assertion("response.error", Operator.EQ, True)]
        )
        threat = _make_threat()
        ctx = ProbeContext(session, config, "http://127.0.0.1:9999")
        result = await ctx.execute_probe(probe, threat)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_execute_probe_transport_error_captured(self):
        """Transport exception is captured in ProbeResult.error, not re-raised."""
        config = _config()
        mock_transport = create_autospec(Transport, instance=True)
        mock_transport.send = AsyncMock(side_effect=ConnectionError("refused"))
        mock_transport.send_notification = AsyncMock()
        mock_transport.close = AsyncMock()

        session = MCPSession(mock_transport, config)
        session._status = type(session._status).READY

        probe = _make_probe()
        threat = _make_threat()
        ctx = ProbeContext(session, config, "http://127.0.0.1:9999")
        result = await ctx.execute_probe(probe, threat)

        assert result.passed is False
        assert result.error is not None
        assert "Transport error" in result.error

    @pytest.mark.asyncio
    async def test_execute_probe_template_error_captured(self):
        """Bad template variable is captured in ProbeResult.error."""
        config = _config()
        mock_transport = create_autospec(Transport, instance=True)
        mock_transport.send = AsyncMock()
        mock_transport.send_notification = AsyncMock()
        mock_transport.close = AsyncMock()

        session = MCPSession(mock_transport, config)
        session._status = type(session._status).READY

        # Probe with {{unknown_var}} in payload — will raise UnknownVariableError
        probe = Probe(
            id="bad-p1",
            transport="http",
            method="tools/call",
            payload=types.MappingProxyType({"name": "{{unknown_var}}", "arguments": {}}),
            assertions=(),
        )
        threat = _make_threat()
        ctx = ProbeContext(session, config, "http://127.0.0.1:9999")
        result = await ctx.execute_probe(probe, threat)

        assert result.passed is False
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_execute_probe_duration_recorded(self):
        """duration_seconds is a non-negative float."""
        config = _config()
        mock_transport = create_autospec(Transport, instance=True)
        mock_transport.send = AsyncMock(return_value=_ok_response())
        mock_transport.send_notification = AsyncMock()
        mock_transport.close = AsyncMock()

        session = MCPSession(mock_transport, config)
        session._status = type(session._status).READY

        probe = _make_probe(assertions=[_make_assertion("response.error", Operator.EQ, False)])
        threat = _make_threat()
        ctx = ProbeContext(session, config, "http://127.0.0.1:9999")
        result = await ctx.execute_probe(probe, threat)

        assert result.duration_seconds >= 0.0


# ===========================================================================
# MockMCPServer
# ===========================================================================

class TestMockMCPServer:

    def test_server_starts_and_stops(self):
        """MockMCPServer starts and stops cleanly as a context manager."""
        with MockMCPServer() as server:
            assert server.port > 0

    def test_handle_initialize(self):
        """initialize returns protocolVersion 2025-03-26."""
        server = MockMCPServer()
        response = server.handle_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        assert response["result"]["protocolVersion"] == "2025-03-26"

    def test_handle_tools_list(self):
        """tools/list returns the configured tool list."""
        tools = [{"name": "my_tool", "description": "...", "inputSchema": {}}]
        server = MockMCPServer(tools=tools)
        response = server.handle_rpc(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        )
        assert len(response["result"]["tools"]) == 1
        assert response["result"]["tools"][0]["name"] == "my_tool"

    def test_handle_tools_call_default(self):
        """tools/call returns echo result by default."""
        server = MockMCPServer()
        response = server.handle_rpc({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"msg": "hello"}},
        })
        assert "result" in response
        assert response["result"]["isError"] is False

    def test_handle_tools_call_override(self):
        """tools/call returns configured override response."""
        override = {"jsonrpc": "2.0", "id": 0, "error": {"code": -32600, "message": "Denied"}}
        server = MockMCPServer(tools_call_response=override)
        response = server.handle_rpc({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {}},
        })
        assert "error" in response
        assert response["error"]["code"] == -32600

    def test_handle_initialize_error_override(self):
        """initialize returns error when initialize_error is set."""
        server = MockMCPServer(initialize_error="Unsupported protocol")
        response = server.handle_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        assert "error" in response
        assert "Unsupported" in response["error"]["message"]

    def test_notification_returns_empty(self):
        """Notification (no 'id') returns empty dict — no response needed."""
        server = MockMCPServer()
        response = server.handle_rpc(
            {"jsonrpc": "2.0", "method": "initialized", "params": {}}
        )
        assert response == {}

    def test_request_log_records_calls(self):
        """All RPC calls are logged for test assertions."""
        server = MockMCPServer()
        server.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        server.handle_rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        assert len(server.request_log) == 2
        assert server.request_log[0]["method"] == "initialize"


# ===========================================================================
# ProbeRunner serialisation helpers
# ===========================================================================

class TestRunnerSerialisation:

    def test_probe_roundtrip(self):
        """Probe → dict → Probe preserves id, method, assertions."""
        probe = _make_probe()
        d = _probe_to_dict(probe)
        reconstructed = _probe_from_dict(d)
        assert reconstructed.id == probe.id
        assert reconstructed.method == probe.method
        assert len(reconstructed.assertions) == len(probe.assertions)
        assert reconstructed.assertions[0].operator == probe.assertions[0].operator

    def test_threat_roundtrip(self):
        """ThreatDefinition → dict → ThreatDefinition preserves id, severity."""
        threat = _make_threat()
        d = _threat_to_dict(threat)
        reconstructed = _threat_from_dict(d)
        assert reconstructed.id == threat.id
        assert reconstructed.severity == threat.severity

    def test_probe_with_tuple_assertion_value_roundtrip(self):
        """Assertion with tuple value (for status_in) survives serialisation."""
        assertion = Assertion(
            target="response.status_code",
            operator=Operator.STATUS_IN,
            value=(400, 401, 403),
        )
        probe = Probe(
            id="p1",
            transport="http",
            method="tools/call",
            payload=types.MappingProxyType({}),
            assertions=(assertion,),
        )
        d = _probe_to_dict(probe)
        reconstructed = _probe_from_dict(d)
        assert reconstructed.assertions[0].value == (400, 401, 403)


# ===========================================================================
# Integration: MockMCPServer + ProbeContext end-to-end
# ===========================================================================

class TestIntegrationMockServer:

    @pytest.mark.asyncio
    async def test_probe_context_against_mock_server_pass(self):
        """End-to-end: ProbeContext runs a probe against MockMCPServer; server
        returns error → probe asserting response.error==True passes."""
        override = {"jsonrpc": "2.0", "id": 0, "error": {"code": -32600, "message": "Auth required"}}

        with MockMCPServer(tools_call_response=override) as server:
            from cosai_mcp.transport.streamable_http import StreamableHTTPTransport

            target_url = f"http://127.0.0.1:{server.port}"
            config = ScanConfig(
                target_host="127.0.0.1",
                target_port=server.port,
                allow_private_targets=True,
                probe_timeout_seconds=10.0,
            )
            transport = StreamableHTTPTransport(target_url, config)
            await transport.connect()
            try:
                session = MCPSession(transport, config)
                await session.start()

                probe = _make_probe(
                    assertions=[_make_assertion("response.error", Operator.EQ, True)]
                )
                threat = _make_threat()
                ctx = ProbeContext(session, config, target_url)
                result = await ctx.execute_probe(probe, threat, {"tool_name": "echo"})
            finally:
                await transport.close()

        assert result.passed is True
        assert result.error is None

    @pytest.mark.asyncio
    async def test_probe_context_against_mock_server_fail(self):
        """End-to-end: server returns ok → probe asserting error fails."""
        with MockMCPServer() as server:
            from cosai_mcp.transport.streamable_http import StreamableHTTPTransport

            target_url = f"http://127.0.0.1:{server.port}"
            config = ScanConfig(
                target_host="127.0.0.1",
                target_port=server.port,
                allow_private_targets=True,
                probe_timeout_seconds=10.0,
            )
            transport = StreamableHTTPTransport(target_url, config)
            await transport.connect()
            try:
                session = MCPSession(transport, config)
                await session.start()

                probe = _make_probe(
                    assertions=[_make_assertion("response.error", Operator.EQ, True)]
                )
                threat = _make_threat()
                ctx = ProbeContext(session, config, target_url)
                result = await ctx.execute_probe(probe, threat, {"tool_name": "echo"})
            finally:
                await transport.close()

        assert result.passed is False


# ===========================================================================
# P3 Panel Regression Tests — all 14 findings
# ===========================================================================

class TestP3PanelRegressions:

    # -----------------------------------------------------------------------
    # Finding 1: _validate_raw_result guards the queue
    # -----------------------------------------------------------------------

    def test_regression_validate_raw_result_rejects_non_dict(self):
        """_validate_raw_result raises ValueError when payload is not a dict."""
        with pytest.raises(ValueError, match="must be a dict"):
            _validate_raw_result(["bad", "payload"])

    def test_regression_validate_raw_result_rejects_missing_keys(self):
        """_validate_raw_result raises ValueError when required keys are absent."""
        with pytest.raises(ValueError, match="missing required keys"):
            _validate_raw_result({"probe_id": "p1"})  # missing threat_id, passed, assertions, duration

    def test_regression_validate_raw_result_accepts_valid_dict(self):
        """_validate_raw_result accepts a valid subprocess result dict."""
        raw = {
            "probe_id": "p1",
            "threat_id": "T01",
            "passed": True,
            "assertions": [],
            "duration_seconds": 0.1,
        }
        assert _validate_raw_result(raw) is raw

    # -----------------------------------------------------------------------
    # Finding 6: transport dispatch on probe.transport
    # -----------------------------------------------------------------------

    def test_regression_probe_transport_field_preserved_in_dict(self):
        """probe.transport is preserved through serialisation — dispatch key survives IPC."""
        probe = _make_probe()
        d = _probe_to_dict(probe)
        assert d["transport"] == "http"
        reconstructed = _probe_from_dict(d)
        assert reconstructed.transport == "http"

    def test_regression_unknown_transport_not_silently_http(self):
        """Unknown transport value is not silently treated as http after roundtrip."""
        probe_dict = _probe_to_dict(_make_probe())
        probe_dict["transport"] = "websocket"
        reconstructed = _probe_from_dict(probe_dict)
        # The transport value must be preserved — the subprocess will raise ValueError
        # for unknown types rather than silently defaulting to http.
        assert reconstructed.transport == "websocket"
        transport_type = probe_dict.get("transport", "http")
        assert transport_type not in ("http", "stdio")

    # -----------------------------------------------------------------------
    # Finding 7: _dispatch uses session.send_raw, not _transport.send directly
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_regression_dispatch_uses_send_raw_not_transport(self):
        """ProbeContext._dispatch calls session.send_raw for non-tools/call methods."""
        config = _config()
        mock_transport = create_autospec(Transport, instance=True)
        mock_transport.send = AsyncMock(return_value=_ok_response())
        mock_transport.send_notification = AsyncMock()
        mock_transport.close = AsyncMock()

        session = MCPSession(mock_transport, config)
        session._status = type(session._status).READY

        ctx = ProbeContext(session, config, "http://127.0.0.1:9999")

        original_send_raw = session.send_raw
        send_raw_called: list[bool] = []

        async def _spy(*args: Any, **kwargs: Any) -> Any:
            send_raw_called.append(True)
            return await original_send_raw(*args, **kwargs)

        session.send_raw = _spy  # type: ignore[method-assign]

        probe = _make_probe(method="resources/list", payload={"cursor": None})
        threat = _make_threat()
        await ctx.execute_probe(probe, threat)

        assert send_raw_called, "send_raw was not called — _dispatch bypassed session API"

    # -----------------------------------------------------------------------
    # Finding 8: request_log is thread-safe
    # -----------------------------------------------------------------------

    def test_regression_request_log_returns_snapshot_not_mutable_ref(self):
        """request_log returns a snapshot; mutating it does not affect the log."""
        server = MockMCPServer()
        server.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        log = server.request_log
        log.clear()
        assert len(server.request_log) == 1

    def test_regression_request_log_concurrent_writes_no_corruption(self):
        """Concurrent writes to request_log do not corrupt the list."""
        server = MockMCPServer()
        errors: list[Exception] = []

        def _write() -> None:
            try:
                for i in range(50):
                    server.handle_rpc(
                        {"jsonrpc": "2.0", "id": i, "method": "tools/list", "params": {}}
                    )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_write) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(server.request_log) == 200  # 4 threads × 50 writes

    # -----------------------------------------------------------------------
    # Finding 9: wait_ready() provides a readiness barrier
    # -----------------------------------------------------------------------

    def test_regression_wait_ready_does_not_block_after_start(self):
        """wait_ready() returns immediately after start()."""
        with MockMCPServer() as server:
            server.wait_ready(timeout=1.0)  # must not raise or block

    def test_regression_wait_ready_raises_if_not_started(self):
        """wait_ready() raises RuntimeError when server has not been started."""
        server = MockMCPServer()
        with pytest.raises(RuntimeError, match="did not become ready"):
            server.wait_ready(timeout=0.05)

    # -----------------------------------------------------------------------
    # Finding 10: notifications get HTTP 204, not 200
    # -----------------------------------------------------------------------

    def test_regression_notification_handle_rpc_returns_empty(self):
        """handle_rpc returns {} for notifications (no 'id') — triggers 204 path."""
        server = MockMCPServer()
        result = server.handle_rpc({"jsonrpc": "2.0", "method": "initialized", "params": {}})
        assert result == {}

    @pytest.mark.asyncio
    async def test_regression_notification_end_to_end_204(self):
        """End-to-end: initialized notification over HTTP returns 204 No Content."""
        import httpx

        with MockMCPServer() as server:
            server.wait_ready()
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://127.0.0.1:{server.port}",
                    json={"jsonrpc": "2.0", "method": "initialized", "params": {}},
                    headers={"Content-Type": "application/json"},
                )
            assert response.status_code == 204

    # -----------------------------------------------------------------------
    # Finding 11: _result_from_dict HTML-escapes the error field
    # -----------------------------------------------------------------------

    def test_regression_result_from_dict_escapes_error_xss(self):
        """_result_from_dict HTML-escapes the error from an untrusted subprocess."""
        raw = {
            "probe_id": "p1",
            "threat_id": "T01",
            "passed": False,
            "status_code": None,
            "response_body": "",
            "error": "<script>alert('xss')</script>",
            "assertions": [],
            "duration_seconds": 0.1,
        }
        result = _result_from_dict(raw)
        assert "<script>" not in (result.error or "")
        assert "&lt;script&gt;" in (result.error or "")

    def test_regression_result_from_dict_none_error_stays_none(self):
        """_result_from_dict preserves None error as None (not empty string)."""
        raw = {
            "probe_id": "p1",
            "threat_id": "T01",
            "passed": True,
            "status_code": None,
            "response_body": "",
            "error": None,
            "assertions": [],
            "duration_seconds": 0.1,
        }
        result = _result_from_dict(raw)
        assert result.error is None

    # -----------------------------------------------------------------------
    # Finding 13: provenance survives threat serialisation roundtrip
    # -----------------------------------------------------------------------

    def test_regression_threat_provenance_official_roundtrip(self):
        """Provenance.OFFICIAL survives _threat_to_dict → _threat_from_dict."""
        threat = _make_threat()
        assert threat.provenance == Provenance.OFFICIAL
        d = _threat_to_dict(threat)
        assert "provenance" in d
        reconstructed = _threat_from_dict(d)
        assert reconstructed.provenance == Provenance.OFFICIAL

    def test_regression_threat_provenance_custom_roundtrip(self):
        """Provenance.CUSTOM survives _threat_to_dict → _threat_from_dict."""
        threat = ThreatDefinition(
            schema_version="1.0",
            id="CUSTOM-001",
            category="T1",
            severity=Severity.HIGH,
            cosai_ref="",
            owasp_ref="",
            cwe=(),
            probes=(),
            remediation="",
            references=(),
            provenance=Provenance.CUSTOM,
        )
        d = _threat_to_dict(threat)
        reconstructed = _threat_from_dict(d)
        assert reconstructed.provenance == Provenance.CUSTOM

    # -----------------------------------------------------------------------
    # Finding 14: Content-Type validation (end-to-end)
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_regression_content_type_wrong_returns_415(self):
        """Request with text/plain Content-Type → 415 Unsupported Media Type."""
        import httpx

        with MockMCPServer() as server:
            server.wait_ready()
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://127.0.0.1:{server.port}",
                    content=b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
                    headers={"Content-Type": "text/plain"},
                )
            assert response.status_code == 415

    @pytest.mark.asyncio
    async def test_regression_content_type_json_accepted_200(self):
        """Request with application/json Content-Type is accepted (200)."""
        import httpx

        with MockMCPServer() as server:
            server.wait_ready()
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://127.0.0.1:{server.port}",
                    json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                    headers={"Content-Type": "application/json"},
                )
            assert response.status_code == 200

    # -----------------------------------------------------------------------
    # Pre-existing regressions confirmed by panel (Findings 2, 3, 4)
    # -----------------------------------------------------------------------

    def test_regression_null_error_not_treated_as_error(self):
        """'error': null alongside 'result' is NOT a real error (JSON-RPC 2.0)."""
        response: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": "1",
            "result": {"content": []},
            "error": None,
        }
        value = _extract_target(response, "response.error")
        assert value is False

    def test_regression_body_reads_from_canonical_key(self):
        """_extract_target('response.body') reads _body, not recomputed result/error JSON."""
        response: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": "1",
            "result": {"content": []},
            "_body": "canonical-content",
        }
        body = _extract_target(response, "response.body")
        assert body == "canonical-content"

    def test_regression_body_empty_when_no_canonical_key(self):
        """_extract_target('response.body') returns '' when _body is absent."""
        response: dict[str, Any] = {"jsonrpc": "2.0", "id": "1", "result": {}}
        body = _extract_target(response, "response.body")
        assert body == ""


# ===========================================================================
# Regression: MappingProxyType pickling bug (found during Mnemo scan 2026-04-27)
# ===========================================================================

class TestMappingProxyPicklingRegression:
    """Bug: nested MappingProxyType in probe.payload caused pickling failure
    when the multiprocessing.spawn context tried to serialise the subprocess
    entry-point arguments.  _probe_to_dict must use _to_json_safe() to
    recursively convert all MappingProxyType objects to plain dicts."""

    def test_regression_probe_to_dict_converts_nested_mappingproxy(self):
        """_probe_to_dict must recursively convert nested MappingProxyType to
        plain dicts so the result can be pickled for subprocess IPC."""
        import pickle

        nested_payload = types.MappingProxyType({
            "name": "{{tool_name}}",
            "arguments": types.MappingProxyType({
                "nested": types.MappingProxyType({"key": "value"}),
                "list_field": ("a", "b"),
            }),
        })
        probe = Probe(
            id="test-p1",
            transport="http",
            method="tools/call",
            payload=nested_payload,
            assertions=(),
        )
        d = _probe_to_dict(probe)

        # Must be pickle-able (no MappingProxyType or tuple anywhere)
        data = pickle.dumps(d)
        loaded = pickle.loads(data)
        assert loaded["payload"]["name"] == "{{tool_name}}"
        assert loaded["payload"]["arguments"]["nested"]["key"] == "value"

    def test_regression_probe_to_dict_no_mappingproxy_in_output(self):
        """_probe_to_dict output must contain no MappingProxyType objects."""
        nested_payload = types.MappingProxyType({
            "x": types.MappingProxyType({"y": "z"}),
        })
        probe = Probe(
            id="test-p2",
            transport="http",
            method="tools/call",
            payload=nested_payload,
            assertions=(),
        )
        d = _probe_to_dict(probe)

        def _has_proxy(obj: Any) -> bool:
            if isinstance(obj, types.MappingProxyType):
                return True
            if isinstance(obj, dict):
                return any(_has_proxy(v) for v in obj.values())
            if isinstance(obj, (list, tuple)):
                return any(_has_proxy(item) for item in obj)
            return False

        assert not _has_proxy(d), "Output must not contain MappingProxyType objects"


# ===========================================================================
# Pentest-derived probe modifier tests (probe_token, probe_count, probe_headers)
# ===========================================================================

class TestProbeModifierFields:
    """Tests for probe_token, probe_count, probe_headers fields added from pentest findings."""

    def test_probe_token_default_is_none(self):
        """Probe.probe_token defaults to None when not specified."""
        probe = _make_probe()
        assert probe.probe_token is None

    def test_probe_count_default_is_one(self):
        """Probe.probe_count defaults to 1."""
        probe = _make_probe()
        assert probe.probe_count == 1

    def test_probe_headers_default_is_none(self):
        """Probe.probe_headers defaults to None."""
        probe = _make_probe()
        assert probe.probe_headers is None

    def test_probe_to_dict_omits_defaults(self):
        """_probe_to_dict omits probe_token/probe_count/probe_headers when at defaults."""
        probe = _make_probe()
        d = _probe_to_dict(probe)
        assert "probe_token" not in d
        assert "probe_count" not in d
        assert "probe_headers" not in d

    def test_probe_to_dict_includes_probe_token(self):
        """_probe_to_dict includes probe_token when set."""
        probe = Probe(
            id="T02-005-p1",
            transport="http",
            method="tools/call",
            payload=types.MappingProxyType({}),
            assertions=(),
            probe_token="read",
        )
        d = _probe_to_dict(probe)
        assert d["probe_token"] == "read"

    def test_probe_to_dict_includes_probe_count(self):
        """_probe_to_dict includes probe_count when > 1."""
        probe = Probe(
            id="T10-004-p1",
            transport="http",
            method="tools/list",
            payload=types.MappingProxyType({}),
            assertions=(),
            probe_count=30,
        )
        d = _probe_to_dict(probe)
        assert d["probe_count"] == 30

    def test_probe_to_dict_includes_probe_headers(self):
        """_probe_to_dict includes probe_headers when set."""
        probe = Probe(
            id="T07-001-p1",
            transport="http",
            method="tools/list",
            payload=types.MappingProxyType({}),
            assertions=(),
            probe_headers=types.MappingProxyType({"Origin": "https://evil.example.com"}),
        )
        d = _probe_to_dict(probe)
        assert d["probe_headers"] == {"Origin": "https://evil.example.com"}

    def test_probe_from_dict_roundtrip_probe_token(self):
        """probe_token survives _probe_to_dict → _probe_from_dict roundtrip."""
        probe = Probe(
            id="T02-005-p1",
            transport="http",
            method="tools/call",
            payload=types.MappingProxyType({}),
            assertions=(),
            probe_token="read",
            probe_count=1,
        )
        d = _probe_to_dict(probe)
        restored = _probe_from_dict(d)
        assert restored.probe_token == "read"

    def test_probe_from_dict_roundtrip_probe_count(self):
        """probe_count survives roundtrip."""
        probe = Probe(
            id="T10-004-p1",
            transport="http",
            method="tools/list",
            payload=types.MappingProxyType({}),
            assertions=(),
            probe_count=30,
        )
        d = _probe_to_dict(probe)
        restored = _probe_from_dict(d)
        assert restored.probe_count == 30

    def test_probe_from_dict_roundtrip_probe_headers(self):
        """probe_headers survives roundtrip as MappingProxyType."""
        probe = Probe(
            id="T07-001-p1",
            transport="http",
            method="tools/list",
            payload=types.MappingProxyType({}),
            assertions=(),
            probe_headers=types.MappingProxyType({"Origin": "https://evil.example.com"}),
        )
        d = _probe_to_dict(probe)
        restored = _probe_from_dict(d)
        assert isinstance(restored.probe_headers, types.MappingProxyType)
        assert restored.probe_headers["Origin"] == "https://evil.example.com"

    def test_probe_token_read_inconclusive_when_no_read_token(self):
        """probe_token='read' with no read_token configured → INCONCLUSIVE result (not crash).

        This exercises the early-exit path in _probe_subprocess_entry that returns
        inconclusive before any network connection is attempted.
        """
        from cosai_mcp.harness.runner import _probe_subprocess_entry
        import multiprocessing
        probe = Probe(
            id="T02-005-p1",
            transport="http",
            method="tools/call",
            payload=types.MappingProxyType({"name": "log_decision", "arguments": {}}),
            assertions=(Assertion(target="response.error", operator=Operator.EQ, value=True),),
            probe_token="read",
        )
        threat = _make_threat("T02-005")
        config = ScanConfig(
            target_host="127.0.0.1",
            target_port=9999,
            allow_private_targets=True,
            read_token=None,  # not configured → should yield inconclusive
        )
        q: multiprocessing.Queue = multiprocessing.Queue()
        # Call the subprocess entry point directly (it is synchronous when invoked inline).
        _probe_subprocess_entry(
            q,
            _probe_to_dict(probe),
            _threat_to_dict(threat),
            config,
            "http://127.0.0.1:9999/mcp",
            {},
        )
        # Use timeout to avoid race on slow machines; the result must be present.
        result = q.get(timeout=5)
        assert result["passed"] is False
        assert result.get("inconclusive_reason") is not None, (
            "probe_token='read' with no read_token must set inconclusive_reason"
        )
        assert "read-token" in result["inconclusive_reason"]


# ===========================================================================
# response.header.* assertion target tests (CORS probe support)
# ===========================================================================

class TestHeaderAssertionTarget:
    """Tests for response.header.* assertion target path."""

    def _response_with_headers(self, headers: dict[str, str]) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "result": {},
            "_body": "{}",
            "_status_code": 200,
            "_headers": {k.lower(): v for k, v in headers.items()},
        }

    def test_extract_header_present(self):
        """response.header.x-frame-options extracts the header value."""
        response = self._response_with_headers({"X-Frame-Options": "DENY"})
        from cosai_mcp.harness.assertions import _extract_target
        assert _extract_target(response, "response.header.x-frame-options") == "DENY"

    def test_extract_header_case_insensitive(self):
        """Header name lookup is case-insensitive."""
        response = self._response_with_headers({"Access-Control-Allow-Origin": "*"})
        from cosai_mcp.harness.assertions import _extract_target
        result = _extract_target(response, "response.header.Access-Control-Allow-Origin")
        assert result == "*"

    def test_extract_header_missing_returns_none(self):
        """Missing header returns None."""
        response = self._response_with_headers({})
        from cosai_mcp.harness.assertions import _extract_target
        assert _extract_target(response, "response.header.x-custom") is None

    def test_extract_header_no_headers_key(self):
        """If _headers not in response, missing header returns None."""
        response = {"jsonrpc": "2.0", "result": {}}
        from cosai_mcp.harness.assertions import _extract_target
        assert _extract_target(response, "response.header.origin") is None

    def test_regression_cors_wildcard_detection(self):
        """NE assertion on response.header.access-control-allow-origin catches wildcard."""
        response = self._response_with_headers({"access-control-allow-origin": "*"})
        assertion = Assertion(
            target="response.header.access-control-allow-origin",
            operator=Operator.NE,
            value="*",
        )
        result = evaluate_assertion(assertion, response)
        assert result.passed is False, "Wildcard CORS must fail the NE assertion (it IS a wildcard)"

    def test_regression_cors_explicit_origin_passes(self):
        """NE assertion passes when CORS is restricted to a specific origin."""
        response = self._response_with_headers({
            "access-control-allow-origin": "https://app.example.com"
        })
        assertion = Assertion(
            target="response.header.access-control-allow-origin",
            operator=Operator.NE,
            value="*",
        )
        result = evaluate_assertion(assertion, response)
        assert result.passed is True

    def test_regression_cors_absent_header_passes(self):
        """NE assertion passes when the header is absent (None != '*')."""
        response = self._response_with_headers({})
        assertion = Assertion(
            target="response.header.access-control-allow-origin",
            operator=Operator.NE,
            value="*",
        )
        result = evaluate_assertion(assertion, response)
        assert result.passed is True


# ===========================================================================
# New catalog entry integration tests (load → scan → report pipeline)
# ===========================================================================

class TestNewCatalogEntriesLoad:
    """Verify new pentest-derived catalog entries load, validate, and parse correctly."""

    def _load_official_catalog(self) -> list:
        from pathlib import Path
        from cosai_mcp.catalog.loader import CatalogLoader
        catalog_root = (
            Path(__file__).parent.parent.parent / "catalog"
        )
        loader = CatalogLoader(catalog_root)
        return loader.load_all()

    def test_regression_t01_005_loads(self):
        """T01-005 (JSON-RPC error code conformance) loads from signed catalog."""
        threats = self._load_official_catalog()
        ids = {t.id for t in threats}
        assert "T01-005" in ids, "T01-005 must be in the official catalog"

    def test_regression_t02_004_loads(self):
        """T02-004 (tool enumeration without scope filter) loads correctly."""
        threats = self._load_official_catalog()
        ids = {t.id for t in threats}
        assert "T02-004" in ids

    def test_regression_t02_005_loads(self):
        """T02-005 (read token reaches write tool) loads and has probe_token='read'."""
        threats = self._load_official_catalog()
        t = next(t for t in threats if t.id == "T02-005")
        assert any(p.probe_token == "read" for p in t.probes), (
            "T02-005 probes must have probe_token='read'"
        )

    def test_regression_t07_001_loads(self):
        """T07-001 (CORS wildcard) loads and has probe_headers with Origin."""
        threats = self._load_official_catalog()
        ids = {t.id for t in threats}
        assert "T07-001" in ids
        t = next(t for t in threats if t.id == "T07-001")
        assert any(
            p.probe_headers and "Origin" in p.probe_headers
            for p in t.probes
        ), "T07-001 probes must include an Origin probe_header"

    def test_regression_t10_004_loads(self):
        """T10-004 (rate limiting) loads and has probe_count > 1."""
        threats = self._load_official_catalog()
        t = next(t for t in threats if t.id == "T10-004")
        assert any(p.probe_count > 1 for p in t.probes), (
            "T10-004 probes must have probe_count > 1 for rate-limit detection"
        )

    def test_regression_t01_005_error_code_assertion(self):
        """T01-005 probes assert on response.error_code == -32601."""
        threats = self._load_official_catalog()
        t = next(t for t in threats if t.id == "T01-005")
        assert any(
            a.target == "response.error_code" and a.value == -32601
            for p in t.probes
            for a in p.assertions
        ), "T01-005 must have an assertion checking for error code -32601"

    def test_regression_t07_001_header_assertion(self):
        """T07-001 probes assert on response.header.access-control-allow-origin."""
        threats = self._load_official_catalog()
        t = next(t for t in threats if t.id == "T07-001")
        assert any(
            a.target.startswith("response.header.")
            for p in t.probes
            for a in p.assertions
        ), "T07-001 must assert on a response.header.* target"

