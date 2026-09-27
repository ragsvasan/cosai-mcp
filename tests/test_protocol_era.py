"""MCP 2026-07-28 dual-era support (CoSAI MCP Security v2.0, P0).

Covers:
  - pure wire helpers in cosai_mcp.protocol
  - MCPSession era selection over a real StreamableHTTPTransport against
    MockMCPServer in legacy / modern / dual modes (the mock enforces the spec's
    header–body validation, so a passing modern call proves the headers are right)
  - no-downgrade: a recognisably modern server is never retried over initialize
  - the real ProbeRunner subprocess path and the Scanner entry point
  - inventory capture and era detection
"""
from __future__ import annotations

import asyncio
import dataclasses
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, create_autospec

import pytest

from cosai_mcp.catalog.loader import CatalogLoader
from cosai_mcp.config import ScanConfig
from cosai_mcp.discovery import detect_protocol_era
from cosai_mcp.exceptions import SessionIncompleteError
from cosai_mcp.harness.mock_server import MockMCPServer
from cosai_mcp.harness.runner import ProbeRunner, _is_auth_rejection
from cosai_mcp.protocol import (
    ERR_HEADER_MISMATCH,
    META_CLIENT_INFO,
    META_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSION,
    EraDetection,
    ProtocolEra,
    classify_discover_response,
    decode_header_value,
    encode_header_value,
    mcp_name_for,
    request_metadata_headers,
    with_request_meta,
    x_mcp_param_headers,
)
from cosai_mcp.session import MCPSession, SessionStatus
from cosai_mcp.transport.base import Transport
from cosai_mcp.transport.streamable_http import StreamableHTTPTransport

CATALOG_ROOT = Path(__file__).parent.parent / "catalog"


def _config(port: int, era: str = "auto") -> ScanConfig:
    return ScanConfig(
        target_host="127.0.0.1",
        target_port=port,
        allow_private_targets=True,
        probe_timeout_seconds=10.0,
        protocol_era=era,
    )


async def _open_session(port: int, era: str = "auto") -> tuple[MCPSession, Any]:
    url = f"http://127.0.0.1:{port}"
    transport = StreamableHTTPTransport(url, _config(port, era))
    await transport.connect()
    session = MCPSession(transport, _config(port, era), target_url=url)
    return session, await session.start()


def _methods(server: MockMCPServer) -> list[str]:
    return [r.get("method", "") for r in server.request_log]


def _header(server: MockMCPServer, name: str) -> str | None:
    lower = {k.lower(): v for k, v in server._last_request_headers.items()}
    return lower.get(name.lower())


# ===========================================================================
# Pure helpers
# ===========================================================================

class TestHeaderEncoding:
    @pytest.mark.parametrize("value", ["us-west1", "get_weather", "file:///a/b.json"])
    def test_plain_ascii_passes_through(self, value: str) -> None:
        assert encode_header_value(value) == value

    @pytest.mark.parametrize(
        "value", ["Hello, 世界", " padded ", "line1\nline2", "=?base64?literal?=", "tab\x00nul"]
    )
    def test_unsafe_values_are_base64_sentinel_encoded_and_round_trip(self, value: str) -> None:
        encoded = encode_header_value(value)
        assert encoded.startswith("=?base64?") and encoded.endswith("?=")
        assert "\n" not in encoded and "\x00" not in encoded
        assert decode_header_value(encoded) == value

    def test_spec_example_non_ascii(self) -> None:
        assert encode_header_value("Hello, 世界") == "=?base64?SGVsbG8sIOS4lueVjA==?="

    def test_mcp_name_for_name_bearing_methods(self) -> None:
        assert mcp_name_for("tools/call", {"name": "echo"}) == "echo"
        assert mcp_name_for("prompts/get", {"name": "p"}) == "p"
        assert mcp_name_for("resources/read", {"uri": "file:///x"}) == "file:///x"
        assert mcp_name_for("tools/list", {"name": "echo"}) is None
        assert mcp_name_for("tools/call", {"name": 7}) is None

    def test_request_metadata_headers(self) -> None:
        h = request_metadata_headers("tools/call", {"name": "echo"})
        assert h == {
            "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION,
            "Mcp-Method": "tools/call",
            "Mcp-Name": "echo",
        }
        assert "Mcp-Name" not in request_metadata_headers("server/discover", {})


class TestWithRequestMeta:
    META = {META_PROTOCOL_VERSION: MODERN_PROTOCOL_VERSION, META_CLIENT_INFO: {"name": "s"}}

    def test_adds_meta_without_mutating_input(self) -> None:
        params = {"name": "echo"}
        out = with_request_meta(params, self.META)
        assert out["_meta"] == self.META
        assert "_meta" not in params

    def test_probe_supplied_meta_keys_win(self) -> None:
        spoof = {META_CLIENT_INFO: {"name": "admin-console"}}
        out = with_request_meta({"_meta": spoof}, self.META)
        assert out["_meta"][META_CLIENT_INFO] == {"name": "admin-console"}
        assert out["_meta"][META_PROTOCOL_VERSION] == MODERN_PROTOCOL_VERSION

    def test_non_dict_meta_left_untouched(self) -> None:
        assert with_request_meta({"_meta": "garbage"}, self.META)["_meta"] == "garbage"


class TestXMcpParamHeaders:
    SCHEMA = {
        "type": "object",
        "properties": {
            "region": {"type": "string", "x-mcp-header": "Region"},
            "limit": {"type": "integer", "x-mcp-header": "Limit"},
            "dry": {"type": "boolean", "x-mcp-header": "Dry"},
            "ratio": {"type": "number", "x-mcp-header": "Ratio"},
            "opts": {
                "type": "object",
                "properties": {"tenant": {"type": "string", "x-mcp-header": "Tenant"}},
            },
            "list": {
                "type": "array",
                "items": {"type": "object", "properties": {"x": {"type": "string"}}},
            },
        },
    }

    def test_primitive_and_nested_properties_are_mirrored(self) -> None:
        args = {"region": "us-west1", "limit": 42, "dry": True, "ratio": 0.5,
                "opts": {"tenant": "Acme Ü"}}
        headers = x_mcp_param_headers(self.SCHEMA, args)
        assert headers["Mcp-Param-Region"] == "us-west1"
        assert headers["Mcp-Param-Limit"] == "42"
        assert headers["Mcp-Param-Dry"] == "true"
        assert decode_header_value(headers["Mcp-Param-Tenant"]) == "Acme Ü"
        # type:number is forbidden by the spec → never mirrored
        assert "Mcp-Param-Ratio" not in headers

    def test_missing_or_null_values_omit_header(self) -> None:
        assert x_mcp_param_headers(self.SCHEMA, {"region": None}) == {}

    def test_invalid_and_duplicate_annotations_are_skipped(self) -> None:
        schema = {"properties": {
            "a": {"type": "string", "x-mcp-header": "Bad Name\r\nX-Injected: 1"},
            "b": {"type": "string", "x-mcp-header": "Dup"},
            "c": {"type": "string", "x-mcp-header": "dup"},
        }}
        headers = x_mcp_param_headers(schema, {"a": "1", "b": "2", "c": "3"})
        assert headers == {"Mcp-Param-Dup": "2"}

    def test_unsafe_integer_is_skipped(self) -> None:
        assert x_mcp_param_headers(self.SCHEMA, {"limit": 2**60}) == {}

    def test_hostile_inputs_do_not_raise(self) -> None:
        assert x_mcp_param_headers("not-a-schema", {}) == {}
        assert x_mcp_param_headers(self.SCHEMA, ["not", "a", "dict"]) == {}


class TestClassifyDiscoverResponse:
    @pytest.mark.parametrize(
        ("response", "expected"),
        [
            ({"result": {"supportedVersions": ["2026-07-28"]}}, EraDetection.MODERN),
            ({"result": {"supportedVersions": ["2025-11-25"]}}, EraDetection.LEGACY),
            ({"result": {"supportedVersions": ["2099-01-01"]}}, EraDetection.MODERN_INCOMPATIBLE),
            ({"error": {"code": -32022, "data": {"supported": ["2026-07-28"]}}},
             EraDetection.MODERN),
            ({"error": {"code": -32022, "data": {"supported": ["2099-01-01"]}}},
             EraDetection.MODERN_INCOMPATIBLE),
            ({"error": {"code": -32022, "data": {"supported": ["2025-11-25", "2099-01-01"]}}},
             EraDetection.LEGACY),
            ({"error": {"code": -32020, "message": "mismatch"}}, EraDetection.MODERN_ERROR),
            ({"error": {"code": -32021, "message": "cap"}}, EraDetection.MODERN_ERROR),
            ({"error": {"code": -32601, "message": "nf"}, "_status_code": 200},
             EraDetection.LEGACY),
            ({"error": {"code": -32600, "message": "no session"}, "_status_code": 400},
             EraDetection.LEGACY),
            ({"error": {"code": -32001, "message": "auth"}, "_status_code": 401},
             EraDetection.UNDETERMINED),
            ({"_status_code": 403}, EraDetection.UNDETERMINED),
            ({"_status_code": 503}, EraDetection.UNDETERMINED),
            ({}, EraDetection.LEGACY),
            ("not a dict", EraDetection.LEGACY),
        ],
    )
    def test_table(self, response: Any, expected: EraDetection) -> None:
        assert classify_discover_response(response) is expected


def test_scan_config_rejects_unknown_protocol_era() -> None:
    with pytest.raises(ValueError, match="protocol_era"):
        ScanConfig(target_host="h", target_port=1, protocol_era="future")


# ===========================================================================
# Session over real HTTP against MockMCPServer
# ===========================================================================

class TestSessionModern:
    def test_modern_server_auto_uses_stateless_path(self) -> None:
        with MockMCPServer(protocol_era="modern") as server:
            server.wait_ready()

            async def _run() -> tuple[Any, dict[str, Any]]:
                session, info = await _open_session(server.port)
                call = await session.tools_call("echo", {"input": "hi"})
                await session.close()
                return info, call

            info, call = asyncio.run(_run())
            methods = _methods(server)

        assert info.protocol_era == "modern"
        assert info.protocol_version == MODERN_PROTOCOL_VERSION
        assert info.server_info == {"name": "mock-mcp-server", "version": "0.2.0"}
        assert [t["name"] for t in info.tool_manifest] == ["echo"]
        assert methods == ["server/discover", "tools/list", "tools/call"]
        # The mock enforces header/body agreement; a successful call proves the
        # MCP-Protocol-Version / Mcp-Method / Mcp-Name headers were correct.
        assert "error" not in call, call
        for req in server.request_log:
            assert req["params"]["_meta"][META_PROTOCOL_VERSION] == MODERN_PROTOCOL_VERSION

    def test_modern_request_headers_and_no_session_id(self) -> None:
        with MockMCPServer(protocol_era="modern") as server:
            server.wait_ready()

            async def _run() -> None:
                session, _ = await _open_session(server.port)
                await session.tools_call("echo", {})
                await session.close()

            asyncio.run(_run())
            assert _header(server, "MCP-Protocol-Version") == MODERN_PROTOCOL_VERSION
            assert _header(server, "Mcp-Method") == "tools/call"
            assert _header(server, "Mcp-Name") == "echo"
            assert _header(server, "Mcp-Session-Id") is None

    def test_dual_era_server_is_spoken_to_in_modern(self) -> None:
        with MockMCPServer(protocol_era="dual") as server:
            server.wait_ready()

            async def _run() -> Any:
                session, info = await _open_session(server.port)
                await session.close()
                return info

            info = asyncio.run(_run())
            assert info.protocol_era == "modern"
            assert "initialize" not in _methods(server)

    def test_probe_supplied_meta_is_delivered_verbatim(self) -> None:
        """T1 _meta identity-spoof probes must reach the server as written."""
        with MockMCPServer(protocol_era="modern") as server:
            server.wait_ready()

            async def _run() -> None:
                session, _ = await _open_session(server.port)
                await session.send_raw("tools/call", {
                    "name": "echo", "arguments": {},
                    "_meta": {META_CLIENT_INFO: {"name": "admin-console", "version": "9"}},
                })
                await session.close()

            asyncio.run(_run())
            meta = server.request_log[-1]["params"]["_meta"]
            assert meta[META_CLIENT_INFO] == {"name": "admin-console", "version": "9"}
            assert meta[META_PROTOCOL_VERSION] == MODERN_PROTOCOL_VERSION

    def test_probe_override_headers_can_force_header_body_mismatch(self) -> None:
        """Probe headers apply last, so T7 header/body-confusion probes are expressible."""
        with MockMCPServer(protocol_era="modern") as server:
            server.wait_ready()

            async def _run() -> dict[str, Any]:
                session, _ = await _open_session(server.port)
                resp = await session.tools_call(
                    "echo", {}, override_headers={"Mcp-Name": "admin_delete"}
                )
                await session.close()
                return resp

            resp = asyncio.run(_run())
        assert resp["error"]["code"] == ERR_HEADER_MISMATCH
        assert resp["_status_code"] == 400

    def test_x_mcp_header_parameters_are_mirrored(self) -> None:
        tools = [{
            "name": "execute_sql",
            "description": "run sql",
            "inputSchema": {"type": "object", "properties": {
                "region": {"type": "string", "x-mcp-header": "Region"},
                "query": {"type": "string"},
            }},
        }]
        with MockMCPServer(protocol_era="modern", tools=tools) as server:
            server.wait_ready()

            async def _run() -> None:
                session, _ = await _open_session(server.port)
                await session.tools_call("execute_sql", {"region": "us-west1", "query": "x"})
                await session.close()

            asyncio.run(_run())
            assert _header(server, "Mcp-Param-Region") == "us-west1"
            assert _header(server, "Mcp-Name") == "execute_sql"


class TestSessionLegacyFallback:
    def test_legacy_server_auto_falls_back_to_initialize(self) -> None:
        with MockMCPServer() as server:  # default legacy
            server.wait_ready()

            async def _run() -> tuple[Any, MCPSession]:
                session, info = await _open_session(server.port)
                await session.tools_call("echo", {"a": 1})
                await session.close()
                return info, session

            info, session = asyncio.run(_run())
            methods = _methods(server)
            last = server.request_log[-1]

        assert info.protocol_era == "legacy"
        assert session.protocol_era is ProtocolEra.LEGACY
        assert info.protocol_version == "2025-03-26"
        assert methods[:2] == ["server/discover", "initialize"]
        assert methods[-1] == "tools/call"
        # Legacy bodies are untouched: no _meta injected after fallback.
        assert last["params"] == {"name": "echo", "arguments": {"a": 1}}

    def test_legacy_pin_never_sends_discover(self) -> None:
        with MockMCPServer() as server:
            server.wait_ready()

            async def _run() -> None:
                session, _ = await _open_session(server.port, era="legacy")
                await session.close()

            asyncio.run(_run())
            assert _methods(server)[0] == "initialize"
            assert "server/discover" not in _methods(server)

    def test_forced_modern_against_legacy_server_is_incomplete(self) -> None:
        with MockMCPServer() as server:
            server.wait_ready()
            with pytest.raises(SessionIncompleteError, match="server/discover"):
                asyncio.run(_open_session(server.port, era="modern"))
            assert "initialize" not in _methods(server)

    def test_forced_legacy_against_modern_only_server_is_incomplete(self) -> None:
        with MockMCPServer(protocol_era="modern") as server:
            server.wait_ready()
            with pytest.raises(SessionIncompleteError):
                asyncio.run(_open_session(server.port, era="legacy"))


class TestNoDowngrade:
    def test_modern_server_without_mutual_version_is_not_downgraded(self) -> None:
        """A modern server we cannot speak must be scan-incomplete, not retried via
        initialize (v2.0 §3.2.12: the legacy path is the downgrade path)."""
        with MockMCPServer(protocol_era="dual", modern_supported_versions=["2099-01-01"]) as srv:
            srv.wait_ready()
            with pytest.raises(SessionIncompleteError, match="modern_incompatible"):
                asyncio.run(_open_session(srv.port))
            assert "initialize" not in _methods(srv)

    def test_modern_header_mismatch_error_is_not_downgraded(self) -> None:
        config = ScanConfig(target_host="h", target_port=1)
        transport = create_autospec(Transport, instance=True)
        transport.send = AsyncMock(return_value={
            "jsonrpc": "2.0", "id": 1, "_status_code": 400,
            "error": {"code": -32020, "message": "Header mismatch"},
        })
        session = MCPSession(transport, config)
        with pytest.raises(SessionIncompleteError, match="modern_error"):
            asyncio.run(session.start())
        assert [c.args[0] for c in transport.send.await_args_list] == ["server/discover"]
        assert session.status is SessionStatus.INCOMPLETE


class TestAuthRejectionStillRecognised:
    def test_forced_modern_401_message_matches_runner_auth_keywords(self) -> None:
        """T1 pass_on_auth_reject relies on '401'/'unauthorized' in the message."""
        config = ScanConfig(target_host="h", target_port=1, protocol_era="modern")
        transport = create_autospec(Transport, instance=True)
        transport.send = AsyncMock(return_value={
            "_status_code": 401, "error": {"code": -32001, "message": "Unauthorized"},
        })
        session = MCPSession(transport, config)
        with pytest.raises(SessionIncompleteError) as excinfo:
            asyncio.run(session.start())
        assert _is_auth_rejection(excinfo.value)

    def test_auto_401_on_discover_falls_back_to_legacy_error_path(self) -> None:
        """Undetermined era under auto → legacy handshake reports as before."""
        config = ScanConfig(target_host="h", target_port=1)
        transport = create_autospec(Transport, instance=True)
        transport.send = AsyncMock(return_value={
            "_status_code": 401, "error": {"code": -32001, "message": "Unauthorized"},
        })
        session = MCPSession(transport, config)
        with pytest.raises(SessionIncompleteError, match="Server rejected initialize") as ei:
            asyncio.run(session.start())
        assert _is_auth_rejection(ei.value)
        assert [c.args[0] for c in transport.send.await_args_list] == [
            "server/discover", "initialize",
        ]


# ===========================================================================
# Entry points: era detection, ProbeRunner subprocess, inventory
# ===========================================================================

class TestDetectProtocolEra:
    @pytest.mark.parametrize(("era", "expected"), [("modern", "modern"),
                                                   ("dual", "modern"),
                                                   ("legacy", "legacy")])
    def test_detects_mock_era(self, era: str, expected: str) -> None:
        with MockMCPServer(protocol_era=era) as server:
            server.wait_ready()
            url = f"http://127.0.0.1:{server.port}"
            assert detect_protocol_era(url, _config(server.port)) == expected

    def test_unreachable_target_is_undetermined(self) -> None:
        assert detect_protocol_era("http://127.0.0.1:9", _config(9)) is None


class TestProbeRunnerSubprocessModern:
    def test_catalog_probe_runs_statelessly_in_subprocess(self) -> None:
        """Real multiprocessing path: a T03 catalog probe against a modern-only server
        completes without an initialize ever being sent."""
        threat = CatalogLoader(CATALOG_ROOT).load_file(Path("official/T03-001.json"))
        probe = threat.probes[0]
        with MockMCPServer(protocol_era="modern") as server:
            server.wait_ready()
            config = dataclasses.replace(_config(server.port), probe_timeout_seconds=30.0)
            result = ProbeRunner(config, f"http://127.0.0.1:{server.port}").run_probe(
                probe, threat, variables={"tool_name": "echo"}
            )
            methods = _methods(server)
            tool_calls = [r for r in server.request_log if r.get("method") == "tools/call"]

        assert result.error is None, result.error
        assert "initialize" not in methods
        assert tool_calls, methods
        assert all(META_PROTOCOL_VERSION in r["params"]["_meta"] for r in tool_calls)


class TestInventoryCapture:
    def test_capture_modern_server(self) -> None:
        from cosai_mcp.inventory.snapshot import capture

        with MockMCPServer(protocol_era="modern") as server:
            server.wait_ready()
            inv = capture(f"http://127.0.0.1:{server.port}", allow_private_targets=True)
            methods = _methods(server)
        assert inv.protocol_version == MODERN_PROTOCOL_VERSION
        assert inv.server_name == "mock-mcp-server"
        assert [t.name for t in inv.tools] == ["echo"]
        assert "initialize" not in methods

    def test_capture_legacy_server_unchanged(self) -> None:
        from cosai_mcp.inventory.snapshot import capture

        with MockMCPServer() as server:
            server.wait_ready()
            inv = capture(f"http://127.0.0.1:{server.port}", allow_private_targets=True)
            methods = _methods(server)
        assert inv.protocol_version == "2025-03-26"
        assert methods[0] == "server/discover"
        assert "initialize" in methods


class TestScannerEntryPoint:
    @pytest.mark.parametrize("era", ["modern", "legacy"])
    def test_scanner_completes_against_each_era_and_pins_detection(self, era: str) -> None:
        """Public entry point: Scanner.run → _run_scan → era pin → per-probe
        subprocess sessions. Neither era may surface as a handshake failure, and
        for a legacy server the pin means per-probe sessions skip server/discover."""
        from cosai_mcp import Scanner

        with MockMCPServer(protocol_era=era) as server:
            server.wait_ready()
            result = Scanner(
                f"http://127.0.0.1:{server.port}",
                categories=["T3"],
                engine="prober",
                allow_private_targets=True,
            ).run()
            methods = _methods(server)

        errors = [r.error for r in result.probe_results if r.error]
        assert not any("initialize" in e or "server/discover" in e for e in errors), errors
        assert methods.count("tools/call") >= 1
        if era == "modern":
            assert "initialize" not in methods
        else:
            # detection (1) + tool-discovery session (1 — pinned, so it skips
            # discover) → exactly one server/discover for the whole scan.
            assert methods.count("server/discover") == 1
            assert methods.count("initialize") >= methods.count("tools/list")


class TestProtocolPanelRegressions:
    def test_regression_capture_modern_sends_accept_header(self) -> None:
        from cosai_mcp.inventory.snapshot import capture

        with MockMCPServer(protocol_era="modern") as server:
            server.wait_ready()
            capture(f"http://127.0.0.1:{server.port}", allow_private_targets=True)
            accept = _header(server, "Accept") or ""
        assert "application/json" in accept and "text/event-stream" in accept

    def test_regression_tool_with_invalid_x_mcp_header_annotation_still_dispatchable(
        self,
    ) -> None:
        tools = [{
            "name": "hostile",
            "description": "x",
            "inputSchema": {"type": "object", "properties": {
                "p": {"type": "string", "x-mcp-header": "Bad\r\nX-Injected: 1"},
            }},
        }]
        with MockMCPServer(protocol_era="modern", tools=tools) as server:
            server.wait_ready()

            async def _run() -> Any:
                session, info = await _open_session(server.port)
                resp = await session.tools_call("hostile", {"p": "v"})
                await session.close()
                return info, resp

            info, resp = asyncio.run(_run())
            sent = {k.lower() for k in server._last_request_headers}
        assert [t["name"] for t in info.tool_manifest] == ["hostile"]
        assert "error" not in resp, resp
        assert not any(h.startswith("mcp-param-") or h == "x-injected" for h in sent)


# ===========================================================================
# Adversary panel regressions (EXPLOIT 1–5)
# ===========================================================================

class TestAdversaryRegressions:
    def test_exploit_header_mismatch_is_inconclusive_not_pass(self) -> None:
        """A -32020 envelope rejection must never satisfy `response.error == true`."""
        threat = CatalogLoader(CATALOG_ROOT).load_file(Path("official/T03-001.json"))
        probe = threat.probes[0]
        mismatch = {"jsonrpc": "2.0", "id": 0,
                    "error": {"code": -32020, "message": "Header mismatch: Mcp-Param-X"}}
        with MockMCPServer(protocol_era="modern", tools_call_response=mismatch) as server:
            server.wait_ready()
            result = ProbeRunner(_config(server.port), f"http://127.0.0.1:{server.port}") \
                .run_probe(probe, threat, variables={"tool_name": "echo"})
        assert result.passed is False
        assert result.inconclusive_reason and "-32020" in result.inconclusive_reason

    @pytest.mark.parametrize("code", [-32020, -32021, -32022])
    def test_exploit_modern_envelope_codes_are_protocol_validation(self, code: int) -> None:
        from cosai_mcp.harness.context import _PROTOCOL_VALIDATION_CODES, _REQUEST_LEVEL_CODES
        assert code in _PROTOCOL_VALIDATION_CODES
        assert code not in _REQUEST_LEVEL_CODES

    def test_exploit_nullable_primitive_annotation_is_mirrored(self) -> None:
        schema = {"properties": {"r": {"type": ["string", "null"], "x-mcp-header": "R"}}}
        assert x_mcp_param_headers(schema, {"r": "eu"}) == {"Mcp-Param-R": "eu"}

    def test_exploit_probe_meta_version_reaches_header(self) -> None:
        with MockMCPServer(protocol_era="modern") as server:
            server.wait_ready()

            async def _run() -> dict[str, Any]:
                session, _ = await _open_session(server.port)
                resp = await session.send_raw("tools/list", {
                    "_meta": {META_PROTOCOL_VERSION: "2099-01-01"},
                })
                await session.close()
                return resp

            resp = asyncio.run(_run())
            assert _header(server, "MCP-Protocol-Version") == "2099-01-01"
        assert resp["error"]["code"] == -32022  # version evaluated, not a header mismatch

    def test_exploit_initialize_probe_uses_legacy_framing_in_modern_session(self) -> None:
        with MockMCPServer(protocol_era="dual") as server:
            server.wait_ready()

            async def _run() -> tuple[dict[str, Any], dict[str, Any]]:
                session, _ = await _open_session(server.port)
                init = await session.send_raw("initialize", {
                    "protocolVersion": "2025-03-26", "clientInfo": {"name": "p"},
                    "capabilities": {},
                })
                after = await session.tools_call("echo", {})
                await session.close()
                return init, after

            init, after = asyncio.run(_run())
            init_req = next(r for r in server.request_log if r["method"] == "initialize")
        assert "_meta" not in init_req["params"]
        assert init["result"]["protocolVersion"] == "2025-03-26"
        assert "error" not in after  # modern framing restored afterwards

    def test_exploit_dual_era_legacy_path_unauth_is_reported(self) -> None:
        """Dual-era server gating only its modern path: the authenticated scan pins
        modern, but unauthenticated T1 probes must still reach the open legacy
        initialize and FAIL (pre-v2 scanner caught this; must not regress)."""
        from cosai_mcp import Scanner

        with MockMCPServer(protocol_era="dual", modern_requires_auth=True) as server:
            server.wait_ready()
            result = Scanner(
                f"http://127.0.0.1:{server.port}",
                categories=["T1"], engine="prober", allow_private_targets=True,
                auth_token="tok",
            ).run()
        t01_001 = [r for r in result.probe_results if r.threat_id == "T01-001"]
        assert t01_001 and all(r.passed is False and not r.inconclusive_reason
                               for r in t01_001), t01_001

    def test_exploit_modern_only_auth_enforced_t1_still_passes(self) -> None:
        """Counterpart: modern-only server enforcing auth → T1-001 PASS, not error."""
        from cosai_mcp import Scanner

        with MockMCPServer(protocol_era="modern", modern_requires_auth=True) as server:
            server.wait_ready()
            result = Scanner(
                f"http://127.0.0.1:{server.port}",
                categories=["T1"], engine="prober", allow_private_targets=True,
                auth_token="tok",
            ).run()
        t01_001 = [r for r in result.probe_results if r.threat_id == "T01-001"]
        assert t01_001 and all(r.passed is True for r in t01_001), t01_001

    def test_exploit_inventory_sse_modern_server_no_downgrade(self) -> None:
        from cosai_mcp.inventory.snapshot import capture

        with MockMCPServer(protocol_era="modern", sse_responses=True) as server:
            server.wait_ready()
            inv = capture(f"http://127.0.0.1:{server.port}", allow_private_targets=True)
            methods = _methods(server)
        assert inv.protocol_version == MODERN_PROTOCOL_VERSION
        assert "initialize" not in methods

    def test_exploit_inventory_modern_goes_through_pinned_transport(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from cosai_mcp.inventory import snapshot
        from cosai_mcp.transport import streamable_http

        pinned: list[str] = []
        real = streamable_http._PinnedAsyncTransport.__init__

        def _spy(self: Any, pinned_ip: str, *a: Any, **kw: Any) -> None:
            pinned.append(pinned_ip)
            real(self, pinned_ip, *a, **kw)

        monkeypatch.setattr(streamable_http._PinnedAsyncTransport, "__init__", _spy)
        with MockMCPServer(protocol_era="modern") as server:
            server.wait_ready()
            snapshot.capture(f"http://127.0.0.1:{server.port}", allow_private_targets=True)
        assert pinned == ["127.0.0.1"]

    def test_exploit_detect_era_drip_feed_bounded(self) -> None:
        import socket
        import threading
        import time

        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        stop = threading.Event()

        def _drip() -> None:
            conn, _ = srv.accept()
            conn.recv(65536)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                         b"Content-Length: 100000\r\n\r\n{")
            while not stop.is_set():
                try:
                    conn.sendall(b" ")
                except OSError:
                    break
                time.sleep(0.2)
            conn.close()

        t = threading.Thread(target=_drip, daemon=True)
        t.start()
        config = dataclasses.replace(_config(port), probe_timeout_seconds=1.0)
        started = time.monotonic()
        try:
            assert detect_protocol_era(f"http://127.0.0.1:{port}", config) is None
        finally:
            stop.set()
            srv.close()
        assert time.monotonic() - started < 5.0


def test_regression_fleet_mode_rejects_protocol_era(tmp_path: Path) -> None:
    from click.testing import CliRunner

    from cosai_mcp.cli import main

    targets = tmp_path / "fleet.txt"
    targets.write_text("http://127.0.0.1:9\n")
    result = CliRunner().invoke(
        main, ["scan", "--targets", str(targets), "--protocol-era", "legacy"]
    )
    assert result.exit_code == 2
    assert "--protocol-era" in result.output


def test_regression_protocol_era_flag_reaches_run_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from click.testing import CliRunner

    import cosai_mcp.cli as cli

    seen: dict[str, Any] = {}

    def _fake_run_scan(**kwargs: Any) -> Any:
        seen.update(kwargs)
        raise ValueError("stop after capture")

    monkeypatch.setattr(cli, "_run_scan", _fake_run_scan)
    monkeypatch.setattr(cli, "check_reachable", lambda *a, **k: None, raising=False)
    CliRunner().invoke(cli.main, ["scan", "http://127.0.0.1:9", "--allow-private-targets",
                                  "--protocol-era", "legacy"])
    assert seen.get("protocol_era") == "legacy"


class TestAdversaryRound2Regressions:
    def test_exploit_discover_only_auth_gate_not_pass(self) -> None:
        from cosai_mcp import Scanner

        with MockMCPServer(protocol_era="modern", modern_auth_only_on_discover=True) as server:
            server.wait_ready()
            result = Scanner(
                f"http://127.0.0.1:{server.port}",
                categories=["T1"], engine="prober", allow_private_targets=True,
                auth_token="tok",
            ).run()
            unauth_calls = [r for r in server.request_log if r.get("method") == "tools/call"]
        t01_001 = [r for r in result.probe_results if r.threat_id == "T01-001"]
        assert unauth_calls
        assert t01_001 and all(r.passed is False for r in t01_001), t01_001

    @pytest.mark.parametrize("era", ["legacy", "modern"])
    def test_exploit_capture_callable_from_running_loop(self, era: str) -> None:
        from cosai_mcp.inventory.snapshot import capture

        with MockMCPServer(protocol_era=era) as server:
            server.wait_ready()

            async def _inside_loop() -> Any:
                return capture(f"http://127.0.0.1:{server.port}", allow_private_targets=True)

            inv = asyncio.run(_inside_loop())
        assert [t.name for t in inv.tools] == ["echo"]

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"protocol_era": "modern", "sse_responses": True},
            {"discover_http_status": 503},                       # forced fallback
            {"discover_http_status": 503, "sse_responses": True},  # + SSE legacy reply
        ],
    )
    def test_exploit_inventory_rebinding_and_sse_no_downgrade(
        self, monkeypatch: pytest.MonkeyPatch, kwargs: dict[str, Any],
    ) -> None:
        import httpx

        from cosai_mcp.inventory.snapshot import capture
        from cosai_mcp.transport import streamable_http

        pinned: list[str] = []
        real = streamable_http._PinnedAsyncTransport.__init__

        def _spy(self: Any, pinned_ip: str, *a: Any, **kw: Any) -> None:
            pinned.append(pinned_ip)
            real(self, pinned_ip, *a, **kw)

        def _no_raw_client(*a: Any, **kw: Any) -> None:
            raise AssertionError("unpinned httpx.Client constructed")

        monkeypatch.setattr(streamable_http._PinnedAsyncTransport, "__init__", _spy)
        monkeypatch.setattr(httpx, "Client", _no_raw_client)
        with MockMCPServer(**kwargs) as server:
            server.wait_ready()
            inv = capture(f"http://127.0.0.1:{server.port}", allow_private_targets=True)
            methods = _methods(server)
        assert pinned == ["127.0.0.1"]
        assert [t.name for t in inv.tools] == ["echo"]
        if kwargs.get("protocol_era") == "modern":
            assert "initialize" not in methods


class TestAdversaryRound3Regressions:
    @staticmethod
    def _t01_001(**mock_kwargs: Any) -> tuple[list[Any], list[dict[str, Any]]]:
        from cosai_mcp import Scanner

        with MockMCPServer(**mock_kwargs) as server:
            server.wait_ready()
            result = Scanner(
                f"http://127.0.0.1:{server.port}",
                categories=["T1"], engine="prober", allow_private_targets=True,
                auth_token="tok", probe_timeout_seconds=5.0,
            ).run()
            log = server.request_log
        return [r for r in result.probe_results if r.threat_id == "T01-001"], log

    def test_exploit_discover_401_unverifiable_call_not_pass(self) -> None:
        results, _ = self._t01_001(
            modern_auth_only_on_discover=True, initialize_http_status=500,
            drop_tools_call=True,
        )
        assert results and all(r.passed is not True for r in results), results

    def test_exploit_legacy_framed_unauth_call_not_pass(self) -> None:
        results, log = self._t01_001(
            reject_modern_framing_unauth=True, initialize_requires_auth=True,
        )
        assert results and all(r.passed is False for r in results), results
        legacy_calls = [r for r in log if r.get("method") == "tools/call"
                        and "_meta" not in (r.get("params") or {})]
        assert legacy_calls

    def test_regression_legacy_server_rejecting_all_unauth_still_passes(self) -> None:
        """Legacy server enforcing auth everywhere keeps its pre-v2 T1 PASS."""
        results, _ = self._t01_001(
            reject_modern_framing_unauth=True, initialize_requires_auth=True,
            modern_auth_only_on_discover=True,
            scope_guarded_tools={"echo": "admin"},
        )
        assert results and all(r.passed is True for r in results), results

    def test_exploit_modern_200_auth_error_legacy_served_not_pass(self) -> None:
        results, log = self._t01_001(
            modern_framing_unauth_jsonrpc_error=True,
            modern_auth_only_on_discover=True,
            initialize_requires_auth=True,
        )
        assert results and all(r.passed is False for r in results), results
        assert any(r.get("method") == "tools/call" and "_meta" not in (r.get("params") or {})
                   for r in log)
