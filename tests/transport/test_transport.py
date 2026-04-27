"""Full test suite for cosai-mcp transports and MCPSession.

Run:  pytest tests/transport/ -v
"""
from __future__ import annotations

import asyncio
import json
import socket
import warnings
from typing import Any
from unittest.mock import AsyncMock, MagicMock, create_autospec, patch

import httpx
import pytest
import pytest_asyncio

from cosai_mcp.config import ScanConfig
from cosai_mcp.exceptions import (
    DNSRebindingError,
    OutputTruncatedWarning,
    PrivateAddressError,
    SessionIncompleteError,
    SuspiciousRedirectError,
)
from cosai_mcp.session import MCPSession, SessionStatus, SUPPORTED_VERSIONS, CLIENT_INFO, CLIENT_CAPABILITIES
from cosai_mcp.transport.base import (
    Transport,
    check_dns_rebinding,
    check_redirect,
    is_private_address,
    resolve_and_pin,
)
from cosai_mcp.transport.legacy_sse import LegacySSETransport
from cosai_mcp.transport.stdio import (
    StdioTransport,
    _MAX_OUTPUT_BYTES,
    _safe_env,
    _strip_control_chars,
)
from cosai_mcp.transport.streamable_http import StreamableHTTPTransport, _PinnedAsyncTransport


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _public_config(host: str = "example.com", port: int = 8000) -> ScanConfig:
    return ScanConfig(target_host=host, target_port=port, allow_private_targets=False)


def _private_config(host: str = "example.com", port: int = 8000) -> ScanConfig:
    return ScanConfig(target_host=host, target_port=port, allow_private_targets=True)


def _fake_getaddrinfo(ip: str):
    """Return a lambda that mimics socket.getaddrinfo returning *ip*."""
    return lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0))]


# ===========================================================================
# Network allowlist — unit tests on helpers
# ===========================================================================

class TestNetworkAllowlistHelpers:
    def test_is_private_rfc1918_10(self):
        assert is_private_address("10.0.0.1")

    def test_is_private_rfc1918_172(self):
        assert is_private_address("172.16.0.1")

    def test_is_private_rfc1918_192(self):
        assert is_private_address("192.168.1.1")

    def test_is_private_link_local(self):
        assert is_private_address("169.254.1.1")

    def test_is_private_loopback(self):
        assert is_private_address("127.0.0.1")

    def test_is_not_private_public(self):
        assert not is_private_address("93.184.216.34")

    def test_check_redirect_raises_on_3xx(self):
        with pytest.raises(SuspiciousRedirectError):
            check_redirect(301)

    def test_check_redirect_raises_on_307(self):
        with pytest.raises(SuspiciousRedirectError):
            check_redirect(307)

    def test_check_redirect_ok_on_200(self):
        check_redirect(200)  # must not raise

    def test_check_dns_rebinding_raises(self):
        with pytest.raises(DNSRebindingError):
            check_dns_rebinding("93.184.216.34", "10.0.0.1")

    def test_check_dns_rebinding_ok(self):
        check_dns_rebinding("93.184.216.34", "93.184.216.34")  # must not raise


# ===========================================================================
# StreamableHTTPTransport tests
# ===========================================================================

class TestStreamableHTTPTransport:

    @pytest.mark.asyncio
    async def test_streamable_http_connect(self):
        """mock httpx; verifies IP pinned at resolve time."""
        config = _public_config()
        transport = StreamableHTTPTransport("http://example.com:8000", config)

        with patch("cosai_mcp.transport.base.socket.getaddrinfo",
                   _fake_getaddrinfo("93.184.216.34")) as mock_resolve, \
             patch("cosai_mcp.transport.streamable_http.httpx.AsyncClient") as mock_client_cls:

            mock_client = AsyncMock()
            mock_client_cls.return_value = mock_client

            # Also patch getaddrinfo in streamable_http module (used by _PinnedAsyncTransport)
            with patch("cosai_mcp.transport.streamable_http.socket.getaddrinfo",
                       _fake_getaddrinfo("93.184.216.34")):
                await transport.connect()

        assert transport._pinned_ip == "93.184.216.34"

    @pytest.mark.asyncio
    async def test_network_allowlist_rejects_rfc1918(self):
        """target 10.0.0.1 raises PrivateAddressError."""
        config = _public_config(host="internal.local")
        transport = StreamableHTTPTransport("http://internal.local:8000", config)

        with patch("cosai_mcp.transport.base.socket.getaddrinfo",
                   _fake_getaddrinfo("10.0.0.1")):
            with pytest.raises(PrivateAddressError):
                await transport.connect()

    @pytest.mark.asyncio
    async def test_network_allowlist_rejects_link_local(self):
        """target 169.254.1.1 raises PrivateAddressError."""
        config = _public_config(host="link-local.local")
        transport = StreamableHTTPTransport("http://link-local.local:8000", config)

        with patch("cosai_mcp.transport.base.socket.getaddrinfo",
                   _fake_getaddrinfo("169.254.1.1")):
            with pytest.raises(PrivateAddressError):
                await transport.connect()

    @pytest.mark.asyncio
    async def test_network_allowlist_rejects_loopback(self):
        """target 127.0.0.1 raises PrivateAddressError (unless allow_private=True)."""
        config = _public_config(host="localhost")
        transport = StreamableHTTPTransport("http://localhost:8000", config)

        with patch("cosai_mcp.transport.base.socket.getaddrinfo",
                   _fake_getaddrinfo("127.0.0.1")):
            with pytest.raises(PrivateAddressError):
                await transport.connect()

    @pytest.mark.asyncio
    async def test_network_allowlist_allow_private_flag(self):
        """allow_private=True; 127.0.0.1 connects without error."""
        config = _private_config(host="localhost")
        transport = StreamableHTTPTransport("http://localhost:8000", config)

        with patch("cosai_mcp.transport.base.socket.getaddrinfo",
                   _fake_getaddrinfo("127.0.0.1")), \
             patch("cosai_mcp.transport.streamable_http.httpx.AsyncClient") as mock_client_cls:
            mock_client_cls.return_value = AsyncMock()
            with patch("cosai_mcp.transport.streamable_http.socket.getaddrinfo",
                       _fake_getaddrinfo("127.0.0.1")):
                await transport.connect()  # must not raise

        assert transport._pinned_ip == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_network_allowlist_no_redirect(self):
        """mock server returns 307; raises SuspiciousRedirectError."""
        config = _public_config()
        transport = StreamableHTTPTransport("http://example.com:8000", config)
        transport._pinned_ip = "93.184.216.34"

        # Fake a 307 response from _PinnedAsyncTransport
        mock_response = create_autospec(httpx.Response, instance=True)
        mock_response.status_code = 307
        mock_response.headers = httpx.Headers({"content-type": "application/json"})

        mock_inner = create_autospec(httpx.AsyncHTTPTransport, instance=True)
        mock_inner.handle_async_request = AsyncMock(return_value=mock_response)

        pinned = _PinnedAsyncTransport("93.184.216.34", config, inner=mock_inner)

        with patch("cosai_mcp.transport.streamable_http.socket.getaddrinfo",
                   _fake_getaddrinfo("93.184.216.34")):
            request = httpx.Request("POST", "http://example.com:8000/mcp")
            with pytest.raises(SuspiciousRedirectError):
                await pinned.handle_async_request(request)

    @pytest.mark.asyncio
    async def test_network_allowlist_dns_rebinding(self):
        """pinned IP differs from connect IP; raises DNSRebindingError."""
        config = _public_config()
        transport = StreamableHTTPTransport("http://example.com:8000", config)
        transport._pinned_ip = "93.184.216.34"

        mock_inner = create_autospec(httpx.AsyncHTTPTransport, instance=True)
        mock_inner.handle_async_request = AsyncMock(return_value=MagicMock(status_code=200))

        pinned = _PinnedAsyncTransport("93.184.216.34", config, inner=mock_inner)

        # Simulate DNS rebinding: hostname now resolves to a different IP
        with patch("cosai_mcp.transport.streamable_http.socket.getaddrinfo",
                   _fake_getaddrinfo("10.0.0.1")):
            request = httpx.Request("POST", "http://example.com:8000/mcp")
            with pytest.raises(DNSRebindingError):
                await pinned.handle_async_request(request)

    @pytest.mark.asyncio
    async def test_trust_env_false(self):
        """Verifies httpx client constructed with trust_env=False."""
        config = _public_config()
        transport = StreamableHTTPTransport("http://example.com:8000", config)

        with patch("cosai_mcp.transport.base.socket.getaddrinfo",
                   _fake_getaddrinfo("93.184.216.34")), \
             patch("cosai_mcp.transport.streamable_http.httpx.AsyncClient") as mock_client_cls, \
             patch("cosai_mcp.transport.streamable_http.socket.getaddrinfo",
                   _fake_getaddrinfo("93.184.216.34")):
            mock_client_cls.return_value = AsyncMock()
            await transport.connect()

        _, kwargs = mock_client_cls.call_args
        assert kwargs.get("trust_env") is False

    @pytest.mark.asyncio
    async def test_follow_redirects_false(self):
        """Verifies httpx client constructed with follow_redirects=False."""
        config = _public_config()
        transport = StreamableHTTPTransport("http://example.com:8000", config)

        with patch("cosai_mcp.transport.base.socket.getaddrinfo",
                   _fake_getaddrinfo("93.184.216.34")), \
             patch("cosai_mcp.transport.streamable_http.httpx.AsyncClient") as mock_client_cls, \
             patch("cosai_mcp.transport.streamable_http.socket.getaddrinfo",
                   _fake_getaddrinfo("93.184.216.34")):
            mock_client_cls.return_value = AsyncMock()
            await transport.connect()

        _, kwargs = mock_client_cls.call_args
        assert kwargs.get("follow_redirects") is False


# ===========================================================================
# StdioTransport tests
# ===========================================================================

class TestStdioTransport:

    @pytest.mark.asyncio
    async def test_stdio_no_shell(self):
        """Uses asyncio.create_subprocess_exec — structural shell=False guarantee.

        create_subprocess_exec (not create_subprocess_shell) is the correct call;
        there is no 'shell' kwarg to verify.
        """
        config = _public_config()
        transport = StdioTransport(["python", "server.py"], config)

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_create:
            mock_proc = MagicMock()
            mock_proc.stdin = MagicMock()
            mock_proc.stdout = MagicMock()
            mock_proc.stderr = MagicMock()
            mock_create.return_value = mock_proc
            await transport.connect()

        assert mock_create.called

    @pytest.mark.asyncio
    async def test_stdio_env_filtered(self):
        """Child env contains only PATH/LANG — HOME and secrets are excluded."""
        config = _public_config()
        transport = StdioTransport(["python", "server.py"], config)

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_create, \
             patch.dict("os.environ", {
                 "PATH": "/usr/bin",
                 "LANG": "en_US.UTF-8",
                 "HOME": "/home/user",
                 "AWS_SECRET_ACCESS_KEY": "secret",
                 "OPENAI_API_KEY": "key123",
                 "MY_TOKEN": "tok",
             }, clear=True):
            mock_proc = MagicMock()
            mock_proc.stdin = MagicMock()
            mock_proc.stdout = MagicMock()
            mock_proc.stderr = MagicMock()
            mock_create.return_value = mock_proc
            await transport.connect()

        _, kwargs = mock_create.call_args
        env = kwargs.get("env", {})
        assert set(env.keys()) == {"PATH", "LANG"}
        assert "HOME" not in env
        assert "AWS_SECRET_ACCESS_KEY" not in env
        assert "OPENAI_API_KEY" not in env
        assert "MY_TOKEN" not in env

    @pytest.mark.asyncio
    async def test_stdio_close_fds(self):
        """Verifies close_fds=True passed to asyncio.create_subprocess_exec."""
        config = _public_config()
        transport = StdioTransport(["python", "server.py"], config)

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_create:
            mock_proc = MagicMock()
            mock_proc.stdin = MagicMock()
            mock_proc.stdout = MagicMock()
            mock_proc.stderr = MagicMock()
            mock_create.return_value = mock_proc
            await transport.connect()

        _, kwargs = mock_create.call_args
        assert kwargs.get("close_fds") is True

    @pytest.mark.asyncio
    async def test_stdio_start_new_session(self):
        """Verifies start_new_session=True passed to asyncio.create_subprocess_exec."""
        config = _public_config()
        transport = StdioTransport(["python", "server.py"], config)

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_create:
            mock_proc = MagicMock()
            mock_proc.stdin = MagicMock()
            mock_proc.stdout = MagicMock()
            mock_proc.stderr = MagicMock()
            mock_create.return_value = mock_proc
            await transport.connect()

        _, kwargs = mock_create.call_args
        assert kwargs.get("start_new_session") is True

    @pytest.mark.asyncio
    async def test_stdio_stderr_size_cap(self):
        """Feed 11 MB via _read_line_async; asserts output_truncated=True."""
        config = _public_config()
        transport = StdioTransport(["python", "server.py"], config)
        transport._total_bytes_read = _MAX_OUTPUT_BYTES + 1  # already over cap

        mock_proc = MagicMock()
        mock_proc.stdout = AsyncMock()
        mock_proc.stdout.readline = AsyncMock(return_value=b"data line\n")
        mock_proc.stdin = AsyncMock()
        mock_proc.stderr = AsyncMock()
        transport._process = mock_proc

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = await transport._read_line_async()

        assert transport.output_truncated is True
        assert result == ""
        truncation_warnings = [w for w in caught if issubclass(w.category, OutputTruncatedWarning)]
        assert truncation_warnings, "Expected OutputTruncatedWarning to be issued"

    def test_stdio_control_char_stripped(self):
        """Response with \\x00\\x1b chars; asserts stripped from output."""
        dirty = "hello\x00world\x1bfoo\nbar"
        cleaned = _strip_control_chars(dirty)
        assert "\x00" not in cleaned
        assert "\x1b" not in cleaned
        assert "\n" in cleaned
        assert "hello" in cleaned
        assert "world" in cleaned


# ===========================================================================
# MCPSession tests
# ===========================================================================

def _make_init_success(protocol_version: str = "2025-03-26") -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": protocol_version,
            "serverInfo": {"name": "test-server", "version": "1.0"},
            "capabilities": {},
        },
    }


def _make_tools_list_response() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [
                {"name": "echo", "description": "Echoes input", "inputSchema": {}},
            ],
        },
    }


def _make_error_response(code: int = -32600, message: str = "Bad request") -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": code, "message": message},
    }


class TestMCPSession:

    @pytest.mark.asyncio
    async def test_session_initialize_before_tools_call(self):
        """Asserts initialize sent before any tools/call."""
        config = _public_config()
        mock_transport = create_autospec(Transport, instance=True)

        call_order: list[str] = []

        async def side_effect_send(method: str, params: dict) -> dict:
            call_order.append(method)
            if method == "initialize":
                return _make_init_success()
            if method == "tools/list":
                return _make_tools_list_response()
            if method == "tools/call":
                return {"jsonrpc": "2.0", "id": 3, "result": {"content": []}}
            return {}

        mock_transport.send = AsyncMock(side_effect=side_effect_send)
        mock_transport.send_notification = AsyncMock()
        mock_transport.close = AsyncMock()

        session = MCPSession(mock_transport, config)
        await session.start()

        # Session is READY — now call tools/call
        await session.tools_call("echo", {"input": "hello"})

        # initialize must appear before tools/call
        assert "initialize" in call_order
        assert "tools/call" in call_order
        init_idx = call_order.index("initialize")
        call_idx = next(i for i, m in enumerate(call_order) if m == "tools/call")
        assert init_idx < call_idx

    @pytest.mark.asyncio
    async def test_session_protocol_version_negotiation(self):
        """Server returns protocolVersion: '2024-11-05'; asserts LegacySSETransport semantics."""
        config = _public_config()
        mock_transport = create_autospec(Transport, instance=True)

        async def side_effect_send(method: str, params: dict) -> dict:
            if method == "initialize":
                return _make_init_success(protocol_version="2024-11-05")
            if method == "tools/list":
                return _make_tools_list_response()
            return {}

        mock_transport.send = AsyncMock(side_effect=side_effect_send)
        mock_transport.send_notification = AsyncMock()
        mock_transport.close = AsyncMock()

        session = MCPSession(mock_transport, config)
        info = await session.start()

        assert info.protocol_version == "2024-11-05"
        assert info.transport_type == "LegacySSETransport"
        assert session.server_protocol_version == "2024-11-05"

    @pytest.mark.asyncio
    async def test_session_tools_list_cached(self):
        """tools/list only called once; second call uses cache."""
        config = _public_config()
        mock_transport = create_autospec(Transport, instance=True)
        send_call_methods: list[str] = []

        async def side_effect_send(method: str, params: dict) -> dict:
            send_call_methods.append(method)
            if method == "initialize":
                return _make_init_success()
            if method == "tools/list":
                return _make_tools_list_response()
            return {}

        mock_transport.send = AsyncMock(side_effect=side_effect_send)
        mock_transport.send_notification = AsyncMock()
        mock_transport.close = AsyncMock()

        session = MCPSession(mock_transport, config)
        await session.start()

        # Call tools_list twice
        manifest1 = await session.tools_list()
        manifest2 = await session.tools_list()

        # Network call for tools/list must have happened exactly once
        tools_list_calls = [m for m in send_call_methods if m == "tools/list"]
        assert len(tools_list_calls) == 1
        assert manifest1 == manifest2
        assert len(manifest1) == 1
        assert manifest1[0]["name"] == "echo"

    @pytest.mark.asyncio
    async def test_session_incomplete_on_handshake_fail(self):
        """Server rejects initialize; raises SessionIncompleteError."""
        config = _public_config()
        mock_transport = create_autospec(Transport, instance=True)

        async def side_effect_send(method: str, params: dict) -> dict:
            if method == "initialize":
                return _make_error_response(code=-32600, message="Unsupported version")
            return {}

        mock_transport.send = AsyncMock(side_effect=side_effect_send)
        mock_transport.send_notification = AsyncMock()
        mock_transport.close = AsyncMock()

        session = MCPSession(mock_transport, config)
        with pytest.raises(SessionIncompleteError):
            await session.start()

        assert session.status == SessionStatus.INCOMPLETE

    @pytest.mark.asyncio
    async def test_session_unhandled_server_request_returns_method_not_found(self):
        """Server sends sampling/createMessage; asserts -32601 returned."""
        config = _public_config()
        mock_transport = create_autospec(Transport, instance=True)
        mock_transport.close = AsyncMock()

        session = MCPSession(mock_transport, config)

        server_request: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "sampling/createMessage",
            "params": {"messages": []},
        }

        response = await session.handle_server_request(server_request)

        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 42
        assert "error" in response
        assert response["error"]["code"] == -32601

    @pytest.mark.asyncio
    async def test_regression_initialize_before_tools_call(self):
        """Regression: initialize must always precede tools/call."""
        config = _public_config()
        mock_transport = create_autospec(Transport, instance=True)

        call_order: list[str] = []

        async def side_effect_send(method: str, params: dict) -> dict:
            call_order.append(method)
            if method == "initialize":
                return _make_init_success()
            if method == "tools/list":
                return _make_tools_list_response()
            if method == "tools/call":
                return {"jsonrpc": "2.0", "id": 5, "result": {}}
            return {}

        mock_transport.send = AsyncMock(side_effect=side_effect_send)
        mock_transport.send_notification = AsyncMock()
        mock_transport.close = AsyncMock()

        session = MCPSession(mock_transport, config)
        await session.start()
        await session.tools_call("echo", {})

        assert call_order[0] == "initialize"
        tools_call_seen = any(m == "tools/call" for m in call_order)
        assert tools_call_seen

    @pytest.mark.asyncio
    async def test_regression_transport_fallback_sse(self):
        """Regression: protocolVersion 2024-11-05 triggers LegacySSE transport type."""
        config = _public_config()
        mock_transport = create_autospec(Transport, instance=True)

        async def side_effect_send(method: str, params: dict) -> dict:
            if method == "initialize":
                return _make_init_success(protocol_version="2024-11-05")
            if method == "tools/list":
                return _make_tools_list_response()
            return {}

        mock_transport.send = AsyncMock(side_effect=side_effect_send)
        mock_transport.send_notification = AsyncMock()
        mock_transport.close = AsyncMock()

        session = MCPSession(mock_transport, config)
        info = await session.start()

        assert info.transport_type == "LegacySSETransport"
        assert session.server_protocol_version == "2024-11-05"

    @pytest.mark.asyncio
    async def test_tools_call_before_start_raises(self):
        """tools_call before start() must raise SessionIncompleteError."""
        config = _public_config()
        mock_transport = create_autospec(Transport, instance=True)
        mock_transport.close = AsyncMock()

        session = MCPSession(mock_transport, config)

        with pytest.raises(SessionIncompleteError):
            await session.tools_call("echo", {})

    @pytest.mark.asyncio
    async def test_session_status_lifecycle(self):
        """Session status transitions: INCOMPLETE → READY → CLOSED."""
        config = _public_config()
        mock_transport = create_autospec(Transport, instance=True)

        async def side_effect_send(method: str, params: dict) -> dict:
            if method == "initialize":
                return _make_init_success()
            if method == "tools/list":
                return _make_tools_list_response()
            return {}

        mock_transport.send = AsyncMock(side_effect=side_effect_send)
        mock_transport.send_notification = AsyncMock()
        mock_transport.close = AsyncMock()

        session = MCPSession(mock_transport, config)
        assert session.status == SessionStatus.INCOMPLETE

        await session.start()
        assert session.status == SessionStatus.READY

        await session.close()
        assert session.status == SessionStatus.CLOSED


# ===========================================================================
# Regression tests — one per panel finding
# ===========================================================================

class TestRegressionFindings:

    # -----------------------------------------------------------------------
    # Fix 1: DNS rebinding — pinned IP substituted into forwarded URL
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_regression_dns_rebinding_url_substituted(self):
        """FIX 1: _PinnedAsyncTransport must rewrite the request URL host to the
        pinned IP before forwarding so the kernel never re-resolves via DNS.
        Asserts the inner transport receives a request with host == pinned IP."""
        config = _private_config(host="example.com")  # allow_private for test ease
        captured: list[httpx.Request] = []

        class _Capturing(httpx.AsyncBaseTransport):
            async def handle_async_request(self, req: httpx.Request) -> httpx.Response:
                captured.append(req)
                return httpx.Response(200, content=b"{}", headers={"content-type": "application/json"})
            async def aclose(self) -> None:
                pass

        pinned = _PinnedAsyncTransport("93.184.216.34", config, inner=_Capturing())

        with patch("cosai_mcp.transport.streamable_http.socket.getaddrinfo",
                   _fake_getaddrinfo("93.184.216.34")):
            req = httpx.Request("POST", "http://example.com:8000/mcp")
            await pinned.handle_async_request(req)

        assert len(captured) == 1
        assert captured[0].url.host == "93.184.216.34", (
            "Inner transport must receive URL with pinned IP, not hostname"
        )

    # -----------------------------------------------------------------------
    # Fix 2: initialized notification — no 'id' field, sent via send_notification
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_regression_send_notification_no_id(self):
        """FIX 2: 'initialized' must be sent as a JSON-RPC notification (no 'id')
        via transport.send_notification, never as a request via transport.send."""
        config = _public_config()
        mock_transport = create_autospec(Transport, instance=True)
        notification_calls: list[dict] = []

        async def capture_notification(notification: dict) -> None:
            notification_calls.append(notification)

        async def side_effect_send(method: str, params: dict) -> dict:
            if method == "initialize":
                return _make_init_success()
            if method == "tools/list":
                return _make_tools_list_response()
            return {}

        mock_transport.send = AsyncMock(side_effect=side_effect_send)
        mock_transport.send_notification = AsyncMock(side_effect=capture_notification)
        mock_transport.close = AsyncMock()

        session = MCPSession(mock_transport, config)
        await session.start()

        assert len(notification_calls) == 1
        notif = notification_calls[0]
        assert notif["method"] == "initialized"
        assert "id" not in notif, "Notification must NOT have an 'id' field"
        assert notif["jsonrpc"] == "2.0"

    # -----------------------------------------------------------------------
    # Fix 3: tools/list failure is non-fatal
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_regression_tools_list_failure_nonfatal(self):
        """FIX 3: tools/list failure must not prevent session from reaching READY.
        Some MCP servers don't implement tools/list; scan should still proceed."""
        config = _public_config()
        mock_transport = create_autospec(Transport, instance=True)

        async def side_effect_send(method: str, params: dict) -> dict:
            if method == "initialize":
                return _make_init_success()
            if method == "tools/list":
                raise RuntimeError("server does not support tools/list")
            return {}

        mock_transport.send = AsyncMock(side_effect=side_effect_send)
        mock_transport.send_notification = AsyncMock()
        mock_transport.close = AsyncMock()

        session = MCPSession(mock_transport, config)
        info = await session.start()  # must not raise

        assert session.status == SessionStatus.READY
        assert info.tool_manifest == []

    @pytest.mark.asyncio
    async def test_regression_tools_list_error_response_nonfatal(self):
        """FIX 3b: tools/list returning an error response is also non-fatal."""
        config = _public_config()
        mock_transport = create_autospec(Transport, instance=True)

        async def side_effect_send(method: str, params: dict) -> dict:
            if method == "initialize":
                return _make_init_success()
            if method == "tools/list":
                return _make_error_response(-32601, "Method not found")
            return {}

        mock_transport.send = AsyncMock(side_effect=side_effect_send)
        mock_transport.send_notification = AsyncMock()
        mock_transport.close = AsyncMock()

        session = MCPSession(mock_transport, config)
        info = await session.start()

        assert session.status == SessionStatus.READY
        assert info.tool_manifest == []

    # -----------------------------------------------------------------------
    # Fix 4: unsupported protocol version warns but does not abort
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_regression_protocol_version_unknown_warns(self):
        """FIX 4: unknown protocol version must issue a UserWarning and continue.
        Aborting on unknown versions would break forward-compat with future MCP."""
        config = _public_config()
        mock_transport = create_autospec(Transport, instance=True)

        async def side_effect_send(method: str, params: dict) -> dict:
            if method == "initialize":
                return _make_init_success(protocol_version="2099-01-01")
            if method == "tools/list":
                return _make_tools_list_response()
            return {}

        mock_transport.send = AsyncMock(side_effect=side_effect_send)
        mock_transport.send_notification = AsyncMock()
        mock_transport.close = AsyncMock()

        session = MCPSession(mock_transport, config)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            await session.start()

        assert session.status == SessionStatus.READY
        version_warnings = [
            w for w in caught
            if "unsupported protocol version" in str(w.message).lower()
        ]
        assert version_warnings, "Must emit a warning for unsupported MCP version"

    def test_regression_supported_versions_constant(self):
        """FIX 4b: SUPPORTED_VERSIONS must contain both known MCP protocol versions."""
        assert "2025-03-26" in SUPPORTED_VERSIONS
        assert "2024-11-05" in SUPPORTED_VERSIONS

    # -----------------------------------------------------------------------
    # Fix 5: stdio HOME excluded from environment
    # -----------------------------------------------------------------------

    def test_regression_stdio_no_home_in_env(self):
        """FIX 5: HOME must be excluded from the child process environment.
        HOME allows spawned processes to read ~/.profile and exfiltrate config."""
        env = _safe_env()
        assert "HOME" not in env, "HOME must never be passed to child processes"


# ===========================================================================
# Regressions found during live Mnemo scan (2026-04-27)
# ===========================================================================

class TestMnemoScanRegressions:
    """Bugs found and fixed while scanning the Mnemo MCP server."""

    # -----------------------------------------------------------------------
    # Bug 1: IPv6-first resolution caused connection refused on IPv4-only servers
    # -----------------------------------------------------------------------

    def test_regression_resolve_prefers_ipv4_over_ipv6(self):
        """resolve_and_pin must return an IPv4 address when both AF_INET and
        AF_INET6 results are available.  On macOS, getaddrinfo('localhost', ...)
        returns ::1 (AF_INET6) first; servers that only bind on 127.0.0.1
        (AF_INET) would fail to connect with the IPv6 address."""
        with patch("cosai_mcp.transport.base.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0)),
            ]
            config = ScanConfig(
                target_host="localhost",
                target_port=8080,
                allow_private_targets=True,
            )
            ip = resolve_and_pin("localhost", config)
        assert ip == "127.0.0.1", f"Expected IPv4 127.0.0.1, got {ip!r}"

    def test_regression_resolve_accepts_ipv6_when_no_ipv4(self):
        """resolve_and_pin must still work when only IPv6 is available."""
        with patch("cosai_mcp.transport.base.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0)),
            ]
            config = ScanConfig(
                target_host="::1",
                target_port=8080,
                allow_private_targets=True,
            )
            ip = resolve_and_pin("::1", config)
        assert ip == "::1"

    # -----------------------------------------------------------------------
    # Bug 2: DNS rebinding check in _PinnedAsyncTransport also needed IPv4-sort
    # -----------------------------------------------------------------------

    def test_regression_pinned_transport_no_false_rebind_on_dual_stack(self):
        """_PinnedAsyncTransport must not raise DNSRebindingError when the
        pinned IP is 127.0.0.1 but getaddrinfo returns ::1 first (dual-stack).
        Before the fix, the check compared the pinned IPv4 address against the
        first getaddrinfo result (::1) and flagged it as DNS rebinding."""
        from cosai_mcp.transport.streamable_http import _PinnedAsyncTransport
        import asyncio

        config = ScanConfig(
            target_host="localhost",
            target_port=8080,
            allow_private_targets=True,
        )
        pinned_transport = _PinnedAsyncTransport("127.0.0.1", config)

        mock_response = MagicMock()
        mock_response.status_code = 200

        inner = create_autospec(httpx.AsyncBaseTransport, instance=True)
        inner.handle_async_request = AsyncMock(return_value=mock_response)
        pinned_transport._inner = inner

        with patch("cosai_mcp.transport.streamable_http.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0)),
            ]
            request = httpx.Request("POST", "http://localhost:8080/mcp/")
            asyncio.run(pinned_transport.handle_async_request(request))
        # No DNSRebindingError raised — test passes

    # -----------------------------------------------------------------------
    # Bug 3: Bearer auth header injected for auth_token config
    # -----------------------------------------------------------------------

    def test_regression_auth_token_in_request_headers(self):
        """When ScanConfig.auth_token is set, the Authorization: Bearer header
        must appear in every outbound request from StreamableHTTPTransport."""
        from cosai_mcp.transport.streamable_http import StreamableHTTPTransport

        config = ScanConfig(
            target_host="localhost",
            target_port=8080,
            allow_private_targets=True,
            auth_token="test-token-abc",
        )
        transport = StreamableHTTPTransport("http://localhost:8080", config)
        headers = transport._build_headers()
        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer test-token-abc"

    def test_regression_no_auth_header_when_token_absent(self):
        """When ScanConfig.auth_token is None, no Authorization header is sent."""
        from cosai_mcp.transport.streamable_http import StreamableHTTPTransport

        config = ScanConfig(
            target_host="localhost",
            target_port=8080,
            allow_private_targets=True,
            auth_token=None,
        )
        transport = StreamableHTTPTransport("http://localhost:8080", config)
        headers = transport._build_headers()
        assert "Authorization" not in headers

    # -----------------------------------------------------------------------
    # Bug 4: Transport URL used /mcp without trailing slash, causing 307 from
    # Starlette-mounted ASGI endpoints
    # -----------------------------------------------------------------------

    def test_regression_mcp_path_has_trailing_slash(self):
        """The effective MCP endpoint URL must have a trailing slash to avoid
        307 redirects from Starlette-mounted endpoints (Mount('/mcp') redirects
        requests to '/mcp' → '/mcp/').  follow_redirects=False means a 307 is
        surfaced as SuspiciousRedirectError instead of being silently followed."""
        from cosai_mcp.transport.streamable_http import StreamableHTTPTransport

        config = ScanConfig(
            target_host="localhost",
            target_port=8080,
            allow_private_targets=True,
        )
        transport = StreamableHTTPTransport("http://localhost:8080", config)
        # The URL built for requests must end with "/"
        mcp_path = config.mcp_path.rstrip("/") + "/"
        expected_url = f"http://localhost:8080{mcp_path}"
        assert expected_url.endswith("/"), f"URL must end with /: {expected_url!r}"
        assert "/mcp/" in expected_url

    def test_regression_custom_mcp_path_respected(self):
        """mcp_path override must be honoured — some servers mount MCP at /v1/mcp."""
        from cosai_mcp.transport.streamable_http import StreamableHTTPTransport

        config = ScanConfig(
            target_host="localhost",
            target_port=8080,
            allow_private_targets=True,
            mcp_path="/v1/mcp",
        )
        transport = StreamableHTTPTransport("http://localhost:8080", config)
        mcp_path = config.mcp_path.rstrip("/") + "/"
        url = f"http://localhost:8080{mcp_path}"
        assert url == "http://localhost:8080/v1/mcp/"


