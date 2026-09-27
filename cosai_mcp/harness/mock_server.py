"""In-process mock MCP server for harness integration tests.

Uses a background thread with http.server.HTTPServer to serve JSON-RPC
over HTTP.  The server handles the full MCP handshake (initialize →
initialized → tools/list → tools/call) and supports configurable
response overrides.

Usage::

    with MockMCPServer() as server:
        server.wait_ready()   # barrier: blocks until TCP socket is accepting
        target_url = f"http://127.0.0.1:{server.port}"
        # run probes against target_url ...
"""
from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from cosai_mcp.protocol import (
    ERR_HEADER_MISMATCH,
    ERR_UNSUPPORTED_PROTOCOL_VERSION,
    HEADER_METHOD,
    HEADER_NAME,
    HEADER_PROTOCOL_VERSION,
    META_PROTOCOL_VERSION,
    META_SERVER_INFO,
    MODERN_PROTOCOL_VERSION,
    decode_header_value,
    mcp_name_for,
)

_DEFAULT_TOOLS = [
    {"name": "echo", "description": "Echoes input", "inputSchema": {"type": "object"}},
]


class _MCPHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler implementing the MCP Streamable HTTP transport."""

    # Injected by MockMCPServer
    server: _MockHTTPServer

    def log_message(self, fmt: str, *args: Any) -> None:
        pass  # suppress noisy output in tests

    def do_POST(self) -> None:
        # Finding 14: validate Content-Type before parsing body
        content_type = self.headers.get("Content-Type", "")
        if not content_type.startswith("application/json"):
            self._send_json(
                415,
                {"error": "Unsupported Media Type — expected application/json"},
            )
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON"})
            return

        headers = dict(self.headers)
        response = self.server.mock_server.handle_rpc(request, headers)

        if response.get("_drop"):
            self.close_connection = True
            self.connection.close()
            return

        # Finding 10: notifications (no 'id') → 204 No Content, not 200 + body
        if not response:
            self.send_response(204)
            self.end_headers()
        else:
            status = response.pop("_http_status", 200)
            if self.server.mock_server._sse_responses:
                payload = f"event: message\ndata: {json.dumps(response)}\n\n".encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            else:
                self._send_json(status, response)

    def _send_json(self, status: int, data: dict[str, Any]) -> None:
        payload = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class _MockHTTPServer(HTTPServer):
    """HTTPServer subclass that holds a reference to MockMCPServer."""

    def __init__(self, server_address: tuple[str, int], mock_server: MockMCPServer) -> None:
        self.mock_server = mock_server
        super().__init__(server_address, _MCPHandler)


class MockMCPServer:
    """Configurable in-process MCP mock server for integration testing.

    Parameters
    ----------
    tools:
        Tool list returned by tools/list.  Defaults to a single 'echo' tool.
    tools_call_response:
        Optional override for the tools/call response.  When set, all
        tools/call requests return this dict instead of the default.
    initialize_error:
        If set, initialize returns an error response with this message.
    port:
        Port to listen on (0 = OS-assigned ephemeral port).
    tools_list_sequence:
        If set, successive tools/list calls return items from this list in
        order.  After the sequence is exhausted the last entry repeats.
        Used to simulate tool shadowing mid-session (T6).
    privileged_tools:
        Set of tool names that require the ``X-Privileged: true`` request
        header.  Calls without the header receive a JSON-RPC error response.
        Used to test access-control enforcement (T2).
    scope_guarded_tools:
        Mapping of tool name → required OAuth scope string.  When set, the
        server decodes the Bearer token from the ``Authorization`` header and
        checks that the token's ``scope`` claim contains the required scope.
        Used to test T7-002 and T7-003 (CIBA / MCP confirmation vs OAuth scope).
    confirmation_bypasses_scope:
        If True, a ``confirmation=true`` argument in the tool call bypasses the
        scope check entirely — simulating the vulnerable "confirmation as auth"
        pattern that T07-002 detects.  Default False (secure).
    confirmation_gates_access:
        If True, the server requires ``confirmation=true`` in arguments even
        when the OAuth scope is valid — simulating the inverted authorization
        model that T07-003 detects.  Default False (secure).
    reject_replayed_tokens:
        If True, the server maintains a JTI replay cache (T1).  The first
        ``tools/call`` presenting a given token is served; any *subsequent*
        ``tools/call`` presenting the SAME token (same ``jti`` claim, or the
        whole token string when no ``jti`` is decodable) is rejected with a
        JSON-RPC error.  Calls with no Bearer token are not de-duplicated.
        Default False (vulnerable: a replayed token is accepted every time),
        which is exactly the condition T01-003 must detect.
    call_budget:
        If set, the server enforces a per-session ``tools/call`` budget: the
        first ``call_budget`` calls are answered normally and every call beyond
        it returns a JSON-RPC rate-limit error (-32029).  Once tripped it stays
        tripped (all subsequent calls rejected), modelling a secure server that
        bounds recursive/looping tool chains (T10 denial-of-wallet).  Default
        None = unlimited (vulnerable). ``tools/list`` is never counted, so the
        MCP handshake does not consume the budget.
    protocol_era:
        ``"legacy"`` (default): initialize-handshake server; ``server/discover``
        is an unknown method (-32601).  ``"modern"``: MCP 2026-07-28 stateless
        server — answers ``server/discover``, validates per-request ``_meta``
        and the ``MCP-Protocol-Version`` / ``Mcp-Method`` / ``Mcp-Name`` headers
        against the body (400 + -32020 HeaderMismatch on disagreement), and
        rejects ``initialize``.  ``"dual"``: both — ``_meta``-bearing requests
        are served statelessly, ``initialize`` selects legacy semantics.
    modern_supported_versions:
        ``supportedVersions`` advertised in modern mode (default
        ``["2026-07-28"]``).  Set to e.g. ``["2099-01-01"]`` to simulate a
        modern server with no mutually supported version.
    modern_requires_auth:
        Modern (``_meta``-bearing) requests without an ``Authorization`` header
        get HTTP 401 / -32001, while the legacy path stays open — the v2.0
        dual-era "legacy downgrade" vulnerability.
    sse_responses:
        Frame every JSON-RPC response as a ``text/event-stream`` event.
    modern_auth_only_on_discover:
        Only ``server/discover`` requires ``Authorization`` (401 otherwise);
        every other stateless request is served — a vulnerable modern server
        whose discover gate protects nothing.
    discover_http_status:
        If set, ``server/discover`` always gets this HTTP status with a
        non-modern JSON-RPC error (any era) — e.g. 503 to force the
        undetermined-era fallback.
    reject_modern_framing_unauth:
        Any request carrying modern framing (``MCP-Protocol-Version`` header or
        protocol ``_meta``) without ``Authorization`` gets 401, while
        legacy-framed requests are served — a framing-dependent auth gate.
    initialize_http_status:
        If set, ``initialize`` always fails with this HTTP status (-32603).
    initialize_requires_auth:
        ``initialize`` without ``Authorization`` gets 401 / -32001.
    drop_tools_call:
        ``tools/call`` gets no HTTP response — the connection is closed.
    modern_framing_unauth_jsonrpc_error:
        Like ``reject_modern_framing_unauth`` but the rejection is HTTP 200 with
        a JSON-RPC -32001 error (common real-world shape).
    skip_header_validation:
        VULNERABLE (T07-004): modern requests are served even when
        ``Mcp-Method`` / ``Mcp-Name`` disagree with the body.
    accept_unknown_versions:
        VULNERABLE (T07-005): any ``_meta`` protocolVersion is served instead of
        returning -32022 UnsupportedProtocolVersion.
    advertise_logging:
        ``server/discover`` advertises the deprecated ``logging`` capability.
    """

    def __init__(
        self,
        tools: list[dict[str, Any]] | None = None,
        tools_call_response: dict[str, Any] | None = None,
        initialize_error: str | None = None,
        port: int = 0,
        tools_list_sequence: list[list[dict[str, Any]]] | None = None,
        privileged_tools: set[str] | None = None,
        scope_guarded_tools: dict[str, str] | None = None,
        confirmation_bypasses_scope: bool = False,
        confirmation_gates_access: bool = False,
        reject_replayed_tokens: bool = False,
        call_budget: int | None = None,
        protocol_era: str = "legacy",
        modern_supported_versions: list[str] | None = None,
        modern_requires_auth: bool = False,
        sse_responses: bool = False,
        modern_auth_only_on_discover: bool = False,
        discover_http_status: int | None = None,
        reject_modern_framing_unauth: bool = False,
        initialize_http_status: int | None = None,
        initialize_requires_auth: bool = False,
        drop_tools_call: bool = False,
        modern_framing_unauth_jsonrpc_error: bool = False,
        skip_header_validation: bool = False,
        accept_unknown_versions: bool = False,
        advertise_logging: bool = False,
    ) -> None:
        self._skip_header_validation = skip_header_validation
        self._accept_unknown_versions = accept_unknown_versions
        self._advertise_logging = advertise_logging
        self._modern_framing_unauth_jsonrpc_error = modern_framing_unauth_jsonrpc_error
        self._reject_modern_framing_unauth = reject_modern_framing_unauth
        self._initialize_http_status = initialize_http_status
        self._initialize_requires_auth = initialize_requires_auth
        self._drop_tools_call = drop_tools_call
        self._modern_auth_only_on_discover = modern_auth_only_on_discover
        self._discover_http_status = discover_http_status
        self._modern_requires_auth = modern_requires_auth
        self._sse_responses = sse_responses
        if protocol_era not in ("legacy", "modern", "dual"):
            raise ValueError(f"protocol_era must be legacy|modern|dual, got {protocol_era!r}")
        self._protocol_era = protocol_era
        self._modern_supported = list(modern_supported_versions or [MODERN_PROTOCOL_VERSION])
        self._tools = tools if tools is not None else list(_DEFAULT_TOOLS)
        self._tools_call_response = tools_call_response
        self._initialize_error = initialize_error
        self._server: _MockHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._port: int = port
        self._request_log: list[dict[str, Any]] = []
        self._log_lock = threading.Lock()       # Finding 8: thread-safe log access
        self._ready = threading.Event()          # Finding 9: readiness barrier
        self._tools_list_sequence = tools_list_sequence
        self._tools_list_call_count: int = 0
        self._privileged_tools: set[str] = privileged_tools or set()
        self._scope_guarded_tools: dict[str, str] = scope_guarded_tools or {}
        self._confirmation_bypasses_scope = confirmation_bypasses_scope
        self._confirmation_gates_access = confirmation_gates_access
        self._reject_replayed_tokens = reject_replayed_tokens
        self._seen_token_ids: set[str] = set()  # JTI replay cache (guarded by _log_lock)
        self._call_budget = call_budget
        self._tools_call_count: int = 0
        self._last_request_headers: dict[str, str] = {}

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("MockMCPServer not started — use as context manager")
        return self._server.server_address[1]

    @property
    def request_log(self) -> list[dict[str, Any]]:
        """Returns a snapshot of all JSON-RPC requests received (thread-safe)."""
        with self._log_lock:
            return list(self._request_log)

    def wait_ready(self, timeout: float = 5.0) -> None:
        """Block until the server is ready to accept connections.

        The HTTPServer binds its socket in __init__, so by the time start()
        returns the port is already listening.  This event is set immediately
        after the background thread starts, providing a memory barrier so
        callers see the fully initialised server state.

        Raises
        ------
        RuntimeError
            If the server does not become ready within ``timeout`` seconds.
        """
        if not self._ready.wait(timeout):
            raise RuntimeError(
                f"MockMCPServer did not become ready within {timeout}s"
            )

    def handle_rpc(
        self,
        request: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Process one JSON-RPC request and return a response dict."""
        with self._log_lock:
            self._request_log.append(request)
            if headers is not None:
                self._last_request_headers = dict(headers)

        method = request.get("method", "")
        req_id = request.get("id")

        # Notifications have no 'id' — no response needed, return empty
        if req_id is None:
            return {}

        lower_headers = {k.lower(): v for k, v in (headers or {}).items()}
        unauthenticated = "authorization" not in lower_headers
        raw_p = request.get("params")
        has_modern_meta = isinstance(raw_p, dict) and isinstance(raw_p.get("_meta"), dict) \
            and META_PROTOCOL_VERSION in raw_p["_meta"]
        if self._reject_modern_framing_unauth and unauthenticated and (
            HEADER_PROTOCOL_VERSION.lower() in lower_headers or has_modern_meta
        ):
            return {"jsonrpc": "2.0", "id": req_id, "_http_status": 401,
                    "error": {"code": -32001, "message": "Unauthorized"}}
        if self._modern_framing_unauth_jsonrpc_error and unauthenticated and (
            HEADER_PROTOCOL_VERSION.lower() in lower_headers or has_modern_meta
        ) and method != "server/discover":
            return {"jsonrpc": "2.0", "id": req_id,
                    "error": {"code": -32001, "message": "Unauthorized"}}
        if method == "initialize" and self._initialize_requires_auth and unauthenticated:
            return {"jsonrpc": "2.0", "id": req_id, "_http_status": 401,
                    "error": {"code": -32001, "message": "Unauthorized"}}
        if method == "initialize" and self._initialize_http_status is not None:
            return {"jsonrpc": "2.0", "id": req_id, "_http_status": self._initialize_http_status,
                    "error": {"code": -32603, "message": "Internal error"}}
        if method == "tools/call" and self._drop_tools_call:
            return {"_drop": True}

        if method == "server/discover" and self._discover_http_status is not None:
            return {"jsonrpc": "2.0", "id": req_id, "_http_status": self._discover_http_status,
                    "error": {"code": -32000, "message": "unavailable"}}
        if (
            method == "server/discover"
            and self._modern_auth_only_on_discover
            and "authorization" not in {k.lower() for k in (headers or {})}
        ):
            return {"jsonrpc": "2.0", "id": req_id, "_http_status": 401,
                    "error": {"code": -32001, "message": "Unauthorized"}}

        if self._protocol_era != "legacy":
            rejection = self._modern_gate(request, headers or {})
            if rejection is not None:
                return rejection
            params = request.get("params")
            is_modern_request = isinstance(params, dict) and isinstance(params.get("_meta"), dict) \
                and META_PROTOCOL_VERSION in params["_meta"]
            if method == "server/discover" and is_modern_request:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "resultType": "complete",
                        "supportedVersions": list(self._modern_supported),
                        "capabilities": (
                            {"tools": {}, "logging": {}} if self._advertise_logging
                            else {"tools": {}}
                        ),
                        "_meta": {
                            META_SERVER_INFO: {"name": "mock-mcp-server", "version": "0.2.0"},
                        },
                    },
                }
            if method == "tools/list" and is_modern_request:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"resultType": "complete", "tools": self._get_tools_for_call()},
                }

        if method == "initialize":
            if self._initialize_error:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32600, "message": self._initialize_error},
                }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "serverInfo": {"name": "mock-mcp-server", "version": "0.1.0"},
                    "capabilities": {},
                },
            }

        if method == "tools/list":
            tools = self._get_tools_for_call()
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": tools},
            }

        if method == "tools/call":
            params = request.get("params", {})
            name = params.get("name", "unknown")

            # Per-session call budget (T10 denial-of-wallet).
            if self._call_budget is not None:
                with self._log_lock:
                    self._tools_call_count += 1
                    over_budget = self._tools_call_count > self._call_budget
                if over_budget:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32029,
                            "message": "Per-session call budget exceeded",
                        },
                    }

            # JTI replay cache (T1): reject the SECOND presentation of a token.
            if self._reject_replayed_tokens:
                request_headers = headers or {}
                auth = request_headers.get("Authorization", "")
                token = auth[len("Bearer "):].strip() if auth.startswith("Bearer ") else ""
                token_id = self._token_replay_id(token)
                if token_id is not None:
                    with self._log_lock:
                        replayed = token_id in self._seen_token_ids
                        self._seen_token_ids.add(token_id)
                    if replayed:
                        return {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {
                                "code": -32001,
                                "message": "Token replayed: jti already seen in session window",
                            },
                        }

            # Check privileged tool access
            if name in self._privileged_tools:
                request_headers = headers or {}
                is_privileged = request_headers.get("X-Privileged", "").lower() == "true"
                if not is_privileged:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32000,
                            "message": f"Unauthorized: {name!r} requires X-Privileged: true",
                        },
                    }

            # Check OAuth scope-guarded tool access (T07-002 / T07-003)
            if name in self._scope_guarded_tools:
                required_scope = self._scope_guarded_tools[name]
                request_headers = headers or {}
                auth = request_headers.get("Authorization", "")
                token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
                args = params.get("arguments", {})
                has_confirmation = args.get("confirmation") is True

                if self._confirmation_gates_access and not has_confirmation:
                    # Vulnerable: confirmation is the access gate (T07-003 detection)
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32001,
                            "message": "Confirmation required to call this tool",
                        },
                    }

                if self._confirmation_bypasses_scope and has_confirmation:
                    pass  # Vulnerable: confirmation bypasses scope check (T07-002 detection)
                elif not self._token_has_scope(token, required_scope):
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32001,
                            "message": f"Insufficient scope: {required_scope!r} required",
                        },
                    }

            if self._tools_call_response is not None:
                response = dict(self._tools_call_response)
                response["id"] = req_id
                response.setdefault("jsonrpc", "2.0")
                return response
            arguments = params.get("arguments", {})
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {"type": "text", "text": f"echo: {json.dumps(arguments)}"}
                    ],
                    "isError": False,
                },
            }

        # Unknown method
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method!r}"},
        }

    def _modern_gate(
        self, request: dict[str, Any], headers: dict[str, str],
    ) -> dict[str, Any] | None:
        """Spec server validation for 2026-07-28; None means "serve it".

        Modern-only servers reject ``initialize`` and any request lacking the
        required ``_meta``; dual-era servers let those through to legacy
        handling.  ``_meta``-bearing requests must agree with their headers.
        """
        req_id = request.get("id")
        method = request.get("method", "")
        raw_params = request.get("params")
        params: dict[str, Any] = raw_params if isinstance(raw_params, dict) else {}
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else None
        lower = {k.lower(): v for k, v in headers.items()}

        def _err(code: int, message: str, data: Any = None) -> dict[str, Any]:
            error: dict[str, Any] = {"code": code, "message": message}
            if data is not None:
                error["data"] = data
            return {"jsonrpc": "2.0", "id": req_id, "error": error, "_http_status": 400}

        if (
            self._modern_requires_auth
            and meta is not None
            and "authorization" not in lower
        ):
            return {"jsonrpc": "2.0", "id": req_id, "_http_status": 401,
                    "error": {"code": -32001, "message": "Unauthorized"}}

        if meta is None or META_PROTOCOL_VERSION not in meta:
            if self._protocol_era == "dual":
                return None
            if method == "initialize":
                return _err(-32601, f"initialize not supported; supported versions: "
                                    f"{self._modern_supported}")
            return _err(-32602, "Missing required _meta field "
                                f"{META_PROTOCOL_VERSION!r}")

        version = meta.get(META_PROTOCOL_VERSION)
        if lower.get(HEADER_PROTOCOL_VERSION.lower()) != version:
            return _err(ERR_HEADER_MISMATCH, "Header mismatch: MCP-Protocol-Version")
        if version not in self._modern_supported and not self._accept_unknown_versions:
            return _err(ERR_UNSUPPORTED_PROTOCOL_VERSION, "Unsupported protocol version",
                        {"supported": list(self._modern_supported), "requested": version})
        if self._skip_header_validation:
            return None
        if lower.get(HEADER_METHOD.lower()) != method:
            return _err(ERR_HEADER_MISMATCH, "Header mismatch: Mcp-Method")
        expected_name = mcp_name_for(method, params)
        if expected_name is not None:
            raw = lower.get(HEADER_NAME.lower())
            try:
                decoded = decode_header_value(raw) if raw is not None else None
            except ValueError:
                decoded = None
            if decoded != expected_name:
                return _err(ERR_HEADER_MISMATCH, "Header mismatch: Mcp-Name")
        return None

    def _token_replay_id(self, token: str) -> str | None:
        """Return a stable replay key for a Bearer token, or None to skip dedup.

        Prefers the JWT ``jti`` claim (the canonical replay identifier, RFC 7519
        §4.1.7); falls back to the whole token string when no ``jti`` is
        decodable.  Returns None for an empty token so unauthenticated calls are
        never de-duplicated.
        """
        if not token:
            return None
        try:
            parts = token.split(".")
            if len(parts) >= 2:
                padding = (4 - len(parts[1]) % 4) % 4
                payload = json.loads(
                    base64.urlsafe_b64decode(parts[1] + "=" * padding)
                )
                jti = payload.get("jti")
                if jti:
                    return f"jti:{jti}"
        except Exception:  # noqa: BLE001, S110
            pass
        return f"tok:{token}"

    def _token_has_scope(self, token: str, required: str) -> bool:
        """Return True if the Bearer token's scope claim contains required.

        Decodes the JWT payload without signature verification — safe for the
        test harness because mock servers are not production code.  Returns
        False on any parse failure (treat malformed / absent token as no scope).
        """
        if not token:
            return False
        try:
            parts = token.split(".")
            if len(parts) >= 2:
                padding = (4 - len(parts[1]) % 4) % 4
                payload = json.loads(
                    base64.urlsafe_b64decode(parts[1] + "=" * padding)
                )
                scope_str: str = payload.get("scope", "")
                return required in scope_str.split()
        except Exception:  # noqa: BLE001, S110
            pass
        return False

    def _get_tools_for_call(self) -> list[dict[str, Any]]:
        """Return the appropriate tools list for this tools/list call."""
        with self._log_lock:
            if self._tools_list_sequence is not None:
                idx = min(self._tools_list_call_count, len(self._tools_list_sequence) - 1)
                tools = self._tools_list_sequence[idx]
                self._tools_list_call_count += 1
                return tools
            return self._tools

    def start(self) -> None:
        self._server = _MockHTTPServer(("127.0.0.1", self._port), self)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="MockMCPServer",
        )
        self._thread.start()
        # HTTPServer binds in __init__, so socket is ready before thread starts.
        # Set the event after thread.start() to provide the memory barrier.
        self._ready.set()

    def stop(self) -> None:
        self._ready.clear()
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> MockMCPServer:
        self.start()
        return self

    def __exit__(self, *_: Any) -> None:
        self.stop()
