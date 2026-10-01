"""CoSAI v2.0 P2 middleware: requestState sealing (SD-03), server-held handle
integrity (SD-01), request-envelope validation (TN-04), _meta reconciliation
(SD-02), OCSF agentic activity (LO-01/LO-04) and W3C trace context (LO-03)."""
from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from cosai_mcp.middleware import (
    AuthenticatedPrincipal,
    CoSAIStack,
    HandleError,
    HandleRegistry,
    MetaTrustError,
    RequestMetadataError,
    RequestStateSealer,
    StateVerificationError,
    reconcile_meta,
    request_fingerprint,
    validate_request_metadata,
)
from cosai_mcp.protocol import (
    META_CLIENT_CAPABILITIES,
    META_CLIENT_INFO,
    META_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSION,
    encode_header_value,
    request_metadata_headers,
    with_request_meta,
)
from cosai_mcp.telemetry.ocsf import build_mcp_api_activity
from cosai_mcp.telemetry.tracecontext import (
    parse_traceparent,
    preserve_client_trace,
    sanitize_baggage,
)


class _Clock:
    def __init__(self, t: float = 1_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


# ===========================================================================
# requestState sealing (SD-03)
# ===========================================================================

PARAMS = {"name": "book", "arguments": {"when": "tomorrow"}}
RID = request_fingerprint("tools/call", PARAMS)


def _sealer(**kw: Any) -> RequestStateSealer:
    kw.setdefault("audience", "https://mcp.example/mcp")
    return RequestStateSealer({"k1": b"\x01" * 32}, active_kid="k1", **kw)


class TestRequestStateSealer:
    def test_round_trip(self) -> None:
        s = _sealer()
        token = s.seal({"step": 2}, tenant="t", principal="alice", request_id=RID)
        assert s.open(token, tenant="t", principal="alice", request_id=RID) == {"step": 2}

    def test_opaque_to_client(self) -> None:
        token = _sealer().seal({"secret": "top-secret-value"}, tenant="t", principal="alice",
                               request_id=RID)
        assert "top-secret-value" not in token
        blob = token.split(".", 2)[2]
        assert b"top-secret" not in base64.urlsafe_b64decode(blob + "==")

    @pytest.mark.parametrize("mutate", [
        lambda t: t[:-2] + ("A" if t[-2] != "A" else "B") + t[-1],      # flip ciphertext
        lambda t: t.replace("v1.", "v2.", 1),                          # wrong format
        lambda t: t.replace(".k1.", ".k9.", 1),                        # unknown key id
        lambda t: "not-a-state",
        lambda t: 12345,
        lambda t: "v1.k1." + "A" * 5,                                  # too short
    ])
    def test_tampering_rejected(self, mutate: Any) -> None:
        s = _sealer()
        token = s.seal({"step": 2}, tenant="t", principal="alice", request_id=RID)
        with pytest.raises(StateVerificationError):
            s.open(mutate(token), tenant="t", principal="alice", request_id=RID)

    def test_other_principal_rejected(self) -> None:
        s = _sealer()
        token = s.seal({}, tenant="t", principal="alice", request_id=RID)
        with pytest.raises(StateVerificationError):
            s.open(token, tenant="t", principal="mallory", request_id=RID)

    def test_other_request_rejected(self) -> None:
        s = _sealer()
        token = s.seal({}, tenant="t", principal="alice", request_id=RID)
        other = request_fingerprint("tools/call", {"name": "book",
                                                   "arguments": {"when": "never"}})
        with pytest.raises(StateVerificationError):
            s.open(token, tenant="t", principal="alice", request_id=other)

    def test_retry_params_do_not_change_fingerprint(self) -> None:
        retry = {**PARAMS, "requestState": "x", "inputResponses": {"q": {}},
                 "_meta": {META_PROTOCOL_VERSION: MODERN_PROTOCOL_VERSION}}
        assert request_fingerprint("tools/call", retry) == RID

    def test_expiry(self) -> None:
        clock = _Clock()
        s = _sealer(clock=clock, default_ttl_seconds=60)
        token = s.seal({}, tenant="t", principal="alice", request_id=RID)
        clock.t += 61
        with pytest.raises(StateVerificationError):
            s.open(token, tenant="t", principal="alice", request_id=RID)

    def test_single_use(self) -> None:
        s = _sealer(single_use=True)
        token = s.seal({}, tenant="t", principal="alice", request_id=RID)
        s.open(token, tenant="t", principal="alice", request_id=RID)
        with pytest.raises(StateVerificationError):
            s.open(token, tenant="t", principal="alice", request_id=RID)

    def test_key_rotation(self) -> None:
        old = RequestStateSealer({"k1": b"\x01" * 32}, active_kid="k1", audience="aud")
        token = old.seal({"a": 1}, tenant="t", principal="alice", request_id=RID)
        rotated = RequestStateSealer({"k1": b"\x01" * 32, "k2": b"\x02" * 32},
                                     active_kid="k2", audience="aud")
        assert rotated.open(token, tenant="t", principal="alice", request_id=RID) == {"a": 1}
        assert rotated.seal({}, tenant="t", principal="alice", request_id=RID).startswith("v1.k2.")
        retired = RequestStateSealer({"k2": b"\x02" * 32}, active_kid="k2", audience="aud")
        with pytest.raises(StateVerificationError):
            retired.open(token, tenant="t", principal="alice", request_id=RID)

    def test_error_is_uninformative(self) -> None:
        s = _sealer()
        token = s.seal({}, tenant="t", principal="alice", request_id=RID)
        msgs = set()
        for bad in (token[:-3] + "AAA", token.replace("k1", "k9"), "junk"):
            try:
                s.open(bad, tenant="t", principal="alice", request_id=RID)
            except StateVerificationError as exc:
                msgs.add(str(exc))
        try:
            s.open(token, tenant="t", principal="mallory", request_id=RID)
        except StateVerificationError as exc:
            msgs.add(str(exc))
        assert len(msgs) == 1

    @pytest.mark.parametrize("kwargs", [
        {"keys": {}, "active_kid": "k1"},
        {"keys": {"k1": b"short"}, "active_kid": "k1"},
        {"keys": {"k1": b"\x01" * 32}, "active_kid": "k2"},
        {"keys": {"bad kid!": b"\x01" * 32}, "active_kid": "bad kid!"},
    ])
    def test_config_validation(self, kwargs: dict[str, Any]) -> None:
        with pytest.raises(ValueError):
            RequestStateSealer(kwargs["keys"], active_kid=kwargs["active_kid"],
                               audience="aud")

    def test_generated_keys_are_random_256_bit(self) -> None:
        a, b = RequestStateSealer.generate_key(), RequestStateSealer.generate_key()
        assert len(a) == 32 and a != b


# ===========================================================================
# Server-held handles (SD-01)
# ===========================================================================

class TestHandleRegistry:
    def test_mint_is_opaque_and_unguessable(self) -> None:
        reg = HandleRegistry()
        handles = {reg.mint(principal="alice", tenant="acme", kind="task", ttl_seconds=60)
                   for _ in range(200)}
        assert len(handles) == 200
        for h in handles:
            assert len(h) >= 43 and "alice" not in h and "acme" not in h

    def test_possession_is_not_authority(self) -> None:
        reg = HandleRegistry()
        h = reg.mint(principal="alice", tenant="acme", kind="task", ttl_seconds=60)
        assert reg.resolve(h, principal="alice", tenant="acme").principal == "alice"
        for principal, tenant in (("mallory", "acme"), ("alice", "evil-corp")):
            with pytest.raises(HandleError):
                reg.resolve(h, principal=principal, tenant=tenant)
        with pytest.raises(HandleError):
            reg.resolve(h, principal="alice", tenant="acme", kind="cursor")

    def test_unknown_expired_and_revoked_indistinguishable(self) -> None:
        clock = _Clock()
        reg = HandleRegistry(clock=clock)
        expired = reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=10)
        revoked = reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=100)
        reg.revoke(revoked, principal="a", tenant="t")
        clock.t += 11
        msgs = set()
        for h in ("unknown", expired, revoked, 42):
            with pytest.raises(HandleError) as ei:
                reg.resolve(h, principal="a", tenant="t")
            msgs.add(str(ei.value))
        assert len(msgs) == 1

    def test_revoke_principal_cancels_and_enumerates(self) -> None:
        cancelled: list[str] = []
        reg = HandleRegistry(on_revoke=lambda r: cancelled.append(r.handle))
        mine = [reg.mint(principal="alice", tenant="acme", kind="task", ttl_seconds=60)
                for _ in range(3)]
        other = reg.mint(principal="bob", tenant="acme", kind="task", ttl_seconds=60)
        assert {r.handle for r in reg.list_for_principal("alice")} == set(mine)
        revoked = reg.revoke_principal("alice")
        assert {r.handle for r in revoked} == set(mine) == set(cancelled)
        assert reg.list_for_principal("alice") == []
        for h in mine:
            with pytest.raises(HandleError):
                reg.resolve(h, principal="alice", tenant="acme")
        assert reg.resolve(other, principal="bob", tenant="acme")

    def test_bounds(self) -> None:
        reg = HandleRegistry(max_handles=2, max_handles_per_tenant=100, max_ttl_seconds=100)
        with pytest.raises(ValueError):
            reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=101)
        with pytest.raises(ValueError):
            reg.mint(principal="", tenant="t", kind="task", ttl_seconds=10)
        for _ in range(4):      # global cap 2; owner floor admits up to the 2x ceiling
            reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=10)
        with pytest.raises(RuntimeError):
            reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=10)


# ===========================================================================
# Request envelope validation (TN-04)
# ===========================================================================

_META = {META_PROTOCOL_VERSION: MODERN_PROTOCOL_VERSION, META_CLIENT_INFO: {"name": "c"},
         META_CLIENT_CAPABILITIES: {}}


def _request(method: str, params: dict[str, Any]) -> tuple[dict[str, str], dict[str, Any]]:
    params = with_request_meta(params, _META)
    headers = request_metadata_headers(method, params)
    return headers, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}


class TestEnvelopeValidation:
    def test_conforming_request_passes(self) -> None:
        h, b = _request("tools/call", {"name": "echo", "arguments": {}})
        assert validate_request_metadata(h, b) == MODERN_PROTOCOL_VERSION

    @pytest.mark.parametrize(("header", "value"), [
        ("Mcp-Method", "tools/list"),
        ("Mcp-Name", "admin_delete"),
        ("MCP-Protocol-Version", "2025-11-25"),
    ])
    def test_mismatch_is_32020(self, header: str, value: str) -> None:
        h, b = _request("tools/call", {"name": "echo", "arguments": {}})
        h[header] = value
        with pytest.raises(RequestMetadataError) as ei:
            validate_request_metadata(h, b)
        assert ei.value.code == -32020 and ei.value.http_status == 400

    @pytest.mark.parametrize("missing", ["Mcp-Method", "Mcp-Name", "MCP-Protocol-Version"])
    def test_missing_header_is_32020(self, missing: str) -> None:
        h, b = _request("tools/call", {"name": "echo", "arguments": {}})
        del h[missing]
        with pytest.raises(RequestMetadataError) as ei:
            validate_request_metadata(h, b)
        assert ei.value.code == -32020

    def test_unsupported_version_is_32022_with_supported_list(self) -> None:
        h, b = _request("tools/list", {})
        b["params"]["_meta"][META_PROTOCOL_VERSION] = "1900-01-01"
        h["MCP-Protocol-Version"] = "1900-01-01"
        with pytest.raises(RequestMetadataError) as ei:
            validate_request_metadata(h, b)
        err = ei.value.to_jsonrpc_error()
        assert err["code"] == -32022 and err["data"]["supported"] == [MODERN_PROTOCOL_VERSION]

    def test_missing_meta_is_32602(self) -> None:
        with pytest.raises(RequestMetadataError) as ei:
            validate_request_metadata({}, {"method": "tools/list", "params": {}})
        assert ei.value.code == -32602

    def test_base64_encoded_name_is_decoded(self) -> None:
        h, b = _request("tools/call", {"name": "résumé", "arguments": {}})
        assert h["Mcp-Name"].startswith("=?base64?")
        validate_request_metadata(h, b)

    def test_header_names_case_insensitive(self) -> None:
        h, b = _request("tools/list", {})
        validate_request_metadata({k.lower(): v for k, v in h.items()}, b)

    def test_x_mcp_param_headers_enforced(self) -> None:
        schemas = {"sql": {"type": "object", "properties": {
            "region": {"type": "string", "x-mcp-header": "Region"},
            "limit": {"type": "integer", "x-mcp-header": "Limit"}}}}
        h, b = _request("tools/call", {"name": "sql",
                                       "arguments": {"region": "eu", "limit": 5}})
        h["Mcp-Param-Region"] = "eu"
        h["Mcp-Param-Limit"] = "5"
        validate_request_metadata(h, b, tool_schemas=schemas)
        h["Mcp-Param-Region"] = encode_header_value("us")
        with pytest.raises(RequestMetadataError):
            validate_request_metadata(h, b, tool_schemas=schemas)
        del h["Mcp-Param-Region"]
        with pytest.raises(RequestMetadataError):
            validate_request_metadata(h, b, tool_schemas=schemas)

    def test_control_chars_in_name_header_rejected(self) -> None:
        h, b = _request("tools/call", {"name": "echo", "arguments": {}})
        h["Mcp-Name"] = "echo\r\nX-Injected: 1"
        with pytest.raises(RequestMetadataError):
            validate_request_metadata(h, b)

    def test_scanner_probes_are_rejected_by_this_middleware(self) -> None:
        """The scanner's T07-004 (header≠body) and T07-005 (bogus version)
        requests are exactly what this validator rejects."""
        h, b = _request("tools/list", {})
        h["Mcp-Method"] = "tools/call"                         # T07-004-p1
        with pytest.raises(RequestMetadataError) as ei:
            validate_request_metadata(h, b)
        assert ei.value.code == -32020
        h, b = _request("tools/list", {"_meta": {META_PROTOCOL_VERSION: "1900-01-01"}})
        h["MCP-Protocol-Version"] = "1900-01-01"   # transport mirrors the body version
        with pytest.raises(RequestMetadataError) as ei:           # T07-005-p1
            validate_request_metadata(h, b)
        assert ei.value.code == -32022


# ===========================================================================
# _meta reconciliation (SD-02)
# ===========================================================================

ALICE = AuthenticatedPrincipal(subject="alice", tenant="acme", client_id="app-1",
                               scopes=frozenset({"read", "write"}))


class TestReconcileMeta:
    def test_consistent_or_absent_claims_pass(self) -> None:
        reconcile_meta(None, ALICE)
        reconcile_meta({**_META, "com.example/user": "alice", "com.example/tenant": "acme",
                        "com.example/scopes": ["read"], "com.example/is_admin": False}, ALICE)

    def test_client_info_is_display_only(self) -> None:
        reconcile_meta({META_CLIENT_INFO: {"name": "admin-console"}}, ALICE)

    @pytest.mark.parametrize("claim", [
        {"com.example/user": "bob"},
        {"x.y/sub": "root"},
        {"com.example/tenant": "evil-corp"},
        {"com.example/client_id": "other-app"},
        {"com.example/role": "admin"},
        {"com.example/scopes": ["read", "delete"]},
        {"com.example/scopes": 42},
        {"com.example/is_admin": True},
    ])
    def test_conflicting_or_expanding_claims_rejected(self, claim: dict[str, Any]) -> None:
        with pytest.raises(MetaTrustError):
            reconcile_meta({**_META, **claim}, ALICE)

    def test_tenant_claim_rejected_when_principal_has_no_tenant(self) -> None:
        with pytest.raises(MetaTrustError):
            reconcile_meta({"com.example/tenant": "acme"},
                           AuthenticatedPrincipal(subject="alice"))

    def test_error_never_echoes_claimed_values(self) -> None:
        seen: list[tuple[str, ...]] = []
        with pytest.raises(MetaTrustError) as ei:
            reconcile_meta({"com.example/user": "<script>bob</script>"}, ALICE,
                           on_mismatch=seen.append)
        assert "bob" not in str(ei.value) and seen == [("com.example/user",)]


# ===========================================================================
# CoSAIStack wiring + audit
# ===========================================================================

class _Audit:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def log(self, *, method: str, session_id: str, params: Any = None,
            parent_id: Any = None, event: Any = None) -> str:
        self.entries.append({"method": method, "params": params, "event": event})
        return "id"


def test_stack_check_request_envelope_validates_and_audits() -> None:
    audit = _Audit()
    stack = CoSAIStack(audit_logger=audit)  # type: ignore[arg-type]
    h, b = _request("tools/call", {"name": "echo", "arguments": {}})
    assert stack.check_request_envelope(h, b, ALICE) == MODERN_PROTOCOL_VERSION
    h["Mcp-Name"] = "other"
    with pytest.raises(RequestMetadataError):
        stack.check_request_envelope(h, b, ALICE)
    h, b = _request("tools/call", {"name": "echo", "arguments": {},
                                   "_meta": {"com.example/user": "bob"}})
    with pytest.raises(MetaTrustError):
        stack.check_request_envelope(h, b, ALICE)
    methods = [e["method"] for e in audit.entries]
    assert methods == ["check_request_envelope:header_mismatch",
                       "check_request_envelope:meta_mismatch"]
    assert "bob" not in json.dumps(audit.entries)


# ===========================================================================
# OCSF agentic activity (LO-01 / LO-04) and trace context (LO-03)
# ===========================================================================

def test_ocsf_activity_has_agentic_fields_and_hashes_params() -> None:
    ev = build_mcp_api_activity(
        server="https://mcp.example/mcp", mcp_method="tools/call", mcp_name="echo",
        decision="deny", principal="alice", tenant="acme",
        params={"password": "hunter2"}, params_key=b"k" * 32, correlation_id="c-1",
        delegation_path=["user:alice", "agent:planner"], attestation_state="verified",
        trace_id="0af7651916cd43dd8448eb211c80319c", reason="meta_mismatch",
    ).to_dict()
    agentic = ev["unmapped"]["cosai_agentic"]
    assert ev["class_uid"] == 6003
    assert {"delegation_path", "attestation_state", "correlation_id", "mcp_method",
            "mcp_name"} <= agentic.keys()
    assert "hunter2" not in json.dumps(ev) and len(agentic["params_hmac_sha256"]) == 64
    with pytest.raises(ValueError):
        build_mcp_api_activity(server="s", mcp_method="m", decision="maybe")


def test_traceparent_parsing() -> None:
    tp = "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"
    assert parse_traceparent(tp) == ("0af7651916cd43dd8448eb211c80319c",
                                     "00f067aa0ba902b7", "01")
    for bad in ("", "01-" + tp[3:], "00-" + "0" * 32 + "-00f067aa0ba902b7-01", 7):
        assert parse_traceparent(bad) is None


def test_baggage_allowlisted_bounded_and_no_identity() -> None:
    raw = "env=prod,user_id=alice,tenant=acme,feature=x;prop=1,junk key=1," + \
          ",".join(f"k{i}=v" for i in range(200))
    out = sanitize_baggage(raw, allowed_keys={"env", "feature", "user_id", "tenant"})
    assert out == "env=prod,feature=x"
    big = sanitize_baggage("env=" + "a" * 5000, allowed_keys={"env"}, max_bytes=100)
    assert big is None or len(big) <= 100


def test_server_cannot_overwrite_client_trace_identity() -> None:
    client = {"traceparent": "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"}
    child = {"traceparent": "00-0af7651916cd43dd8448eb211c80319c-1111111111111111-01"}
    hijack = {"traceparent": "00-ffffffffffffffffffffffffffffffff-1111111111111111-01"}
    assert preserve_client_trace(client, child) == (child, False)
    assert preserve_client_trace(client, hijack) == (client, True)
    assert preserve_client_trace(None, child) == (child, False)


# ===========================================================================
# Panel round 1 regressions
# ===========================================================================

class _Store:
    def __init__(self) -> None:
        self.seen: set[str] = set()

    def add_if_absent(self, jti: str, expires_at: float) -> bool:
        if jti in self.seen:
            return False
        self.seen.add(jti)
        return True


class TestStateRegressions:
    def test_regression_non_ascii_principal_roundtrip(self) -> None:
        s = _sealer()
        tok = s.seal({"x": 1}, principal="jürgen", tenant="tënant", request_id=RID)
        with pytest.raises(StateVerificationError):
            s.open(tok, principal="josé", tenant="tënant", request_id=RID)
        assert s.open(tok, principal="jürgen", tenant="tënant", request_id=RID) == {"x": 1}
        reg = HandleRegistry()
        h = reg.mint(principal="jürgen", tenant="acmé", kind="task", ttl_seconds=60)
        assert reg.resolve(h, principal="jürgen", tenant="acmé")
        with pytest.raises(HandleError):
            reg.resolve(h, principal="josé", tenant="acmé")

    def test_regression_revoke_principal_callback_failure_continues(self) -> None:
        called: list[str] = []

        def cb(r: Any) -> None:
            called.append(r.handle)
            if len(called) == 1:
                raise RuntimeError("boom")

        reg = HandleRegistry(on_revoke=cb)
        hs = {reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=60)
              for _ in range(3)}
        with pytest.raises(RuntimeError):
            reg.revoke_principal("a")
        assert set(called) == hs and reg.list_for_principal("a") == []

    def test_regression_seal_rejects_oversized_state(self) -> None:
        s = _sealer()
        with pytest.raises(ValueError):
            s.seal({"blob": "x" * 70_000}, tenant="t", principal="a", request_id=RID)
        tok = s.seal({"blob": "x" * 40_000}, tenant="t", principal="a", request_id=RID)
        assert s.open(tok, tenant="t", principal="a", request_id=RID)["blob"] == "x" * 40_000

    def test_regression_fingerprint_no_str_coercion_collision(self) -> None:
        class Obj:
            def __str__(self) -> str:
                return "x"

        assert request_fingerprint("m", {"a": 5}) != request_fingerprint("m", {"a": "5"})
        with pytest.raises(TypeError):
            request_fingerprint("m", {"a": Obj()})
        with pytest.raises(ValueError):
            request_fingerprint("m", {"a": float("nan")})

    def test_regression_seal_counter_limit_forces_rotation(
            self, monkeypatch: pytest.MonkeyPatch) -> None:
        import cosai_mcp.middleware.state as st
        monkeypatch.setattr(st, "_MAX_SEALS_PER_KEY", 2)
        s = _sealer()
        s.seal({}, tenant="t", principal="a", request_id=RID)
        s.seal({}, tenant="t", principal="a", request_id=RID)
        with pytest.raises(RuntimeError):
            s.seal({}, tenant="t", principal="a", request_id=RID)

    def test_exploit_requeststate_replay_default_rejected(self) -> None:
        s = RequestStateSealer({"k1": b"\x01" * 32}, active_kid="k1", audience="aud")
        tok = s.seal({}, tenant="t", principal="a", request_id=RID)
        s.open(tok, tenant="t", principal="a", request_id=RID)
        with pytest.raises(StateVerificationError):
            s.open(tok, tenant="t", principal="a", request_id=RID)

    def test_regression_single_use_shared_store_atomic(self) -> None:
        store = _Store()
        keys = {"k1": b"\x01" * 32}
        a = RequestStateSealer(keys, active_kid="k1", audience="aud", spent_store=store)
        b = RequestStateSealer(keys, active_kid="k1", audience="aud", spent_store=store)
        tok = a.seal({}, tenant="t", principal="p", request_id=RID)
        a.open(tok, tenant="t", principal="p", request_id=RID)
        with pytest.raises(StateVerificationError):
            b.open(tok, tenant="t", principal="p", request_id=RID)

    def test_regression_single_use_store_failure_fails_closed(self) -> None:
        class Broken:
            def add_if_absent(self, jti: str, expires_at: float) -> bool:
                raise ConnectionError

        s = RequestStateSealer({"k1": b"\x01" * 32}, active_kid="k1", audience="aud",
                               spent_store=Broken())
        tok = s.seal({}, tenant="t", principal="p", request_id=RID)
        with pytest.raises(StateVerificationError):
            s.open(tok, tenant="t", principal="p", request_id=RID)

    def test_exploit_requeststate_cross_tenant_rejected(self) -> None:
        keys = {"k1": b"\x01" * 32}
        x = RequestStateSealer(keys, active_kid="k1", audience="https://x/mcp")
        y = RequestStateSealer(keys, active_kid="k1", audience="https://y/mcp")
        tok = x.seal({}, principal="p", tenant="A", request_id=RID)
        with pytest.raises(StateVerificationError):
            x.open(tok, principal="p", tenant="B", request_id=RID)
        with pytest.raises(StateVerificationError):
            y.open(tok, principal="p", tenant="A", request_id=RID)
        assert x.open(tok, principal="p", tenant="A", request_id=RID) == {}

    def test_regression_per_principal_handle_cap(self) -> None:
        reg = HandleRegistry(max_handles_per_principal=2)
        for _ in range(2):
            reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=60)
        with pytest.raises(RuntimeError):
            reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=60)
        assert reg.mint(principal="b", tenant="t", kind="task", ttl_seconds=60)

    def test_regression_expired_handles_free_quota(self) -> None:
        clock = _Clock()
        reg = HandleRegistry(max_handles_per_principal=1, clock=clock)
        reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=5)
        clock.t += 6
        assert reg.mint(principal="a", tenant="t", kind="task", ttl_seconds=5)

    def test_exploit_cross_tenant_revoke_rejected(self) -> None:
        cancelled: list[str] = []
        reg = HandleRegistry(on_revoke=lambda r: cancelled.append(r.handle))
        h = reg.mint(principal="alice", tenant="acme", kind="task", ttl_seconds=60)
        with pytest.raises(HandleError):
            reg.revoke(h, principal="mallory", tenant="evil")
        assert cancelled == [] and reg.resolve(h, principal="alice", tenant="acme")
        assert reg.revoke(h, principal="alice", tenant="acme") and cancelled == [h]


_SCHEMAS = {"sql": {"type": "object", "properties": {
    "region": {"type": "string", "x-mcp-header": "Region"},
    "limit": {"type": "integer", "x-mcp-header": "Limit"}}}}


def _sql(args: dict[str, Any]) -> tuple[dict[str, str], dict[str, Any]]:
    h, b = _request("tools/call", {"name": "sql", "arguments": args})
    from cosai_mcp.protocol import x_mcp_param_headers
    h.update(x_mcp_param_headers(_SCHEMAS["sql"], args))
    return h, b


def _code(headers: Any, body: Any, **kw: Any) -> int:
    with pytest.raises(RequestMetadataError) as ei:
        validate_request_metadata(headers, body, **kw)
    return ei.value.code


class TestEnvelopeRegressions:
    def test_regression_envelope_rejects_batch_and_non_object_body(self) -> None:
        h, b = _request("tools/list", {})
        audit = _Audit()
        stack = CoSAIStack(audit_logger=audit)  # type: ignore[arg-type]
        for body in ([b], None, "x", {"id": 1, "result": {}}):
            assert _code({}, body) == -32600         # no modern headers: plain -32600
        assert _code(h, [b]) == -32020               # modern headers + batch: split-brain
        for body in ([b], {"id": 1, "result": {}}):
            with pytest.raises(RequestMetadataError):
                stack.check_request_envelope({}, body, ALICE)
        for body in (None, "x"):
            with pytest.raises(TypeError):
                stack.check_request_envelope(h, body, ALICE)
        assert [e["method"] for e in audit.entries] == [
            "check_request_envelope:invalid_request"] * 2 + [
            "check_request_envelope:invalid_body"] * 2

    def test_regression_error_code_selection_matrix(self) -> None:
        assert _code({"MCP-Protocol-Version": "2025-03-26"},
                     {"method": "initialize", "params": {}}) == -32602   # legacy fallback
        assert _code({"MCP-Protocol-Version": "1900-01-01"},
                     {"method": "initialize", "params": {}}) == -32022
        assert _code({}, {"method": "notifications/x"}) == -32602
        assert _code({}, {"method": "tools/list", "params": {"_meta": {}}}) == -32602
        assert _code({"MCP-Protocol-Version": MODERN_PROTOCOL_VERSION},
                     {"method": "tools/list", "params": {"_meta": {}}}) == -32020
        h, b = _request("tools/list", {})
        del h["Mcp-Method"]
        assert _code(h, b) == -32020

    def test_exploit_nonstring_name_with_header_rejected(self) -> None:
        h, b = _request("tools/call", {"name": ["t"], "arguments": {}})
        h["Mcp-Name"] = "public"
        assert _code(h, b) == -32602
        h, b = _request("tools/call", {"arguments": {}})
        assert _code(h, b) == -32602
        h, b = _request("tools/list", {})
        h["Mcp-Name"] = "x"
        assert _code(h, b) == -32020

    def test_exploit_param_header_without_body_value_rejected(self) -> None:
        for args in ({}, {"region": None}, {"limit": 2**60}):
            h, b = _sql(args)
            h["Mcp-Param-Region" if "limit" not in args else "Mcp-Param-Limit"] = "eu"
            assert _code(h, b, tool_schemas=_SCHEMAS) == -32020

    def test_exploit_param_headers_unchecked_without_schema(self) -> None:
        h, b = _sql({"region": "eu"})
        h["Mcp-Param-Region"] = "us"
        assert _code(h, b) == -32020                             # no schemas
        h, b = _request("tools/call", {"name": "ghost", "arguments": {}})
        assert _code(h, b, tool_schemas=_SCHEMAS) == -32602      # unknown tool
        stack = CoSAIStack()
        h, b = _sql({"region": "eu"})
        h["Mcp-Param-Region"] = "us"
        with pytest.raises(RequestMetadataError):
            stack.check_request_envelope(h, b, ALICE)

    def test_exploit_string_param_numeric_equivalence_rejected(self) -> None:
        for body_val, header in (("10", "1_0.0"), ("10", "1e1"), ("10", "10.0"),
                                 ("10", " 10"), ("Infinity", "inf")):
            h, b = _sql({"region": body_val})
            h["Mcp-Param-Region"] = header
            assert _code(h, b, tool_schemas=_SCHEMAS) == -32020
        for header in ("5.0", "1_0", "05"):
            h, b = _sql({"limit": 5})
            h["Mcp-Param-Limit"] = header
            assert _code(h, b, tool_schemas=_SCHEMAS) == -32020
        h, b = _sql({"limit": 5, "region": "10"})
        assert validate_request_metadata(h, b, tool_schemas=_SCHEMAS)

    def test_exploit_noncanonical_base64_mcp_name_rejected(self) -> None:
        h, b = _request("tools/call", {"name": "t", "arguments": {}})
        h["Mcp-Name"] = "=?base64?dA==?="
        assert _code(h, b) == -32020
        h, b = _sql({"region": "eu"})
        h["Mcp-Param-Region"] = "=?base64?ZXU=?="
        assert _code(h, b, tool_schemas=_SCHEMAS) == -32020

    def test_exploit_duplicate_mcp_method_header_rejected(self) -> None:
        h, b = _request("tools/list", {})
        for dup in ("tools/call", "tools/list"):
            pairs = [*h.items(), ("mcp-method", dup)]
            assert _code(pairs, b) == -32020
        joined = dict(h, **{"Mcp-Method": "tools/list, tools/call"})
        assert _code(joined, b) == -32020
        assert validate_request_metadata(list(h.items()), b)

    @pytest.mark.parametrize("claim", [
        {"com.acme.tenant_id": "evil"},
        {"x/user-id": "bob"},
        {"x/enduser.id": "bob"},
        {"x/impersonate": "bob"},
        {"X-Tenant-ID": "evil"},
        {"client.id": "other"},
        {"is-admin": True},
        {"ｔｅｎａｎｔ": "evil"},
        {"acme/identity": {"user": "bob"}},
        {"auth": {"tenant": "other"}},
        {"a": {"b": {"c": {"d": {"e": 1}}}}},
    ])
    def test_exploit_meta_identity_smuggling_variants(self, claim: dict[str, Any]) -> None:
        with pytest.raises(MetaTrustError):
            reconcile_meta(claim, ALICE)

    def test_regression_meta_allowlist_mode(self) -> None:
        reconcile_meta({**_META, "com.acme/feature": 1,
                        "traceparent": "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"},
                       ALICE,
                       allowed_keys={"com.acme/feature"})
        with pytest.raises(MetaTrustError):
            reconcile_meta({"com.acme/other": 1}, ALICE, allowed_keys={"com.acme/feature"})

    def test_exploit_mappingproxy_body_skips_meta_reconcile(self) -> None:
        from types import MappingProxyType
        h, b = _request("tools/list", {"_meta": {"x/user": "bob"}})
        b["params"] = MappingProxyType(b["params"])
        with pytest.raises(MetaTrustError):
            CoSAIStack().check_request_envelope(h, MappingProxyType(b), ALICE)

    def test_regression_envelope_audit_label_by_code(self) -> None:
        audit = _Audit()
        stack = CoSAIStack(audit_logger=audit)  # type: ignore[arg-type]
        h, b = _request("tools/list", {})
        b["params"]["_meta"][META_PROTOCOL_VERSION] = "1900-01-01"
        h["MCP-Protocol-Version"] = "1900-01-01"
        with pytest.raises(RequestMetadataError):
            stack.check_request_envelope(h, b, ALICE)
        with pytest.raises(RequestMetadataError):
            stack.check_request_envelope({}, {"method": "tools/list", "params": {}}, ALICE)
        h, b = _request("tools/list", {"_meta": {"x/user": "<bob>"}})
        with pytest.raises(MetaTrustError):
            stack.check_request_envelope(h, b, ALICE)
        assert [e["method"] for e in audit.entries] == [
            "check_request_envelope:unsupported_version",
            "check_request_envelope:invalid_params",
            "check_request_envelope:meta_mismatch"]
        assert all(e["params"]["principal"] == "alice" for e in audit.entries)
        assert "bob" not in json.dumps(audit.entries)

    def test_regression_envelope_audit_uses_real_audit_logger(self, tmp_path: Any) -> None:
        from cosai_mcp.middleware import AuditLogger
        log = AuditLogger(tmp_path / "audit.log")
        stack = CoSAIStack(audit_logger=log)
        h, b = _sql({"region": "eu"})
        h["Mcp-Param-Region"] = "us"
        with pytest.raises(RequestMetadataError):
            stack.check_request_envelope(h, b, ALICE, tool_schemas=_SCHEMAS)
        assert log.verify_chain() == 1
        entry = json.loads((tmp_path / "audit.log").read_text().splitlines()[0])
        assert entry["method"] == "check_request_envelope:header_mismatch"


def test_exploit_params_hash_not_bruteforceable() -> None:
    import hashlib
    params = {"user_id": 1234}
    canon = json.dumps(params, sort_keys=True, separators=(",", ":")).encode()

    def digest(key: bytes | None) -> Any:
        return build_mcp_api_activity(server="s", mcp_method="tools/call", decision="allow",
                                      params=params, params_key=key
                                      ).to_dict()["unmapped"]["cosai_agentic"][
            "params_hmac_sha256"]

    assert digest(None) is None
    d1, d2 = digest(b"a" * 32), digest(b"b" * 32)
    assert d1 != d2 and d1 != hashlib.sha256(canon).hexdigest()
    with pytest.raises(ValueError):
        digest(b"short")


def test_exploit_traceparent_returned_canonical() -> None:
    trace = "0af7651916cd43dd8448eb211c80319c"
    client = {"traceparent": f"00-{trace}-00f067aa0ba902b7-01"}
    server = {"traceparent": f"  00-{trace}-1111111111111111-01\r\n"}
    out, _ = preserve_client_trace(client, server)
    assert out["traceparent"] == f"00-{trace}-1111111111111111-01"
    out, _ = preserve_client_trace({"traceparent": " " + client["traceparent"] + "\n"}, None)
    assert out["traceparent"] == client["traceparent"]


def test_exploit_baggage_enduser_id_dropped_and_oversize_rejected() -> None:
    allowed = {"enduser.id", "tenant-id", "session.id", "env", "api_key"}
    assert sanitize_baggage("enduser.id=bob,tenant-id=acme,session.id=s,api_key=k,env=p",
                            allowed) == "env=p"
    assert sanitize_baggage("env=p," + "x" * 9000, {"env"}) is None
    assert sanitize_baggage("env=" + "a" * 2000 + ",env2=b", {"env", "env2"}) == "env2=b"


# ===========================================================================
# Panel round 2 regressions
# ===========================================================================

def test_exploit_requeststate_requires_audience_and_tenant() -> None:
    with pytest.raises(TypeError):
        RequestStateSealer({"k1": b"\x01" * 32}, active_kid="k1")  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        RequestStateSealer({"k1": b"\x01" * 32}, active_kid="k1", audience="")
    s = _sealer()
    with pytest.raises(TypeError):
        s.seal({}, principal="p", request_id=RID)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        s.seal({}, principal="p", request_id=RID, tenant="")


def test_exploit_handle_quota_cross_tenant_isolated() -> None:
    reg = HandleRegistry(max_handles_per_principal=3)
    for _ in range(3):
        reg.mint(principal="alice", tenant="EVIL", kind="task", ttl_seconds=60)
    assert reg.mint(principal="alice", tenant="A", kind="task", ttl_seconds=60)


def test_exploit_ocsf_params_hmac_no_str_collision() -> None:
    from decimal import Decimal

    def agentic(params: Any) -> Any:
        return build_mcp_api_activity(server="s", mcp_method="m", decision="allow",
                                      params=params, params_key=b"k" * 32
                                      ).to_dict()["unmapped"]["cosai_agentic"]

    a, b = agentic({"x": Decimal("1")}), agentic({"x": "1"})
    assert a["params_hmac_sha256"] != b["params_hmac_sha256"]
    assert a["params_hmac_sha256"] is None and a["params_unserializable"] is True
    assert b["params_unserializable"] is False


def test_regression_unannotated_param_header_rejected() -> None:
    schemas = {**_SCHEMAS, "pay": {"type": "object", "properties": {
        "amount": {"type": "number", "x-mcp-header": "Amount"},
        "bad": {"type": "string", "x-mcp-header": "bad name"}}}}
    h, b = _sql({"region": "eu"})
    h["Mcp-Param-Secret"] = "x"
    assert _code(h, b, tool_schemas=schemas) == -32020
    h, b = _request("tools/call", {"name": "pay", "arguments": {"amount": 999}})
    h["Mcp-Param-Amount"] = "999"
    assert _code(h, b, tool_schemas=schemas) == -32020
    for method in ("tools/list", "resources/list"):
        h, b = _request(method, {})
        h["Mcp-Param-Region"] = "eu"
        assert _code(h, b) == -32020
        assert _code(h, b, tool_schemas=schemas) == -32020


def test_exploit_lone_surrogate_name_and_param_rejected_not_crash() -> None:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "\ud800", "arguments": {}, "_meta": dict(_META)}}
    h = {"MCP-Protocol-Version": MODERN_PROTOCOL_VERSION, "Mcp-Method": "tools/call",
         "Mcp-Name": "x"}
    assert _code(h, body) == -32602
    audit = _Audit()
    with pytest.raises(RequestMetadataError):
        CoSAIStack(audit_logger=audit).check_request_envelope(  # type: ignore[arg-type]
            h, body, ALICE)
    assert audit.entries[0]["method"] == "check_request_envelope:invalid_params"
    h, b = _sql({"region": "eu"})
    b["params"]["arguments"]["region"] = "\ud800"
    assert _code(h, b, tool_schemas=_SCHEMAS) == -32020
    # scanner side never crashes on a hostile value
    from cosai_mcp.protocol import request_metadata_headers, x_mcp_param_headers
    assert "Mcp-Name" not in request_metadata_headers("tools/call", {"name": "\ud800"})
    assert x_mcp_param_headers(_SCHEMAS["sql"], {"region": "\ud800"}) == {}


@pytest.mark.parametrize("claim", [
    {"x": [{"user": "bob"}]},
    {"acme/ctx": [{"tenant_id": "B", "role": "admin"}]},
    {"tenant:id": "evil"},
    {"acme:tenant": "evil"},
    {"x/tenant/id": "evil"},
    {"user@id": "bob"},
    {"acme/organization_id": "B"},
    {"acme/user_email": "bob@x"},
    {"acme/as_user": "bob"},
    {"acme/delegate": "bob"},
    {"acme/actingAs": "bob"},
    {"acme/delegatedUser": "bob"},
    {"traceparent": {"tenant_id": "B"}},
    {"traceparent": "not-a-traceparent"},
    {"tracestate": ["x"]},
    {META_CLIENT_INFO: {"name": "c", "tenant_id": "B"}},
    {"baggage": "enduser.id=bob,env=p"},
    {"baggage": "tenant.id=B"},
])
def test_exploit_meta_identity_smuggling_round2(claim: dict[str, Any]) -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta(claim, ALICE)
    with pytest.raises(MetaTrustError):
        reconcile_meta(claim, ALICE, allowed_keys={"x", "acme/ctx"})


def test_regression_meta_benign_keys_still_pass() -> None:
    reconcile_meta({**_META, "org.example/feature": 1, "x/tenant.id": "acme",
                    "acme/ctx": [{"tenant_id": "acme"}], "baggage": "env=prod",
                    "traceparent": "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01",
                    "tracestate": "k=v"}, ALICE)


def test_regression_meta_list_path_reported() -> None:
    seen: list[tuple[str, ...]] = []
    with pytest.raises(MetaTrustError):
        reconcile_meta({"acme/ctx": [{"tenant_id": "B"}]}, ALICE, on_mismatch=seen.append)
    assert seen == [("acme/ctx>0>tenant_id",)]


# ===========================================================================
# Panel round 3 regressions
# ===========================================================================

def test_regression_meta_list_nesting_counted_and_capabilities_extension_passes() -> None:
    deep: Any = "x"
    for _ in range(1200):
        deep = [deep]
    h, b = _request("tools/list", {"_meta": {"acme/ctx": deep}})
    audit = _Audit()
    with pytest.raises(MetaTrustError):
        CoSAIStack(audit_logger=audit).check_request_envelope(  # type: ignore[arg-type]
            h, b, ALICE)
    assert audit.entries[0]["method"] == "check_request_envelope:meta_mismatch"
    caps = {META_CLIENT_CAPABILITIES: {"extensions": {"io.x/ui": {
        "mimeTypes": ["text/html"], "opts": {}, "a": {"b": {"c": 1}}}}}}
    reconcile_meta(caps, ALICE)


def test_regression_meta_error_keys_strip_control_chars() -> None:
    audit = _Audit()
    h, b = _request("tools/list", {"_meta": {"x/user\nFAKE-LOG-LINE\x00 ": "bob"}})
    with pytest.raises(MetaTrustError) as ei:
        CoSAIStack(audit_logger=audit).check_request_envelope(  # type: ignore[arg-type]
            h, b, ALICE)
    for text in (str(ei.value), json.dumps(audit.entries[0]["params"]["keys"],
                                           ensure_ascii=False)):
        assert "\n" not in text and "\x00" not in text and " " not in text


def test_regression_allowlisted_vendor_key_with_identity_word_passes() -> None:
    reconcile_meta({"x/userAgent": "c"}, ALICE, allowed_keys={"x/userAgent"})
    with pytest.raises(MetaTrustError):
        reconcile_meta({"x/userAgent": "c"}, ALICE)
    with pytest.raises(MetaTrustError):
        reconcile_meta({"x/user": "bob"}, ALICE, allowed_keys={"x/user"})
    with pytest.raises(MetaTrustError):
        reconcile_meta({"x/userAgent": {"tenant": "B"}}, ALICE, allowed_keys={"x/userAgent"})



def test_exploit_integral_float_or_unsafe_int_param_cannot_omit_header() -> None:
    for limit in (5.0, 9007199254740993, "5"):
        h, b = _request("tools/call", {"name": "sql", "arguments": {"limit": limit}})
        with pytest.raises(RequestMetadataError) as ei:
            CoSAIStack().check_request_envelope(h, b, ALICE, tool_schemas=_SCHEMAS)
        assert ei.value.code == -32020


@pytest.mark.parametrize("meta", [
    {"baggage": "%75ser_id=victim"},
    {"baggage": "tenant%5Fid=t2"},
    {"baggage": "k=v;user=bob"},
    {"baggage": "k=v;%75ser"},
    {"tracestate": "user=bob"},
    {"tracestate": "vendor=x,tenant_id=t2"},
])
def test_exploit_percent_encoded_and_property_baggage_identity_rejected(
        meta: dict[str, Any]) -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta(meta, ALICE)


def test_regression_sanitize_baggage_shares_identity_predicate() -> None:
    for key in ("workspace_id", "project_id", "team_id", "customer", "realm", "owner",
                "actor", "delegatedUser"):
        assert sanitize_baggage(f"{key}=t2", [key]) is None
    assert sanitize_baggage("env=p", ["env"]) == "env=p"


def test_exploit_legacy_framed_meta_identity_claim_still_reconciled() -> None:
    audit = _Audit()
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "t", "arguments": {},
                       "_meta": {"user_id": "victim", "roles": ["admin"]}}}
    with pytest.raises(MetaTrustError):
        CoSAIStack(audit_logger=audit).check_request_envelope(  # type: ignore[arg-type]
            {}, body, ALICE)
    assert audit.entries[0]["method"] == "check_request_envelope:meta_mismatch"
    body["params"]["_meta"] = {}
    with pytest.raises(RequestMetadataError) as ei:
        CoSAIStack().check_request_envelope({}, body, ALICE)
    assert ei.value.reason == "missing_meta"     # legacy fallback signal, after reconcile


def test_exploit_one_principal_cannot_exhaust_spent_cache_for_others(
        monkeypatch: pytest.MonkeyPatch) -> None:
    import cosai_mcp.middleware.state as st
    monkeypatch.setattr(st, "_MAX_SPENT_PER_OWNER", 3)
    s = _sealer()
    for _ in range(3):
        s.open(s.seal({}, principal="A", tenant="t", request_id=RID),
               principal="A", tenant="t", request_id=RID)
    with pytest.raises(StateVerificationError):
        s.open(s.seal({}, principal="A", tenant="t", request_id=RID),
               principal="A", tenant="t", request_id=RID)
    assert s.open(s.seal({}, principal="B", tenant="t", request_id=RID),
                  principal="B", tenant="t", request_id=RID) == {}


def test_regression_spent_cache_purges_expired_entries() -> None:
    import cosai_mcp.middleware.state as st
    clock = _Clock()
    s = _sealer(clock=clock, default_ttl_seconds=10)
    for _ in range(5):
        s.open(s.seal({}, principal="A", tenant="t", request_id=RID),
               principal="A", tenant="t", request_id=RID)
    clock.t += 11
    s.open(s.seal({}, principal="A", tenant="t", request_id=RID),
           principal="A", tenant="t", request_id=RID)
    assert len(s._spent) == 1 and s._spent_per_owner == {("A", "t"): 1}
    assert st._MAX_SPENT_PER_OWNER > 0


@pytest.mark.parametrize("key", ["tenant.slug", "acme/tenant.slug", "user.handle",
                                 "acme/tenant/slug", "a/b/c"])
def test_exploit_identity_word_in_non_final_key_segment_rejected(key: str) -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta({key: "t2"}, ALICE)
    reconcile_meta({"io.example/feature": 1, "io.example/feature.flag": True}, ALICE)


# ===========================================================================
# Panel round 4 regressions
# ===========================================================================

@pytest.mark.parametrize("key", ["x/us​er.handle", "x/ten­ant.slug",
                                 "x/ro⁠le.name"])
def test_regression_identity_key_zero_width_and_soft_hyphen_split(key: str) -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta({key: "t2"}, ALICE)
    bkey = key.split("/", 1)[1]
    assert sanitize_baggage(f"{bkey}=1", [bkey]) is None
    reconcile_meta({"io.example/feature.flag": True}, ALICE)



def test_exploit_legacy_batch_meta_identity_claim_still_reconciled() -> None:
    audit = _Audit()
    body = [{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "t", "_meta": {"acme/tenant_id": "victim"}}}]
    with pytest.raises(MetaTrustError):
        CoSAIStack(audit_logger=audit).check_request_envelope(  # type: ignore[arg-type]
            {}, body, ALICE)
    assert audit.entries[0]["method"] == "check_request_envelope:meta_mismatch"
    with pytest.raises(MetaTrustError):
        CoSAIStack().check_request_envelope({}, [body[0], "junk"], ALICE)
    ok = [{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}]
    with pytest.raises(RequestMetadataError) as ei:
        CoSAIStack().check_request_envelope({}, ok, ALICE)
    assert ei.value.code == -32600


@pytest.mark.parametrize("key", ["acme/userrole", "acme/TENANTNAME", "acme/issuperuser",
                                 "acme/adminmode", "acme/actasuser"])
def test_exploit_unsegmented_compound_identity_key_rejected(key: str) -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta({key: "admin"}, ALICE)


def test_regression_compound_identity_baggage_and_allowlist() -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta({"baggage": "userrole=admin"}, ALICE)
    reconcile_meta({"acme/useragent": "c"}, ALICE, allowed_keys={"acme/useragent"})
    reconcile_meta({"io.example/feature.flag": True, "acme/ctx": {"mode": 1}}, ALICE)


def test_exploit_many_principals_cannot_exhaust_spent_cache_or_handle_registry(
        monkeypatch: pytest.MonkeyPatch) -> None:
    import cosai_mcp.middleware.state as st
    monkeypatch.setattr(st, "_MAX_SPENT_ENTRIES", 4)
    monkeypatch.setattr(st, "_MAX_SPENT_PER_OWNER", 100)
    monkeypatch.setattr(st, "_OWNER_FLOOR", 2)
    s = _sealer()

    def redeem(p: str) -> None:
        s.open(s.seal({}, principal=p, tenant="t", request_id=RID),
               principal=p, tenant="t", request_id=RID)

    for p in ("A", "A", "B", "B"):
        redeem(p)
    with pytest.raises(StateVerificationError):
        redeem("A")                       # at floor, global full
    redeem("victim")                      # below floor: admitted
    reg = HandleRegistry(max_handles=4, max_handles_per_principal=100,
                         max_handles_per_tenant=100)
    monkeypatch.setattr(st, "_OWNER_FLOOR", 2)
    for p in ("A", "A", "B", "B"):
        reg.mint(principal=p, tenant="t", kind="task", ttl_seconds=60)
    with pytest.raises(RuntimeError):
        reg.mint(principal="A", tenant="t", kind="task", ttl_seconds=60)
    assert reg.mint(principal="victim", tenant="t", kind="task", ttl_seconds=60)


def test_exploit_envelope_audit_entry_names_subject_and_keys_not_unsalted_digest(
        tmp_path: Any) -> None:
    from cosai_mcp.middleware import AuditLogger
    log = AuditLogger(tmp_path / "audit.log")
    h, b = _request("tools/list", {"_meta": {"x/user\n": "<bob>"}})
    with pytest.raises(MetaTrustError):
        CoSAIStack(audit_logger=log).check_request_envelope(h, b, ALICE)
    h, b = _request("tools/list", {})
    h["Mcp-Method"] = "tools/call"
    with pytest.raises(RequestMetadataError):
        CoSAIStack(audit_logger=log).check_request_envelope(h, b, ALICE)
    assert log.verify_chain() == 2
    lines = [json.loads(x) for x in (tmp_path / "audit.log").read_text().splitlines()]
    assert lines[0]["event"] == {"principal": "alice", "keys": ["x/user?"]}
    assert lines[1]["event"] == {"principal": "alice", "code": -32020, "check": "Mcp-Method"}
    assert "bob" not in (tmp_path / "audit.log").read_text()


# ===========================================================================
# Panel round 5 regressions
# ===========================================================================

@pytest.mark.parametrize("key", ["x/us️er.handle", "x/ten͏ant.slug",
                                 "x/róle.name"])
def test_regression_identity_key_combining_mark_and_variation_selector_split(key: str) -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta({key: "t2"}, ALICE)
    bkey = key.split("/", 1)[1]
    assert sanitize_baggage(f"{bkey}=1", [bkey]) is None
    reconcile_meta({"io.example/feature.flag": True}, ALICE)


@pytest.mark.parametrize("key", ["x/team.name", "x/caller.id", "x/groupName",
                                 "x/projectName", "x/actas", "x/onBehalfOf.x"])
def test_regression_identity_names_without_token_counterpart_rejected(key: str) -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta({key: "t2"}, ALICE)


def test_regression_identity_names_and_tokens_stay_in_sync() -> None:
    from cosai_mcp.meta_identity import IDENTITY_NAMES, TOKEN_EXEMPT_WORDS, has_identity_word
    assert [w for w in IDENTITY_NAMES - TOKEN_EXEMPT_WORDS
            if not has_identity_word(w + ".x")] == []
    # pinned exemptions: common non-identity compounds stay allowed
    reconcile_meta({"x/rootDir": "/", "x/clientVersion": "1", "x/actions": []}, ALICE)


def test_regression_audit_event_field_backward_compatible_chain(tmp_path: Any) -> None:
    from cosai_mcp.middleware import AuditLogger
    from cosai_mcp.middleware.audit import (
        AuditChainError,
        AuditEntry,
        _compute_chain_hash,
    )

    path = tmp_path / "audit.log"
    legacy = {"entry_id": "e1", "parent_id": None, "session_id": "s", "method": "m",
              "params_digest": "0" * 64, "timestamp_utc": 1.0, "prev_hash": "0" * 64}
    legacy["chain_hash"] = _compute_chain_hash(legacy)
    path.write_text(json.dumps(legacy, sort_keys=True, separators=(",", ":")) + "\n")
    log = AuditLogger(path)
    log.log(method="check", session_id="s", event={"principal": "alice"})
    assert log.verify_chain() == 2
    entries = log.entries()
    assert entries[0].event is None and entries[1].event == {"principal": "alice"}
    for e in entries:
        assert AuditEntry.from_dict(e.to_dict()) == e
    assert "event" not in entries[0].to_dict()
    tampered = path.read_text().replace('"principal":"alice"', '"principal":"mallory"')
    path.write_text(tampered)
    with pytest.raises(AuditChainError):
        log.verify_chain()


def test_regression_audit_event_values_capped_and_sanitized() -> None:
    from cosai_mcp.middleware.audit import _clean_event
    ev = _clean_event({**{f"k{i}": i for i in range(40)}})
    assert len(ev) == 16
    ev = _clean_event({"s": "a\nb\x00" + "x" * 500, "l": list(range(100)), "o": object()})
    assert ev["s"].startswith("a?b?") and len(ev["s"]) == 256
    assert len(ev["l"]) == 32 and isinstance(ev["o"], str)


def test_regression_owner_floor_hard_ceiling_and_boundary(
        monkeypatch: pytest.MonkeyPatch) -> None:
    import cosai_mcp.middleware.state as st
    monkeypatch.setattr(st, "_MAX_SPENT_ENTRIES", 2)
    monkeypatch.setattr(st, "_MAX_SPENT_PER_OWNER", 100)
    monkeypatch.setattr(st, "_OWNER_FLOOR", 2)
    clock = _Clock()
    s = _sealer(clock=clock, default_ttl_seconds=10)

    def redeem(p: str) -> None:
        s.open(s.seal({}, principal=p, tenant="t", request_id=RID),
               principal=p, tenant="t", request_id=RID)

    redeem("A")
    redeem("A")                   # global full (2)
    redeem("B")                   # B=0 < floor: admitted
    redeem("B")                   # B=1 < floor: admitted (total 4 = 2x ceiling)
    with pytest.raises(StateVerificationError):
        redeem("C")               # below floor but at the 2x hard ceiling
    clock.t += 11
    redeem("C")
    assert s._spent_per_owner == {("C", "t"): 1}

    reg = HandleRegistry(max_handles=2, max_handles_per_principal=100,
                         max_handles_per_tenant=100)
    for p in ("A", "A", "B", "B"):
        reg.mint(principal=p, tenant="t", kind="task", ttl_seconds=60)
    with pytest.raises(RuntimeError):
        reg.mint(principal="C", tenant="t", kind="task", ttl_seconds=60)
    with pytest.raises(RuntimeError):
        reg.mint(principal="B", tenant="t", kind="task", ttl_seconds=60)  # B at floor



def test_exploit_raw_bytes_body_with_meta_identity_not_fallback_eligible() -> None:
    _, b = _request("tools/list", {"_meta": {"tenant_id": "victim"}})
    raw = json.dumps(b)
    for body in (raw, raw.encode()):
        audit = _Audit()
        with pytest.raises(TypeError):
            CoSAIStack(audit_logger=audit).check_request_envelope(  # type: ignore[arg-type]
                {}, body, ALICE)
        assert audit.entries[0]["method"] == "check_request_envelope:invalid_body"


def test_exploit_single_tenant_sybils_cannot_exhaust_other_tenants(
        monkeypatch: pytest.MonkeyPatch) -> None:
    import cosai_mcp.middleware.state as st
    monkeypatch.setattr(st, "_OWNER_FLOOR", 0)   # isolate the tenant partition
    reg = HandleRegistry(max_handles=100, max_handles_per_principal=1000)
    minted = 0
    for i in range(100):
        try:
            reg.mint(principal=f"sybil{i}", tenant="evil", kind="task", ttl_seconds=60)
            minted += 1
        except RuntimeError:
            pass
    assert minted == 25                          # tenant share = max // 4
    assert reg.mint(principal="bob", tenant="good", kind="task", ttl_seconds=60)

    monkeypatch.setattr(st, "_MAX_SPENT_PER_TENANT", 3)
    s = _sealer()

    def redeem(p: str, t: str) -> None:
        s.open(s.seal({}, principal=p, tenant=t, request_id=RID),
               principal=p, tenant=t, request_id=RID)

    for i in range(3):
        redeem(f"sybil{i}", "evil")
    with pytest.raises(StateVerificationError):
        redeem("sybil9", "evil")
    redeem("bob", "good")


# ===========================================================================
# Panel round 6 regressions
# ===========================================================================

def test_regression_tenant_counters_released_on_expiry_revoke_and_purge(
        monkeypatch: pytest.MonkeyPatch) -> None:
    import cosai_mcp.middleware.state as st
    monkeypatch.setattr(st, "_MAX_SPENT_PER_TENANT", 2)
    monkeypatch.setattr(st, "_OWNER_FLOOR", 0)   # isolate the tenant cap itself
    clock = _Clock()
    s = _sealer(clock=clock, default_ttl_seconds=10)

    def redeem(p: str) -> None:
        s.open(s.seal({}, principal=p, tenant="T", request_id=RID),
               principal=p, tenant="T", request_id=RID)

    redeem("a")
    redeem("b")
    with pytest.raises(StateVerificationError):
        redeem("c")
    clock.t += 11
    redeem("c")                                   # expiry released the tenant cap
    assert s._spent_per_tenant == {"T": 1}

    clock2 = _Clock()
    reg = HandleRegistry(max_handles_per_tenant=2, clock=clock2)
    h1 = reg.mint(principal="a", tenant="T", kind="task", ttl_seconds=60)
    h2 = reg.mint(principal="b", tenant="T", kind="task", ttl_seconds=60)
    other = reg.mint(principal="a", tenant="U", kind="task", ttl_seconds=60)
    with pytest.raises(RuntimeError):
        reg.mint(principal="c", tenant="T", kind="task", ttl_seconds=60)
    reg.revoke(h1, principal="a", tenant="T")
    h3 = reg.mint(principal="c", tenant="T", kind="task", ttl_seconds=5)  # cap released
    reg.admin_revoke(h2)
    reg.revoke_principal("c", tenant="T")
    assert reg._tenant_counts == {"U": 1} and reg._counts == {("a", "U"): 1}
    with pytest.raises(HandleError):
        reg.resolve(h3, principal="c", tenant="T")
    reg.mint(principal="d", tenant="T", kind="task", ttl_seconds=5)
    clock2.t += 6
    assert reg.list_for_principal("d") == []      # expiry purge
    assert reg._tenant_counts == {"U": 1}
    assert reg.resolve(other, principal="a", tenant="U")


def test_regression_identity_affix_false_positives_allowed() -> None:
    benign = ["x/scalingFactor", "x/refactor", "x/telescope", "x/steam", "x/teamwork",
              "x/groupingMode"]
    reconcile_meta(dict.fromkeys(benign, 1), ALICE)
    for k in benign:
        b = k.split("/", 1)[1]
        assert sanitize_baggage(f"{b}=1", [b]) == f"{b}=1"
    for k in ("x/userrole", "x/TENANTNAME", "x/issuperuser", "x/userId", "x/adminmode",
              "x/actasuser"):
        with pytest.raises(MetaTrustError):
            reconcile_meta({k: "admin"}, ALICE)


@pytest.mark.parametrize("meta", ["tenant=victim", ["x"], 7])
def test_exploit_non_mapping_meta_not_fallback_eligible(meta: Any) -> None:
    audit = _Audit()
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": meta}}
    with pytest.raises(MetaTrustError):
        CoSAIStack(audit_logger=audit).check_request_envelope(  # type: ignore[arg-type]
            {}, body, ALICE)
    assert audit.entries[0]["method"] == "check_request_envelope:meta_mismatch"


@pytest.mark.parametrize("meta", [
    {"tenant/id": "victim"}, {"user/id": "victim"}, {"org/id": "victim"},
    {"tenant/name": "victim"}, {"tenant/slug": "victim"}, {"acme.tenant/id": "victim"},
    {"com.acme.user/id": "victim"},
    {"acme/ctx": {"tenant/id": "victim"}},
    {META_CLIENT_INFO: {"name": "x", "tenant/id": "v"}},
    {"tracestate": "tenant/id=x"},
])
def test_exploit_identity_word_in_meta_prefix_or_nested_slash_key_rejected(
        meta: dict[str, Any]) -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta(meta, ALICE)


def test_regression_reverse_dns_prefix_still_allowed() -> None:
    reconcile_meta({"org.example/feature": 1, "com.example.tools/flag": True,
                    "io.example/feature.flag": True}, ALICE)


def test_exploit_intra_tenant_sybils_cannot_lock_out_tenant_peers(
        monkeypatch: pytest.MonkeyPatch) -> None:
    import cosai_mcp.middleware.state as st
    monkeypatch.setattr(st, "_MAX_SPENT_PER_TENANT", 4)
    monkeypatch.setattr(st, "_OWNER_FLOOR", 2)
    s = _sealer()

    def redeem(p: str) -> None:
        s.open(s.seal({}, principal=p, tenant="default", request_id=RID),
               principal=p, tenant="default", request_id=RID)

    for p in ("s1", "s1", "s2", "s2"):
        redeem(p)
    with pytest.raises(StateVerificationError):
        redeem("s1")                  # Sybil at floor, tenant full
    redeem("alice")                   # peer below floor still admitted
    reg = HandleRegistry(max_handles_per_tenant=4)
    for p in ("s1", "s1", "s2", "s2"):
        reg.mint(principal=p, tenant="default", kind="task", ttl_seconds=60)
    with pytest.raises(RuntimeError):
        for _ in range(st._OWNER_FLOOR + 1):
            reg.mint(principal="s1", tenant="default", kind="task", ttl_seconds=60)
    assert reg.mint(principal="alice", tenant="default", kind="task", ttl_seconds=60)


@pytest.mark.parametrize("claim", [{"acme/tid": "victim-tenant"}, {"acme/oid": "victim"},
                                   {"acme/upn": "v@x"}, {"acme/wids": ["r"]},
                                   {"acme/iss": "https://x"}, {"acme/aud": "y"},
                                   {"acme/login": "victim"}, {"acme/unique_name": "v"},
                                   {"acme/appid": "v"}, {"acme/cid": "v"},
                                   {"acme/resource_access": {}}, {"acme/given_name": "v"}])
def test_exploit_entra_oidc_claim_names_rejected(claim: dict[str, Any]) -> None:
    with pytest.raises(MetaTrustError):
        reconcile_meta(claim, ALICE)



def test_exploit_entra_oidc_claim_names_rejected_v1() -> None:
    assert sanitize_baggage("unique_name=v", ["unique_name"]) is None
    assert sanitize_baggage("given_name=v", ["given_name"]) is None


def test_regression_owner_floor_tenant_2x_ceiling_sealer_and_registry(
        monkeypatch: pytest.MonkeyPatch) -> None:
    import cosai_mcp.middleware.state as st
    monkeypatch.setattr(st, "_MAX_SPENT_PER_TENANT", 2)
    monkeypatch.setattr(st, "_OWNER_FLOOR", 2)
    s = _sealer()

    def redeem(p: str) -> None:
        s.open(s.seal({}, principal=p, tenant="T", request_id=RID),
               principal=p, tenant="T", request_id=RID)

    redeem("a")
    redeem("a")                       # tenant cap reached
    redeem("b")                       # b below floor: admitted
    redeem("c")                       # c below floor: admitted (tenant = 4 = 2x)
    with pytest.raises(StateVerificationError):
        redeem("d")                   # below floor, but tenant 2x ceiling reached
    assert s._spent_per_tenant == {"T": 4}

    reg = HandleRegistry(max_handles_per_tenant=2)
    for p in ("a", "a"):
        reg.mint(principal=p, tenant="T", kind="task", ttl_seconds=60)
    with pytest.raises(RuntimeError):
        reg.mint(principal="a", tenant="T", kind="task", ttl_seconds=60)   # a at floor
    reg.mint(principal="b", tenant="T", kind="task", ttl_seconds=60)
    reg.mint(principal="c", tenant="T", kind="task", ttl_seconds=60)
    with pytest.raises(RuntimeError):
        reg.mint(principal="d", tenant="T", kind="task", ttl_seconds=60)   # 2x ceiling
    assert reg._tenant_counts == {"T": 4}


ADMIN = AuthenticatedPrincipal(subject="alice", tenant="t1", scopes=frozenset({"admin"}))


def test_exploit_admin_key_mapping_value_cannot_smuggle_nested_claims() -> None:
    meta = {"acme/admin": {"tenant": "t2", "user": "bob", "roles": ["root"]}}
    with pytest.raises(MetaTrustError):
        reconcile_meta(meta, ADMIN)
    with pytest.raises(MetaTrustError):
        reconcile_meta(meta, ADMIN, allowed_keys=["acme/admin"])
    reconcile_meta({"acme/admin": True}, ADMIN)            # scalar restating scope is fine


def test_exploit_response_body_result_meta_identity_claim_reconciled() -> None:
    resp = {"jsonrpc": "2.0", "id": 1, "result": {"_meta": {"tenant": "other"}}}
    err = {"jsonrpc": "2.0", "id": 2, "error": {"code": 1, "message": "x",
                                               "data": {"_meta": {"user": "bob"}}}}
    for body in (resp, [resp], err, [err]):
        with pytest.raises(MetaTrustError):
            CoSAIStack().check_request_envelope({}, body, ALICE)
    clean = {"jsonrpc": "2.0", "id": 1, "result": {}}
    with pytest.raises(RequestMetadataError) as ei:
        CoSAIStack().check_request_envelope({}, clean, ALICE)
    assert ei.value.code == -32600 and ei.value.reason == "not_a_request"
    with pytest.raises(RequestMetadataError) as ei:
        CoSAIStack().check_request_envelope({}, [clean], ALICE)
    assert ei.value.reason == "batch"


def test_regression_invalid_request_reason_not_fallback_eligible() -> None:
    for body in ({"jsonrpc": "2.0", "id": 1, "method": 5},
                 {"jsonrpc": "2.0", "id": 1, "method": None}, 7):
        with pytest.raises(RequestMetadataError) as ei:
            validate_request_metadata({}, body)
        assert ei.value.code == -32600 and ei.value.reason == "invalid_request"
    with pytest.raises(RequestMetadataError) as ei:
        validate_request_metadata({}, [])
    assert ei.value.reason == "batch"
    audit = _Audit()
    with pytest.raises(RequestMetadataError):
        CoSAIStack(audit_logger=audit).check_request_envelope(  # type: ignore[arg-type]
            {}, {"id": 1, "result": {}}, ALICE)
    assert audit.entries[-1]["params"]["check"] == "not_a_request"
    assert audit.entries[-1]["event"]["check"] == "not_a_request"



def _reason(headers: Any, body: Any) -> tuple[int, str]:
    with pytest.raises(RequestMetadataError) as ei:
        CoSAIStack().check_request_envelope(headers, body, ALICE)
    return ei.value.code, ei.value.reason


def test_exploit_modern_routing_headers_with_legacy_body_not_fallback_eligible() -> None:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "delete_all", "arguments": {}}}
    modern = {"MCP-Protocol-Version": MODERN_PROTOCOL_VERSION, "Mcp-Method": "tools/call",
              "Mcp-Name": "read_only_search", "Mcp-Param-Region": "us"}
    assert _reason(modern, body)[0] == -32020
    assert _reason(modern, [body])[0] == -32020
    assert _reason({"Mcp-Name": "read_only_search"}, body)[0] == -32020
    assert _reason({"Mcp-Param-Region": "us"}, [body])[0] == -32020
    assert _reason({"MCP-Protocol-Version": MODERN_PROTOCOL_VERSION}, body)[0] == -32020
    assert _reason({}, body) == (-32602, "missing_meta")
    assert _reason({"MCP-Protocol-Version": "2025-11-25"}, body) == (-32602, "missing_meta")
    assert _reason({"MCP-Protocol-Version": "2025-03-26"}, [body]) == (-32600, "batch")


@pytest.mark.parametrize("value", [{"user_id": "victim"}, ["admin"], 123, "x" * 100])
def test_exploit_nonstring_protocol_version_cannot_carry_unreconciled_claims(
        value: Any) -> None:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": {"_meta": {META_PROTOCOL_VERSION: value}}}
    with pytest.raises(MetaTrustError):
        CoSAIStack().check_request_envelope({}, body, ALICE)
    if not isinstance(value, str):
        with pytest.raises(RequestMetadataError) as ei:
            validate_request_metadata({}, body)
        assert ei.value.reason == "invalid_meta"
    h, b = _request("tools/list", {})
    assert CoSAIStack().check_request_envelope(h, b, ALICE) == MODERN_PROTOCOL_VERSION


def test_regression_invalid_meta_reason_and_gate_duplicate_header() -> None:
    def body(meta: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": meta}}

    modern = {"MCP-Protocol-Version": MODERN_PROTOCOL_VERSION, "Mcp-Method": "tools/list"}
    for meta in (["x"], 7, "tenant=v", {META_PROTOCOL_VERSION: None}):
        for headers in ({}, modern):
            with pytest.raises(RequestMetadataError) as ei:
                validate_request_metadata(headers, body(meta))
            assert (ei.value.code, ei.value.reason) == (-32602, "invalid_meta")
    no_meta = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    dup = [("MCP-Protocol-Version", "2025-11-25"), ("MCP-Protocol-Version", "2025-11-25")]
    assert _code(dup, no_meta) == -32020
    assert _reason({"MCP-Protocol-Version": "1900-01-01"}, [no_meta]) == (
        -32022, "unsupported_version")
    assert _reason({"MCP-Protocol-Version": "1900-01-01"}, no_meta) == (
        -32022, "unsupported_version")


def test_exploit_bytes_header_pairs_cannot_bypass_legacy_gate() -> None:
    legacy_body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "delete_all", "arguments": {}}}
    asgi = [(b"mcp-method", b"tools/call"), (b"mcp-name", b"delete_all"),
            (b"mcp-protocol-version", MODERN_PROTOCOL_VERSION.encode())]
    code, reason = _reason(asgi, legacy_body)
    assert code == -32020 and reason != "missing_meta"
    wsgi = {"HTTP_MCP_METHOD": "tools/call", "HTTP_MCP_NAME": "delete_all"}
    assert _reason(wsgi, legacy_body)[0] == -32020
    h, b = _request("tools/call", {"name": "echo", "arguments": {}})
    pairs = [(k.encode(), v.encode()) for k, v in h.items()]
    assert CoSAIStack().check_request_envelope(pairs, b, ALICE) == MODERN_PROTOCOL_VERSION
    with pytest.raises(TypeError):
        CoSAIStack().check_request_envelope([("Mcp-Method", 5)], legacy_body, ALICE)


def test_regression_header_input_normalization_matrix() -> None:
    legacy = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": "delete_all", "arguments": {}}}
    assert _reason({b"Mcp-Method": b"tools/call", b"Mcp-Name": b"delete_all"}, legacy)[0] \
        == -32020
    assert _reason({b"MCP-METHOD": b"tools/call"}, legacy)[0] == -32020
    assert _reason([(bytearray(b"Mcp-Method"), bytearray(b"tools/call"))], legacy)[0] \
        == -32020
    assert _reason({"HTTP_MCP_PARAM_REGION": "us"}, [legacy]) == (-32020, "header-alias")
    with pytest.raises(RequestMetadataError) as ei:
        CoSAIStack().check_request_envelope({"HTTP_MCP_PARAM_REGION": "us"}, [legacy], ALICE,
                                            wsgi_environ=True)
    assert (ei.value.code, ei.value.reason) == (-32020, "Mcp-Param-*")
    for bad in ([(1, "x")], [("Mcp-Method", None)]):
        audit = _Audit()
        with pytest.raises(TypeError):
            CoSAIStack(audit_logger=audit).check_request_envelope(  # type: ignore[arg-type]
                bad, legacy, ALICE)
        assert audit.entries[-1]["method"] == "check_request_envelope:invalid_headers"
    h, b = _request("tools/list", {})
    padded = dict(h, **{"Mcp-Method": " tools/list"})
    assert _reason(padded, b)[0] == -32020
    as_bytes = {k.encode(): v.encode() for k, v in h.items()}
    assert CoSAIStack().check_request_envelope(as_bytes, b, ALICE) == MODERN_PROTOCOL_VERSION
    h, b = _request("tools/call", {"name": "café", "arguments": {}})
    latin = [(k.encode(), v.encode("latin-1")) for k, v in h.items()]
    assert CoSAIStack().check_request_envelope(latin, b, ALICE) == MODERN_PROTOCOL_VERSION



def test_exploit_http_prefixed_or_underscore_header_alias_rejected() -> None:
    h, b = _request("tools/list", {})
    aliased = [("http_mcp_protocol_version", MODERN_PROTOCOL_VERSION),
               ("http_mcp_method", "tools/list")]
    assert _reason(aliased, b) == (-32020, "header-alias")
    legacy = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    code, reason = _reason([("Mcp_Method", "tools/list")], legacy)
    assert code == -32020 and reason != "missing_meta"
    environ = {"wsgi.input": object(), "wsgi.version": (1, 0), "wsgi.multithread": True,
               "REQUEST_METHOD": "POST",
               "HTTP_MCP_PROTOCOL_VERSION": MODERN_PROTOCOL_VERSION,
               "HTTP_MCP_METHOD": "tools/list"}
    assert CoSAIStack().check_request_envelope(environ, b, ALICE,
                                               wsgi_environ=True) == MODERN_PROTOCOL_VERSION
    with pytest.raises(RequestMetadataError) as ei:
        CoSAIStack().check_request_envelope({"HTTP_MCP_METHOD": "tools/call"}, legacy, ALICE,
                                            wsgi_environ=True)
    assert ei.value.code == -32020


def test_exploit_wsgi_input_header_name_cannot_switch_mode() -> None:
    legacy = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": "delete_all", "arguments": {}}}
    spoof = {"wsgi.input": "x", "mcp-method": "tools/call", "mcp-name": "delete_all"}
    assert _reason(spoof, legacy)[0] == -32020
    assert _reason([(b"wsgi.input", b"x"), (b"mcp-method", b"tools/call")], legacy)[0] \
        == -32020
    assert _reason({"wsgi.input": "x", "Mcp_Method": "tools/call"}, legacy) == (
        -32020, "header-alias")
    # an environ-shaped mapping is NOT treated as an environ unless the caller
    # says so: its non-string entries fail closed, never a fallback signal
    with pytest.raises(TypeError):
        CoSAIStack().check_request_envelope(
            {"wsgi.input": object(), "HTTP_MCP_METHOD": "tools/call"}, legacy, ALICE)


def test_exploit_list_valued_header_map_with_wsgi_input_header_not_fallback_eligible() -> None:
    legacy = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": "delete_all", "arguments": {}}}
    with pytest.raises(TypeError):
        CoSAIStack().check_request_envelope(
            {"mcp-method": ["tools/call"], "wsgi.input": ["1"]}, legacy, ALICE)


@pytest.mark.parametrize("bad", [[("a", "b", "c")], ["ab"], [5]])
def test_regression_header_pair_shape_error_audited(bad: Any) -> None:
    legacy = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    audit = _Audit()
    with pytest.raises(TypeError):
        CoSAIStack(audit_logger=audit).check_request_envelope(  # type: ignore[arg-type]
            bad, legacy, ALICE)
    assert audit.entries[-1]["method"] == "check_request_envelope:invalid_headers"


@pytest.mark.parametrize("bad", [[("HTTP_MCP_METHOD", "tools/call")],
                                 {"HTTP_MCP_METHOD": ["tools/call"]},
                                 {"HTTP_MCP_METHOD": None}])
def test_regression_wsgi_environ_mode_shape_errors_audited(bad: Any) -> None:
    legacy = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    audit = _Audit()
    with pytest.raises(TypeError):
        CoSAIStack(audit_logger=audit).check_request_envelope(  # type: ignore[arg-type]
            bad, legacy, ALICE, wsgi_environ=True)
    assert audit.entries[-1]["method"] == "check_request_envelope:invalid_headers"


def test_regression_wsgi_environ_skips_non_http_keys_and_gates_routing() -> None:
    legacy = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    with pytest.raises(RequestMetadataError) as ei:
        CoSAIStack().check_request_envelope(
            {"wsgi.input": object(), "HTTP_MCP_METHOD": "tools/call"}, legacy, ALICE,
            wsgi_environ=True)
    assert ei.value.code == -32020
