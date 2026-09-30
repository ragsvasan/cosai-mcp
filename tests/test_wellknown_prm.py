"""RFC 9728 Protected Resource Metadata check (CoSAI v2.0 SD-04) and the RFC 8707
audience-restriction probe T01-008 (AZ-06).

The PRM check only ever contacts the scanned target's own origin through the
pinned transport (Mnemo dec_451b2d49f9); an off-origin ``resource_metadata`` is
reported and never fetched.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from cosai_mcp import Scanner
from cosai_mcp.assurance import Verdict, evaluate_assurance
from cosai_mcp.config import ScanConfig
from cosai_mcp.harness.mock_server import MockMCPServer
from cosai_mcp.harness.result import ProbeResult
from cosai_mcp.transport.streamable_http import StreamableHTTPTransport
from cosai_mcp.wellknown import scan_protected_resource_metadata

_PRM_PATH = "/.well-known/oauth-protected-resource/mcp"


def _config(port: int) -> ScanConfig:
    return ScanConfig(target_host="127.0.0.1", target_port=port,
                      allow_private_targets=True, probe_timeout_seconds=10.0)


def _prm(server: MockMCPServer, **overrides: Any) -> dict[str, Any]:
    doc = {"resource": f"http://127.0.0.1:{server.port}/mcp",
           "authorization_servers": ["https://auth.example.com"]}
    doc.update(overrides)
    return doc


def _run(mock_kwargs: dict[str, Any], prm_builder: Any = None) -> tuple[list[ProbeResult], Any]:
    with MockMCPServer(require_bearer="good", **mock_kwargs) as server:
        server.wait_ready()
        if prm_builder is not None:
            server._well_known.update(prm_builder(server))
        results = scan_protected_resource_metadata(
            f"http://127.0.0.1:{server.port}/mcp", _config(server.port))
        gets = list(server._get_log)
    return results, gets


class TestPrmCheck:
    def test_valid_prm_passes(self) -> None:
        results, gets = _run({}, lambda s: {_PRM_PATH: _prm(s)})
        assert len(results) == 1 and results[0].passed is True
        assert gets[0] == _PRM_PATH

    def test_advertised_same_origin_metadata_is_used(self) -> None:
        results, gets = _run(
            {"www_authenticate": 'Bearer resource_metadata="/custom/prm.json"'},
            lambda s: {"/custom/prm.json": _prm(s)})
        assert results[0].passed is True and gets == ["/custom/prm.json"]

    def test_missing_prm_is_a_finding(self) -> None:
        results, _ = _run({})
        assert results[0].passed is False and results[0].inconclusive_reason is None
        assert "serves no usable" in results[0].response_body

    def test_resource_mismatch_is_a_finding(self) -> None:
        results, _ = _run({}, lambda s: {_PRM_PATH: _prm(s, resource="https://other.example/mcp")})
        assert results[0].passed is False
        assert "does not identify this MCP server" in results[0].response_body

    @pytest.mark.parametrize("servers", [[], ["http://auth.example.com"], ["not a url"]])
    def test_bad_authorization_servers_are_findings(self, servers: list[str]) -> None:
        results, _ = _run({}, lambda s: {_PRM_PATH: _prm(s, authorization_servers=servers)})
        assert results[0].passed is False

    def test_off_origin_metadata_reported_never_fetched(self) -> None:
        results, gets = _run(
            {"www_authenticate": 'Bearer resource_metadata="https://evil.example/prm"'})
        # Off-origin advertisement is reported (never fetched); with no same-origin
        # metadata either, the check fails.
        assert results[0].passed is False and "another origin" in results[0].response_body
        assert all(not g.startswith("http") for g in gets)

    def test_no_auth_required_is_inconclusive(self) -> None:
        with MockMCPServer() as server:
            server.wait_ready()
            results = scan_protected_resource_metadata(
                f"http://127.0.0.1:{server.port}/mcp", _config(server.port))
        assert results[0].inconclusive_reason and results[0].passed is False

    def test_hostile_text_is_escaped(self) -> None:
        results, _ = _run({}, lambda s: {_PRM_PATH: _prm(s, resource="<script>x</script>")})
        assert "<script>" not in results[0].response_body


def test_request_raw_refuses_cross_origin() -> None:
    async def _go() -> None:
        with MockMCPServer() as server:
            server.wait_ready()
            t = StreamableHTTPTransport(f"http://127.0.0.1:{server.port}/mcp",
                                        _config(server.port))
            await t.connect()
            try:
                with pytest.raises(ValueError, match="cross-origin"):
                    await t.request_raw("GET", "http://example.com/.well-known/x")
            finally:
                await t.close()

    asyncio.run(_go())


def test_prm_finding_reaches_sarif(tmp_path: Path) -> None:
    from cosai_mcp.cli import main

    sarif = tmp_path / "out.sarif"
    with MockMCPServer(require_bearer="good") as server:
        server.wait_ready()
        CliRunner().invoke(main, [
            "scan", f"http://127.0.0.1:{server.port}/mcp", "--allow-private-targets",
            "--categories", "T1", "--engine", "prober", "--no-report",
            "--auth-token", "good", "--report-sarif", str(sarif),
        ])
    results = json.loads(sarif.read_text())["runs"][0]["results"]
    assert "T01-100" in {r["ruleId"] for r in results}


# ===========================================================================
# T01-008 — RFC 8707 audience restriction
# ===========================================================================

def _jwt(aud: Any = "https://other-api.example/", exp_in: float = 600.0) -> str:
    import base64
    import time

    def b64(obj: Any) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{b64({'alg': 'RS256'})}.{b64({'aud': aud, 'exp': time.time() + exp_in})}.sig"


FOREIGN = _jwt()


def _t01_008(mock_kwargs: dict[str, Any], foreign: str | None) -> list[Any]:
    with MockMCPServer(require_bearer="good", **mock_kwargs) as server:
        server.wait_ready()
        result = Scanner(f"http://127.0.0.1:{server.port}/mcp", categories=["T1"],
                         engine="prober", allow_private_targets=True,
                         probe_timeout_seconds=10.0, auth_token="good",
                         foreign_audience_token=foreign).run()
    found = [r for r in result.probe_results if r.threat_id == "T01-008"]
    assert found
    return found


def test_foreign_audience_token_rejected_passes() -> None:
    assert all(r.passed is True for r in _t01_008({}, FOREIGN))


def test_foreign_audience_token_accepted_is_a_finding() -> None:
    results = _t01_008({"accept_any_bearer": True}, FOREIGN)
    assert all(r.passed is False and r.inconclusive_reason is None and r.error is None
               for r in results), results


def test_without_foreign_token_is_inconclusive() -> None:
    results = _t01_008({}, None)
    assert all(r.inconclusive_reason and "--foreign-audience-token" in r.inconclusive_reason
               for r in results)


# ===========================================================================
# Assurance links
# ===========================================================================

def _pr(threat_id: str, passed: bool) -> ProbeResult:
    return ProbeResult(probe_id=f"{threat_id}-p", threat_id=threat_id, passed=passed,
                       status_code=200, response_body="", error=None, assertions=(),
                       duration_seconds=0.0)


def _verdict(report: Any, cid: str) -> Verdict:
    return next(c.verdict for c in report.controls if c.control_id == cid)


def test_prm_finding_fails_sd04() -> None:
    assert _verdict(evaluate_assurance(3, [_pr("T01", False)]), "SD-04") is Verdict.FAIL


def test_audience_finding_fails_az06() -> None:
    assert _verdict(evaluate_assurance(3, [_pr("T01-008", False)]), "AZ-06") is Verdict.FAIL



# ===========================================================================
# Adversary PRM-round regressions
# ===========================================================================

def test_exploit_t01_008_invalid_params_is_not_pass() -> None:
    """T01-008 uses tools/list: a server that accepts the foreign token cannot
    hide behind an argument-validation error."""
    bad_args = {"jsonrpc": "2.0", "id": 0, "error": {"code": -32602, "message": "missing args"}}
    results = _t01_008({"accept_any_bearer": True, "tools_call_response": bad_args}, FOREIGN)
    assert all(r.passed is False and r.inconclusive_reason is None for r in results), results


@pytest.mark.parametrize(("token", "target", "auth", "match"), [
    ("garbage", "http://127.0.0.1:9", "good", "must be a JWT"),
    (_jwt(aud=None), "http://127.0.0.1:9", "good", "'aud'"),
    (_jwt(aud="http://127.0.0.1:9"), "http://127.0.0.1:9", "good", "names this server"),
    (_jwt(exp_in=-10), "http://127.0.0.1:9", "good", "unexpired"),
    (_jwt(exp_in=86400), "http://127.0.0.1:9", "good", "short-lived"),
    (FOREIGN, "http://127.0.0.1:9", None, "requires --auth-token"),
], ids=["not-jwt", "no-aud", "aud-is-target", "expired", "long-lived", "no-auth-token"])
def test_exploit_foreign_token_garbage_is_inconclusive(
    token: str, target: str, auth: str | None, match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        Scanner(target, categories=["T1"], engine="prober", allow_private_targets=True,
                auth_token=auth, foreign_audience_token=token).run()


def test_exploit_foreign_token_refused_over_plain_http() -> None:
    with pytest.raises(ValueError, match="cleartext"):
        Scanner("http://mcp.example.com/mcp", categories=["T1"], engine="prober",
                auth_token="good", foreign_audience_token=FOREIGN).run()


def test_exploit_sd04_absent_prm_not_attested() -> None:
    from cosai_mcp.assurance import EvidenceItem

    ev = {"SD-04": EvidenceItem(control_id="SD-04", artifact="a", sha256="0" * 64)}
    report = evaluate_assurance(3, [], evidence=ev)
    assert _verdict(report, "SD-04") is Verdict.UNVERIFIED


def test_exploit_az06_not_attested_without_foreign_token_on_auth_target(tmp_path: Path) -> None:
    with MockMCPServer(require_bearer="good") as server:
        server.wait_ready()
        target = f"http://127.0.0.1:{server.port}/mcp"
        ev = tmp_path / "ev"
        ev.mkdir()
        (ev / "a.txt").write_text("x")
        (ev / "evidence.json").write_text(json.dumps({
            "schema_version": "1.0", "target": target,
            "controls": {"AZ-06": {"artifact": "a.txt"}}}))
        result = Scanner(target, allow_private_targets=True, probe_timeout_seconds=10.0,
                         auth_token="good", assurance_level=3, evidence_dir=ev).run()
    az06 = next(c for c in result.assurance.controls if c.control_id == "AZ-06")
    assert az06.verdict is Verdict.UNVERIFIED, az06.reason


def test_exploit_prm_malformed_as_url_still_fails() -> None:
    results, _ = _run({}, lambda s: {_PRM_PATH: _prm(
        s, authorization_servers=["https://[x", "http://evil.example"])})
    assert results[0].passed is False and results[0].inconclusive_reason is None


def test_exploit_prm_malformed_resource_metadata_fails() -> None:
    results, _ = _run({"www_authenticate": 'Bearer resource_metadata="http://[::1"'})
    assert results[0].passed is False and results[0].inconclusive_reason is None


def test_exploit_prm_deeply_nested_json_fails() -> None:
    results, _ = _run({}, lambda s: {_PRM_PATH: json.loads("[" * 500 + "]" * 500)})
    assert results[0].passed is False and results[0].inconclusive_reason is None


def test_exploit_prm_remote_target_loopback_as_fails() -> None:
    from cosai_mcp.wellknown import _validate_prm

    doc = {"resource": "https://mcp.example.com/mcp",
           "authorization_servers": ["http://localhost:8080"]}
    assert _validate_prm(doc, "https://mcp.example.com/mcp", target_is_loopback=False)
    assert not _validate_prm(doc | {"resource": "http://127.0.0.1/mcp"},
                             "http://127.0.0.1/mcp", target_is_loopback=True)


def test_exploit_prm_17th_http_as_fails() -> None:
    from cosai_mcp.wellknown import _validate_prm

    servers = [f"https://as{i}.example.com" for i in range(16)] + ["http://evil.example"]
    doc = {"resource": "https://m.example/mcp", "authorization_servers": servers}
    problems = _validate_prm(doc, "https://m.example/mcp", target_is_loopback=False)
    assert any("not HTTPS" in p for p in problems)
    assert any("more than 16" in p for p in problems)


def test_exploit_prm_origin_resource_for_path_endpoint_fails() -> None:
    results, _ = _run({}, lambda s: {_PRM_PATH: _prm(s, resource=f"http://127.0.0.1:{s.port}")})
    assert results[0].passed is False


def test_regression_prm_resource_case_and_default_port_normalized_passes() -> None:
    from cosai_mcp.wellknown import _canonical

    assert _canonical("https://Host.Example:443/mcp/") == _canonical("https://host.example/mcp")
    assert _canonical("HTTP://127.0.0.1:80/mcp") == _canonical("http://127.0.0.1/mcp")
    results, _ = _run({}, lambda s: {_PRM_PATH: _prm(
        s, resource=f"HTTP://127.0.0.1:{s.port}/mcp/")})
    assert results[0].passed is True


def test_exploit_prm_cross_origin_advertised_with_valid_wellknown_not_fail() -> None:
    """Not a FAIL (the same-origin metadata is valid) — and, per round-2 FIX 6,
    not a PASS either: clients use the advertised off-origin document, which is
    never fetched, so the result is INCONCLUSIVE."""
    results, gets = _run(
        {"www_authenticate": 'Bearer resource_metadata="https://cdn.example/prm"'},
        lambda s: {_PRM_PATH: _prm(s)})
    assert results[0].passed is False and results[0].inconclusive_reason
    assert "another origin" in results[0].response_body
    assert all(not g.startswith("http") for g in gets)


def test_exploit_prm_off_origin_advertised_is_not_pass() -> None:
    results, _ = _run(
        {"www_authenticate": 'Bearer resource_metadata="https://cdn.example/prm"'},
        lambda s: {_PRM_PATH: _prm(s)})
    assert results[0].probe_id == "T01-prm-6" and results[0].passed is False


# ===========================================================================
# PRM round-2 regressions
# ===========================================================================

def test_exploit_prm_wellknown_redirect_is_fail_and_promotes_t01_008(tmp_path: Path) -> None:
    """Redirect on the well-known path: never PASS; see the promotion test."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:
            pass

        def do_POST(self) -> None:  # noqa: N802
            auth = self.headers.get("Authorization", "")
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if auth != "Bearer good":
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "https://evil.example/prm")
            self.send_header("Content-Length", "0")
            self.end_headers()

    httpd = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        results = scan_protected_resource_metadata(
            f"http://127.0.0.1:{port}/mcp", _config(port))
    finally:
        httpd.shutdown()
    # A redirect's target is not visible through the pinned transport, so the
    # location is undeterminable: INCONCLUSIVE (never PASS), and the observed
    # 401 still promotes T01-008 (see the promotion test below).
    assert results[0].probe_id == "T01-prm-5" and results[0].passed is False, results


def _redirecting_auth_server() -> Any:
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:
            pass

        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "https://evil.example/prm")
            self.send_header("Content-Length", "0")
            self.end_headers()

    httpd = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def test_exploit_prm_redirect_promotes_t01_008_az06_unverified() -> None:
    """The PRM result after a redirect is inconclusive-but-401-observed, which
    still promotes T01-008 so AZ-06 cannot be attested without the audience test."""
    from cosai_mcp.assurance import EvidenceItem

    httpd = _redirecting_auth_server()
    port = httpd.server_address[1]
    try:
        prm = scan_protected_resource_metadata(f"http://127.0.0.1:{port}/mcp", _config(port))
    finally:
        httpd.shutdown()
    assert prm[0].probe_id == "T01-prm-5"
    # Feed the same result through the api's promotion rule.
    seen = any(r.threat_id == "T01" and (r.inconclusive_reason is None
               or r.probe_id in ("T01-prm-5", "T01-prm-6")) for r in prm)
    assert seen
    report = evaluate_assurance(
        3, prm,
        evidence={"AZ-06": EvidenceItem(control_id="AZ-06", artifact="a", sha256="0" * 64)},
        required_optional=frozenset({"T01-008"}))
    assert _verdict(report, "AZ-06") is Verdict.UNVERIFIED


def test_regression_prm_path_candidate_timeout_root_404_is_inconclusive() -> None:
    import gzip
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    body = gzip.compress(b"{}")

    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:
            pass

        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            if self.path.endswith("/mcp"):          # path candidate: unreadable
                self.send_response(200)
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:                                    # root candidate: definite 404
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

    httpd = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        results = scan_protected_resource_metadata(
            f"http://127.0.0.1:{port}/mcp", _config(port))
    finally:
        httpd.shutdown()
    assert results[0].probe_id == "T01-prm-5" and results[0].inconclusive_reason


def test_exploit_az06_promoted_when_auth_token_supplied_and_unauth_returns_403(
    tmp_path: Path,
) -> None:
    with MockMCPServer(**{"modern_requires_auth": False}) as server:
        server.wait_ready()
        target = f"http://127.0.0.1:{server.port}/mcp"
        ev = tmp_path / "ev"
        ev.mkdir()
        (ev / "a.txt").write_text("x")
        (ev / "evidence.json").write_text(json.dumps({
            "schema_version": "1.0", "target": target,
            "controls": {"AZ-06": {"artifact": "a.txt"}}}))
        # No 401 anywhere (the default mock never demands auth), but a token is
        # supplied: the audience test still applies and must not be skipped.
        result = Scanner(target, allow_private_targets=True, probe_timeout_seconds=10.0,
                         auth_token="good", assurance_level=3, evidence_dir=ev).run()
    az06 = next(c for c in result.assurance.controls if c.control_id == "AZ-06")
    assert az06.verdict is Verdict.UNVERIFIED, az06.reason


@pytest.mark.parametrize("aud_fmt", [
    "http://127.0.0.1:{port}/mcp",        # endpoint when the target is origin-only
    "HTTP://127.0.0.1:{port}/MCP/",       # case variant — path case kept, so not equal
    "http://127.0.0.1:{port}",             # origin
], ids=["endpoint", "case", "origin"])
def test_regression_foreign_token_aud_equal_to_endpoint_case_port_variants_rejected(
    aud_fmt: str,
) -> None:
    port = 9
    aud = aud_fmt.format(port=port)
    token = _jwt(aud=aud)
    if aud_fmt.startswith("HTTP://") and aud.endswith("/MCP/"):
        # Path is case-sensitive; only scheme/host normalize. Use a matching path.
        token = _jwt(aud=f"HTTP://127.0.0.1:{port}/mcp/")
    with pytest.raises(ValueError, match="names this server"):
        Scanner(f"http://127.0.0.1:{port}", categories=["T1"], engine="prober",
                allow_private_targets=True, auth_token="good",
                foreign_audience_token=token).run()


def test_regression_foreign_token_nan_exp_rejected() -> None:
    import base64

    def b64(raw: str) -> str:
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    payload = '{"aud": "https://x.example/", "exp": NaN}'
    token = f"{b64('{}')}.{b64(payload)}.s"
    with pytest.raises(ValueError, match="unexpired"):
        Scanner("http://127.0.0.1:9", categories=["T1"], engine="prober",
                allow_private_targets=True, auth_token="good",
                foreign_audience_token=token).run()


def test_regression_prm_all_candidates_error_is_inconclusive_not_fail() -> None:
    import gzip
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    body = gzip.compress(b"{}")

    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:
            pass

        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        results = scan_protected_resource_metadata(
            f"http://127.0.0.1:{port}/mcp", _config(port))
    finally:
        httpd.shutdown()
    assert results[0].probe_id == "T01-prm-5"
    assert results[0].passed is False and results[0].inconclusive_reason


def test_exploit_request_raw_gzip_bomb_bounded() -> None:
    import gzip
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    bomb = gzip.compress(gzip.compress(b"0" * 20_000_000))

    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip, gzip")
            self.send_header("Content-Length", str(len(bomb)))
            self.end_headers()
            self.wfile.write(bomb)

    httpd = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]

    async def _go() -> None:
        t = StreamableHTTPTransport(f"http://127.0.0.1:{port}/mcp", _config(port))
        await t.connect()
        try:
            with pytest.raises(ValueError, match="content-encoded"):
                await t.request_raw("GET", f"http://127.0.0.1:{port}/.well-known/x")
        finally:
            await t.close()

    try:
        asyncio.run(_go())
    finally:
        httpd.shutdown()
