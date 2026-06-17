"""Extended black-box probes for T3 — Input Validation Failures (WG-89 item 8).

Covers:
  T03-003  Server-Side Template Injection (SSTI)
  T03-004  SQL injection (error-based)
  T03-005  NoSQL operator injection
  T03-006  XXE (XML External Entity)
  T03-007  CRLF / HTTP response-header injection

Probe semantics:
  result.passed = True  → server did NOT exhibit the vulnerability (secure)
  result.passed = False → server is vulnerable (or INCONCLUSIVE on protocol error)
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cosai_mcp.harness.mock_server import MockMCPServer
from cosai_mcp.harness.assertions import evaluate_assertion
from cosai_mcp.catalog.models import Assertion, Operator
from tests.probes.conftest import error_response, ok_response, run_probe


# ---------------------------------------------------------------------------
# T03-003  SSTI
# ---------------------------------------------------------------------------

class TestT03003SSTICatalogLoad:

    def test_t03_003_loads(self, catalog):
        t = catalog.load_file(Path("official/T03-003.json"))
        assert t.id == "T03-003"
        assert t.category == "T3"
        assert len(t.probes) == 2

    def test_t03_003_probe_ids(self, catalog):
        t = catalog.load_file(Path("official/T03-003.json"))
        assert t.probes[0].id == "T03-003-p1"
        assert t.probes[1].id == "T03-003-p2"

    def test_t03_003_assertions_check_evaluated_product(self, catalog):
        """Both probes assert that '1787569' (1337*1337) is absent."""
        t = catalog.load_file(Path("official/T03-003.json"))
        for probe in t.probes:
            values = [a.value for a in probe.assertions]
            assert "1787569" in values

    def test_t03_003_corroboration_present(self, catalog):
        """Both probes have corroboration to suppress FP from incidental matches."""
        t = catalog.load_file(Path("official/T03-003.json"))
        for probe in t.probes:
            assert len(probe.corroboration) >= 1

    def test_t03_003_protocol_error_not_expected(self, catalog):
        """protocol_error_is_expected must be False (default) — a -32602 is INCONCLUSIVE."""
        t = catalog.load_file(Path("official/T03-003.json"))
        for probe in t.probes:
            assert probe.protocol_error_is_expected is False


class TestT03003SSTIBehavior:

    @pytest.mark.asyncio
    async def test_secure_server_passes_jinja2_probe(self, catalog):
        """Secure server: returns benign output (no arithmetic evaluation) → PASS."""
        threat = catalog.load_file(Path("official/T03-003.json"))
        probe = threat.probes[0]  # {1337*1337} (Smarty/Twig single-brace form)

        with MockMCPServer(tools_call_response=ok_response("processed ok")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_secure_server_passes_el_probe(self, catalog):
        """Secure server: returns benign output for ${...} probe → PASS."""
        threat = catalog.load_file(Path("official/T03-003.json"))
        probe = threat.probes[1]  # ${1337*1337}

        with MockMCPServer(tools_call_response=ok_response("processed ok")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_vulnerable_server_evaluates_jinja2_template(self, catalog):
        """Vulnerable server: evaluates {1337*1337} and returns the product → probe fails."""
        threat = catalog.load_file(Path("official/T03-003.json"))
        probe = threat.probes[0]

        # Body contains evaluated arithmetic product
        with MockMCPServer(tools_call_response=ok_response("result: 1787569")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_vulnerable_server_evaluates_el_template(self, catalog):
        """Vulnerable server: evaluates ${1337*1337} and returns 1787569 → probe fails."""
        threat = catalog.load_file(Path("official/T03-003.json"))
        probe = threat.probes[1]

        with MockMCPServer(tools_call_response=ok_response("1787569")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_protocol_error_on_ssti_probe_is_inconclusive(self, catalog):
        """Audit §2: a -32602 schema rejection on the SSTI probe is INCONCLUSIVE."""
        threat = catalog.load_file(Path("official/T03-003.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32602, "Invalid params")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False
        assert result.inconclusive_reason is not None


# ---------------------------------------------------------------------------
# T03-004  SQL injection (error-based)
# ---------------------------------------------------------------------------

class TestT03004SQLiCatalogLoad:

    def test_t03_004_loads(self, catalog):
        t = catalog.load_file(Path("official/T03-004.json"))
        assert t.id == "T03-004"
        assert t.category == "T3"
        assert len(t.probes) == 1

    def test_t03_004_assertions_cover_all_sql_markers(self, catalog):
        """Probe must assert absence of all 5 SQL error markers."""
        t = catalog.load_file(Path("official/T03-004.json"))
        probe = t.probes[0]
        denied_values = {a.value for a in probe.assertions}
        assert "SQL syntax" in denied_values
        assert "sqlite3." in denied_values
        assert "psycopg2" in denied_values
        assert "ORA-" in denied_values
        assert "SQLSTATE" in denied_values

    def test_t03_004_protocol_error_not_expected(self, catalog):
        t = catalog.load_file(Path("official/T03-004.json"))
        for probe in t.probes:
            assert probe.protocol_error_is_expected is False


class TestT03004SQLiBehavior:

    @pytest.mark.asyncio
    async def test_secure_server_passes_sqli_probe(self, catalog):
        """Secure server: returns generic error without DB internals → PASS."""
        threat = catalog.load_file(Path("official/T03-004.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response("no results found")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_vulnerable_server_leaks_sqlite_error(self, catalog):
        """Vulnerable server: echoes sqlite3. error string → probe fails."""
        threat = catalog.load_file(Path("official/T03-004.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response(
            "sqlite3.OperationalError: near '1': syntax error"
        )) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_vulnerable_server_leaks_sql_syntax_error(self, catalog):
        """Vulnerable server: returns 'SQL syntax' fragment → probe fails."""
        threat = catalog.load_file(Path("official/T03-004.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response(
            "You have an error in your SQL syntax"
        )) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_vulnerable_server_leaks_psycopg2_error(self, catalog):
        """Vulnerable server: returns 'psycopg2' error string → probe fails."""
        threat = catalog.load_file(Path("official/T03-004.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response(
            "psycopg2.errors.SyntaxError: syntax error"
        )) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_vulnerable_server_leaks_ora_error(self, catalog):
        """Vulnerable server: returns 'ORA-' error string → probe fails."""
        threat = catalog.load_file(Path("official/T03-004.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response(
            "ORA-00907: missing right parenthesis"
        )) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_protocol_error_on_sqli_probe_is_inconclusive(self, catalog):
        """Audit §2: -32602 on the SQL injection probe is INCONCLUSIVE."""
        threat = catalog.load_file(Path("official/T03-004.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32602, "Bad request")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False
        assert result.inconclusive_reason is not None


# ---------------------------------------------------------------------------
# T03-005  NoSQL operator injection
# ---------------------------------------------------------------------------

class TestT03005NoSQLCatalogLoad:

    def test_t03_005_loads(self, catalog):
        t = catalog.load_file(Path("official/T03-005.json"))
        assert t.id == "T03-005"
        assert t.category == "T3"
        assert len(t.probes) == 1

    def test_t03_005_asserts_ne_operator_absent(self, catalog):
        """Probe asserts that '$ne' is not reflected in the response body."""
        t = catalog.load_file(Path("official/T03-005.json"))
        probe = t.probes[0]
        values = [a.value for a in probe.assertions]
        assert "$ne" in values

    def test_t03_005_protocol_error_not_expected(self, catalog):
        """A -32602 from the server must be INCONCLUSIVE (injection reached no logic)."""
        t = catalog.load_file(Path("official/T03-005.json"))
        for probe in t.probes:
            assert probe.protocol_error_is_expected is False


class TestT03005NoSQLBehavior:

    @pytest.mark.asyncio
    async def test_secure_server_passes_nosql_probe(self, catalog):
        """Secure server: never reflects $ne back in the response → PASS."""
        threat = catalog.load_file(Path("official/T03-005.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response("no results")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_vulnerable_server_reflects_ne_operator(self, catalog):
        """Vulnerable server: echoes the $ne operator in its response → probe fails."""
        threat = catalog.load_file(Path("official/T03-005.json"))
        probe = threat.probes[0]

        # Simulate a server that deserialises and reflects the query operator
        with MockMCPServer(tools_call_response=ok_response(
            'filter applied: {"$ne": null}'
        )) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_protocol_error_on_nosql_probe_is_inconclusive(self, catalog):
        """Audit §2: -32602 on the NoSQL probe is INCONCLUSIVE."""
        threat = catalog.load_file(Path("official/T03-005.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32602, "Invalid params")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False
        assert result.inconclusive_reason is not None


# ---------------------------------------------------------------------------
# T03-006  XXE
# ---------------------------------------------------------------------------

class TestT03006XXECatalogLoad:

    def test_t03_006_loads(self, catalog):
        t = catalog.load_file(Path("official/T03-006.json"))
        assert t.id == "T03-006"
        assert t.category == "T3"
        assert len(t.probes) == 1

    def test_t03_006_asserts_passwd_absent(self, catalog):
        """Probe asserts that 'root:x:0:0' is not in the response body."""
        t = catalog.load_file(Path("official/T03-006.json"))
        probe = t.probes[0]
        values = [a.value for a in probe.assertions]
        assert "root:x:0:0" in values

    def test_t03_006_has_corroboration(self, catalog):
        """Probe has corroboration to prevent FP on incidental 'root:' matches."""
        t = catalog.load_file(Path("official/T03-006.json"))
        probe = t.probes[0]
        assert len(probe.corroboration) >= 1

    def test_t03_006_protocol_error_not_expected(self, catalog):
        t = catalog.load_file(Path("official/T03-006.json"))
        for probe in t.probes:
            assert probe.protocol_error_is_expected is False


class TestT03006XXEBehavior:

    @pytest.mark.asyncio
    async def test_secure_server_passes_xxe_probe(self, catalog):
        """Secure server: rejects or ignores external entity → benign response → PASS."""
        threat = catalog.load_file(Path("official/T03-006.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response("XML processed")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    @pytest.mark.asyncio
    async def test_vulnerable_server_resolves_external_entity(self, catalog):
        """Vulnerable server: resolves file:///etc/passwd and returns its contents → probe fails."""
        threat = catalog.load_file(Path("official/T03-006.json"))
        probe = threat.probes[0]

        # Root account line from /etc/passwd — the distinctive corroboration marker
        with MockMCPServer(tools_call_response=ok_response(
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        )) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False

    @pytest.mark.asyncio
    async def test_protocol_error_on_xxe_probe_is_inconclusive(self, catalog):
        """Audit §2: -32602 on the XXE probe is INCONCLUSIVE."""
        threat = catalog.load_file(Path("official/T03-006.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32602, "Invalid content")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False
        assert result.inconclusive_reason is not None


# ---------------------------------------------------------------------------
# T03-007  CRLF / HTTP response-header injection
# ---------------------------------------------------------------------------

class TestT03007CRLFCatalogLoad:

    def test_t03_007_loads(self, catalog):
        t = catalog.load_file(Path("official/T03-007.json"))
        assert t.id == "T03-007"
        assert t.category == "T3"
        assert len(t.probes) == 1

    def test_t03_007_asserts_header_absent(self, catalog):
        """Probe asserts that x-cosai-injected header is null (absent)."""
        t = catalog.load_file(Path("official/T03-007.json"))
        probe = t.probes[0]
        assert probe.assertions[0].target == "response.header.x-cosai-injected"
        assert probe.assertions[0].operator.value == "eq"
        assert probe.assertions[0].value is None

    def test_t03_007_protocol_error_not_expected(self, catalog):
        t = catalog.load_file(Path("official/T03-007.json"))
        for probe in t.probes:
            assert probe.protocol_error_is_expected is False


class TestT03007CRLFBehavior:

    @pytest.mark.asyncio
    async def test_secure_server_passes_crlf_probe(self, catalog):
        """Secure server: does not echo CRLF payload into response headers → PASS.

        The MockMCPServer never injects extra response headers, so
        x-cosai-injected is always absent — this is the expected secure outcome.
        """
        threat = catalog.load_file(Path("official/T03-007.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=ok_response("ok")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is True

    def test_vulnerable_assertion_fires_when_header_present(self, catalog):
        """Unit test for the assertion evaluator: if the response dict contains
        the injected header, the eq-null assertion must fail.

        This directly exercises the assertion path that a real vulnerable server
        would trigger (one that reflects CRLF payloads into response headers).
        """
        threat = catalog.load_file(Path("official/T03-007.json"))
        probe = threat.probes[0]
        assertion = probe.assertions[0]  # response.header.x-cosai-injected eq null

        # Simulate a response dict as populated by streamable_http.py transport
        # when a vulnerable server injects the header via CRLF splitting
        vulnerable_response = {
            "_body": "ok",
            "_status_code": 200,
            "_headers": {
                "content-type": "application/json",
                "x-cosai-injected": "1",   # injected by CRLF payload
            },
            "jsonrpc": "2.0",
            "id": 0,
            "result": {"content": [{"type": "text", "text": "ok"}], "isError": False},
        }

        result = evaluate_assertion(assertion, vulnerable_response)
        # eq-null fails because actual is "1", not None
        assert result.passed is False

    def test_secure_assertion_passes_when_header_absent(self, catalog):
        """Unit test: if the injected header is absent, eq-null assertion passes."""
        threat = catalog.load_file(Path("official/T03-007.json"))
        probe = threat.probes[0]
        assertion = probe.assertions[0]

        secure_response = {
            "_body": "ok",
            "_status_code": 200,
            "_headers": {"content-type": "application/json"},
            "jsonrpc": "2.0",
            "id": 0,
            "result": {"content": [{"type": "text", "text": "ok"}], "isError": False},
        }

        result = evaluate_assertion(assertion, secure_response)
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_protocol_error_on_crlf_probe_is_inconclusive(self, catalog):
        """Audit §2: -32602 on the CRLF probe is INCONCLUSIVE."""
        threat = catalog.load_file(Path("official/T03-007.json"))
        probe = threat.probes[0]

        with MockMCPServer(tools_call_response=error_response(-32602, "Invalid params")) as server:
            server.wait_ready()
            result = await run_probe(probe, threat, server)

        assert result.passed is False
        assert result.inconclusive_reason is not None
