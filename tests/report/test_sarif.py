"""Tests for SARIF 2.1.0 builder — injection safety, structure, scanner-controlled fields."""
from __future__ import annotations

import json

import pytest

from cosai_mcp.catalog.models import Severity
from cosai_mcp.harness.result import make_probe_result, AssertionResult
from cosai_mcp.report.sarif import SarifBuilder, ScanContext, _sanitize_message


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _context(
    execution_successful: bool = True,
    exit_code: int = 0,
) -> ScanContext:
    return ScanContext(
        target_url="http://localhost:8000",
        scan_timestamp="2026-04-27T00:00:00Z",
        catalog_hash="a" * 64,
        execution_successful=execution_successful,
        exit_code=exit_code,
    )


def _failed_result(
    probe_id: str = "T01-001",
    threat_id: str = "T01",
    response_body: str = "",
    error: str | None = None,
) -> "make_probe_result":
    assertion = AssertionResult(
        target="response.error",
        operator="eq",
        expected="True",
        actual="False",
        passed=False,
        message="expected error=True",
    )
    return make_probe_result(
        probe_id=probe_id,
        threat_id=threat_id,
        passed=False,
        assertions=(assertion,),
        response={"_body": response_body, "_status_code": 200},
        error=error,
    )


def _passed_result(probe_id: str = "T01-001", threat_id: str = "T01") -> "make_probe_result":
    assertion = AssertionResult(
        target="response.error",
        operator="eq",
        expected="False",
        actual="False",
        passed=True,
        message="ok",
    )
    return make_probe_result(
        probe_id=probe_id,
        threat_id=threat_id,
        passed=True,
        assertions=(assertion,),
        response={"_body": "", "_status_code": 200},
    )


def _add(builder: SarifBuilder, result, rule_id: str = "T01-001") -> None:
    builder.add_result(
        result,
        severity=Severity.HIGH,
        rule_id=rule_id,
        rule_name="Improper Authentication",
        rule_description="Missing or weak authentication on MCP endpoint.",
    )


# ---------------------------------------------------------------------------
# SARIF structure
# ---------------------------------------------------------------------------

class TestSarifStructure:

    def test_sarif_version_is_2_1_0(self):
        b = SarifBuilder(_context())
        doc = b.build()
        assert doc["version"] == "2.1.0"

    def test_sarif_has_runs(self):
        b = SarifBuilder(_context())
        doc = b.build()
        assert len(doc["runs"]) == 1

    def test_sarif_tool_driver_name(self):
        b = SarifBuilder(_context())
        doc = b.build()
        assert doc["runs"][0]["tool"]["driver"]["name"] == "cosai-mcp"

    def test_sarif_invocation_execution_successful_true(self):
        b = SarifBuilder(_context(execution_successful=True))
        doc = b.build()
        inv = doc["runs"][0]["invocations"][0]
        assert inv["executionSuccessful"] is True

    def test_sarif_partial_scan_execution_unsuccessful(self):
        """Exit code 2 (scanner internal error) → executionSuccessful: false."""
        b = SarifBuilder(_context(execution_successful=False, exit_code=2))
        doc = b.build()
        inv = doc["runs"][0]["invocations"][0]
        assert inv["executionSuccessful"] is False
        assert inv["exitCode"] == 2

    def test_sarif_passed_probe_produces_no_result(self):
        b = SarifBuilder(_context())
        _add(b, _passed_result())
        doc = b.build()
        assert doc["runs"][0]["results"] == []

    def test_sarif_failed_probe_produces_result(self):
        b = SarifBuilder(_context())
        _add(b, _failed_result())
        doc = b.build()
        assert len(doc["runs"][0]["results"]) == 1

    def test_sarif_result_count_matches_failures(self):
        b = SarifBuilder(_context())
        _add(b, _failed_result(probe_id="T01-001"), rule_id="T01-001")
        _add(b, _passed_result(probe_id="T01-002"), rule_id="T01-001")
        _add(b, _failed_result(probe_id="T01-003"), rule_id="T01-001")
        doc = b.build()
        assert len(doc["runs"][0]["results"]) == 2


# ---------------------------------------------------------------------------
# Security: attacker bytes confined to message.text
# ---------------------------------------------------------------------------

class TestSarifInjectionSafety:

    def test_sarif_no_json_injection(self):
        """Attacker response body with injected JSON structure must not alter SARIF."""
        injected = '","level":"error","ruleId":"INJECTED","message":{"text":"pwned"}'
        b = SarifBuilder(_context())
        _add(b, _failed_result(response_body=injected))
        sarif_json = b.build_json()

        doc = json.loads(sarif_json)
        results = doc["runs"][0]["results"]
        assert len(results) == 1
        # ruleId must be catalog ID, not the injected value
        assert results[0]["ruleId"] == "T01-001"
        # "INJECTED" must not appear as a ruleId
        assert all(r["ruleId"] != "INJECTED" for r in results)

    def test_sarif_attacker_bytes_confined_to_message_text(self):
        """A sentinel string from the response must appear ONLY in message.text."""
        sentinel = "ATTACKER_SENTINEL_XYZ"
        b = SarifBuilder(_context())
        _add(b, _failed_result(response_body=sentinel))
        sarif_json = b.build_json()

        doc = json.loads(sarif_json)
        result = doc["runs"][0]["results"][0]

        # Sentinel may appear in message.text (that's the confined location)
        # — but must not appear in any scanner-controlled field.
        assert result["ruleId"] != sentinel
        assert result["level"] in ("error", "warning", "note")
        # invocation fields are scanner-generated
        inv = doc["runs"][0]["invocations"][0]
        assert sentinel not in inv.get("commandLine", "")

    def test_sarif_ruleId_scanner_generated(self):
        """ruleId must always be the catalog threat ID, never response content."""
        b = SarifBuilder(_context())
        # Response body contains a string that looks like a ruleId
        _add(b, _failed_result(response_body="T99-999"), rule_id="T01-001")
        doc = b.build()
        result = doc["runs"][0]["results"][0]
        assert result["ruleId"] == "T01-001"

    def test_sarif_suppressions_not_from_response(self):
        """Response body containing 'suppressions' key must not produce suppressions in SARIF."""
        malicious_body = '{"suppressions": [{"kind": "external", "justification": "fp"}]}'
        b = SarifBuilder(_context())
        _add(b, _failed_result(response_body=malicious_body))
        doc = b.build()
        result = doc["runs"][0]["results"][0]
        assert "suppressions" not in result

    def test_sarif_partial_fingerprints_not_from_response(self):
        """Response body must not produce partialFingerprints in SARIF result."""
        malicious_body = '{"partialFingerprints": {"primaryLocationLineHash": "abc"}}'
        b = SarifBuilder(_context())
        _add(b, _failed_result(response_body=malicious_body))
        doc = b.build()
        result = doc["runs"][0]["results"][0]
        assert "partialFingerprints" not in result

    def test_sarif_control_chars_stripped_from_message(self):
        """Control characters in response body must be stripped from message.text."""
        body_with_ctrl = "data\x00\x01\x02\x1b[31mred\x1b[0m"
        b = SarifBuilder(_context())
        _add(b, _failed_result(response_body=body_with_ctrl))
        doc = b.build()
        msg = doc["runs"][0]["results"][0]["message"]["text"]
        assert "\x00" not in msg
        assert "\x01" not in msg
        assert "\x1b" not in msg

    def test_sarif_message_text_capped_at_4096(self):
        """Message text must not exceed 4096 characters."""
        long_body = "X" * 10_000
        b = SarifBuilder(_context())
        _add(b, _failed_result(response_body=long_body))
        doc = b.build()
        msg = doc["runs"][0]["results"][0]["message"]["text"]
        assert len(msg) <= 4096 + len("…[truncated]")

    def test_sarif_invalid_rule_id_raises(self):
        """Passing a non-catalog rule_id raises ValueError."""
        b = SarifBuilder(_context())
        result = _failed_result()
        with pytest.raises(ValueError, match="not a valid catalog threat ID"):
            b.add_result(
                result,
                severity=Severity.HIGH,
                rule_id="INJECTED",
                rule_name="x",
                rule_description="x",
            )

    def test_regression_adversarial_rule_id_accepted(self):
        """FIX [Codex P2]: Adversarial threat IDs (T03-ADV-001) must be valid SARIF ruleIds.

        Previously _RULE_ID_RE = r'^T\d{2}-\d{3}$' rejected any ID with a text
        segment, so --adversarial --report-sarif raised ValueError for every result.
        The regex was widened to r'^T\d{2}(-[A-Z]{2,5})?-\d{3}$'.
        Test: adversarial IDs pass add_result without raising; standard IDs still pass.
        """
        b = SarifBuilder(_context())
        for adv_id in ("T03-ADV-001", "T05-ADV-001", "T07-ADV-001", "T11-ADV-001"):
            r = _failed_result(probe_id=adv_id, threat_id="T3")
            b.add_result(
                r,
                severity=Severity.HIGH,
                rule_id=adv_id,
                rule_name="Adversarial probe",
                rule_description="Adversarial threat test",
            )
        # Standard IDs still work
        r_std = _failed_result(probe_id="T01-001", threat_id="T1")
        b.add_result(r_std, severity=Severity.HIGH, rule_id="T01-001",
                     rule_name="Auth", rule_description="Auth test")
        doc = b.build()
        rule_ids = {r["ruleId"] for r in doc["runs"][0]["results"]}
        assert "T03-ADV-001" in rule_ids
        assert "T01-001" in rule_ids


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class TestSarifValidation:

    def test_build_json_validates_and_returns_string(self):
        b = SarifBuilder(_context())
        _add(b, _failed_result())
        sarif_json = b.build_json()
        assert isinstance(sarif_json, str)
        doc = json.loads(sarif_json)
        assert doc["version"] == "2.1.0"

    def test_build_json_is_valid_json(self):
        b = SarifBuilder(_context())
        sarif_json = b.build_json()
        json.loads(sarif_json)  # must not raise


# ---------------------------------------------------------------------------
# Sanitize message helper
# ---------------------------------------------------------------------------

class TestSanitizeMessage:

    def test_strips_null_bytes(self):
        assert "\x00" not in _sanitize_message("abc\x00def")

    def test_strips_escape_sequences(self):
        assert "\x1b" not in _sanitize_message("\x1b[31mred\x1b[0m")

    def test_preserves_newline_and_tab(self):
        s = "line1\nline2\ttab"
        result = _sanitize_message(s)
        assert "\n" in result
        assert "\t" in result

    def test_caps_at_4096(self):
        long = "a" * 5000
        result = _sanitize_message(long)
        assert len(result) <= 4096 + len("…[truncated]")
        assert result.endswith("…[truncated]")


# ---------------------------------------------------------------------------
# Regression tests
# ---------------------------------------------------------------------------

class TestSarifRegressions:

    def test_regression_sarif_no_json_injection(self):
        """Regression: injected JSON in response body must not alter SARIF structure."""
        injected = ',"level":"error","ruleId":"CVE-INJECTED"'
        b = SarifBuilder(_context())
        _add(b, _failed_result(response_body=injected))
        sarif_json = b.build_json()
        doc = json.loads(sarif_json)
        for r in doc["runs"][0]["results"]:
            assert r.get("ruleId") == "T01-001"
            assert "CVE-INJECTED" not in r.get("ruleId", "")

    def test_regression_html_escape_before_template(self):
        """Regression: response body with HTML special chars must not break SARIF JSON."""
        xss_body = '<script>alert("xss")</script>'
        b = SarifBuilder(_context())
        _add(b, _failed_result(response_body=xss_body))
        sarif_json = b.build_json()
        doc = json.loads(sarif_json)
        assert len(doc["runs"][0]["results"]) == 1

    def test_regression_scan_context_immutable(self):
        """ScanContext must be frozen so SARIF output cannot be altered post-construction.

        FIX 2: ScanContext was a mutable dataclass — a mutation between add_result()
        and build() would silently alter scanner-controlled SARIF fields.
        """
        ctx = _context()
        with pytest.raises((AttributeError, TypeError)):
            ctx.target_url = "http://mutated.attacker.com"  # type: ignore[misc]

    def test_regression_rule_name_control_chars_stripped(self):
        """rule_name with control characters must be sanitized before SARIF storage.

        FIX 3: rule_name and rule_description were written verbatim into
        tool.driver.rules[] without sanitization.
        """
        b = SarifBuilder(_context())
        result = _failed_result()
        b.add_result(
            result,
            severity=Severity.HIGH,
            rule_id="T01-001",
            rule_name="Auth\x00Test\x1b[31mRED",
            rule_description="Normal description",
        )
        doc = b.build()
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert "\x00" not in rule["name"]
        assert "\x1b" not in rule["name"]

    def test_regression_sarif_message_text_no_html_entities(self):
        """message.text must contain literal characters, not HTML entities.

        FIX 7: AssertionResult.actual is HTML-escaped at ingestion. Without
        unescape, SARIF viewers display &lt;tag&gt; instead of <tag>.
        """
        from cosai_mcp.harness.result import AssertionResult, make_probe_result
        assertion = AssertionResult(
            target="response.body",
            operator="not_contains",
            expected="&lt;root:&gt;",   # HTML-escaped at ingestion
            actual="&lt;root:admin&gt;",  # HTML-escaped at ingestion
            passed=False,
            message="contains sensitive data",
        )
        result = make_probe_result(
            probe_id="T01-001",
            threat_id="T01",
            passed=False,
            assertions=(assertion,),
            response={"_body": "<root:admin>", "_status_code": 200},
        )
        b = SarifBuilder(_context())
        _add(b, result)
        doc = b.build()
        msg = doc["runs"][0]["results"][0]["message"]["text"]
        # Literal < and > must appear, not HTML entities
        assert "&lt;" not in msg
        assert "&gt;" not in msg


# ---------------------------------------------------------------------------
# Framework metadata — CWE, OWASP ref, ATLAS techniques
# ---------------------------------------------------------------------------

class TestSarifFrameworkMetadata:

    def _add_with_metadata(
        self,
        builder: SarifBuilder,
        result,
        rule_id: str = "T04-001",
        owasp_ref: str = "MCP-Top10-A04",
        cwe: tuple = ("CWE-74",),
    ) -> None:
        builder.add_result(
            result,
            severity=Severity.HIGH,
            rule_id=rule_id,
            rule_name="Data/Control Boundary",
            rule_description="Tool poisoning — control/data boundary violation.",
            owasp_ref=owasp_ref,
            cwe=cwe,
        )

    def test_cwe_appears_in_rule_properties(self):
        """CWE tags from signed catalog must appear in rule properties."""
        b = SarifBuilder(_context())
        self._add_with_metadata(b, _failed_result(probe_id="T04-001", threat_id="T4"))
        doc = b.build()
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert "properties" in rule
        assert rule["properties"]["cwe"] == ["CWE-74"]

    def test_owasp_ref_appears_in_rule_properties(self):
        """OWASP MCP Top 10 ref from signed catalog must appear in rule properties."""
        b = SarifBuilder(_context())
        self._add_with_metadata(b, _failed_result(probe_id="T04-001", threat_id="T4"))
        doc = b.build()
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["owasp_ref"] == "MCP-Top10-A04"

    def test_helpuri_set_when_owasp_ref_present(self):
        """helpUri must be set on the rule when owasp_ref is provided."""
        b = SarifBuilder(_context())
        self._add_with_metadata(b, _failed_result(probe_id="T04-001", threat_id="T4"))
        doc = b.build()
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert "helpUri" in rule
        assert "owasp" in rule["helpUri"].lower()

    def test_atlas_techniques_wired_for_t4(self):
        """T4 rules must carry AML.T0051 (LLM Prompt Injection) in ATLAS properties."""
        b = SarifBuilder(_context())
        self._add_with_metadata(b, _failed_result(probe_id="T04-001", threat_id="T4"),
                                 rule_id="T04-001")
        doc = b.build()
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert "AML.T0051" in rule["properties"]["atlas_techniques"]

    def test_atlas_techniques_wired_for_t8(self):
        """T8 rules must carry both AML.T0013 and AML.T0024."""
        b = SarifBuilder(_context())
        b.add_result(
            _failed_result(probe_id="T08-001", threat_id="T8"),
            severity=Severity.HIGH,
            rule_id="T08-001",
            rule_name="Network Binding",
            rule_description="SSRF / shadow server detection.",
            owasp_ref="MCP-Top10-A08",
            cwe=("CWE-918",),
        )
        doc = b.build()
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        atlas = rule["properties"]["atlas_techniques"]
        assert "AML.T0013" in atlas
        assert "AML.T0024" in atlas

    def test_no_atlas_for_categories_without_mapping(self):
        """T1 has no ATLAS mapping — properties must not contain atlas_techniques."""
        b = SarifBuilder(_context())
        b.add_result(
            _failed_result(probe_id="T01-001", threat_id="T1"),
            severity=Severity.CRITICAL,
            rule_id="T01-001",
            rule_name="Improper Authentication",
            rule_description="Missing auth.",
            owasp_ref="MCP-Top10-A01",
            cwe=("CWE-287",),
        )
        doc = b.build()
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert "atlas_techniques" not in rule.get("properties", {})

    def test_framework_metadata_not_populated_from_response(self):
        """CWE and OWASP ref in rule properties must be scanner-provided, not derived
        from response body — the attacker sentinel must not appear in properties."""
        sentinel = "ATTACKER_CWE_INJECT"
        b = SarifBuilder(_context())
        b.add_result(
            _failed_result(probe_id="T01-001", threat_id="T1", response_body=sentinel),
            severity=Severity.HIGH,
            rule_id="T01-001",
            rule_name="Auth",
            rule_description="Auth.",
            owasp_ref="MCP-Top10-A01",
            cwe=("CWE-287",),
        )
        doc = b.build()
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        props_str = json.dumps(rule.get("properties", {}))
        assert sentinel not in props_str

    def test_no_properties_when_no_metadata(self):
        """Rules with no owasp_ref and no cwe must not add an empty properties dict."""
        b = SarifBuilder(_context())
        _add(b, _failed_result())  # _add passes no owasp_ref or cwe
        doc = b.build()
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        # T01-001 has no ATLAS mapping and _add() passes no owasp_ref/cwe
        assert "properties" not in rule

    def test_full_pipeline_t4_metadata_survives_build_json(self):
        """Framework metadata must survive from add_result through build_json serialisation.

        End-to-end: catalog load (simulated) → add_result → build_json → JSON parse.
        Verifies the metadata is not dropped or corrupted at serialisation time.
        """
        b = SarifBuilder(_context())
        self._add_with_metadata(b, _failed_result(probe_id="T04-001", threat_id="T4"),
                                 rule_id="T04-001")
        sarif_json = b.build_json()
        doc = json.loads(sarif_json)
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["cwe"] == ["CWE-74"]
        assert rule["properties"]["owasp_ref"] == "MCP-Top10-A04"
        assert "AML.T0051" in rule["properties"]["atlas_techniques"]
