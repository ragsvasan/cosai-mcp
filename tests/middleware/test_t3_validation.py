"""Tests for T3 middleware: ParameterValidator and InjectionGuard."""
from __future__ import annotations

import pytest

from cosai_mcp.middleware.validation import (
    InjectionGuard,
    ParameterValidationError,
    ParameterValidator,
)

# ===========================================================================
# InjectionGuard — standalone scan
# ===========================================================================

class TestInjectionGuard:

    def test_clean_string_passes(self):
        guard = InjectionGuard()
        assert guard.scan({"query": "hello world"}) == []

    def test_sql_union_select_detected(self):
        guard = InjectionGuard()
        findings = guard.scan({"q": "foo UNION SELECT * FROM users"})
        assert len(findings) == 1
        assert "sql_injection" in findings[0].issue

    def test_path_traversal_detected(self):
        guard = InjectionGuard()
        findings = guard.scan({"file": "../../etc/passwd"})
        assert any("path_traversal" in f.issue for f in findings)

    def test_null_byte_detected(self):
        guard = InjectionGuard()
        findings = guard.scan({"name": "foo\x00bar"})
        assert any("null_byte" in f.issue for f in findings)

    def test_shell_metachar_semicolon_detected(self):
        guard = InjectionGuard()
        findings = guard.scan({"cmd": "ls; cat /etc/passwd"})
        assert any("shell_metachar" in f.issue for f in findings)

    def test_template_injection_detected(self):
        guard = InjectionGuard()
        findings = guard.scan({"template": "Hello {{7*7}}"})
        assert any("template_injection" in f.issue for f in findings)

    def test_script_injection_detected(self):
        guard = InjectionGuard()
        findings = guard.scan({"html": '<script>alert(1)</script>'})
        assert any("script_injection" in f.issue for f in findings)

    def test_nested_dict_scanned(self):
        guard = InjectionGuard()
        findings = guard.scan({"outer": {"inner": "DROP TABLE users"}})
        assert any("sql_injection" in f.issue for f in findings)
        assert any("outer.inner" in f.parameter for f in findings)

    def test_list_values_scanned(self):
        guard = InjectionGuard()
        findings = guard.scan({"items": ["safe", "../../etc/passwd"]})
        assert any("items[1]" in f.parameter for f in findings)

    def test_excerpt_is_html_escaped(self):
        guard = InjectionGuard()
        findings = guard.scan({"q": 'foo <script> DROP TABLE users'})
        for f in findings:
            assert "<script>" not in f.excerpt  # raw tag must be escaped

    def test_clean_nested_structure_passes(self):
        guard = InjectionGuard()
        assert guard.scan({"a": {"b": {"c": "safe text"}}}) == []


# ===========================================================================
# ParameterValidator — schema registration and validation
# ===========================================================================

class TestParameterValidator:

    def _validator_with_schema(self, tool_name: str = "search") -> ParameterValidator:
        v = ParameterValidator()
        v.register_schema(tool_name, {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        })
        return v

    def test_valid_params_pass(self):
        v = self._validator_with_schema()
        v.validate("search", {"query": "hello"})  # must not raise

    def test_missing_required_field_raises(self):
        v = self._validator_with_schema()
        with pytest.raises(ParameterValidationError) as exc_info:
            v.validate("search", {})
        assert any("schema_violation" in f.issue for f in exc_info.value.findings)

    def test_wrong_type_raises(self):
        v = self._validator_with_schema()
        with pytest.raises(ParameterValidationError) as exc_info:
            v.validate("search", {"query": 42})
        assert any("schema_violation:type" in f.issue for f in exc_info.value.findings)

    def test_additional_property_rejected_in_strict_mode(self):
        """additionalProperties: false enforced automatically when schema has properties."""
        v = self._validator_with_schema()
        with pytest.raises(ParameterValidationError) as exc_info:
            v.validate("search", {"query": "hello", "extra": "not allowed"})
        assert any("schema_violation:additionalProperties" in f.issue for f in exc_info.value.findings)  # noqa: E501

    def test_unknown_tool_rejected_by_default(self):
        v = ParameterValidator()  # allow_unknown_tools=False by default
        with pytest.raises(ParameterValidationError) as exc_info:
            v.validate("unknown_tool", {"arg": "val"})
        assert any("schema_not_registered" in f.issue for f in exc_info.value.findings)

    def test_unknown_tool_allowed_when_flag_set(self):
        v = ParameterValidator(allow_unknown_tools=True)
        # No exception; injection guard still runs on clean args.
        v.validate("any_tool", {"query": "hello"})

    def test_injection_in_valid_schema_args_raises(self):
        v = self._validator_with_schema()
        with pytest.raises(ParameterValidationError) as exc_info:
            v.validate("search", {"query": "foo; DROP TABLE users --"})
        assert any("injection" in f.issue for f in exc_info.value.findings)

    def test_findings_do_not_contain_raw_param_values(self):
        """Error message must not leak raw parameter values."""
        v = self._validator_with_schema()
        secret = "s3cr3t_token"
        with pytest.raises(ParameterValidationError) as exc_info:
            v.validate("search", {"query": 42, "secret_field": secret})
        error_str = str(exc_info.value)
        assert secret not in error_str

    def test_multiple_schema_violations_all_reported(self):
        v = ParameterValidator()
        v.register_schema("multi", {
            "type": "object",
            "properties": {
                "a": {"type": "string"},
                "b": {"type": "integer"},
            },
            "required": ["a", "b"],
        })
        with pytest.raises(ParameterValidationError) as exc_info:
            v.validate("multi", {"a": 1, "b": "wrong"})
        # Both type violations should be in findings.
        assert len(exc_info.value.findings) >= 2
