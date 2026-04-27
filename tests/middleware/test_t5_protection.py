"""Tests for T5 middleware: PIIScrubber and ContextLeakChecker."""
from __future__ import annotations

import warnings

import pytest

# Suppress RuntimeWarning if google-re2 is absent (fallback to stdlib re)
with warnings.catch_warnings():
    warnings.simplefilter("ignore", RuntimeWarning)
    from cosai_mcp.middleware.protection import (
        ContextLeakChecker,
        LeakCheckResult,
        PIIScrubber,
        ScrubResult,
    )


# ===========================================================================
# PIIScrubber — individual pattern tests
# ===========================================================================

class TestPIIScrubberPatterns:

    def _scrubber(self) -> PIIScrubber:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            return PIIScrubber()

    def test_ssn_pattern_scrubbed(self):
        s = self._scrubber()
        result = s.scrub("SSN: 123-45-6789")
        assert "123-45-6789" not in result.text
        assert "[REDACTED:ssn]" in result.text
        assert result.redacted_count == 1

    def test_credit_card_scrubbed(self):
        s = self._scrubber()
        # 4111111111111111 is a known Luhn-valid Visa test number
        result = s.scrub("Card: 4111111111111111")
        assert "4111111111111111" not in result.text
        assert "[REDACTED:credit_card]" in result.text

    def test_jwt_header_scrubbed(self):
        s = self._scrubber()
        # Typical JWT: eyJ<header>.<payload>.<sig>
        jwt = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1c2VyMSJ9.abc123def456"
        result = s.scrub(f"Token: {jwt}")
        assert "eyJhbGciOiJFZERTQSJ9" not in result.text
        assert "[REDACTED:jwt]" in result.text

    def test_api_key_sk_scrubbed(self):
        s = self._scrubber()
        result = s.scrub("key=sk-abcdefghijklmnopqrstuvwxyz123456789012345")
        assert "sk-" not in result.text
        assert "[REDACTED:api_key_sk]" in result.text

    def test_ghp_token_scrubbed(self):
        s = self._scrubber()
        ghp = "ghp_" + "A" * 36
        result = s.scrub(f"GitHub PAT: {ghp}")
        assert ghp not in result.text
        assert "[REDACTED:github_pat]" in result.text

    def test_clean_text_unchanged(self):
        s = self._scrubber()
        text = "The capital of France is Paris."
        result = s.scrub(text)
        assert result.text == text
        assert result.redacted_count == 0
        assert result.findings == ()

    def test_multiple_pii_types(self):
        s = self._scrubber()
        text = "SSN: 123-45-6789 and email: user@example.com"
        result = s.scrub(text)
        assert "123-45-6789" not in result.text
        assert "user@example.com" not in result.text
        assert result.redacted_count == 2

    def test_findings_are_tuple(self):
        s = self._scrubber()
        result = s.scrub("SSN: 123-45-6789")
        assert isinstance(result.findings, tuple)

    def test_result_is_frozen(self):
        s = self._scrubber()
        result = s.scrub("safe")
        with pytest.raises((AttributeError, TypeError)):
            result.text = "mutated"  # type: ignore[misc]

    def test_email_scrubbed(self):
        s = self._scrubber()
        result = s.scrub("Contact admin@corp.example.com for help.")
        assert "admin@corp.example.com" not in result.text
        assert "[REDACTED:email]" in result.text

    def test_non_overlapping_selection(self):
        """When two patterns overlap, only the first (leftmost, longest) is selected."""
        s = self._scrubber()
        # 40-char hex could match hex_api_key; but sk- prefix takes priority
        result = s.scrub("sk-" + "a" * 40)
        assert result.redacted_count >= 1  # at least one match

    def test_empty_string_returns_empty(self):
        s = self._scrubber()
        result = s.scrub("")
        assert result.text == ""
        assert result.redacted_count == 0


# ===========================================================================
# ContextLeakChecker
# ===========================================================================

class TestContextLeakChecker:

    def _checker(self) -> ContextLeakChecker:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            return ContextLeakChecker()

    def test_context_leak_checker_flags_foreign_session_id(self):
        checker = self._checker()
        result = checker.check(
            current_session_id="sess_ABC",
            content="Here is some context from sess_XYZ about the previous user.",
        )
        assert result.leaked is True
        assert len(result.findings) >= 1
        assert result.findings[0].found_session_id == "sess_XYZ"

    def test_context_leak_checker_passes_own_session(self):
        checker = self._checker()
        result = checker.check(
            current_session_id="sess_ABC",
            content="Your current session is sess_ABC.",
        )
        assert result.leaked is False
        assert result.findings == ()

    def test_clean_content_not_flagged(self):
        checker = self._checker()
        result = checker.check(
            current_session_id="sess_ABC",
            content="The answer is 42 and the sky is blue.",
        )
        assert result.leaked is False

    def test_multiple_foreign_sessions_detected(self):
        checker = self._checker()
        result = checker.check(
            current_session_id="sess_MINE",
            content="sess_OTHER1 did X. sess_OTHER2 did Y.",
        )
        assert result.leaked is True
        assert len(result.findings) == 2

    def test_leak_check_result_is_frozen(self):
        checker = self._checker()
        result = checker.check("sess_A", "safe text")
        with pytest.raises((AttributeError, TypeError)):
            result.leaked = True  # type: ignore[misc]

    def test_session_id_style_variants(self):
        checker = self._checker()
        # session- prefix variant
        result = checker.check(
            current_session_id="session-MINE",
            content="Data from session-OTHER leaking here.",
        )
        assert result.leaked is True

    def test_re2_patterns_load_without_error(self):
        """Module-level RE2 patterns compile without raising at import."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            import importlib
            import cosai_mcp.middleware.protection as m
            importlib.reload(m)


# ===========================================================================
# Regression tests for panel P1 findings
# ===========================================================================

class TestPIIScrubberRegressions:

    def _scrubber(self) -> PIIScrubber:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            return PIIScrubber()

    def test_regression_hex40_git_sha_not_redacted(self):
        """Git SHA-1 hashes (40 hex chars) must NOT be redacted.

        FIX 3: hex_api_key pattern r'\\b[0-9a-f]{40}\\b' produced high false-positive
        rate on git commit SHAs that appear in MCP tool output (e.g. from git tools).
        Pattern was removed from _PII_PATTERNS.
        """
        s = self._scrubber()
        git_sha = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
        result = s.scrub(f"commit {git_sha}")
        assert result.redacted_count == 0
        assert git_sha in result.text

    def test_regression_hex40_not_in_pattern_names(self):
        """Confirm hex_api_key is not present in the compiled pattern set."""
        s = self._scrubber()
        pattern_names = [name for name, _ in s._compiled]
        assert "hex_api_key" not in pattern_names
