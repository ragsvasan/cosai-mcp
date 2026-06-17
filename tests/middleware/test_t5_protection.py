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

    def _strict_scrubber(self) -> PIIScrubber:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            return PIIScrubber(pii_strict=True)

    def test_ssn_pattern_scrubbed(self):
        # SSN moved to the strict (--pii-strict) tier (WG-89 item 3).
        s = self._strict_scrubber()
        result = s.scrub("SSN: 123-45-6789")
        assert "123-45-6789" not in result.text
        assert "[REDACTED:ssn]" in result.text
        assert result.redacted_count == 1

    def test_pan_scrubbed_strict(self):
        s = self._strict_scrubber()
        # 4111111111111111 is a known Luhn-valid Visa test number
        result = s.scrub("Card: 4111111111111111")
        assert "4111111111111111" not in result.text
        assert "[REDACTED:pan]" in result.text

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
        # ssn is strict-tier, email is default-tier → use strict to catch both.
        s = self._strict_scrubber()
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


# ===========================================================================
# WG-89 item 3 — expanded credential pattern set (always-on, anchored)
# ===========================================================================

class TestExpandedCredentialPatterns:

    def _scrubber(self) -> PIIScrubber:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            return PIIScrubber()

    def test_aws_access_key_scrubbed(self):
        s = self._scrubber()
        key = "AKIA" + "ABCDEFGH12345678"  # AKIA + 16 alnum
        result = s.scrub(f"aws_access_key_id={key}")
        assert key not in result.text
        assert "[REDACTED:aws_access_key]" in result.text

    def test_google_api_key_scrubbed(self):
        s = self._scrubber()
        key = "AIza" + "B" * 35
        result = s.scrub(f"key={key}")
        assert key not in result.text
        assert "[REDACTED:google_api_key]" in result.text

    def test_gitlab_pat_scrubbed(self):
        s = self._scrubber()
        tok = "glpat-" + "x" * 20
        result = s.scrub(f"token: {tok}")
        assert tok not in result.text
        assert "[REDACTED:gitlab_pat]" in result.text

    def test_github_pat_gho_variant_scrubbed(self):
        s = self._scrubber()
        tok = "gho_" + "Z" * 36
        result = s.scrub(f"oauth: {tok}")
        assert "[REDACTED:github_pat]" in result.text

    def test_gcp_service_account_marker_scrubbed(self):
        s = self._scrubber()
        blob = '{"type": "service_account", "project_id": "x"}'
        result = s.scrub(blob)
        assert "[REDACTED:gcp_service_account]" in result.text

    def test_azure_sas_signature_scrubbed(self):
        s = self._scrubber()
        url = "https://acct.blob.core.windows.net/c/b?sv=2021&sig=" + "A" * 30
        result = s.scrub(url)
        assert "[REDACTED:azure_sas]" in result.text

    def test_jwt_two_segment_eyj_scrubbed(self):
        s = self._scrubber()
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig123"
        result = s.scrub(f"auth: {jwt}")
        assert "[REDACTED:jwt]" in result.text

    def test_credentials_not_in_default_email_only_doc(self):
        """A clean tool description with no secret produces zero findings."""
        s = self._scrubber()
        result = s.scrub("Searches the corpus and returns ranked results.")
        assert result.redacted_count == 0


class TestContextLeakPatterns:

    def _scrubber(self) -> PIIScrubber:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            return PIIScrubber()

    def test_internal_hostname_flagged(self):
        s = self._scrubber()
        result = s.scrub("connect to db-primary.internal for the data")
        assert "[REDACTED:internal_hostname]" in result.text

    def test_k8s_svc_hostname_flagged(self):
        s = self._scrubber()
        result = s.scrub("upstream is api.payments.svc.cluster.local here")
        assert "[REDACTED:internal_hostname]" in result.text

    def test_public_hostname_not_flagged(self):
        s = self._scrubber()
        result = s.scrub("see https://example.com/docs for details")
        assert "internal_hostname" not in {f.pii_type for f in result.findings}

    def test_stack_trace_flagged(self):
        s = self._scrubber()
        result = s.scrub("Traceback (most recent call last): ValueError")
        assert "[REDACTED:stack_trace]" in result.text


# ===========================================================================
# WG-89 item 3 — strict-tier gating + Luhn corroboration
# ===========================================================================

class TestPIIStrictGating:

    def _default(self) -> PIIScrubber:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            return PIIScrubber()

    def _strict(self) -> PIIScrubber:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            return PIIScrubber(pii_strict=True)

    def test_ssn_not_scrubbed_in_default_mode(self):
        result = self._default().scrub("SSN: 123-45-6789")
        assert "123-45-6789" in result.text
        assert result.redacted_count == 0

    def test_ssn_scrubbed_in_strict_mode(self):
        result = self._strict().scrub("SSN: 123-45-6789")
        assert "[REDACTED:ssn]" in result.text

    def test_iban_scrubbed_only_in_strict(self):
        iban = "DE89370400440532013000"
        assert iban in self._default().scrub(f"IBAN {iban}").text
        assert "[REDACTED:iban]" in self._strict().scrub(f"IBAN {iban}").text

    def test_pan_luhn_valid_scrubbed_in_strict(self):
        # Luhn-valid Visa test number
        result = self._strict().scrub("4111111111111111")
        assert "[REDACTED:pan]" in result.text

    def test_pan_luhn_invalid_not_scrubbed_even_in_strict(self):
        """A 16-digit number that fails Luhn must NOT be redacted — corroboration."""
        # 4111111111111112 fails the Luhn checksum
        result = self._strict().scrub("order id 4111111111111112")
        assert "4111111111111112" in result.text
        assert result.redacted_count == 0

    def test_default_credentials_still_on_in_default_mode(self):
        """Strict gating must not disable the always-on credential tier."""
        result = self._default().scrub("key=sk-abcdefghijklmnopqrstuvwxyz123456")
        assert "[REDACTED:api_key_sk]" in result.text

    def test_pii_strict_property_reflects_mode(self):
        assert self._default().pii_strict is False
        assert self._strict().pii_strict is True


class TestLuhnValidator:

    def _luhn(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            from cosai_mcp.middleware.protection import _luhn_valid
            return _luhn_valid

    def test_known_valid_card(self):
        assert self._luhn()("4111111111111111") is True

    def test_known_invalid_card(self):
        assert self._luhn()("4111111111111112") is False

    def test_strips_spaces_and_dashes(self):
        assert self._luhn()("4111-1111-1111-1111") is True

    def test_rejects_too_short(self):
        assert self._luhn()("123456789012") is False  # 12 digits < 13

    def test_rejects_too_long(self):
        assert self._luhn()("1" * 20) is False  # 20 digits > 19
