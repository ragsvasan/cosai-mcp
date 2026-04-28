"""Tests for adversarial probe infrastructure: canary, enforcer, AdversarialMode."""
from __future__ import annotations

import pytest

from cosai_mcp.adversarial.canary import (
    Canary,
    _CANARY_PATTERN,
    generate_canary,
    detect_canary,
)
from cosai_mcp.adversarial.enforcer import (
    UnsafeProbeError,
    validate_dual_optin,
    check_no_external_endpoints,
    _reject_if_external_url,
)
from cosai_mcp.adversarial import AdversarialMode


# ---------------------------------------------------------------------------
# Canary generation
# ---------------------------------------------------------------------------

class TestCanaryGeneration:

    def test_generate_canary_format(self):
        """Generated canary must match the expected format."""
        c = generate_canary("T03-ADV-001", "abc12345-xxxx-xxxx-xxxx")
        assert c.value.startswith("COSAI_PROBE_T03-ADV-001_ABC12345_")
        # Last segment is the 8-byte hex token (16 hex chars — 64-bit entropy)
        token = c.value.split("_")[-1]
        assert len(token) == 16
        assert all(ch in "0123456789abcdef" for ch in token)

    def test_generate_canary_unique(self):
        """Two canaries for the same threat+scan must not be identical (CSPRNG)."""
        c1 = generate_canary("T03-ADV-001", "abc12345")
        c2 = generate_canary("T03-ADV-001", "abc12345")
        # Token component is CSPRNG; collision probability is ~1/2^64 — negligible
        assert c1.value != c2.value

    def test_generate_canary_empty_scan_id(self):
        """Empty scan_id falls back to 00000000 prefix."""
        c = generate_canary("T03-ADV-001", "")
        assert "_00000000_" in c.value

    def test_canary_redacted(self):
        """redacted() always returns the sentinel string."""
        c = generate_canary("T03-ADV-001", "abc12345")
        assert c.redacted() == "[CANARY REDACTED]"

    def test_detect_canary_present(self):
        c = generate_canary("T03-ADV-001", "abc12345")
        assert detect_canary(f"some prefix {c.value} some suffix", c) is True

    def test_detect_canary_absent(self):
        c = generate_canary("T03-ADV-001", "abc12345")
        assert detect_canary("no canary here", c) is False

    def test_detect_canary_empty_body(self):
        c = generate_canary("T03-ADV-001", "abc12345")
        assert detect_canary("", c) is False

    def test_regression_canary_pattern_matches_generated_value(self):
        """_CANARY_PATTERN must match every value produced by generate_canary.

        FIX [1]: the original pattern didn't account for hyphens in threat IDs
        (T03-ADV-001) and the no-op replace(-,-) left the format as-written.
        """
        for threat_id in ("T03-ADV-001", "T11-ADV-001", "T07-ADV-001"):
            c = generate_canary(threat_id, "abc12345")
            assert _CANARY_PATTERN.search(c.value) is not None, (
                f"Pattern did not match canary: {c.value!r}"
            )

    def test_regression_canary_token_is_64_bits(self):
        """Token component must be 16 hex chars (64 bits).

        FIX [7]: original used token_hex(4) = 32 bits, below NIST SP 800-131A minimum.
        """
        c = generate_canary("T03-ADV-001", "abc12345")
        token = c.value.split("_")[-1]
        assert len(token) == 16, f"Expected 16 hex chars, got {len(token)}: {token!r}"


# ---------------------------------------------------------------------------
# Dual opt-in validation
# ---------------------------------------------------------------------------

class TestDualOptin:

    def test_disabled_adversarial_always_passes(self):
        """validate_dual_optin must be a no-op when adversarial=False."""
        validate_dual_optin(
            adversarial=False,
            ownership_declaration=None,
            target_url="http://example.com",
        )

    def test_adversarial_without_declaration_raises(self):
        """adversarial=True without ownership_declaration must raise ValueError."""
        with pytest.raises(ValueError, match="--i-own-this-target"):
            validate_dual_optin(
                adversarial=True,
                ownership_declaration=None,
                target_url="http://example.com",
            )

    def test_adversarial_declaration_missing_hostname_raises(self):
        """Declaration that doesn't contain the target hostname must raise."""
        with pytest.raises(ValueError, match="example.com"):
            validate_dual_optin(
                adversarial=True,
                ownership_declaration="myserver.different.com",
                target_url="http://example.com",
            )

    def test_adversarial_declaration_contains_hostname_passes(self):
        """Declaration containing the target hostname must pass."""
        validate_dual_optin(
            adversarial=True,
            ownership_declaration="I own example.com and have authorization",
            target_url="http://example.com/mcp",
        )

    def test_adversarial_declaration_case_insensitive(self):
        """Hostname matching should be case-insensitive."""
        validate_dual_optin(
            adversarial=True,
            ownership_declaration="EXAMPLE.COM",
            target_url="http://example.com",
        )

    def test_regression_short_hostname_rejected(self):
        """Short hostnames (< 4 chars) must be rejected as too ambiguous.

        FIX [4]: short hostnames like 'api', 'mcp' are generic enough that
        a free-form declaration like 'I own the api server' could pass for any
        short-hostname target. Minimum length enforced.
        """
        with pytest.raises(ValueError, match="too short"):
            validate_dual_optin(
                adversarial=True,
                ownership_declaration="I own the api server",
                target_url="http://api/mcp",
            )

    def test_regression_word_boundary_prevents_suffix_match(self):
        """Hostname must match as a complete word, not as a substring of another hostname.

        FIX [4]: 'localhost' in declaration must NOT match target 'localhost.evil.com'.
        """
        with pytest.raises(ValueError):
            validate_dual_optin(
                adversarial=True,
                ownership_declaration="I own localhost server",
                target_url="http://localhost.evil.com",
            )

    def test_regression_word_boundary_prevents_prefix_match(self):
        """Hostname must not match as prefix of a longer word."""
        with pytest.raises(ValueError):
            validate_dual_optin(
                adversarial=True,
                ownership_declaration="notexample.com is my property",
                target_url="http://example.com",
            )

    def test_regression_url_with_credentials_hostname_extracted_correctly(self):
        """urlparse extracts hostname correctly from URLs with userinfo.

        Documents that urlparse('http://target@evil.com').hostname = 'evil.com',
        so the check correctly validates against the real destination host.
        """
        # target URL has userinfo — urlparse should give hostname='evil.com'
        # declaration contains 'evil.com' → this SHOULD pass (evil.com is the target)
        validate_dual_optin(
            adversarial=True,
            ownership_declaration="I own evil.com for testing",
            target_url="http://target@evil.com",
        )


# ---------------------------------------------------------------------------
# External endpoint check
# ---------------------------------------------------------------------------

class TestExternalEndpointCheck:

    def test_no_urls_passes(self):
        probe = {"id": "T03-ADV-001-p1", "payload": {"name": "my_tool", "arguments": {"input": "hello"}}}
        check_no_external_endpoints(probe, "http://myserver.example.com:8000")

    def test_same_host_url_passes(self):
        probe = {"id": "T03-ADV-001-p1", "callback": "http://myserver.example.com:8000/callback"}
        check_no_external_endpoints(probe, "http://myserver.example.com:8000")

    def test_external_url_raises(self):
        probe = {"id": "T03-ADV-001-p1", "callback": "http://attacker.com/exfil"}
        with pytest.raises(UnsafeProbeError, match="external URL"):
            check_no_external_endpoints(probe, "http://myserver.example.com:8000")

    def test_https_external_url_raises(self):
        probe = {"callback": "https://evil.com/hook"}
        with pytest.raises(UnsafeProbeError, match="external URL"):
            check_no_external_endpoints(probe, "http://myserver.example.com:8000")

    def test_stateful_probe_without_flag_raises(self):
        probe = {"id": "T05-ADV-001", "mode": "stateful"}
        with pytest.raises(UnsafeProbeError, match="stateful"):
            check_no_external_endpoints(probe, "http://myserver.example.com:8000", allow_stateful=False)

    def test_stateful_probe_with_flag_passes(self):
        probe = {"id": "T05-ADV-001", "mode": "stateful"}
        check_no_external_endpoints(probe, "http://myserver.example.com:8000", allow_stateful=True)

    def test_nested_external_url_in_list_raises(self):
        probe = {"probes": [{"payload": {"urls": ["https://exfil.com/endpoint"]}}]}
        with pytest.raises(UnsafeProbeError, match="external URL"):
            check_no_external_endpoints(probe, "http://myserver.example.com:8000")

    def test_regression_loopback_127_raises_even_when_target_is_loopback(self):
        """127.x.x.x in probe must raise even when target is also 127.0.0.1.

        FIX [3]: original code only checked host != target_host, so a probe URL
        pointing to 127.0.0.1/admin-panel would pass through when scanning 127.0.0.1:8000.
        Loopback addresses are always blocked in probe payloads.
        """
        probe = {"callback": "http://127.0.0.1/admin"}
        with pytest.raises(UnsafeProbeError, match="blocked address"):
            check_no_external_endpoints(probe, "http://127.0.0.1:8000")

    def test_regression_zero_addr_raises(self):
        """0.0.0.0 in probe URL must always raise.

        FIX [3]: defense-in-depth — 0.0.0.0 is never a legitimate callback target.
        """
        probe = {"callback": "http://0.0.0.0/callback"}
        with pytest.raises(UnsafeProbeError, match="blocked address"):
            check_no_external_endpoints(probe, "http://myserver.example.com:8000")

    def test_regression_ipv6_loopback_raises(self):
        """IPv6 loopback (::1) in probe URL must raise."""
        probe = {"callback": "http://[::1]/callback"}
        with pytest.raises(UnsafeProbeError, match="blocked address"):
            check_no_external_endpoints(probe, "http://myserver.example.com:8000")


# ---------------------------------------------------------------------------
# AdversarialMode dataclass
# ---------------------------------------------------------------------------

class TestAdversarialMode:

    def test_disabled_by_default(self):
        mode = AdversarialMode()
        assert mode.enabled is False

    def test_validate_disabled_noop(self):
        mode = AdversarialMode(enabled=False)
        mode.validate("http://example.com")  # must not raise

    def test_validate_enabled_no_declaration_raises(self):
        mode = AdversarialMode(enabled=True, ownership_declaration=None)
        with pytest.raises(ValueError):
            mode.validate("http://example.com")

    def test_make_canary_returns_canary(self):
        mode = AdversarialMode(enabled=True, scan_id="abc12345")
        c = mode.make_canary("T03-ADV-001")
        assert isinstance(c, Canary)
        assert "T03-ADV-001" in c.value

    def test_adversarial_mode_is_frozen(self):
        mode = AdversarialMode()
        with pytest.raises(Exception):
            mode.enabled = True  # type: ignore[misc]

    def test_regression_scan_id_stamped_into_canary(self):
        """Canary scan_id_prefix must use the AdversarialMode.scan_id.

        FIX [2]: CLI originally passed scan_id="" to AdversarialMode (frozen dataclass),
        so all canaries had _00000000_ prefix. _run_scan now stamps the UUID.
        This test verifies the canary reflects scan_id correctly.
        """
        mode = AdversarialMode(enabled=True, scan_id="deadbeef-1234-5678-abcd-ef0123456789")
        c = mode.make_canary("T03-ADV-001")
        assert "_DEADBEEF_" in c.value
