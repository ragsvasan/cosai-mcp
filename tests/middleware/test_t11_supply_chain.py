"""Tests for T11 middleware: SupplyChainEnforcer, AllowlistEnforcer, RegistrySignatureVerifier."""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cosai_mcp.middleware.supply_chain import (
    AllowlistEnforcer,
    RegistrySignatureVerifier,
    SignatureVerificationError,
    SupplyChainEnforcer,
    SupplyChainError,
)


def _tool(name: str) -> dict:
    return {"name": name, "description": f"{name} tool"}


# ===========================================================================
# AllowlistEnforcer
# ===========================================================================

class TestAllowlistEnforcer:

    def test_exact_match_allowed(self):
        enforcer = AllowlistEnforcer(frozenset({"search", "summarise"}))
        violations = enforcer.check_tools([_tool("search"), _tool("summarise")])
        assert violations == []

    def test_tool_not_in_allowlist_blocked(self):
        enforcer = AllowlistEnforcer(frozenset({"search"}))
        violations = enforcer.check_tools([_tool("execute_shell")])
        assert len(violations) == 1
        assert violations[0].reason == "not_in_allowlist"
        assert violations[0].tool_name == "execute_shell"

    def test_typosquat_distance_1_blocked(self):
        """'searc' is 1 edit away from 'search' — must be blocked as typosquat."""
        enforcer = AllowlistEnforcer(frozenset({"search"}))
        violations = enforcer.check_tools([_tool("searc")])
        assert len(violations) == 1
        assert violations[0].reason == "typosquat"
        assert violations[0].distance == 1
        assert violations[0].closest_match == "search"

    def test_typosquat_distance_2_not_blocked(self):
        """Distance > 1 is 'not_in_allowlist', not typosquat (threshold is ≤ 1)."""
        enforcer = AllowlistEnforcer(frozenset({"search"}))
        violations = enforcer.check_tools([_tool("sear")])  # distance 2
        # sear vs search: s-e-a-r-c-h  → delete c and h from search = 2 edits
        # Should still be a violation but with reason="not_in_allowlist"
        assert len(violations) == 1
        assert violations[0].reason == "not_in_allowlist"

    def test_empty_allowlist_allows_all(self):
        """No allowlist configured → pass-through."""
        enforcer = AllowlistEnforcer()
        violations = enforcer.check_tools([_tool("anything"), _tool("dangerous")])
        assert violations == []

    def test_mixed_tools_partial_violations(self):
        enforcer = AllowlistEnforcer(frozenset({"search", "fetch"}))
        tools = [_tool("search"), _tool("evil_tool"), _tool("fetch")]
        violations = enforcer.check_tools(tools)
        assert len(violations) == 1
        assert violations[0].tool_name == "evil_tool"


# ===========================================================================
# RegistrySignatureVerifier
# ===========================================================================

class TestRegistrySignatureVerifier:

    def _keypair(self):
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        return priv, pub

    def _sign(self, priv: Ed25519PrivateKey, tool_def: dict) -> bytes:
        message = RegistrySignatureVerifier.canonical_bytes(tool_def)
        return priv.sign(message)

    def test_valid_signature_passes(self):
        priv, pub = self._keypair()
        tool_def = {"name": "search", "version": "1.0"}
        sig = self._sign(priv, tool_def)
        verifier = RegistrySignatureVerifier(pub)
        verifier.verify(tool_def, sig)  # must not raise

    def test_tampered_tool_def_raises(self):
        priv, pub = self._keypair()
        tool_def = {"name": "search", "version": "1.0"}
        sig = self._sign(priv, tool_def)
        tampered = {"name": "evil", "version": "1.0"}
        verifier = RegistrySignatureVerifier(pub)
        with pytest.raises(SignatureVerificationError):
            verifier.verify(tampered, sig)

    def test_wrong_key_raises(self):
        priv, _ = self._keypair()
        _, wrong_pub = self._keypair()
        tool_def = {"name": "search"}
        sig = self._sign(priv, tool_def)
        verifier = RegistrySignatureVerifier(wrong_pub)
        with pytest.raises(SignatureVerificationError):
            verifier.verify(tool_def, sig)

    def test_truncated_signature_raises(self):
        priv, pub = self._keypair()
        tool_def = {"name": "search"}
        sig = self._sign(priv, tool_def)
        verifier = RegistrySignatureVerifier(pub)
        with pytest.raises(SignatureVerificationError):
            verifier.verify(tool_def, sig[:32])

    def test_canonical_bytes_deterministic(self):
        tool_a = {"b": 2, "a": 1}
        tool_b = {"a": 1, "b": 2}
        assert RegistrySignatureVerifier.canonical_bytes(tool_a) == \
               RegistrySignatureVerifier.canonical_bytes(tool_b)


# ===========================================================================
# SupplyChainEnforcer — integration (allowlist + signature via check_tools)
# ===========================================================================

class TestSupplyChainEnforcer:

    def test_check_tools_passes_clean_manifest(self):
        enforcer = SupplyChainEnforcer(allowlist=frozenset({"search", "fetch"}))
        enforcer.check_tools([_tool("search"), _tool("fetch")])  # no exception

    def test_check_tools_raises_on_violation(self):
        enforcer = SupplyChainEnforcer(allowlist=frozenset({"search"}))
        with pytest.raises(SupplyChainError) as exc_info:
            enforcer.check_tools([_tool("search"), _tool("malicious")])
        assert len(exc_info.value.violations) == 1
        assert exc_info.value.violations[0].tool_name == "malicious"

    def test_no_verifier_raises_on_verify_signature(self):
        enforcer = SupplyChainEnforcer()
        with pytest.raises(SignatureVerificationError, match="No registry verifier"):
            enforcer.verify_tool_signature({"name": "x"}, b"fake")

    def test_verify_tool_signature_with_valid_key(self):
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        verifier = RegistrySignatureVerifier(pub)
        enforcer = SupplyChainEnforcer(registry_verifier=verifier)
        tool_def = {"name": "search", "version": "2.0"}
        message = RegistrySignatureVerifier.canonical_bytes(tool_def)
        sig = priv.sign(message)
        enforcer.verify_tool_signature(tool_def, sig)  # must not raise

    def test_typosquat_blocked_via_check_tools(self):
        """Gate fires from check_tools entry point (not AllowlistEnforcer directly)."""
        enforcer = SupplyChainEnforcer(allowlist=frozenset({"fetch"}))
        with pytest.raises(SupplyChainError) as exc_info:
            enforcer.check_tools([_tool("fetc")])  # distance 1 from "fetch"
        assert exc_info.value.violations[0].reason == "typosquat"
