"""Tests for report signing and signature verification."""
from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cosai_mcp.report.sign import (
    ReportSignature,
    ReportSigner,
    _pub_fingerprint,
    verify_report_signature,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _signer() -> ReportSigner:
    """Return a ReportSigner with a fresh ephemeral key (no keyring I/O)."""
    return ReportSigner(private_key=Ed25519PrivateKey.generate())


def _sign(signer: ReportSigner, sarif: str = '{"version":"2.1.0"}') -> ReportSignature:
    return signer.sign(
        sarif_json=sarif,
        scan_timestamp="2026-04-27T00:00:00Z",
        catalog_hash="a" * 64,
    )


def _trusted_fp(signer: ReportSigner) -> str:
    """Return the public-key fingerprint for the given signer (the 'trusted' value)."""
    pub = signer._key.public_key()
    return _pub_fingerprint(pub)


# ---------------------------------------------------------------------------
# Signature structure
# ---------------------------------------------------------------------------

class TestReportSignatureStructure:

    def test_signature_has_public_key_fingerprint(self):
        sig = _sign(_signer())
        assert len(sig.public_key_fingerprint) == 64  # hex SHA-256

    def test_signature_has_public_key_b64(self):
        sig = _sign(_signer())
        assert sig.public_key_b64  # non-empty

    def test_signature_has_report_hash(self):
        sarif = '{"version":"2.1.0"}'
        sig = _sign(_signer(), sarif)
        expected = hashlib.sha256(sarif.encode()).hexdigest()
        assert sig.report_hash == expected

    def test_signature_has_catalog_hash(self):
        sig = _sign(_signer())
        assert sig.catalog_hash == "a" * 64

    def test_signature_is_frozen(self):
        sig = _sign(_signer())
        with pytest.raises((AttributeError, TypeError)):
            sig.report_hash = "mutated"  # type: ignore[misc]

    def test_signature_to_dict_roundtrip(self):
        sig = _sign(_signer())
        d = sig.to_dict()
        reconstructed = ReportSignature.from_dict(d)
        assert reconstructed == sig


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

class TestReportSignatureVerification:

    def test_report_signature_verifiable(self):
        """Signed report verifies successfully using the trusted fingerprint."""
        signer = _signer()
        sarif = '{"version":"2.1.0","runs":[]}'
        sig = _sign(signer, sarif)
        assert verify_report_signature(sig, sarif, _trusted_fp(signer)) is True

    def test_tampered_sarif_fails_verification(self):
        """Altering SARIF content after signing must fail verification."""
        signer = _signer()
        sarif = '{"version":"2.1.0","runs":[]}'
        sig = _sign(signer, sarif)
        tampered = '{"version":"2.1.0","runs":[],"extra":"injected"}'
        assert verify_report_signature(sig, tampered, _trusted_fp(signer)) is False

    def test_wrong_key_fails_verification(self):
        """Signature from key1 embedded alongside key2's public key must fail."""
        signer1 = _signer()
        signer2 = _signer()
        sarif = '{"version":"2.1.0"}'
        sig1 = _sign(signer1, sarif)
        sig2 = _sign(signer2, sarif)
        mixed = ReportSignature(
            public_key_fingerprint=sig2.public_key_fingerprint,
            public_key_b64=sig2.public_key_b64,
            scan_timestamp=sig1.scan_timestamp,
            catalog_hash=sig1.catalog_hash,
            report_hash=sig1.report_hash,
            signature_b64=sig1.signature_b64,  # signed by key1, not key2
        )
        assert verify_report_signature(mixed, sarif, _trusted_fp(signer2)) is False

    def test_different_sarif_produces_different_signature(self):
        signer = _signer()
        sarif_a = '{"version":"2.1.0","runs":[]}'
        sarif_b = '{"version":"2.1.0","runs":[],"extra":1}'
        sig_a = _sign(signer, sarif_a)
        sig_b = _sign(signer, sarif_b)
        assert sig_a.signature_b64 != sig_b.signature_b64

    def test_different_keys_produce_different_fingerprints(self):
        s1 = _signer()
        s2 = _signer()
        sig1 = _sign(s1)
        sig2 = _sign(s2)
        assert sig1.public_key_fingerprint != sig2.public_key_fingerprint

    def test_corrupted_signature_b64_fails(self):
        signer = _signer()
        sarif = '{"version":"2.1.0"}'
        sig = _sign(signer, sarif)
        bad_sig = ReportSignature(
            public_key_fingerprint=sig.public_key_fingerprint,
            public_key_b64=sig.public_key_b64,
            scan_timestamp=sig.scan_timestamp,
            catalog_hash=sig.catalog_hash,
            report_hash=sig.report_hash,
            signature_b64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        assert verify_report_signature(bad_sig, sarif, _trusted_fp(signer)) is False

    def test_regression_verify_attacker_key_substitution(self):
        """Attacker substitutes own key pair; verification must fail against trusted fingerprint.

        FIX 1 / ADVERSARY 6: verify_report_signature previously accepted any
        self-consistent sig+key pair regardless of key identity. Now requires a
        trusted_fingerprint from a separate trust store.
        """
        attacker_signer = _signer()
        victim_signer = _signer()
        victim_fp = _trusted_fp(victim_signer)

        # Attacker signs tampered SARIF with their own key
        tampered_sarif = '{"version":"2.1.0","runs":[],"injected":true}'
        attacker_sig = _sign(attacker_signer, tampered_sarif)

        # Verification with victim's trusted fingerprint must fail
        assert verify_report_signature(attacker_sig, tampered_sarif, victim_fp) is False

    def test_regression_verify_invalid_base64_key(self):
        """Invalid base64 in public_key_b64 must return False, not raise."""
        signer = _signer()
        sarif = '{"version":"2.1.0"}'
        sig = _sign(signer, sarif)
        bad = ReportSignature(
            public_key_fingerprint=sig.public_key_fingerprint,
            public_key_b64="!!!not-valid-base64!!!",
            scan_timestamp=sig.scan_timestamp,
            catalog_hash=sig.catalog_hash,
            report_hash=sig.report_hash,
            signature_b64=sig.signature_b64,
        )
        result = verify_report_signature(bad, sarif, _trusted_fp(signer))
        assert result is False  # must not raise
