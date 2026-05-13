"""Report signing — per-installation Ed25519 key stored in OS keychain via keyring.

Set ``COSAI_NO_SIGN=1`` to skip keychain access entirely (no signature written).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

try:
    import keyring as _keyring
    _KEYRING_AVAILABLE = True
except ImportError:
    _KEYRING_AVAILABLE = False

_SERVICE_NAME = "cosai-mcp"
_KEY_ACCOUNT = "report-signing-key"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _pub_fingerprint(public_key: Ed25519PublicKey) -> str:
    """SHA-256 fingerprint of the DER-encoded public key (hex, no colons)."""
    der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


@dataclass(frozen=True)
class ReportSignature:
    """Detached signature for a scan report."""
    public_key_fingerprint: str   # hex SHA-256 of DER public key
    public_key_b64: str           # base64url-encoded raw 32-byte public key
    scan_timestamp: str           # ISO-8601 — signed content includes this
    catalog_hash: str             # signed content
    report_hash: str              # SHA-256 hex of SARIF JSON bytes
    signature_b64: str            # base64url-encoded Ed25519 signature

    def to_dict(self) -> dict[str, Any]:
        return {
            "public_key_fingerprint": self.public_key_fingerprint,
            "public_key_b64": self.public_key_b64,
            "scan_timestamp": self.scan_timestamp,
            "catalog_hash": self.catalog_hash,
            "report_hash": self.report_hash,
            "signature_b64": self.signature_b64,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ReportSignature":
        return cls(
            public_key_fingerprint=d["public_key_fingerprint"],
            public_key_b64=d["public_key_b64"],
            scan_timestamp=d["scan_timestamp"],
            catalog_hash=d["catalog_hash"],
            report_hash=d["report_hash"],
            signature_b64=d["signature_b64"],
        )


def _signing_payload(
    scan_timestamp: str,
    catalog_hash: str,
    report_hash: str,
) -> bytes:
    """Canonical bytes-to-sign: deterministic JSON of the three fixed fields."""
    obj = {
        "catalog_hash": catalog_hash,
        "report_hash": report_hash,
        "scan_timestamp": scan_timestamp,
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class ReportSigner:
    """Sign scan reports with a per-installation Ed25519 key.

    If *private_key* is not supplied, the key is loaded from (or created in)
    the OS keychain via ``keyring``. Pass an explicit key in tests to avoid
    keychain I/O.
    """

    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        if private_key is not None:
            self._key = private_key
        else:
            self._key = self._load_or_create_key()

    def sign(
        self,
        sarif_json: str,
        scan_timestamp: str,
        catalog_hash: str,
    ) -> ReportSignature:
        """Sign the SARIF report and return a detached ReportSignature."""
        report_hash = hashlib.sha256(sarif_json.encode()).hexdigest()
        payload = _signing_payload(scan_timestamp, catalog_hash, report_hash)
        sig_bytes = self._key.sign(payload)

        pub = self._key.public_key()
        pub_raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

        return ReportSignature(
            public_key_fingerprint=_pub_fingerprint(pub),
            public_key_b64=_b64(pub_raw),
            scan_timestamp=scan_timestamp,
            catalog_hash=catalog_hash,
            report_hash=report_hash,
            signature_b64=_b64(sig_bytes),
        )

    @staticmethod
    def _load_or_create_key() -> Ed25519PrivateKey:
        if os.environ.get("COSAI_NO_SIGN", "").strip() not in ("", "0"):
            raise RuntimeError("COSAI_NO_SIGN is set — keychain access skipped")
        if not _KEYRING_AVAILABLE:
            raise RuntimeError(
                "keyring is required for report signing. "
                "Install with: pip install keyring"
            )
        raw_b64 = _keyring.get_password(_SERVICE_NAME, _KEY_ACCOUNT)
        if raw_b64 is None:
            key = Ed25519PrivateKey.generate()
            raw_bytes = key.private_bytes_raw()
            _keyring.set_password(
                _SERVICE_NAME, _KEY_ACCOUNT,
                base64.b64encode(raw_bytes).decode(),
            )
            return key
        raw_bytes = base64.b64decode(raw_b64)
        return Ed25519PrivateKey.from_private_bytes(raw_bytes)


def verify_report_signature(
    sig: ReportSignature,
    sarif_json: str,
    trusted_fingerprint: str,
) -> bool:
    """Verify a ReportSignature against the supplied SARIF JSON.

    Parameters
    ----------
    sig:
        The detached ReportSignature to verify.
    sarif_json:
        The SARIF JSON string whose integrity is being verified.
    trusted_fingerprint:
        The SHA-256 hex fingerprint of the expected signing public key.
        MUST come from a separate trust store (OS keychain, config file,
        or printed on first scan) — NOT from ``sig`` itself.
        This prevents an attacker from substituting their own key pair.

    Returns True only if ALL of the following hold:
    1. report_hash in sig matches SHA-256 of sarif_json.
    2. The public key reconstructed from sig.public_key_b64 has a fingerprint
       matching both sig.public_key_fingerprint AND trusted_fingerprint.
    3. The Ed25519 signature is valid.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    # Step 1: verify report hash
    actual_report_hash = hashlib.sha256(sarif_json.encode()).hexdigest()
    if actual_report_hash != sig.report_hash:
        return False

    try:
        pad = "=" * (-len(sig.public_key_b64) % 4)
        pub_raw = base64.urlsafe_b64decode(sig.public_key_b64 + pad)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_raw)

        # Step 2a: verify the embedded fingerprint is self-consistent
        actual_fp = _pub_fingerprint(pub_key)
        if actual_fp != sig.public_key_fingerprint:
            return False

        # Step 2b: verify the embedded key matches the TRUSTED fingerprint
        # (out-of-band trust anchor — not from the sig object)
        if actual_fp != trusted_fingerprint:
            return False

        # Step 3: verify the Ed25519 signature
        pad_sig = "=" * (-len(sig.signature_b64) % 4)
        sig_bytes = base64.urlsafe_b64decode(sig.signature_b64 + pad_sig)
        payload = _signing_payload(sig.scan_timestamp, sig.catalog_hash, sig.report_hash)
        pub_key.verify(sig_bytes, payload)
        return True
    except (InvalidSignature, ValueError, binascii.Error):
        return False
