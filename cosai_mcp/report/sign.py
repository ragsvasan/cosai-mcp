"""Report / scorecard signing key resolution.

Key precedence (highest first), shared by report AND scorecard signing so a
fleet produces *comparable* artifacts (identical ``public_key_fingerprint``
across every machine):

  1. ``COSAI_REPORT_SIGNING_KEY`` — base64 of a raw 32-byte Ed25519 private
     key.  This is the **org / shared / fleet** key: set it identically on
     every CI runner and laptop in a fleet and every signed report and
     scorecard carries the same public-key fingerprint, so scorecards are
     directly comparable across the fleet.  Fail-closed: if the variable is
     set but is not valid base64 / not 32 bytes, signing raises rather than
     silently falling back to a per-machine key (which would make artifacts
     look authentic but be fleet-incomparable).
  2. Per-installation OS-keychain key (``keyring``) — the default for a single
     developer machine; unique per install, NOT fleet-comparable.

This mirrors the existing ``COSAI_PUBKEY`` (catalog verification) and
``COSAI_SIGNING_SEED`` (catalog signing) override model — same shape, same
fail-closed discipline.
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

_ORG_KEY_ENV = "COSAI_REPORT_SIGNING_KEY"


class OrgSigningKeyError(ValueError):
    """Raised when ``COSAI_REPORT_SIGNING_KEY`` is set but invalid.

    Fail-closed: an explicitly-pinned org key that cannot be loaded must
    abort signing, never silently downgrade to a per-installation key.
    """


def org_signing_key() -> Ed25519PrivateKey | None:
    """Return the org/shared Ed25519 signing key from the environment.

    Returns ``None`` when ``COSAI_REPORT_SIGNING_KEY`` is unset (callers then
    fall back to the per-installation keychain key).  Raises
    :class:`OrgSigningKeyError` when the variable is set but malformed —
    a pinned fleet key must fail closed.
    """
    raw_b64 = os.environ.get(_ORG_KEY_ENV, "")
    if not raw_b64:
        return None
    try:
        raw = base64.b64decode(raw_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise OrgSigningKeyError(
            f"{_ORG_KEY_ENV} is set but is not valid base64. It must be the "
            "base64 encoding of a raw 32-byte Ed25519 private key."
        ) from exc
    if len(raw) != 32:
        raise OrgSigningKeyError(
            f"{_ORG_KEY_ENV} decodes to {len(raw)} bytes; a raw Ed25519 "
            "private key must be exactly 32 bytes."
        )
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError as exc:  # pragma: no cover - 32-byte is always valid
        raise OrgSigningKeyError(
            f"{_ORG_KEY_ENV} is not a valid Ed25519 private key."
        ) from exc


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
        # Org/shared fleet key takes precedence over the per-installation
        # keychain key so every machine in a fleet signs with the same key
        # (comparable scorecards). Fail-closed if it is set but invalid.
        org_key = org_signing_key()
        if org_key is not None:
            return org_key
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
