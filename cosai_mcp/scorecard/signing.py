"""Ed25519 signing and verification for Scorecard artifacts.

Same keyring-backed per-installation signing pattern as inventory signing
(Track A), but applied to Scorecard objects. The signature covers all
non-signature fields serialised as canonical JSON (sorted keys, no whitespace).

Trust anchor:
    COSAI_SCORECARD_PUBKEY env var (base64-encoded) takes precedence over
    the local keyring key — allows cross-machine scorecard verification.
"""
from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cosai_mcp.scorecard.models import Scorecard

_SERVICE = "cosai-mcp-scorecard"
_USERNAME = "signing-key"


class ScorecardVerificationError(Exception):
    pass


def _canonical_bytes(d: dict[str, Any]) -> bytes:
    """Return deterministic UTF-8 JSON bytes for signing (sorted keys, no whitespace)."""
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _get_or_create_private_key() -> Ed25519PrivateKey:
    try:
        import keyring
    except ImportError:
        raise RuntimeError("keyring package is required for scorecard signing")

    raw_b64 = keyring.get_password(_SERVICE, _USERNAME)
    if raw_b64:
        raw = base64.b64decode(raw_b64)
        return Ed25519PrivateKey.from_private_bytes(raw)

    priv = Ed25519PrivateKey.generate()
    raw = priv.private_bytes_raw()
    keyring.set_password(_SERVICE, _USERNAME, base64.b64encode(raw).decode())
    return priv


def _get_trusted_public_key_bytes() -> bytes | None:
    """Return trusted public key bytes from env var or local keyring, or None."""
    env_val = os.environ.get("COSAI_SCORECARD_PUBKEY", "")
    if env_val:
        try:
            return base64.b64decode(env_val)
        except Exception:
            return None
    try:
        priv = _get_or_create_private_key()
        return priv.public_key().public_bytes_raw()
    except RuntimeError:
        return None


def _signable_dict(scorecard: Scorecard) -> dict[str, Any]:
    """Return the dict that is signed — all fields except public_key and signature."""
    d = scorecard.to_dict()
    d.pop("public_key", None)
    d.pop("signature", None)
    return d


def sign_scorecard(scorecard: Scorecard) -> Scorecard:
    """Sign a Scorecard and return a new instance with public_key and signature set."""
    priv = _get_or_create_private_key()
    pub_bytes = priv.public_key().public_bytes_raw()

    payload = _canonical_bytes(_signable_dict(scorecard))
    sig = priv.sign(payload)

    return Scorecard(
        scan_id=scorecard.scan_id,
        target_url=scorecard.target_url,
        scan_timestamp=scorecard.scan_timestamp,
        catalog_hash=scorecard.catalog_hash,
        tool_version=scorecard.tool_version,
        categories=scorecard.categories,
        conformance_level=scorecard.conformance_level,
        public_key=pub_bytes.hex(),
        signature=sig.hex(),
    )


def verify_scorecard(scorecard: Scorecard) -> None:
    """Verify the Ed25519 signature on a Scorecard.

    Raises ScorecardVerificationError if:
    - The scorecard has no signature
    - The signature does not verify against the embedded public key
    - The public key does not match the trusted installation key (when available)

    Returns normally if verification passes.
    """
    if not scorecard.is_signed:
        raise ScorecardVerificationError("Scorecard has no signature (unsigned artifact).")

    try:
        pub_hex = scorecard.public_key
        sig_hex = scorecard.signature
        artifact_pub_bytes = bytes.fromhex(pub_hex)
    except (ValueError, AttributeError) as exc:
        raise ScorecardVerificationError(f"Malformed public_key or signature field: {exc}") from exc

    # Trust anchor check — reject scorecards signed by unknown keys
    trusted = _get_trusted_public_key_bytes()
    if trusted is not None and artifact_pub_bytes != trusted:
        raise ScorecardVerificationError(
            "Scorecard public key does not match the trusted installation key. "
            "Set COSAI_SCORECARD_PUBKEY env var for cross-machine verification."
        )

    payload = _canonical_bytes(_signable_dict(scorecard))
    try:
        pub_key = Ed25519PublicKey.from_public_bytes(artifact_pub_bytes)
        pub_key.verify(bytes.fromhex(sig_hex), payload)
    except Exception as exc:
        raise ScorecardVerificationError(f"Signature verification failed: {exc}") from exc
