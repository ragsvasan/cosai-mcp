"""Ed25519 public key for official catalog verification.

Key is hardcoded here as a bytes literal — never loaded from disk.
COSAI_PUBKEY env var overrides for enterprise key rotation.
Placeholder until real keypair is generated for the project.
"""
from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from cosai_mcp.exceptions import SignatureVerificationError

# Ed25519 public key (32 bytes, raw) — paired with catalog/.signing-key (gitignored)
# Generated 2026-04-26; rotate via COSAI_PUBKEY env var for enterprise deployments.
_HARDCODED_PUBLIC_KEY: bytes = bytes.fromhex(
    "617931990bebd8bf080fca0ced151096"
    "3a88f7e65c893af0709c3eee2cbf06b2"
)


def get_catalog_public_key() -> bytes:
    override = os.environ.get("COSAI_PUBKEY", "")
    if override:
        return base64.b64decode(override)
    return _HARDCODED_PUBLIC_KEY


def verify_catalog_signature(data: bytes, sig: bytes) -> bool:
    """Verify an Ed25519 signature over ``data``.

    Uses the public key from ``COSAI_PUBKEY`` env var (base64-encoded) if set,
    otherwise falls back to ``_HARDCODED_PUBLIC_KEY``.

    Returns True on success.
    Raises SignatureVerificationError on failure (invalid signature, bad key, etc.)
    """
    raw_pub = get_catalog_public_key()
    if not raw_pub:
        raise SignatureVerificationError(
            "No Ed25519 public key configured. "
            "Set COSAI_PUBKEY env var (base64-encoded raw 32-byte key) "
            "or update _HARDCODED_PUBLIC_KEY in cosai_mcp/keys.py."
        )
    try:
        pub_key = Ed25519PublicKey.from_public_bytes(raw_pub)
        pub_key.verify(sig, data)
        return True
    except InvalidSignature as exc:
        raise SignatureVerificationError(
            "Ed25519 signature verification failed — catalog file may have been tampered with."
        ) from exc
    except (ValueError, TypeError) as exc:
        raise SignatureVerificationError(
            f"Ed25519 public key is malformed: {exc}"
        ) from exc
