"""Ed25519 public key for official catalog verification.

Key is hardcoded here as a bytes literal — never loaded from disk.
COSAI_PUBKEY env var overrides for enterprise key rotation.
Placeholder until real keypair is generated for the project.
"""
from __future__ import annotations

import os

# placeholder — replace with real Ed25519 public key bytes before first release
_HARDCODED_PUBLIC_KEY: bytes = b""


def get_catalog_public_key() -> bytes:
    override = os.environ.get("COSAI_PUBKEY", "")
    if override:
        import base64
        return base64.b64decode(override)
    return _HARDCODED_PUBLIC_KEY
