"""Project catalog signing path — Ed25519 signer for official catalog files.

Trust model (locked architecture + WP6 org/shared key extension):

- The **public** key is the verification anchor. It is hardcoded as a bytes
  literal in ``cosai_mcp/keys.py`` (never loaded from disk) and may be
  overridden for enterprise / org-shared key rotation via the ``COSAI_PUBKEY``
  environment variable. This module never weakens that contract — it only
  provides the *signing* side used to (re)generate the committed ``.sig``
  sidecars that the hardcoded public key verifies.

- The reference / development signing key is **deterministically derived from
  a fixed 32-byte seed** (``_DEV_SIGNING_SEED``). It is committed so that any
  contributor can reproduce byte-identical signatures for the official catalog
  in CI without distributing a secret. It is explicitly NOT a production
  signing authority: the CoSAI working group key (or an org key) replaces it
  for published artifacts, and ``COSAI_SIGNING_SEED`` /
  ``COSAI_SIGNING_KEY_FILE`` override it for org/fleet deployments (WP6).

- ``get_signing_private_key`` precedence (highest first):
    1. ``COSAI_SIGNING_KEY_FILE`` — path to a 32-byte raw Ed25519 private key
    2. ``COSAI_SIGNING_SEED``     — base64 of a 32-byte seed (org/shared key)
    3. ``_DEV_SIGNING_SEED``      — committed deterministic dev/reference key

The public key produced by the active signing key MUST match the active
verification key (``cosai_mcp.keys.get_catalog_public_key``); ``sign_catalog``
asserts this before writing any sidecar so a key mismatch fails closed.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cosai_mcp.keys import get_catalog_public_key

# 32-byte deterministic dev/reference seed (NOT a production secret).
# Rotating this requires regenerating cosai_mcp/keys._HARDCODED_PUBLIC_KEY
# and re-signing every official catalog file via scripts/sign_catalog.py.
_DEV_SIGNING_SEED: bytes = b"cosai-mcp-dev-catalog-signing-k0"


def _seed_from_env_b64(name: str) -> bytes | None:
    raw = os.environ.get(name, "")
    if not raw:
        return None
    seed = base64.b64decode(raw)
    if len(seed) != 32:
        raise ValueError(
            f"{name} must decode to exactly 32 bytes, got {len(seed)}"
        )
    return seed


def get_signing_private_key() -> Ed25519PrivateKey:
    """Return the active Ed25519 signing key (see module docstring for order)."""
    key_file = os.environ.get("COSAI_SIGNING_KEY_FILE", "")
    if key_file:
        raw = Path(key_file).read_bytes()
        if len(raw) != 32:
            raise ValueError(
                f"COSAI_SIGNING_KEY_FILE must be a raw 32-byte Ed25519 private "
                f"key, got {len(raw)} bytes"
            )
        return Ed25519PrivateKey.from_private_bytes(raw)

    env_seed = _seed_from_env_b64("COSAI_SIGNING_SEED")
    seed = env_seed if env_seed is not None else _DEV_SIGNING_SEED
    return Ed25519PrivateKey.from_private_bytes(seed)


def signing_public_key_bytes() -> bytes:
    """Raw 32-byte public key for the active signing key."""
    return get_signing_private_key().public_key().public_bytes_raw()


def sign_bytes(data: bytes) -> bytes:
    """Return a base64-encoded Ed25519 signature over ``data``."""
    return base64.b64encode(get_signing_private_key().sign(data))


def sign_catalog(catalog_root: Path) -> list[Path]:
    """(Re)sign every official catalog file under ``catalog_root/official``.

    Fails closed: if the active signing key's public key does not match the
    active verification key (hardcoded literal or ``COSAI_PUBKEY`` override),
    no sidecar is written and ValueError is raised. This prevents producing
    sidecars the shipped scanner cannot verify.

    Returns the list of ``.json.sig`` paths written.
    """
    signer_pub = signing_public_key_bytes()
    verify_pub = get_catalog_public_key()
    if signer_pub != verify_pub:
        raise ValueError(
            "Signing key public bytes do not match the active verification "  # noqa: S608
            "key. Update cosai_mcp/keys._HARDCODED_PUBLIC_KEY (or set "
            "COSAI_PUBKEY) to the signing key's public bytes before re-signing. "
            f"signer={signer_pub.hex()} verify={verify_pub.hex()}"  # noqa: S608
        )

    official_dir = catalog_root / "official"
    written: list[Path] = []
    for json_file in sorted(official_dir.rglob("*.json")):
        raw = json_file.read_bytes()
        # Validate it parses as JSON before signing — never sign garbage.
        json.loads(raw)
        sig = sign_bytes(raw)
        sig_path = json_file.with_suffix(".json.sig")
        sig_path.write_bytes(sig + b"\n")
        written.append(sig_path)
    return written
