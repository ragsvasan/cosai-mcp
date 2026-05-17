"""Ed25519 signing for ToolInventory artifacts.

Uses a per-installation key stored in the OS keychain (via ``keyring``).
On first use the key is generated and stored; subsequent calls load it.

The signed artifact format is::

    {
        "inventory": { ...ToolInventory.to_dict()... },
        "signature": "<hex Ed25519 signature over canonical JSON of inventory>",
        "public_key": "<hex raw 32-byte public key>"
    }

The signature is over the UTF-8 encoding of ``json.dumps(inventory_dict,
sort_keys=True, separators=(',', ':'))`` — canonical JSON, no whitespace.

Trust anchor
------------
``verify_inventory()`` does not accept the artifact's ``public_key`` field
at face value — doing so would let an attacker re-sign a tampered artifact
with a fresh keypair and pass verification.  Instead the function pins the
expected public key from the following sources (checked in order):

1. ``COSAI_INVENTORY_PUBKEY`` environment variable (base64-encoded raw 32 bytes)
   — use this in CI to pin the key from the capture machine.
2. The per-installation keyring key (same key used by ``sign_inventory``).
   — use this for local single-machine workflows.

If neither source is available (keyring package missing and env var unset),
``verify_inventory()`` fails closed and raises ``SignatureVerificationError``.
Signature-only mode is never used: the artifact carries its own public key,
so verifying it against that embedded key authenticates nothing.
"""
from __future__ import annotations

import json
import os
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from cosai_mcp.exceptions import SignatureVerificationError
from cosai_mcp.inventory.snapshot import ToolInventory

_KEYRING_SERVICE = "cosai-mcp-inventory"
_KEYRING_ACCOUNT = "ed25519-private-key"


def _get_or_create_private_key() -> Ed25519PrivateKey:
    """Load the per-installation signing key from keyring, creating it if absent."""
    try:
        import keyring
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "cosai-mcp inventory signing requires the 'keyring' package. "
            "Install it with: pip install keyring"
        ) from exc

    stored = keyring.get_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT)
    if stored:
        raw = bytes.fromhex(stored)
        return Ed25519PrivateKey.from_private_bytes(raw)

    # Generate a new key and persist it.
    priv = Ed25519PrivateKey.generate()
    raw_bytes = priv.private_bytes_raw()
    keyring.set_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT, raw_bytes.hex())
    return priv


def _canonical_bytes(inventory_dict: dict[str, Any]) -> bytes:
    return json.dumps(inventory_dict, sort_keys=True, separators=(",", ":")).encode()


def sign_inventory(inventory: ToolInventory) -> dict[str, Any]:
    """Sign a ToolInventory and return a self-contained signed artifact dict.

    The artifact contains the inventory, the hex signature, and the hex public
    key.  Pass the artifact to ``verify_inventory`` to authenticate it.

    Raises
    ------
    RuntimeError
        If the keyring package is unavailable.
    """
    priv = _get_or_create_private_key()
    pub: Ed25519PublicKey = priv.public_key()

    inv_dict = inventory.to_dict()
    sig_bytes = priv.sign(_canonical_bytes(inv_dict))

    return {
        "inventory": inv_dict,
        "signature": sig_bytes.hex(),
        "public_key": pub.public_bytes_raw().hex(),
    }


def _get_trusted_public_key_bytes() -> bytes | None:
    """Return the trusted public key raw bytes, or None if unavailable.

    Checks (in order):
    1. ``COSAI_INVENTORY_PUBKEY`` env var (base64-encoded, 32 bytes raw Ed25519).
    2. The per-installation keyring key (same key used by ``sign_inventory``).

    Raises
    ------
    SignatureVerificationError
        If ``COSAI_INVENTORY_PUBKEY`` is explicitly set but cannot be decoded
        as a 32-byte raw Ed25519 key.  An explicitly-pinned trust anchor that
        is malformed must fail closed — never silently downgrade to
        signature-only acceptance (see L-1 / H-1).
    """
    import base64

    env_val = os.environ.get("COSAI_INVENTORY_PUBKEY", "")
    if env_val:
        try:
            raw = base64.b64decode(env_val, validate=True)
        except Exception as exc:
            raise SignatureVerificationError(
                "COSAI_INVENTORY_PUBKEY is set but is not valid base64. "
                "It must be a base64-encoded raw 32-byte Ed25519 public key."
            ) from exc
        if len(raw) != 32:
            raise SignatureVerificationError(
                f"COSAI_INVENTORY_PUBKEY decodes to {len(raw)} bytes; "
                "a raw Ed25519 public key must be exactly 32 bytes."
            )
        return raw

    try:
        priv = _get_or_create_private_key()
        return priv.public_key().public_bytes_raw()
    except RuntimeError:
        return None


def verify_inventory(artifact: dict[str, Any]) -> ToolInventory:
    """Verify a signed inventory artifact and return the inner ToolInventory.

    The artifact's ``public_key`` field is compared against the trusted local
    installation key (or ``COSAI_INVENTORY_PUBKEY`` env var) before the
    Ed25519 signature is checked.  This prevents an attacker from re-signing
    a tampered artifact with a fresh keypair and passing verification.

    Raises
    ------
    SignatureVerificationError
        If the public key does not match the trusted key, or the signature is
        invalid, or the artifact is malformed.
    KeyError
        If required fields are missing from the artifact.
    """
    try:
        inv_dict: dict[str, Any] = artifact["inventory"]
        sig_hex: str = artifact["signature"]
        pub_hex: str = artifact["public_key"]
    except KeyError as exc:
        raise SignatureVerificationError(
            f"Signed inventory artifact is missing required field: {exc}"
        ) from exc

    # --- Trust anchor: validate the artifact's public key before use --------
    # Fail CLOSED: signature-only mode authenticates nothing because the
    # artifact carries its own public key — an attacker can re-sign tampered
    # content with a fresh keypair.  If no out-of-band trust anchor is
    # resolvable we must refuse, not proceed (H-1).
    trusted_pub = _get_trusted_public_key_bytes()
    if trusted_pub is None:
        raise SignatureVerificationError(
            "No trust anchor available to authenticate this inventory artifact. "
            "Set the COSAI_INVENTORY_PUBKEY environment variable to the expected "
            "key (base64-encoded raw 32-byte Ed25519 public key), or run on a "
            "machine where the per-installation keyring key is available. "
            "Signature-only verification is refused because the artifact carries "
            "its own public key and proves nothing about authenticity."
        )
    try:
        artifact_pub_bytes = bytes.fromhex(pub_hex)
    except ValueError as exc:
        raise SignatureVerificationError(
            "Inventory artifact has malformed public_key field."
        ) from exc
    if artifact_pub_bytes != trusted_pub:
        raise SignatureVerificationError(
            "Inventory public key does not match the trusted installation key. "
            "If this artifact was produced on another machine, set the "
            "COSAI_INVENTORY_PUBKEY environment variable to the expected key "
            "(base64-encoded raw 32-byte Ed25519 public key)."
        )

    # --- Ed25519 signature verification ------------------------------------
    try:
        pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub_key.verify(bytes.fromhex(sig_hex), _canonical_bytes(inv_dict))
    except (InvalidSignature, ValueError) as exc:
        raise SignatureVerificationError(
            "Inventory signature verification failed — artifact may have been tampered with."
        ) from exc

    return ToolInventory.from_dict(inv_dict)
