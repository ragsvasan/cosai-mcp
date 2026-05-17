#!/usr/bin/env python3
"""(Re)sign every official catalog file with the project signing key.

Usage::

    python scripts/sign_catalog.py [catalog_root]

Defaults ``catalog_root`` to ``<repo>/catalog``.  Uses the active signing key
resolved by ``cosai_mcp.signing.get_signing_private_key`` (dev/reference seed
by default; org key via ``COSAI_SIGNING_SEED`` / ``COSAI_SIGNING_KEY_FILE``).

Fails closed if the signing key's public bytes do not match the active
verification key (``cosai_mcp.keys.get_catalog_public_key``).
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure the repo root (parent of scripts/) is importable when this script is
# run directly (python scripts/sign_catalog.py) rather than as a module.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cosai_mcp.signing import sign_catalog


def main(argv: list[str]) -> int:
    root = (
        Path(argv[1])
        if len(argv) > 1
        else Path(__file__).resolve().parent.parent / "catalog"
    )
    written = sign_catalog(root)
    print(f"Signed {len(written)} official catalog file(s) under {root}/official")
    for p in written:
        print(f"  {p.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
