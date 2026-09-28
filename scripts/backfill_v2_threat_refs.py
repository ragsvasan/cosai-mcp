#!/usr/bin/env python3
"""One-shot backfill of CoSAI MCP Security v2.0 labels into the official catalog.

Adds ``mcp_t_ref`` and ``threat_refs`` (schema 1.3) to every official catalog
file, surgically (formatting elsewhere untouched), then the caller re-signs
with ``scripts/sign_catalog.py``.  Idempotent.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# Catalog entry → v2.0 §3.1 numbered threats. Each number must be one the v2.0
# threat table lists under the entry's category (enforced by
# tests/catalog/test_v2_threat_refs.py).
THREAT_REFS: dict[str, list[int]] = {
    "T01-001": [1, 18], "T01-002": [1, 18], "T01-003": [17], "T01-004": [18],
    "T01-005": [18], "T01-006": [18], "T01-007": [1],
    "T02-001": [8, 20], "T02-003": [9], "T02-004": [20], "T02-005": [8, 20],
    "T03-001": [21], "T03-002": [22], "T03-003": [21], "T03-004": [21],
    "T03-005": [21], "T03-006": [21, 22], "T03-007": [21], "T03-ADV-001": [21],
    "T05-001": [24], "T05-002": [24], "T05-003": [24], "T05-ADV-001": [24],
    "T06-001": [25], "T06-002": [5],
    "T07-001": [30], "T07-002": [27], "T07-003": [27], "T07-004": [27],
    "T07-005": [27], "T07-006": [27], "T07-007": [17, 19], "T07-ADV-001": [17],
    "T08-001": [26], "T08-002": [26], "T08-003": [26], "T08-004": [26],
    "T08-005": [26], "T08-006": [26], "T08-007": [26], "T08-008": [26],
    "T08-009": [26],
    "T10-001": [33], "T10-002": [14], "T10-003": [33], "T10-004": [14],
    "T10-005": [14],
    "T11-001": [25], "T11-002": [25], "T11-ADV-001": [25],
}


def main() -> int:
    root = Path(__file__).resolve().parent.parent / "catalog" / "official"
    for path in sorted(root.rglob("*.json")):
        text = path.read_text()
        data = json.loads(text)
        refs = THREAT_REFS[data["id"]]
        mcp_t = "MCP-" + data["category"]
        if data.get("threat_refs") == refs and data.get("mcp_t_ref") == mcp_t:
            continue
        line = re.search(r'^(\s*)"owasp_ref":\s*"[^"]*",?\n', text, re.M)
        assert line, path
        indent = line.group(1)
        insert = (f'{indent}"mcp_t_ref": "{mcp_t}",\n'
                  f'{indent}"threat_refs": {json.dumps(refs)},\n')
        text = text[:line.end()] + insert + text[line.end():]
        text = re.sub(r'"schema_version":\s*"[0-9.]+"', '"schema_version": "1.3"', text, count=1)
        assert json.loads(text)["threat_refs"] == refs
        path.write_text(text)
        print(f"updated {path.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
