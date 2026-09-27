"""Operator evidence intake for organisational assurance controls.

``--evidence DIR`` points at a directory containing ``evidence.json``::

    {
      "schema_version": "1.0",
      "target": "https://mcp.example.com/mcp",
      "controls": {
        "ID-02": {"artifact": "authz/iss-validation-test.txt",
                  "note": "RFC 9207 iss check, CI job #812"}
      }
    }

Each artifact is hashed (SHA-256) and recorded in the signed scorecard. The
scanner does NOT judge the artifact's content — a control with evidence is
``ATTESTED``, never ``PASS`` (Mnemo dec_8575e56c7c), and any ATTESTED MUST
caps the level result at ``met_with_attestation``. ``target`` binds the
manifest to one deployment: the scan refuses a manifest prepared for a
different target. Empty artifacts are rejected.

The manifest is operator input and treated as untrusted: unknown keys and
unknown control IDs are rejected, artifacts must resolve to regular files
inside DIR with no symlinked path component, and sizes are capped. Any
violation raises ValueError, which the CLI maps to exit 2 (fail-closed).
"""
from __future__ import annotations

import hashlib
import html
import json
import re
import types
from pathlib import Path, PurePosixPath

from cosai_mcp.assurance.controls import CONTROLS_BY_ID
from cosai_mcp.assurance.models import EvidenceItem, EvidenceManifest

MANIFEST_NAME = "evidence.json"
_MAX_MANIFEST_BYTES = 1_000_000
_MAX_ARTIFACT_BYTES = 50_000_000
_MAX_NOTE_CHARS = 500
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _clean_display(text: str, cap: int = _MAX_NOTE_CHARS) -> str:
    """Strip control chars (terminal-escape injection), cap, HTML-escape."""
    return html.escape(_CONTROL_CHARS.sub("", text)[:cap], quote=True)


def _clean_note(note: object) -> str:
    if not isinstance(note, str):
        raise ValueError("evidence note must be a string")
    return _clean_display(note)


def _resolve_artifact(root: Path, artifact: object) -> Path:
    if not isinstance(artifact, str) or not artifact:
        raise ValueError("evidence artifact must be a non-empty relative path")
    rel = PurePosixPath(artifact)
    if rel.is_absolute() or ".." in rel.parts or "\\" in artifact:
        raise ValueError(f"evidence artifact must be a relative path inside the "
                         f"evidence directory: {artifact[:120]!r}")
    current = root
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"evidence artifact path contains a symlink: {artifact[:120]!r}")
    resolved = current.resolve(strict=True)
    if root not in resolved.parents:
        raise ValueError(f"evidence artifact escapes the evidence directory: {artifact[:120]!r}")
    if not resolved.is_file():
        raise ValueError(f"evidence artifact is not a regular file: {artifact[:120]!r}")
    if resolved.stat().st_size == 0:
        raise ValueError(f"evidence artifact is empty: {_clean_display(artifact, 120)!r}")
    if resolved.stat().st_size > _MAX_ARTIFACT_BYTES:
        raise ValueError(f"evidence artifact exceeds {_MAX_ARTIFACT_BYTES} bytes: "
                         f"{artifact[:120]!r}")
    return resolved


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_evidence(evidence_dir: Path) -> EvidenceManifest:
    """Parse and verify ``DIR/evidence.json``; return its target + control items."""
    if evidence_dir.is_symlink():
        raise ValueError("evidence directory must not be a symlink")
    root = evidence_dir.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"evidence path is not a directory: {evidence_dir}")
    manifest = root / MANIFEST_NAME
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError(f"{MANIFEST_NAME} missing (or a symlink) in {evidence_dir}")
    if manifest.stat().st_size > _MAX_MANIFEST_BYTES:
        raise ValueError(f"{MANIFEST_NAME} exceeds {_MAX_MANIFEST_BYTES} bytes")
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{MANIFEST_NAME} is not valid UTF-8 JSON: {exc}") from exc

    if not isinstance(data, dict) or set(data) - {"schema_version", "target", "controls"}:
        raise ValueError(f"{MANIFEST_NAME}: top level must be an object with only "
                         "'schema_version', 'target' and 'controls'")
    if data.get("schema_version") != "1.0":
        raise ValueError(f"{MANIFEST_NAME}: schema_version must be '1.0'")
    target = data.get("target")
    if not isinstance(target, str) or not target.strip():
        raise ValueError(f"{MANIFEST_NAME}: 'target' (the deployment URL this evidence "
                         "is for) is required")
    controls = data.get("controls")
    if not isinstance(controls, dict):
        raise ValueError(f"{MANIFEST_NAME}: 'controls' must be an object")

    items: dict[str, EvidenceItem] = {}
    for control_id, entry in controls.items():
        if control_id not in CONTROLS_BY_ID:
            raise ValueError(f"{MANIFEST_NAME}: unknown control id {str(control_id)[:40]!r}")
        if not isinstance(entry, dict) or set(entry) - {"artifact", "note"}:
            raise ValueError(f"{MANIFEST_NAME}: entry for {control_id} must be an object "
                             "with only 'artifact' and optional 'note'")
        path = _resolve_artifact(root, entry.get("artifact"))
        items[control_id] = EvidenceItem(
            control_id=control_id,
            artifact=_clean_display(str(path.relative_to(root)), 300),
            sha256=_sha256(path),
            note=_clean_note(entry.get("note", "")),
        )
    return EvidenceManifest(target=target.strip(), items=types.MappingProxyType(items))
