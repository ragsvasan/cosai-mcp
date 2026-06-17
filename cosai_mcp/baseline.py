"""`.cosai-baseline` — accepted-finding suppression for CI adoption.

A baseline lets a team accept a set of *known* findings so a scan can gate
only on *new* regressions, without hiding the accepted ones from the report.

Security model (locked by crucible):

- The suppression key is a **scanner-generated, content-stable fingerprint**:
  ``sha256("cosai-finding-v1\x1f<threat_id>\x1f<probe_id>")``.  Both inputs are
  catalog / scanner-controlled identifiers — the fingerprint is NEVER derived
  from attacker-controlled response bytes, so a hostile target cannot craft a
  response that changes (or forges) a fingerprint to slip a real finding past
  the gate.
- A suppressed finding is **excluded from the exit-code computation** but is
  **still present in ``ScanResult.probe_results``** (flagged ``suppressed=True``)
  so every report (SARIF/HTML/CSV) still lists it.
- Only *findings* can be suppressed — a baseline entry never converts a PASS,
  an inconclusive, or a scanner error into anything.

`.cosai-baseline` file format (JSON)::

    {
      "version": 1,
      "fingerprints": [
        {"fingerprint": "<sha256 hex>", "threat_id": "T01-001",
         "probe_id": "T01-001-p1", "note": "accepted 2026-05-17, ticket SEC-42"}
      ]
    }

Only the ``fingerprint`` field is trusted for matching; ``threat_id`` /
``probe_id`` / ``note`` are human-readable annotations and are NOT used for
matching (so a mismatched annotation can never widen suppression).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cosai_mcp.harness.result import ProbeResult

_FINGERPRINT_DOMAIN = "cosai-finding-v1"
_MAX_BASELINE_BYTES = 1 * 1024 * 1024  # 1 MB — a baseline is a small id list
_HEX64 = frozenset("0123456789abcdef")


def finding_fingerprint(threat_id: str, probe_id: str) -> str:
    """Return the content-stable fingerprint for a (threat, probe) finding.

    Inputs are catalog/scanner-controlled identifiers only — never response
    content.  Domain-separated so a fingerprint cannot collide with any other
    hash the scanner emits.
    """
    blob = f"{_FINGERPRINT_DOMAIN}\x1f{threat_id}\x1f{probe_id}".encode()
    return hashlib.sha256(blob).hexdigest()


@dataclass(frozen=True)
class Baseline:
    """An immutable set of accepted-finding fingerprints."""

    fingerprints: frozenset[str]

    @classmethod
    def empty(cls) -> Baseline:
        return cls(fingerprints=frozenset())

    @classmethod
    def load(cls, path: Path) -> Baseline:
        """Load and validate a ``.cosai-baseline`` file.

        Fail-closed: any structural problem raises ValueError rather than
        silently producing an empty (or partial) baseline that would let a
        real finding through unsuppressed OR — worse — be misread as
        suppressing everything.
        """
        raw = path.read_bytes()
        if len(raw) > _MAX_BASELINE_BYTES:
            raise ValueError(
                f".cosai-baseline exceeds {_MAX_BASELINE_BYTES} bytes — refusing"
            )
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f".cosai-baseline is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(".cosai-baseline root must be a JSON object")
        if data.get("version") != 1:
            raise ValueError(
                f".cosai-baseline version must be 1, got {data.get('version')!r}"
            )
        entries = data.get("fingerprints")
        if not isinstance(entries, list):
            raise ValueError(".cosai-baseline 'fingerprints' must be a list")

        fps: set[str] = set()
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ValueError(
                    f".cosai-baseline fingerprints[{i}] must be an object"
                )
            fp = entry.get("fingerprint")
            if not isinstance(fp, str):
                raise ValueError(
                    f".cosai-baseline fingerprints[{i}].fingerprint must be a string"
                )
            fp = fp.strip().lower()
            # A fingerprint is a SHA-256 hex digest — reject anything else so a
            # malformed/garbage entry can never accidentally match.
            if len(fp) != 64 or not set(fp) <= _HEX64:
                raise ValueError(
                    f".cosai-baseline fingerprints[{i}].fingerprint is not a "
                    "64-char lowercase SHA-256 hex digest"
                )
            fps.add(fp)
        return cls(fingerprints=frozenset(fps))

    def is_suppressed(self, threat_id: str, probe_id: str) -> bool:
        return finding_fingerprint(threat_id, probe_id) in self.fingerprints


def apply_baseline(
    probe_results: list[ProbeResult],
    baseline: Baseline,
) -> list[ProbeResult]:
    """Return a new list with ``suppressed=True`` set on baseline-matched FINDINGS.

    Only a genuine finding (``not passed`` and no error and not inconclusive)
    can be suppressed — a baseline entry never alters a pass, an inconclusive,
    or a scanner error.  Non-finding results are returned unchanged.
    """
    import dataclasses

    out: list[ProbeResult] = []
    for r in probe_results:
        is_finding = (
            not r.passed
            and r.error is None
            and r.inconclusive_reason is None
        )
        if is_finding and baseline.is_suppressed(r.threat_id, r.probe_id):
            out.append(dataclasses.replace(r, suppressed=True))
        else:
            out.append(r)
    return out
