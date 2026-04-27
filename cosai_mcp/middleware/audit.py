"""T12: Hash-chained append-only audit log with DAG execution trace.

Why this matters:
  Invisible agent activity (T12) is only detectable if every MCP call is
  logged immutably BEFORE execution. A log that can be silently truncated,
  reordered, or overwritten provides no forensic value.

Design decisions:
  - Hash chain: each entry includes SHA-256(prev_hash + entry_json).
    Tampering with any entry breaks all subsequent hashes.
  - Append-only: AuditLogger.log() opens the file in 'ab' (append binary).
    Never seeks or truncates.
  - DAG: each entry carries a parent_id so concurrent / nested tool calls
    form a directed acyclic graph, not a flat sequence.
  - Frozen entries: AuditEntry is a frozen dataclass — no mutation after
    construction.
  - JSON Lines format: one JSON object per line, easy to stream and tail.

Usage::

    logger = AuditLogger("/var/log/cosai/audit.jsonl")
    root_id = logger.log(method="tools/list", session_id="ses-abc", params={})
    child_id = logger.log(
        method="tools/call", session_id="ses-abc",
        params={"name": "search"}, parent_id=root_id,
    )
    logger.verify_chain()   # raises AuditChainError on tampering
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# AuditEntry — frozen, hash-chained
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuditEntry:
    """A single immutable audit log record."""
    entry_id: str           # UUIDv4
    parent_id: str | None   # parent entry_id for DAG edges; None for roots
    session_id: str
    method: str             # JSON-RPC method (e.g. "tools/call")
    params_digest: str      # SHA-256 hex of json.dumps(params) — not raw params
    timestamp_utc: float    # time.time() — Unix epoch, UTC
    prev_hash: str          # SHA-256 of previous entry's chain_hash ("0"*64 for first)
    chain_hash: str         # SHA-256(prev_hash + canonical_json(this entry minus chain_hash))

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id":     self.entry_id,
            "parent_id":    self.parent_id,
            "session_id":   self.session_id,
            "method":       self.method,
            "params_digest": self.params_digest,
            "timestamp_utc": self.timestamp_utc,
            "prev_hash":    self.prev_hash,
            "chain_hash":   self.chain_hash,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AuditEntry":
        return cls(
            entry_id=d["entry_id"],
            parent_id=d.get("parent_id"),
            session_id=d["session_id"],
            method=d["method"],
            params_digest=d["params_digest"],
            timestamp_utc=d["timestamp_utc"],
            prev_hash=d["prev_hash"],
            chain_hash=d["chain_hash"],
        )


def _sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def _params_digest(params: dict[str, Any]) -> str:
    """Deterministic SHA-256 digest of params — sorted keys, compact JSON."""
    canonical = json.dumps(params, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return _sha256(canonical)


def _compute_chain_hash(entry_without_hash: dict[str, Any]) -> str:
    """Compute chain_hash over the canonical form of the entry (minus chain_hash)."""
    canonical = json.dumps(entry_without_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return _sha256(canonical)


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------

class AuditLogger:
    """Append-only, hash-chained audit logger for MCP operations.

    Thread-safe: a single lock serialises all writes.  Each log() call is
    atomic from the perspective of the chain (prev_hash is read and updated
    under the lock).

    Parameters
    ----------
    log_path:
        Absolute path to the JSON Lines audit file.  Created if absent.
        Parent directory must exist.
    """

    _GENESIS_HASH = "0" * 64  # prev_hash for the first entry

    def __init__(self, log_path: Path | str) -> None:
        self._path = Path(log_path)
        self._lock = threading.Lock()
        self._prev_hash: str = self._GENESIS_HASH
        self._entry_count: int = 0

        # If the file already has entries, read the last chain_hash
        if self._path.exists() and self._path.stat().st_size > 0:
            self._prev_hash, self._entry_count = self._load_tail()

    def log(
        self,
        *,
        method: str,
        session_id: str,
        params: dict[str, Any] | None = None,
        parent_id: str | None = None,
    ) -> str:
        """Append one audit entry and return its entry_id.

        Parameters
        ----------
        method:
            JSON-RPC method name (e.g. ``"tools/call"``).
        session_id:
            The MCP session identifier this call belongs to.
        params:
            The method parameters (logged as a digest, not raw — avoids
            storing sensitive argument values in the log).
        parent_id:
            entry_id of the parent call for DAG edge construction.

        Returns
        -------
        str
            The new entry's entry_id (UUIDv4), usable as parent_id for
            child calls.
        """
        entry_id = str(uuid.uuid4())
        digest = _params_digest(params or {})
        now = time.time()

        with self._lock:
            prev = self._prev_hash

            # Build the entry dict without chain_hash first
            partial: dict[str, Any] = {
                "entry_id":      entry_id,
                "parent_id":     parent_id,
                "session_id":    session_id,
                "method":        method,
                "params_digest": digest,
                "timestamp_utc": now,
                "prev_hash":     prev,
            }
            chain_hash = _compute_chain_hash(partial)
            partial["chain_hash"] = chain_hash

            line = json.dumps(partial, sort_keys=True, separators=(",", ":")) + "\n"
            # Append-only: 'ab' never truncates
            with self._path.open("ab") as fh:
                fh.write(line.encode())

            self._prev_hash = chain_hash
            self._entry_count += 1

        return entry_id

    def verify_chain(self) -> int:
        """Verify the integrity of the entire audit log.

        Reads the log from the beginning and recomputes each chain_hash,
        verifying it matches the stored value and that prev_hash links
        correctly to the previous entry.

        Returns
        -------
        int
            Number of entries verified.

        Raises
        ------
        AuditChainError
            If any hash is missing, mismatched, or the chain is broken.
        """
        if not self._path.exists():
            return 0

        prev_hash = self._GENESIS_HASH
        count = 0

        with self._path.open("rb") as fh:
            for lineno, raw_line in enumerate(fh, start=1):
                line = raw_line.decode().strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditChainError(
                        f"Line {lineno}: invalid JSON — {exc}"
                    ) from exc

                stored_hash = d.get("chain_hash", "")
                stored_prev = d.get("prev_hash", "")

                if stored_prev != prev_hash:
                    raise AuditChainError(
                        f"Line {lineno}: prev_hash mismatch — "
                        f"expected {prev_hash!r}, got {stored_prev!r}"
                    )

                # Recompute chain_hash from entry without chain_hash field
                partial = {k: v for k, v in d.items() if k != "chain_hash"}
                expected_hash = _compute_chain_hash(partial)
                if stored_hash != expected_hash:
                    raise AuditChainError(
                        f"Line {lineno}: chain_hash mismatch for entry "
                        f"{d.get('entry_id', '?')!r} — log may have been tampered with"
                    )

                prev_hash = stored_hash
                count += 1

        return count

    def entries(self) -> list[AuditEntry]:
        """Return all log entries as AuditEntry objects (for testing/reporting)."""
        if not self._path.exists():
            return []
        result: list[AuditEntry] = []
        with self._path.open("rb") as fh:
            for raw_line in fh:
                line = raw_line.decode().strip()
                if line:
                    result.append(AuditEntry.from_dict(json.loads(line)))
        return result

    @property
    def entry_count(self) -> int:
        return self._entry_count

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_tail(self) -> tuple[str, int]:
        """Read the last entry's chain_hash and count all entries."""
        last_hash = self._GENESIS_HASH
        count = 0
        with self._path.open("rb") as fh:
            for raw_line in fh:
                line = raw_line.decode().strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    last_hash = d.get("chain_hash", self._GENESIS_HASH)
                    count += 1
                except json.JSONDecodeError:
                    pass
        return last_hash, count


# ---------------------------------------------------------------------------
# DAG helpers
# ---------------------------------------------------------------------------

def build_dag(entries: list[AuditEntry]) -> dict[str | None, list[AuditEntry]]:
    """Build a parent→children mapping from a list of entries.

    Returns a dict where the key is parent_id (None for root entries) and
    the value is the list of child entries.

    Useful for rendering execution trees and detecting suspicious fan-out
    (one parent spawning many tool calls — potential loop / DoW indicator).
    """
    dag: dict[str | None, list[AuditEntry]] = {}
    for entry in entries:
        dag.setdefault(entry.parent_id, []).append(entry)
    return dag


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class AuditChainError(Exception):
    """Raised when audit log chain verification fails.

    Indicates the log was tampered with, truncated, or corrupted.
    Callers should treat this as a security incident.
    """
