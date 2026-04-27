"""cosai audit verify — hash-chained audit log integrity check."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from cosai_mcp.middleware.audit import AuditChainError, AuditLogger


class VerifyStatus(Enum):
    OK = "ok"
    CHAIN_BROKEN = "chain_broken"
    FILE_NOT_FOUND = "file_not_found"
    EMPTY = "empty"


@dataclass(frozen=True)
class VerifyResult:
    status: VerifyStatus
    entries_verified: int
    error_message: str | None = None
    broken_at_line: int | None = None


def verify_audit_log(log_path: Path | str) -> VerifyResult:
    """Verify the integrity of a hash-chained audit log file.

    Parameters
    ----------
    log_path:
        Path to the JSON Lines audit log written by AuditLogger.

    Returns
    -------
    VerifyResult
        Frozen result with status, count of verified entries, and error details
        if the chain is broken.

    Notes
    -----
    Status semantics:
    - OK: all entries verified, chain intact.
    - CHAIN_BROKEN: at least one hash mismatch or prev_hash link broken.
    - FILE_NOT_FOUND: log file does not exist.
    - EMPTY: file exists but contains no entries.
    """
    path = Path(log_path)
    if not path.exists():
        return VerifyResult(
            status=VerifyStatus.FILE_NOT_FOUND,
            entries_verified=0,
            error_message=f"Audit log not found: {path}",
        )

    logger = AuditLogger(path)
    try:
        count = logger.verify_chain()
    except AuditChainError as exc:
        return VerifyResult(
            status=VerifyStatus.CHAIN_BROKEN,
            entries_verified=0,
            error_message=str(exc),
            broken_at_line=exc.lineno,
        )

    if count == 0:
        return VerifyResult(status=VerifyStatus.EMPTY, entries_verified=0)

    return VerifyResult(status=VerifyStatus.OK, entries_verified=count)
