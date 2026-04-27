"""Tests for audit log chain verification."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from cosai_mcp.middleware.audit import AuditLogger
from cosai_mcp.report.verify import VerifyStatus, verify_audit_log


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_log(entries: int, tmp_path: Path) -> Path:
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path)
    for i in range(entries):
        logger.log(method="tools/call", session_id="ses-test", params={"i": i})
    return log_path


# ---------------------------------------------------------------------------
# verify_audit_log — normal paths
# ---------------------------------------------------------------------------

class TestVerifyAuditLog:

    def test_verify_ok_single_entry(self, tmp_path):
        path = _write_log(1, tmp_path)
        result = verify_audit_log(path)
        assert result.status == VerifyStatus.OK
        assert result.entries_verified == 1

    def test_verify_ok_multiple_entries(self, tmp_path):
        path = _write_log(5, tmp_path)
        result = verify_audit_log(path)
        assert result.status == VerifyStatus.OK
        assert result.entries_verified == 5

    def test_verify_file_not_found(self, tmp_path):
        result = verify_audit_log(tmp_path / "nonexistent.jsonl")
        assert result.status == VerifyStatus.FILE_NOT_FOUND

    def test_verify_empty_file(self, tmp_path):
        path = tmp_path / "empty.jsonl"
        path.write_bytes(b"")
        result = verify_audit_log(path)
        assert result.status == VerifyStatus.EMPTY
        assert result.entries_verified == 0

    def test_verify_accepts_string_path(self, tmp_path):
        path = _write_log(2, tmp_path)
        result = verify_audit_log(str(path))
        assert result.status == VerifyStatus.OK

    def test_verify_result_is_frozen(self, tmp_path):
        path = _write_log(1, tmp_path)
        result = verify_audit_log(path)
        with pytest.raises((AttributeError, TypeError)):
            result.status = VerifyStatus.CHAIN_BROKEN  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------

class TestAuditChainTamperDetection:

    def test_audit_chain_tamper_detection(self, tmp_path):
        """Modifying entry 3 must be detected as CHAIN_BROKEN."""
        path = _write_log(5, tmp_path)

        # Read all lines
        lines = path.read_bytes().decode().strip().splitlines()
        assert len(lines) == 5

        # Tamper entry at index 2 (entry 3)
        entry = json.loads(lines[2])
        entry["method"] = "tools/call_TAMPERED"
        lines[2] = json.dumps(entry)

        path.write_bytes(("\n".join(lines) + "\n").encode())

        result = verify_audit_log(path)
        assert result.status == VerifyStatus.CHAIN_BROKEN
        assert result.error_message is not None

    def test_tampered_chain_hash_detected(self, tmp_path):
        """Directly altering chain_hash of entry 1 breaks the chain."""
        path = _write_log(3, tmp_path)
        lines = path.read_bytes().decode().strip().splitlines()

        entry = json.loads(lines[0])
        entry["chain_hash"] = "0" * 64
        lines[0] = json.dumps(entry)

        path.write_bytes(("\n".join(lines) + "\n").encode())

        result = verify_audit_log(path)
        assert result.status == VerifyStatus.CHAIN_BROKEN

    def test_deleted_entry_breaks_chain(self, tmp_path):
        """Removing an entry from the middle breaks prev_hash linkage."""
        path = _write_log(4, tmp_path)
        lines = path.read_bytes().decode().strip().splitlines()

        # Remove entry at index 1 (second entry)
        del lines[1]
        path.write_bytes(("\n".join(lines) + "\n").encode())

        result = verify_audit_log(path)
        assert result.status == VerifyStatus.CHAIN_BROKEN

    def test_appended_valid_entries_still_verify(self, tmp_path):
        """Log that grows by legitimate appends continues to verify OK."""
        path = _write_log(3, tmp_path)
        logger2 = AuditLogger(path)
        logger2.log(method="tools/list", session_id="ses-2", params={})
        logger2.log(method="tools/list", session_id="ses-2", params={})

        result = verify_audit_log(path)
        assert result.status == VerifyStatus.OK
        assert result.entries_verified == 5

    def test_regression_verify_broken_at_line_populated(self, tmp_path):
        """broken_at_line must be populated when the chain is broken.

        FIX 8: VerifyResult.broken_at_line was always None. AuditChainError
        now carries lineno and verify_audit_log propagates it.
        """
        path = _write_log(5, tmp_path)
        lines = path.read_bytes().decode().strip().splitlines()

        # Tamper entry at line index 2 (line 3, 1-based)
        entry = json.loads(lines[2])
        entry["method"] = "tampered"
        lines[2] = json.dumps(entry)
        path.write_bytes(("\n".join(lines) + "\n").encode())

        result = verify_audit_log(path)
        assert result.status == VerifyStatus.CHAIN_BROKEN
        assert result.broken_at_line == 3
