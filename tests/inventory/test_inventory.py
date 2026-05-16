"""Tests for cosai_mcp.inventory — snapshot, signing, drift, and CLI wiring."""
from __future__ import annotations

import json
from unittest.mock import create_autospec, patch

import pytest
from click.testing import CliRunner

from cosai_mcp.cli import main
from cosai_mcp.exceptions import SignatureVerificationError
from cosai_mcp.inventory.drift import DriftEntry, DriftKind, DriftReport, detect_drift
from cosai_mcp.inventory.signing import _canonical_bytes, sign_inventory, verify_inventory
from cosai_mcp.inventory.snapshot import ToolInventory, ToolRecord, capture


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_RAW_TOOLS = [
    {"name": "echo", "description": "Echoes input", "inputSchema": {"type": "object"}},
    {
        "name": "read_file",
        "description": "Reads a file",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
    },
]


def _make_inventory(
    target: str = "http://example.com",
    tools: list | None = None,
    server_name: str = "mock",
    server_version: str = "1.0",
    protocol_version: str = "2025-03-26",
) -> ToolInventory:
    return ToolInventory.build(
        target=target,
        protocol_version=protocol_version,
        server_name=server_name,
        server_version=server_version,
        raw_tools=tools if tools is not None else list(_RAW_TOOLS),
    )


# ---------------------------------------------------------------------------
# ToolRecord
# ---------------------------------------------------------------------------


class TestToolRecord:
    def test_from_dict_basic(self) -> None:
        rec = ToolRecord.from_dict(_RAW_TOOLS[0])
        assert rec.name == "echo"
        assert rec.description == "Echoes input"
        assert json.loads(rec.input_schema) == {"type": "object"}

    def test_from_dict_canonical_schema_sort(self) -> None:
        raw = {"name": "t", "description": "d", "inputSchema": {"b": 1, "a": 2}}
        rec = ToolRecord.from_dict(raw)
        assert rec.input_schema == '{"a":2,"b":1}'

    def test_to_dict_roundtrip(self) -> None:
        rec = ToolRecord.from_dict(_RAW_TOOLS[1])
        d = rec.to_dict()
        assert d["name"] == "read_file"
        assert d["inputSchema"] == {"type": "object", "properties": {"path": {"type": "string"}}}

    def test_input_schema_fallback_empty(self) -> None:
        rec = ToolRecord.from_dict({"name": "x", "description": "y"})
        assert json.loads(rec.input_schema) == {}


# ---------------------------------------------------------------------------
# ToolInventory
# ---------------------------------------------------------------------------


class TestToolInventory:
    def test_build_sorts_tools_by_name(self) -> None:
        inv = _make_inventory()
        names = [t.name for t in inv.tools]
        assert names == sorted(names)

    def test_content_hash_is_stable(self) -> None:
        inv1 = _make_inventory()
        inv2 = _make_inventory()
        # Same tools → same hash (different captured_at is excluded from hash)
        assert inv1.content_hash == inv2.content_hash

    def test_content_hash_changes_on_tool_change(self) -> None:
        inv1 = _make_inventory()
        inv2 = _make_inventory(tools=[{"name": "other", "description": "d", "inputSchema": {}}])
        assert inv1.content_hash != inv2.content_hash

    def test_to_dict_from_dict_roundtrip(self) -> None:
        inv = _make_inventory()
        d = inv.to_dict()
        inv2 = ToolInventory.from_dict(d)
        assert inv.content_hash == inv2.content_hash
        assert inv.target == inv2.target
        assert len(inv2.tools) == 2

    def test_to_json_from_json_roundtrip(self) -> None:
        inv = _make_inventory()
        inv2 = ToolInventory.from_json(inv.to_json())
        assert inv.content_hash == inv2.content_hash


# ---------------------------------------------------------------------------
# capture() — integration via MockMCPServer
# ---------------------------------------------------------------------------


class TestCapture:
    def test_capture_returns_inventory(self) -> None:
        from cosai_mcp.harness.mock_server import MockMCPServer

        with MockMCPServer(tools=list(_RAW_TOOLS)) as server:
            server.wait_ready()
            inv = capture(
                f"http://127.0.0.1:{server.port}", allow_private_targets=True
            )

        assert len(inv.tools) == 2
        assert {t.name for t in inv.tools} == {"echo", "read_file"}
        assert inv.protocol_version == "2025-03-26"
        assert inv.server_name == "mock-mcp-server"

    def test_capture_content_hash_matches_manual_build(self) -> None:
        from cosai_mcp.harness.mock_server import MockMCPServer

        with MockMCPServer(tools=list(_RAW_TOOLS)) as server:
            server.wait_ready()
            inv = capture(
                f"http://127.0.0.1:{server.port}", allow_private_targets=True
            )

        expected = ToolInventory.build(
            target=inv.target,
            protocol_version=inv.protocol_version,
            server_name=inv.server_name,
            server_version=inv.server_version,
            raw_tools=list(_RAW_TOOLS),
        ).content_hash
        assert inv.content_hash == expected

    def test_capture_raises_on_initialize_error(self) -> None:
        from cosai_mcp.harness.mock_server import MockMCPServer

        with MockMCPServer(initialize_error="auth required") as server:
            server.wait_ready()
            with pytest.raises(RuntimeError, match="initialize failed"):
                capture(
                    f"http://127.0.0.1:{server.port}", allow_private_targets=True
                )

    def test_regression_capture_rejects_private_target_by_default(self) -> None:
        """capture() must reject loopback/private targets without allow_private_targets."""
        from cosai_mcp.exceptions import PrivateAddressError

        with pytest.raises(PrivateAddressError):
            capture("http://127.0.0.1:9999")


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


class TestSigning:
    def _sign_and_verify(self, inv: ToolInventory) -> ToolInventory:
        artifact = sign_inventory(inv)
        return verify_inventory(artifact)

    def test_sign_verify_roundtrip(self) -> None:
        inv = _make_inventory()
        recovered = self._sign_and_verify(inv)
        assert recovered.content_hash == inv.content_hash
        assert len(recovered.tools) == 2

    def test_tampered_inventory_rejected(self) -> None:
        inv = _make_inventory()
        artifact = sign_inventory(inv)
        artifact["inventory"]["tools"].append(
            {"name": "injected", "description": "x", "inputSchema": {}}
        )
        with pytest.raises(SignatureVerificationError):
            verify_inventory(artifact)

    def test_tampered_signature_rejected(self) -> None:
        inv = _make_inventory()
        artifact = sign_inventory(inv)
        bad_sig = "00" * 64
        artifact["signature"] = bad_sig
        with pytest.raises(SignatureVerificationError):
            verify_inventory(artifact)

    def test_missing_signature_field_rejected(self) -> None:
        inv = _make_inventory()
        artifact = sign_inventory(inv)
        del artifact["signature"]
        with pytest.raises(SignatureVerificationError):
            verify_inventory(artifact)

    def test_canonical_bytes_are_deterministic(self) -> None:
        inv = _make_inventory()
        d = inv.to_dict()
        assert _canonical_bytes(d) == _canonical_bytes(d)

    def test_artifact_structure(self) -> None:
        inv = _make_inventory()
        artifact = sign_inventory(inv)
        assert "inventory" in artifact
        assert "signature" in artifact
        assert "public_key" in artifact
        assert len(artifact["public_key"]) == 64  # 32 bytes hex-encoded

    def test_regression_trust_anchor_rejects_foreign_key(self, monkeypatch) -> None:
        """verify_inventory must reject artifacts signed with a different key.

        Simulates the attack: attacker generates fresh keypair, tampers inventory,
        re-signs with their key, and embeds their public_key in the artifact.
        verify_inventory must reject this because the public key doesn't match
        the trusted installation key.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _Priv

        inv = _make_inventory()
        # Attacker generates a fresh keypair and re-signs the (possibly tampered) artifact.
        attacker_priv = _Priv.generate()
        attacker_pub = attacker_priv.public_key()
        from cosai_mcp.inventory.signing import _canonical_bytes
        inv_dict = inv.to_dict()
        forged_sig = attacker_priv.sign(_canonical_bytes(inv_dict))
        forged_artifact = {
            "inventory": inv_dict,
            "signature": forged_sig.hex(),
            "public_key": attacker_pub.public_bytes_raw().hex(),
        }
        # verify_inventory must reject this because attacker_pub != local installation key
        with pytest.raises(SignatureVerificationError, match="trusted"):
            verify_inventory(forged_artifact)


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------


class TestDrift:
    def test_identical_inventories_no_drift(self) -> None:
        inv = _make_inventory()
        report = detect_drift(inv, inv)
        assert not report.has_drift
        assert report.summary() == "No drift detected."

    def test_tool_added(self) -> None:
        base = _make_inventory(tools=[{"name": "echo", "description": "d", "inputSchema": {}}])
        curr = _make_inventory()  # echo + read_file
        report = detect_drift(base, curr)
        assert report.has_drift
        added_names = {e.tool_name for e in report.added}
        assert "read_file" in added_names

    def test_tool_removed(self) -> None:
        base = _make_inventory()
        curr = _make_inventory(tools=[{"name": "echo", "description": "d", "inputSchema": {}}])
        report = detect_drift(base, curr)
        assert report.has_drift
        removed_names = {e.tool_name for e in report.removed}
        assert "read_file" in removed_names

    def test_description_changed(self) -> None:
        base = _make_inventory(tools=[{"name": "echo", "description": "old", "inputSchema": {}}])
        curr = _make_inventory(tools=[{"name": "echo", "description": "new", "inputSchema": {}}])
        report = detect_drift(base, curr)
        assert report.has_drift
        assert any(e.kind == DriftKind.DESCRIPTION_CHANGED for e in report.entries)

    def test_schema_changed(self) -> None:
        base = _make_inventory(tools=[{"name": "echo", "description": "d", "inputSchema": {}}])
        curr = _make_inventory(tools=[{"name": "echo", "description": "d", "inputSchema": {"type": "object"}}])
        report = detect_drift(base, curr)
        assert report.has_drift
        assert any(e.kind == DriftKind.SCHEMA_CHANGED for e in report.entries)

    def test_summary_message(self) -> None:
        base = _make_inventory()
        curr = _make_inventory(tools=[
            {"name": "echo", "description": "changed", "inputSchema": {}},
            {"name": "new_tool", "description": "n", "inputSchema": {}},
        ])
        report = detect_drift(base, curr)
        s = report.summary()
        assert "added" in s
        assert "changed" in s or "description" in s.lower() or "removed" in s


# ---------------------------------------------------------------------------
# CLI wiring — cosai inventory capture / verify / diff
# ---------------------------------------------------------------------------


class TestInventoryCLI:
    def test_capture_command_wired(self) -> None:
        """capture subcommand must exist and reach the inventory module."""
        from cosai_mcp.harness.mock_server import MockMCPServer

        runner = CliRunner()
        with MockMCPServer(tools=list(_RAW_TOOLS)) as server:
            server.wait_ready()
            result = runner.invoke(
                main,
                [
                    "inventory", "capture",
                    f"http://127.0.0.1:{server.port}",
                    "--no-sign", "--allow-private",
                ],
            )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert "tools" in data
        assert len(data["tools"]) == 2

    def test_capture_signed_output(self, tmp_path) -> None:
        from cosai_mcp.harness.mock_server import MockMCPServer

        out = tmp_path / "inv.json"
        runner = CliRunner()
        with MockMCPServer(tools=list(_RAW_TOOLS)) as server:
            server.wait_ready()
            result = runner.invoke(
                main,
                [
                    "inventory", "capture",
                    f"http://127.0.0.1:{server.port}",
                    "-o", str(out), "--allow-private",
                ],
            )
        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text())
        assert "signature" in data
        assert "inventory" in data

    def test_verify_command_valid(self, tmp_path) -> None:
        inv = _make_inventory()
        artifact = sign_inventory(inv)
        p = tmp_path / "inv.json"
        p.write_text(json.dumps(artifact))

        runner = CliRunner()
        result = runner.invoke(main, ["inventory", "verify", str(p)])
        assert result.exit_code == 0, result.output
        assert "VALID" in result.output

    def test_verify_command_tampered(self, tmp_path) -> None:
        inv = _make_inventory()
        artifact = sign_inventory(inv)
        artifact["signature"] = "00" * 64
        p = tmp_path / "inv.json"
        p.write_text(json.dumps(artifact))

        runner = CliRunner()
        result = runner.invoke(main, ["inventory", "verify", str(p)])
        assert result.exit_code == 1

    def test_diff_no_drift(self, tmp_path) -> None:
        inv = _make_inventory()
        raw = json.dumps(inv.to_dict())
        base_p = tmp_path / "base.json"
        curr_p = tmp_path / "curr.json"
        base_p.write_text(raw)
        curr_p.write_text(raw)

        runner = CliRunner()
        result = runner.invoke(main, ["inventory", "diff", str(base_p), str(curr_p)])
        assert result.exit_code == 0
        assert "No drift" in result.output

    def test_diff_with_drift_exits_0_without_flag(self, tmp_path) -> None:
        base_inv = _make_inventory(tools=[{"name": "echo", "description": "d", "inputSchema": {}}])
        curr_inv = _make_inventory()  # echo + read_file
        base_p = tmp_path / "base.json"
        curr_p = tmp_path / "curr.json"
        base_p.write_text(json.dumps(base_inv.to_dict()))
        curr_p.write_text(json.dumps(curr_inv.to_dict()))

        runner = CliRunner()
        result = runner.invoke(main, ["inventory", "diff", str(base_p), str(curr_p)])
        assert result.exit_code == 0
        assert "Drift detected" in result.output

    def test_diff_fail_on_drift_exits_1(self, tmp_path) -> None:
        base_inv = _make_inventory(tools=[{"name": "echo", "description": "d", "inputSchema": {}}])
        curr_inv = _make_inventory()
        base_p = tmp_path / "base.json"
        curr_p = tmp_path / "curr.json"
        base_p.write_text(json.dumps(base_inv.to_dict()))
        curr_p.write_text(json.dumps(curr_inv.to_dict()))

        runner = CliRunner()
        result = runner.invoke(
            main, ["inventory", "diff", str(base_p), str(curr_p), "--fail-on-drift"]
        )
        assert result.exit_code == 1

    def test_diff_auto_verifies_signed_artifact(self, tmp_path) -> None:
        inv = _make_inventory()
        artifact = sign_inventory(inv)
        base_p = tmp_path / "base.json"
        curr_p = tmp_path / "curr.json"
        base_p.write_text(json.dumps(artifact))
        curr_p.write_text(json.dumps(artifact))

        runner = CliRunner()
        result = runner.invoke(main, ["inventory", "diff", str(base_p), str(curr_p)])
        assert result.exit_code == 0, result.output
        assert "No drift" in result.output

    def test_regression_diff_tampered_signed_rejected_by_default(self, tmp_path) -> None:
        """Tampered signed artifact must be rejected by diff without any flags."""
        inv = _make_inventory()
        artifact = sign_inventory(inv)
        artifact["signature"] = "00" * 64  # corrupt signature
        base_p = tmp_path / "base.json"
        curr_p = tmp_path / "curr.json"
        base_p.write_text(json.dumps(sign_inventory(inv)))
        curr_p.write_text(json.dumps(artifact))

        runner = CliRunner()
        result = runner.invoke(main, ["inventory", "diff", str(base_p), str(curr_p)])
        assert result.exit_code == 2
        assert "verification failed" in result.output.lower() or "Signature" in result.output

    def test_regression_diff_skip_verify_emits_warning(self, tmp_path) -> None:
        """--skip-verify-signatures must emit a stderr warning when loading signed artifact."""
        inv = _make_inventory()
        artifact = sign_inventory(inv)
        base_p = tmp_path / "base.json"
        curr_p = tmp_path / "curr.json"
        base_p.write_text(json.dumps(artifact))
        curr_p.write_text(json.dumps(artifact))

        runner = CliRunner()
        result = runner.invoke(
            main, ["inventory", "diff", str(base_p), str(curr_p), "--skip-verify-signatures"]
        )
        assert result.exit_code == 0, result.output
        # The warning goes to stderr which CliRunner captures in result.output
        assert "WARN" in result.output or "not guaranteed" in result.output.lower()

    def test_capture_unreachable_exits_2(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["inventory", "capture", "http://127.0.0.1:1", "--no-sign", "--allow-private"]
        )
        assert result.exit_code == 2

    def test_regression_control_chars_stripped_from_description(self) -> None:
        """Malicious server cannot inject terminal escape sequences via tool descriptions."""
        rec = ToolRecord.from_dict(
            {"name": "evil", "description": "Normal\x1b[2J\x00hidden", "inputSchema": {}}
        )
        assert "\x1b" not in rec.description
        assert "\x00" not in rec.description
        assert "Normal" in rec.description
        assert "hidden" in rec.description

    def test_regression_verify_signatures_tampered_with_flag(self, tmp_path) -> None:
        """--verify-signatures (verify command) must reject tampered artifact with exit 1."""
        inv = _make_inventory()
        artifact = sign_inventory(inv)
        artifact["signature"] = "ff" * 64
        p = tmp_path / "tampered.json"
        p.write_text(json.dumps(artifact))

        runner = CliRunner()
        result = runner.invoke(main, ["inventory", "verify", str(p)])
        assert result.exit_code == 1
