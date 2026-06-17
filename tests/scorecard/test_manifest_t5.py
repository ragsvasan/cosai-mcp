"""Passive T5 secret/PII manifest scan (WG-89 reviewer item 3).

``_scan_manifest_t5`` scans the already-fetched tools/list manifest (tool names
and descriptions) for embedded credentials / PII via the expanded PIIScrubber.
Default tier = anchored credentials only (low FP); ``--pii-strict`` widens to the
broad-PII tier (SSN/IBAN/phone/Luhn-PAN).  Mirrors the T4/T6/T9 passive scans.
"""
from __future__ import annotations

import types

from cosai_mcp.api import _scan_manifest_t5
from cosai_mcp.discovery import DiscoveredTool


def _tool(name: str, description: str = "") -> DiscoveredTool:
    return DiscoveredTool(
        name=name,
        description=description,
        input_schema=types.MappingProxyType({}),
        boolean_params=(),
        string_params=(),
        numeric_params=(),
        required_params=(),
    )


class TestScanManifestT5:
    def test_empty_manifest_yields_nothing(self) -> None:
        assert _scan_manifest_t5(()) == []

    def test_clean_manifest_yields_nothing(self) -> None:
        tools = (_tool("search", "Searches the corpus and ranks results."),)
        assert _scan_manifest_t5(tools) == []

    def test_credential_in_description_is_a_finding(self) -> None:
        leaked = _tool(
            "deploy",
            "Deploys using aws key AKIAABCDEFGH12345678 — internal helper.",
        )
        results = _scan_manifest_t5((leaked,))
        assert results, "embedded AWS key must produce a T5 finding"
        assert all(r.threat_id == "T05" for r in results)
        assert not results[0].passed

    def test_finding_redacts_the_secret_never_echoes_it(self) -> None:
        secret = "AKIAABCDEFGH12345678"
        leaked = _tool("deploy", f"key {secret}")
        results = _scan_manifest_t5((leaked,))
        assert secret not in results[0].response_body
        assert "[REDACTED:aws_access_key]" in results[0].response_body

    def test_example_email_not_flagged_by_default(self) -> None:
        """Manifest scan must NOT false-positive on legit example emails."""
        tools = (_tool("notify", "Emails support@example.com on completion."),)
        assert _scan_manifest_t5(tools) == []

    def test_ssn_not_flagged_without_pii_strict(self) -> None:
        tools = (_tool("lookup", "Looks up record for 123-45-6789 quickly."),)
        assert _scan_manifest_t5(tools, pii_strict=False) == []

    def test_ssn_flagged_with_pii_strict(self) -> None:
        tools = (_tool("lookup", "Looks up record for 123-45-6789 quickly."),)
        results = _scan_manifest_t5(tools, pii_strict=True)
        assert results
        assert "[REDACTED:ssn]" in results[0].response_body

    def test_internal_hostname_in_description_not_manifest_finding(self) -> None:
        """Defense FIX [2]: context-leak patterns (internal_hostname / stack_trace)
        are matched by PIIScrubber for RESPONSE-BODY scrubbing but are intentionally
        NOT reported by the passive manifest scan — internal hostnames appear in
        legitimate tool documentation, so flagging them on the manifest is high-FP.
        This test pins that deliberate exclusion (the gap is by design, not a miss).
        """
        tools = (_tool("query", "Connects to db-primary.internal to run the query."),)
        assert _scan_manifest_t5(tools, pii_strict=False) == []
        assert _scan_manifest_t5(tools, pii_strict=True) == []

    def test_stack_trace_in_description_not_manifest_finding(self) -> None:
        tools = (_tool("debug", "Traceback (most recent call last): on failure."),)
        assert _scan_manifest_t5(tools, pii_strict=True) == []


class TestScanManifestT5Wiring:
    """Prove _scan_manifest_t5 is actually reached from _run_scan — guards the
    historical 'function exists + unit-tested but never wired' dead-code mode."""

    def test_regression_t5_wiring_run_scan_credential_leak(self) -> None:
        from pathlib import Path

        from cosai_mcp.api import _run_scan
        from cosai_mcp.harness.mock_server import MockMCPServer

        catalog_root = Path(__file__).parent.parent.parent / "catalog"
        poisoned = [{
            "name": "deploy",
            "description": "Deploys with token ghp_" + "A" * 36 + " baked in.",
            "inputSchema": {"type": "object"},
        }]
        with MockMCPServer(tools=poisoned) as server:
            server.wait_ready()
            result = _run_scan(
                target=f"http://127.0.0.1:{server.port}",
                categories=["T5"],
                engine="prober",
                allow_custom_catalog=False,
                probe_timeout_seconds=15.0,
                catalog_root=catalog_root,
                allow_private_targets=True,
            )
        t5 = [r for r in result.probe_results if r.threat_id == "T05"]
        assert any(
            not r.passed and "github_pat" in r.response_body for r in t5
        ), "T5 manifest scan must fire via _run_scan on an embedded GitHub PAT"

    def test_regression_t5_pii_strict_flows_through_run_scan(self) -> None:
        from pathlib import Path

        from cosai_mcp.api import _run_scan
        from cosai_mcp.harness.mock_server import MockMCPServer

        catalog_root = Path(__file__).parent.parent.parent / "catalog"
        pan_tool = [{
            "name": "charge",
            "description": "Charges card 4111111111111111 on file.",
            "inputSchema": {"type": "object"},
        }]
        # Without --pii-strict: PAN is NOT flagged.
        with MockMCPServer(tools=pan_tool) as server:
            server.wait_ready()
            default = _run_scan(
                target=f"http://127.0.0.1:{server.port}",
                categories=["T5"],
                engine="prober",
                allow_custom_catalog=False,
                probe_timeout_seconds=15.0,
                catalog_root=catalog_root,
                allow_private_targets=True,
                pii_strict=False,
            )
        assert not any(
            "[REDACTED:pan]" in r.response_body
            for r in default.probe_results
            if r.threat_id == "T05"
        )
        # With --pii-strict: the Luhn-valid PAN IS flagged.
        with MockMCPServer(tools=pan_tool) as server:
            server.wait_ready()
            strict = _run_scan(
                target=f"http://127.0.0.1:{server.port}",
                categories=["T5"],
                engine="prober",
                allow_custom_catalog=False,
                probe_timeout_seconds=15.0,
                catalog_root=catalog_root,
                allow_private_targets=True,
                pii_strict=True,
            )
        assert any(
            "[REDACTED:pan]" in r.response_body
            for r in strict.probe_results
            if r.threat_id == "T05"
        ), "PAN must be flagged when --pii-strict flows through _run_scan"
