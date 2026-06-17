"""Live-manifest probe binding (WG-89 reviewer item 1).

The reference probe set historically fired against a fictional ``tool_name=echo``
(conftest ``run_probe`` default) with fictional argument names (``cmd``, ``url``,
``path``).  Against a real third-party MCP server every such probe hits a
non-existent tool, the server returns ``-32601``/``-32602``, the
``response.error == True`` assertion PASSES, and the scan reports CLEAN on a
vulnerable server — a false-clean.

The production scanner already avoids this: it discovers the real ``tools/list``
manifest (``api.py:_run_discovery``) and synthesizes schema-conforming payloads
bound to discovered tools (``cosai_mcp.synthesis.synthesize_probe_payload``).
This module brings the *reference* probe set onto that same path:

* ``TestLiveProbeBinding`` — opt-in (`-m probes_live`), parametrized over the
  LIVE discovered manifest of ``--target-url``.  Skipped (never false-clean on
  ``echo``) when no target is configured.
* ``TestLiveBindingAgainstMock`` — always-on CI coverage proving discovery +
  synthesis bind probes to the *real* discovered tool/param names rather than
  the ``echo``/``cmd`` placeholders, exercised against a real MockMCPServer.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cosai_mcp.config import ScanConfig
from cosai_mcp.discovery import discover_tools
from cosai_mcp.harness.mock_server import MockMCPServer
from cosai_mcp.harness.runner import ProbeRunner
from cosai_mcp.synthesis import synthesize_probe_payload, threat_pattern_from_category

# A real server tool whose parameter is `query` — deliberately NOT the catalog's
# fictional `cmd`/`input`/`echo` names, so a bound probe must adapt to it.
_SEARCH_TOOL = {
    "name": "search_docs",
    "description": "Full-text search over the documentation corpus.",
    "inputSchema": {
        "type": "object",
        "properties": {"query": {"type": "string"}},
        "required": ["query"],
    },
}

_T03_INJECTION = Path("official/T03-001.json")


def _live_config(url: str, port: int) -> ScanConfig:
    return ScanConfig(
        target_host="127.0.0.1",
        target_port=port,
        allow_private_targets=True,
        probe_timeout_seconds=15.0,
    )


# ---------------------------------------------------------------------------
# Opt-in live suite — parametrized over a real --target-url manifest
# ---------------------------------------------------------------------------

@pytest.mark.probes_live
class TestLiveProbeBinding:
    """Runs against a real server's discovered tools. Skips without --target-url."""

    def test_injection_probe_binds_to_each_discovered_tool(
        self, live_target, live_tool, catalog
    ):
        if live_tool is None:
            pytest.skip("--target-url not set — no live manifest to probe")

        threat = catalog.load_file(_T03_INJECTION)
        cfg = ScanConfig(
            target=live_target,
            allow_private_targets=True,
            probe_timeout_seconds=15.0,
        )
        runner = ProbeRunner(config=cfg, target_url=live_target)
        results = runner.run_threat(
            threat,
            variables={
                "target_url": live_target,
                "session_id": "cosai-live",
                "tool_name": live_tool.name,  # the REAL discovered tool, not "echo"
            },
            discovered_tool=live_tool,
        )

        assert results, "probe produced no results"
        # The probe must reach the real tool, not be dismissed as an unknown-tool
        # / schema-mismatch INCONCLUSIVE — that is the exact false-clean the
        # reviewer flagged. A determinate pass/fail is the success criterion here.
        for r in results:
            reason = (r.inconclusive_reason or "").lower()
            assert "unknown tool" not in reason
            assert "does not exist" not in reason


# ---------------------------------------------------------------------------
# Always-on CI coverage — discovery + synthesis against a real MockMCPServer
# ---------------------------------------------------------------------------

class TestLiveBindingAgainstMock:
    """Proves the live-binding mechanism in CI without an external server."""

    def test_discovery_returns_real_manifest_not_echo_default(self):
        with MockMCPServer(tools=[_SEARCH_TOOL]) as server:
            server.wait_ready()
            url = f"http://127.0.0.1:{server.port}"
            tools = discover_tools(url, _live_config(url, server.port))

        assert [t.name for t in tools] == ["search_docs"]
        assert "query" in tools[0].string_params

    def test_synthesis_binds_injection_to_real_param_not_cmd(self):
        """The catalog payload targets a fictional `cmd`; synthesis must rebind
        the adversarial value onto the real `query` param of the discovered tool."""
        with MockMCPServer(tools=[_SEARCH_TOOL]) as server:
            server.wait_ready()
            url = f"http://127.0.0.1:{server.port}"
            tools = discover_tools(url, _live_config(url, server.port))

        tool = tools[0]
        pattern = threat_pattern_from_category("T3")
        catalog_payload = {
            "name": "{{tool_name}}",
            "arguments": {"cmd": "; cat /etc/passwd", "input": "; cat /etc/passwd"},
        }
        synth = synthesize_probe_payload(tool, pattern, catalog_payload)

        assert synth["name"] == "search_docs"          # bound to the real tool name
        assert "query" in synth["arguments"]            # bound to the real param
        assert "cmd" not in synth["arguments"]          # fictional param dropped
        assert synth["arguments"]["query"] == "; cat /etc/passwd"

    def test_probe_runner_reaches_discovered_tool(self, catalog):
        """End-to-end: run_threat with the discovered tool produces a determinate
        result that reached the real tool (no unknown-tool INCONCLUSIVE)."""
        with MockMCPServer(tools=[_SEARCH_TOOL]) as server:
            server.wait_ready()
            url = f"http://127.0.0.1:{server.port}"
            cfg = _live_config(url, server.port)
            tools = discover_tools(url, cfg)
            tool = next(t for t in tools if t.name == "search_docs")

            threat = catalog.load_file(_T03_INJECTION)
            runner = ProbeRunner(config=cfg, target_url=url)
            results = runner.run_threat(
                threat,
                variables={
                    "target_url": url,
                    "session_id": "cosai-live",
                    "tool_name": "search_docs",
                },
                discovered_tool=tool,
            )

        assert results
        for r in results:
            reason = (r.inconclusive_reason or "").lower()
            assert "unknown tool" not in reason
