"""Batch 3 — wiring the missing CLI/scan surface.

EFF-05: --read-token / COSAI_READ_TOKEN must reach ScanConfig.read_token so the
        T02-005 scope-enforcement probes actually run instead of being silently
        reported INCONCLUSIVE ("requires --read-token") forever.
COV-10: the T7-SC-002 session-revocation scenario must be registered in the
        stateful engine (it existed but was never wired into _run_scan).
"""
from __future__ import annotations

from pathlib import Path

from cosai_mcp.api import _run_scan
from cosai_mcp.harness.mock_server import MockMCPServer

_CATALOG_ROOT = Path(__file__).parent.parent / "catalog"

# alg=none JWT with scope "read" — the mock decodes the payload (no signature
# check) so this stands in for a real read-scoped operator token.
_READ_TOKEN = (
    "eyJhbGciOiJub25lIn0"
    ".eyJzdWIiOiJ0ZXN0LWFnZW50Iiwic2NvcGUiOiJyZWFkIiwiZXhwIjo5OTk5OTk5OTk5fQ"
    "."
)


class TestReadTokenWiring:
    """EFF-05."""

    def test_read_token_makes_t02_005_probes_run(self) -> None:
        """With --read-token configured, T02-005 probes execute (no longer the
        'requires --read-token' inconclusive)."""
        with MockMCPServer() as server:
            server.wait_ready()
            result = _run_scan(
                target=f"http://127.0.0.1:{server.port}",
                categories=["T2"],
                engine="prober",
                allow_custom_catalog=False,
                probe_timeout_seconds=15.0,
                catalog_root=_CATALOG_ROOT,
                allow_private_targets=True,
                read_token=_READ_TOKEN,
            )
        t02_005 = [r for r in result.probe_results if r.probe_id.startswith("T02-005")]
        assert t02_005, "T02-005 probes should be present in a T2 scan"
        for r in t02_005:
            assert not (r.inconclusive_reason and "requires --read-token" in r.inconclusive_reason), (  # noqa: E501
                f"{r.probe_id} still skipped for missing read token despite "
                f"--read-token being configured"
            )

    def test_without_read_token_t02_005_is_inconclusive(self) -> None:
        """Control: with NO read token, T02-005 probes are INCONCLUSIVE (the
        documented skip), confirming the flag is what flips them live."""
        with MockMCPServer() as server:
            server.wait_ready()
            result = _run_scan(
                target=f"http://127.0.0.1:{server.port}",
                categories=["T2"],
                engine="prober",
                allow_custom_catalog=False,
                probe_timeout_seconds=15.0,
                catalog_root=_CATALOG_ROOT,
                allow_private_targets=True,
                read_token=None,
            )
        t02_005 = [r for r in result.probe_results if r.probe_id.startswith("T02-005")]
        assert any(
            r.inconclusive_reason and "requires --read-token" in r.inconclusive_reason
            for r in t02_005
        )


class TestRevocationScenarioRegistered:
    """COV-10."""

    def test_t7_revocation_scenario_runs(self) -> None:
        with MockMCPServer() as server:
            server.wait_ready()
            result = _run_scan(
                target=f"http://127.0.0.1:{server.port}",
                categories=["T7"],
                engine="stateful",
                allow_custom_catalog=False,
                probe_timeout_seconds=15.0,
                catalog_root=_CATALOG_ROOT,
                allow_private_targets=True,
            )
        ids = {s.scenario_id for s in result.scenario_results}
        assert "T7-SC-002" in ids, (
            f"session-revocation scenario not registered; ran: {sorted(ids)}"
        )
