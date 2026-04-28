"""Tests for the P11 server profile system."""
from __future__ import annotations

import types
import warnings
from pathlib import Path
from unittest.mock import create_autospec, patch, MagicMock

import pytest
from click.testing import CliRunner

from cosai_mcp.cli import main
from cosai_mcp.harness.runner import ProbeRunner
from cosai_mcp.profiles import BUILTIN_PROFILES, ServerProfile, resolve_profile
from cosai_mcp.profiles.loader import _parse_user_profile, _SAFE_AST_TYPES
from cosai_mcp.stateful.harness import StatefulHarness


# ---------------------------------------------------------------------------
# test_builtin_profiles_load_without_error
# ---------------------------------------------------------------------------

def test_builtin_profiles_load_without_error():
    """All built-in profiles import cleanly and pass type invariants."""
    assert len(BUILTIN_PROFILES) >= 5, "Expected at least 5 built-in profiles"
    for name, p in BUILTIN_PROFILES.items():
        assert isinstance(p, ServerProfile), f"{name}: expected ServerProfile"
        assert isinstance(p.name, str) and p.name
        assert isinstance(p.description, str) and p.description
        assert isinstance(p.mcp_path, str) and p.mcp_path.startswith("/")
        assert p.auth_header_format is None or isinstance(p.auth_header_format, str)
        assert isinstance(p.tool_name_map, types.MappingProxyType)
        assert isinstance(p.skip_categories, frozenset)
        # Frozen — mutation must raise
        with pytest.raises((AttributeError, TypeError)):
            p.name = "mutated"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# test_profile_applies_tool_name_map
# ---------------------------------------------------------------------------

def test_profile_applies_tool_name_map():
    """mnemo profile maps 'admin_delete' → 'purge_records'."""
    mnemo = BUILTIN_PROFILES["mnemo"]
    assert mnemo.apply_tool_name("admin_delete") == "purge_records"
    assert mnemo.apply_tool_name("read_file") == "search_memories"
    assert mnemo.apply_tool_name("echo") == "ping"
    # Unknown placeholder is returned unchanged
    assert mnemo.apply_tool_name("some_other_tool") == "some_other_tool"


# ---------------------------------------------------------------------------
# test_profile_skips_categories
# ---------------------------------------------------------------------------

def test_profile_skips_categories():
    """Profiles with skip_categories cause those categories to be absent from scan."""
    from cosai_mcp.api import _run_scan, CATALOG_ROOT
    from pathlib import Path

    mnemo = BUILTIN_PROFILES["mnemo"]
    assert "T8" in mnemo.skip_categories

    # Patch _run_discovery so the scan doesn't try to reach a real server,
    # and patch _determine_exit_code + the engines to prevent real network calls.
    with (
        patch("cosai_mcp.api._run_discovery", return_value=("ping", ())),
        patch("cosai_mcp.api.ProbeRunner") as MockRunner,
        patch("cosai_mcp.api.StatefulHarness") as MockHarness,
    ):
        mock_runner_inst = create_autospec(ProbeRunner, instance=True)
        mock_runner_inst.run_threat.return_value = []
        MockRunner.return_value = mock_runner_inst

        mock_harness_inst = create_autospec(StatefulHarness, instance=True)
        mock_harness_inst.run_scenario.return_value = MagicMock(
            passed=True, status="complete", threat_categories=["T7"],
            step_results=[], scenario_id="s1", scenario_name="s1",
            inconclusive_reason=None,
        )
        MockHarness.return_value = mock_harness_inst

        result = _run_scan(
            target="http://localhost:8000",
            categories=None,
            engine="prober",
            allow_custom_catalog=False,
            probe_timeout_seconds=5.0,
            catalog_root=CATALOG_ROOT,
            fail_on="critical",
            allow_private_targets=True,
            auth_token="tok",
            profile=mnemo,
        )

    # Confirm run_threat was never called with a T8 threat
    for call in mock_runner_inst.run_threat.call_args_list:
        threat_arg = call.args[0] if call.args else call.kwargs.get("threat")
        if threat_arg is not None:
            assert threat_arg.category.upper() != "T8", (
                f"T8 threat {threat_arg.id} was probed despite skip_categories"
            )


# ---------------------------------------------------------------------------
# test_profile_list_output
# ---------------------------------------------------------------------------

def test_profile_list_output():
    """'cosai profile list' shows all built-in profile names."""
    runner = CliRunner()
    result = runner.invoke(main, ["profile", "list"])
    assert result.exit_code == 0, result.output
    for name in BUILTIN_PROFILES:
        assert name in result.output, f"Profile {name!r} missing from 'cosai profile list' output"


# ---------------------------------------------------------------------------
# test_user_profile_requires_flag
# ---------------------------------------------------------------------------

def test_user_profile_requires_flag(tmp_path: Path):
    """Loading a custom profile without --allow-custom-profiles raises ValueError (exit 2)."""
    profile_dir = tmp_path / ".cosai" / "profiles"
    profile_dir.mkdir(parents=True)
    (profile_dir / "custom.py").write_text(
        'profile = {"name": "custom", "description": "test", "mcp_path": "/mcp", '
        '"auth_header_format": None, "tool_name_map": {}, "skip_categories": [], "notes": "x"}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="--allow-custom-profiles"):
        resolve_profile("custom", allow_custom=False, project_root=tmp_path)


# ---------------------------------------------------------------------------
# test_user_profile_no_exec
# ---------------------------------------------------------------------------

def test_user_profile_no_exec(tmp_path: Path):
    """A profile file with os.system() is rejected before any code runs."""
    profile_file = tmp_path / "evil.py"
    profile_file.write_text(
        'import os; os.system("rm -rf /")\nprofile = {}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        _parse_user_profile(profile_file)


def test_user_profile_no_exec_via_call(tmp_path: Path):
    """A profile file with a function call in the value is rejected."""
    profile_file = tmp_path / "evil2.py"
    profile_file.write_text(
        'profile = dict(name="x", description=__import__("os").system("echo hi"))',
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        _parse_user_profile(profile_file)


def test_user_profile_valid(tmp_path: Path):
    """A correctly formed user profile file is parsed into a ServerProfile."""
    profile_file = tmp_path / "good.py"
    profile_file.write_text(
        'profile = {"name": "myserver", "description": "My server", "mcp_path": "/api/mcp", '
        '"auth_header_format": "Bearer {token}", "tool_name_map": {"ping": "health"}, '
        '"skip_categories": ["T8"], "notes": "Custom notes."}',
        encoding="utf-8",
    )
    p = _parse_user_profile(profile_file)
    assert p.name == "myserver"
    assert p.mcp_path == "/api/mcp"
    assert p.auth_header_format == "Bearer {token}"
    assert p.tool_name_map["ping"] == "health"
    assert "T8" in p.skip_categories
    assert isinstance(p.tool_name_map, types.MappingProxyType)
    assert isinstance(p.skip_categories, frozenset)


# ---------------------------------------------------------------------------
# test_profile_unknown_name_errors_clearly
# ---------------------------------------------------------------------------

def test_profile_unknown_name_errors_clearly():
    """resolve_profile with an unknown name raises ValueError containing the name."""
    with pytest.raises(ValueError, match="nonexistent"):
        resolve_profile("nonexistent", allow_custom=False)


def test_profile_unknown_name_cli_exit2():
    """'cosai scan --profile nonexistent' exits with code 2 and prints the name."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "scan", "http://localhost:8000", "--profile", "nonexistent",
        "--skip-reachability",
    ])
    assert result.exit_code == 2
    assert "nonexistent" in result.output or "nonexistent" in (result.stderr or "")


# ---------------------------------------------------------------------------
# test_regression_no_profile_behavior_unchanged
# ---------------------------------------------------------------------------

def test_regression_no_profile_behavior_unchanged():
    """With no --profile, _run_scan() accepts profile=None without error and uses mcp_path as-is."""
    from cosai_mcp.api import _run_scan, CATALOG_ROOT

    with (
        patch("cosai_mcp.api._run_discovery", return_value=("ping", ())),
        patch("cosai_mcp.api.ProbeRunner") as MockRunner,
        patch("cosai_mcp.api.StatefulHarness") as MockHarness,
    ):
        mock_runner_inst = create_autospec(ProbeRunner, instance=True)
        mock_runner_inst.run_threat.return_value = []
        MockRunner.return_value = mock_runner_inst

        mock_harness_inst = create_autospec(StatefulHarness, instance=True)
        mock_harness_inst.run_scenario.return_value = MagicMock(
            passed=True, status="complete", threat_categories=["T7"],
            step_results=[], scenario_id="s1", scenario_name="s1",
            inconclusive_reason=None,
        )
        MockHarness.return_value = mock_harness_inst

        result = _run_scan(
            target="http://localhost:8000",
            categories=["T3"],
            engine="prober",
            allow_custom_catalog=False,
            probe_timeout_seconds=5.0,
            catalog_root=CATALOG_ROOT,
            fail_on="critical",
            allow_private_targets=True,
            profile=None,
        )

    assert result is not None
    assert result.target_url == "http://localhost:8000"


# ---------------------------------------------------------------------------
# Panel P1 regression tests (fixes [1]–[4])
# ---------------------------------------------------------------------------

def test_regression_crlf_in_auth_header_format(tmp_path: Path):
    """auth_header_format with CRLF is rejected at validation — not at wire layer."""
    profile_file = tmp_path / "evil_crlf.py"
    profile_file.write_text(
        'profile = {"name": "evilcrlf", "description": "d", "mcp_path": "/mcp", '
        '"auth_header_format": "Bearer {token}\\r\\nX-Evil: injected", '
        '"tool_name_map": {}, "skip_categories": [], "notes": "n"}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="CR, LF, or null"):
        _parse_user_profile(profile_file)


def test_regression_null_in_auth_header_format(tmp_path: Path):
    """auth_header_format with null byte is rejected at validation."""
    profile_file = tmp_path / "evil_null.py"
    profile_file.write_text(
        'profile = {"name": "evilnull", "description": "d", "mcp_path": "/mcp", '
        '"auth_header_format": "Bearer {token}\\x00injected", '
        '"tool_name_map": {}, "skip_categories": [], "notes": "n"}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="CR, LF, or null"):
        _parse_user_profile(profile_file)


def test_regression_stateful_engine_respects_skip_categories():
    """openai-plugin profile (skip_categories=T7) prevents t7_session_token_binding from running."""
    from cosai_mcp.api import _run_scan, CATALOG_ROOT
    from cosai_mcp.stateful.scenarios import t7_session_token_binding

    openai_plugin = BUILTIN_PROFILES["openai-plugin"]
    assert "T7" in openai_plugin.skip_categories

    scenario_factories_called = []

    def _fake_harness_run(scenario, target_url):
        scenario_factories_called.append(type(scenario).__name__)
        return MagicMock(
            passed=True, status="complete", threat_categories=["T2"],
            step_results=[], scenario_id="s1", scenario_name="s1",
            inconclusive_reason=None,
        )

    with (
        patch("cosai_mcp.api._run_discovery", return_value=("ping", ())),
        patch("cosai_mcp.api.ProbeRunner") as MockRunner,
        patch("cosai_mcp.api.StatefulHarness") as MockHarness,
    ):
        mock_runner_inst = create_autospec(ProbeRunner, instance=True)
        mock_runner_inst.run_threat.return_value = []
        MockRunner.return_value = mock_runner_inst

        mock_harness_inst = create_autospec(StatefulHarness, instance=True)
        mock_harness_inst.run_scenario.side_effect = _fake_harness_run
        MockHarness.return_value = mock_harness_inst

        _run_scan(
            target="http://localhost:8000",
            categories=None,
            engine="stateful",
            allow_custom_catalog=False,
            probe_timeout_seconds=5.0,
            catalog_root=CATALOG_ROOT,
            fail_on="critical",
            allow_private_targets=True,
            profile=openai_plugin,
        )

    # T7 scenario must not have been passed to the harness
    for call in mock_harness_inst.run_scenario.call_args_list:
        scenario_arg = call.args[0] if call.args else call.kwargs.get("scenario")
        if scenario_arg is not None:
            cats = getattr(scenario_arg, "threat_categories", frozenset())
            assert "T7" not in cats, (
                f"T7 scenario {scenario_arg!r} was run despite openai-plugin skip_categories"
            )


def test_regression_skip_categories_case_normalised(tmp_path: Path):
    """skip_categories with lowercase values are normalised to uppercase at ingest."""
    profile_file = tmp_path / "lowercase_skip.py"
    profile_file.write_text(
        'profile = {"name": "myprofile", "description": "d", "mcp_path": "/mcp", '
        '"auth_header_format": None, "tool_name_map": {}, '
        '"skip_categories": ["t8", "t1"], "notes": "n"}',
        encoding="utf-8",
    )
    p = _parse_user_profile(profile_file)
    assert p.skip_categories == frozenset({"T8", "T1"}), (
        f"Expected frozenset({{'T8', 'T1'}}), got {p.skip_categories}"
    )


def test_regression_empty_threat_list_warning():
    """skip_categories that filters all threats emits a warning rather than silently exiting 0."""
    from cosai_mcp.api import _run_scan, CATALOG_ROOT
    import types as _types

    # Profile that skips every T-category
    all_cats = frozenset(f"T{i}" for i in range(1, 13))
    skip_all = ServerProfile(
        name="skipall",
        description="Skips everything",
        mcp_path="/mcp",
        auth_header_format=None,
        tool_name_map=_types.MappingProxyType({}),
        skip_categories=all_cats,
        notes="test only",
    )

    with (
        patch("cosai_mcp.api._run_discovery", return_value=("ping", ())),
        patch("cosai_mcp.api.ProbeRunner") as MockRunner,
        patch("cosai_mcp.api.StatefulHarness") as MockHarness,
    ):
        mock_runner_inst = create_autospec(ProbeRunner, instance=True)
        mock_runner_inst.run_threat.return_value = []
        MockRunner.return_value = mock_runner_inst

        mock_harness_inst = create_autospec(StatefulHarness, instance=True)
        mock_harness_inst.run_scenario.return_value = MagicMock(
            passed=True, status="complete", threat_categories=[],
            step_results=[], scenario_id="s1", scenario_name="s1",
            inconclusive_reason=None,
        )
        MockHarness.return_value = mock_harness_inst

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _run_scan(
                target="http://localhost:8000",
                categories=None,
                engine="prober",
                allow_custom_catalog=False,
                probe_timeout_seconds=5.0,
                catalog_root=CATALOG_ROOT,
                fail_on="critical",
                allow_private_targets=True,
                profile=skip_all,
            )

    assert any("skip_categories filtered out all threats" in str(w.message) for w in caught), (
        "Expected a UserWarning about empty threat list after skip_categories"
    )
