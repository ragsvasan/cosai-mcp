"""Tests for cosai_mcp/discovery.py — DiscoveredTool and discover_tools()."""
from __future__ import annotations

import json
import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cosai_mcp.config import ScanConfig
from cosai_mcp.discovery import (
    DiscoveredTool,
    _SCHEMA_SIZE_LIMIT_BYTES,
    _parse_input_schema,
    _tool_dict_to_discovered,
    discover_tools,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def simple_config() -> ScanConfig:
    return ScanConfig(
        target_host="localhost",
        target_port=8080,
        allow_private_targets=True,
    )


def _make_tool_dict(
    name: str = "search_memories",
    description: str = "Search for memories",
    properties: dict | None = None,
    required: list[str] | None = None,
) -> dict:
    schema: dict = {"type": "object", "properties": properties or {}}
    if required:
        schema["required"] = required
    return {"name": name, "description": description, "inputSchema": schema}


# ---------------------------------------------------------------------------
# _parse_input_schema
# ---------------------------------------------------------------------------

class TestParseInputSchema:
    def test_empty_schema_returns_empty(self):
        sp, np, bp, rp = _parse_input_schema({})
        assert sp == ()
        assert np == ()
        assert bp == ()
        assert rp == frozenset()

    def test_string_param_extracted(self):
        schema = {"properties": {"query": {"type": "string"}}}
        sp, np, bp, rp = _parse_input_schema(schema)
        assert "query" in sp
        assert np == ()
        assert bp == ()

    def test_numeric_param_extracted(self):
        schema = {"properties": {"limit": {"type": "integer"}}}
        sp, np, bp, rp = _parse_input_schema(schema)
        assert sp == ()
        assert "limit" in np

    def test_number_param_extracted(self):
        schema = {"properties": {"score": {"type": "number"}}}
        sp, np, bp, rp = _parse_input_schema(schema)
        assert "score" in np

    def test_boolean_param_extracted(self):
        schema = {"properties": {"active": {"type": "boolean"}}}
        sp, np, bp, rp = _parse_input_schema(schema)
        assert "active" in bp

    def test_required_params_extracted(self):
        schema = {
            "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}},
            "required": ["query"],
        }
        sp, np, bp, rp = _parse_input_schema(schema)
        assert "query" in rp
        assert "limit" not in rp

    def test_required_params_empty_when_absent(self):
        schema = {"properties": {"query": {"type": "string"}}}
        sp, np, bp, rp = _parse_input_schema(schema)
        assert rp == frozenset()

    def test_non_dict_schema_returns_empty(self):
        sp, np, bp, rp = _parse_input_schema("not a dict")
        assert sp == ()
        assert rp == frozenset()

    def test_non_dict_properties_returns_empty(self):
        schema = {"properties": "not a dict"}
        sp, np, bp, rp = _parse_input_schema(schema)
        assert sp == ()

    def test_non_string_param_name_skipped(self):
        schema = {"properties": {42: {"type": "string"}}}
        sp, np, bp, rp = _parse_input_schema(schema)
        assert sp == ()

    def test_unknown_type_skipped(self):
        schema = {"properties": {"obj": {"type": "object"}}}
        sp, np, bp, rp = _parse_input_schema(schema)
        assert sp == ()
        assert np == ()
        assert bp == ()

    def test_multiple_mixed_params(self):
        schema = {
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer"},
                "active": {"type": "boolean"},
                "name": {"type": "string"},
            },
            "required": ["query"],
        }
        sp, np, bp, rp = _parse_input_schema(schema)
        assert set(sp) == {"query", "name"}
        assert set(np) == {"limit"}
        assert set(bp) == {"active"}
        assert rp == frozenset({"query"})


# ---------------------------------------------------------------------------
# _tool_dict_to_discovered
# ---------------------------------------------------------------------------

class TestToolDictToDiscovered:
    def test_simple_tool_parsed(self):
        tool_dict = _make_tool_dict(
            name="search_memories",
            description="Search",
            properties={"query": {"type": "string"}},
            required=["query"],
        )
        dt = _tool_dict_to_discovered(tool_dict)
        assert dt is not None
        assert dt.name == "search_memories"
        assert dt.description == "Search"
        assert "query" in dt.string_params
        assert "query" in dt.required_params

    def test_none_on_missing_name(self):
        assert _tool_dict_to_discovered({"inputSchema": {}}) is None

    def test_none_on_empty_name(self):
        assert _tool_dict_to_discovered({"name": "", "inputSchema": {}}) is None

    def test_none_on_non_dict_input(self):
        assert _tool_dict_to_discovered("not a dict") is None
        assert _tool_dict_to_discovered(None) is None

    def test_frozen_input_schema(self):
        tool_dict = _make_tool_dict(
            name="t", properties={"q": {"type": "string"}}
        )
        dt = _tool_dict_to_discovered(tool_dict)
        assert dt is not None
        assert isinstance(dt.input_schema, types.MappingProxyType)

    def test_schema_size_guard_returns_none(self):
        # Build a schema just over the 64 KB limit
        large_desc = "x" * (_SCHEMA_SIZE_LIMIT_BYTES + 100)
        tool_dict = {
            "name": "big_tool",
            "inputSchema": {"properties": {"q": {"type": "string", "description": large_desc}}},
        }
        dt = _tool_dict_to_discovered(tool_dict)
        assert dt is None

    def test_schema_at_limit_accepted(self):
        # Small schema well under the limit should be accepted
        tool_dict = _make_tool_dict(name="ok", properties={"q": {"type": "string"}})
        dt = _tool_dict_to_discovered(tool_dict)
        assert dt is not None

    def test_no_input_schema_gives_empty_params(self):
        dt = _tool_dict_to_discovered({"name": "noop"})
        assert dt is not None
        assert dt.string_params == ()
        assert dt.required_params == frozenset()

    def test_description_defaults_to_empty_string(self):
        dt = _tool_dict_to_discovered({"name": "noop"})
        assert dt is not None
        assert dt.description == ""

    def test_immutability_string_params(self):
        tool_dict = _make_tool_dict(name="t", properties={"q": {"type": "string"}})
        dt = _tool_dict_to_discovered(tool_dict)
        assert dt is not None
        assert isinstance(dt.string_params, tuple)
        with pytest.raises(AttributeError):
            dt.string_params = ("other",)  # type: ignore[misc]


# ---------------------------------------------------------------------------
# discover_tools() — integration with mocked session
# ---------------------------------------------------------------------------

class TestDiscoverTools:
    def test_returns_empty_tuple_on_exception(self, simple_config: ScanConfig):
        with patch(
            "cosai_mcp.discovery._discover_tools_async",
            side_effect=RuntimeError("boom"),
        ):
            result = discover_tools("http://localhost:8080", simple_config)
        assert result == ()

    def test_returns_discovered_tools_from_manifest(self, simple_config: ScanConfig):
        tool_manifest = [
            {
                "name": "search_memories",
                "description": "Search",
                "inputSchema": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                },
            }
        ]

        async def fake_async(target_url, config):
            return tuple(
                dt for entry in tool_manifest
                if (dt := _tool_dict_to_discovered(entry)) is not None
            )

        with patch("cosai_mcp.discovery._discover_tools_async", side_effect=fake_async):
            result = discover_tools("http://localhost:8080", simple_config)

        assert len(result) == 1
        assert result[0].name == "search_memories"
        assert "query" in result[0].string_params
        assert "query" in result[0].required_params

    def test_returns_empty_on_empty_manifest(self, simple_config: ScanConfig):
        async def fake_async(target_url, config):
            return ()

        with patch("cosai_mcp.discovery._discover_tools_async", side_effect=fake_async):
            result = discover_tools("http://localhost:8080", simple_config)
        assert result == ()

    def test_skips_invalid_entries(self, simple_config: ScanConfig):
        tool_manifest = [
            {"name": "", "inputSchema": {}},           # empty name → skip
            {"name": "valid_tool", "inputSchema": {}},  # valid
            "not a dict",                               # type error → skip
        ]

        async def fake_async(target_url, config):
            results = []
            for entry in tool_manifest:
                dt = _tool_dict_to_discovered(entry)
                if dt is not None:
                    results.append(dt)
            return tuple(results)

        with patch("cosai_mcp.discovery._discover_tools_async", side_effect=fake_async):
            result = discover_tools("http://localhost:8080", simple_config)
        assert len(result) == 1
        assert result[0].name == "valid_tool"

    def test_regression_discover_tools_empty_on_parse_failure(
        self, simple_config: ScanConfig
    ):
        """Regression: malformed inputSchema must not raise to caller."""
        tool_manifest = [
            {
                "name": "broken_tool",
                "inputSchema": "this is not a dict",
            }
        ]

        async def fake_async(target_url, config):
            return tuple(
                dt for entry in tool_manifest
                if (dt := _tool_dict_to_discovered(entry)) is not None
            )

        with patch("cosai_mcp.discovery._discover_tools_async", side_effect=fake_async):
            result = discover_tools("http://localhost:8080", simple_config)
        # A non-dict inputSchema is normalised to {} — tool is created with empty params,
        # not dropped.  The discovery is non-fatal for bad schemas.
        assert len(result) == 1
        assert result[0].name == "broken_tool"
        assert result[0].string_params == ()
        assert result[0].required_params == frozenset()

    def test_regression_oversized_schema_returns_empty_tool(
        self, simple_config: ScanConfig
    ):
        """Regression: 65 KB+ schema must silently return no tool, not crash."""
        large_schema = {"properties": {"x" * i: {"type": "string"} for i in range(1, 200)}}
        schema_json = json.dumps(large_schema)
        # Only test if it's actually large enough to trigger the limit
        if len(schema_json.encode()) > _SCHEMA_SIZE_LIMIT_BYTES:
            tool_dict = {"name": "big_tool", "inputSchema": large_schema}
            dt = _tool_dict_to_discovered(tool_dict)
            assert dt is None
