"""Tool schema discovery — DiscoveredTool dataclass and live tools/list introspection.

Calls the target server's tools/list once at scan start and parses each tool's
inputSchema (JSON Schema draft-07 subset).  The result is a frozen tuple of
DiscoveredTool objects cached for the session lifetime.

Security constraints (non-negotiable):
- No code execution from schema — only reads "type", "required", "properties"
- Schemas larger than 64 KB are silently skipped (schema bombing protection)
- Property count capped at 64 per tool (memory amplification protection — prevents
  a malicious schema with 2800 single-char properties from allocating 280 MB in the
  oversize synthesis path: 2800 × 100 KB = 280 MB)
- Tool names validated against an allowlist regex; names with template markers or
  control characters are rejected at ingestion (prevents {{target_url}} injection
  into synthesized payloads via DiscoveredTool.name)
- Description length capped at 4096 chars (prevents large-body report injection)
- Manifest capped at 256 tools (prevents iteration DoS in the parent process)
- All container fields frozen (MappingProxyType / tuple / frozenset)
- Failures are non-fatal — returns empty tuple, never raises to caller
"""
from __future__ import annotations

import asyncio
import json
import re
import types
from dataclasses import dataclass

from cosai_mcp.config import ScanConfig

# ---------------------------------------------------------------------------
# Size / count guards
# ---------------------------------------------------------------------------

# Schema bombing protection — reject inputSchema before parsing
_SCHEMA_SIZE_LIMIT_BYTES: int = 64 * 1024  # 64 KB

# Max properties per inputSchema.  Bounds memory in synthesis:
# at most _MAX_PROPERTIES string params × 100 KB oversize value = 6.4 MB / tool.
_MAX_PROPERTIES: int = 64

# Description length cap — prevents large injection via tool description
_MAX_DESCRIPTION_LEN: int = 4096

# Cap on number of tools returned by tools/list — prevents iteration DoS
_MAX_TOOLS_PER_MANIFEST: int = 256

# ---------------------------------------------------------------------------
# Tool name validation
#
# A malicious server can return tool names that contain template markers
# ({{target_url}}, {{session_id}}) which would be expanded by
# substitute_probe_payload() in the probe subprocess, making the scanner
# send a request to a target-controlled URL.  Validate at ingestion.
#
# Allowed characters: letters, digits, underscore, hyphen, dot, slash.
# (slash is used by some MCP method names; included for forward compatibility)
# Max length: 256 chars (well beyond any real MCP tool name).
# ---------------------------------------------------------------------------

_SAFE_TOOL_NAME_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,255}$")


def _validate_tool_name(name: str) -> bool:
    """Return True iff name is a safe MCP tool identifier.

    Rejects any name containing template markers ({{...}}), control characters,
    non-ASCII, or characters outside the allowlist.
    """
    return bool(_SAFE_TOOL_NAME_RE.match(name))


@dataclass(frozen=True)
class DiscoveredTool:
    """Frozen snapshot of a single tool's schema from a tools/list response.

    Attributes
    ----------
    name:
        The tool's exact name as returned by tools/list.  Validated against
        _SAFE_TOOL_NAME_RE at discovery time — guaranteed to contain no
        template markers or control characters.
    description:
        Human-readable description string, capped at _MAX_DESCRIPTION_LEN chars.
    input_schema:
        The raw inputSchema dict, frozen as MappingProxyType.
    string_params:
        Top-level parameters with JSON Schema type "string".  These are the
        primary injection targets for adversarial synthesis.
    numeric_params:
        Top-level parameters with type "integer" or "number".
    boolean_params:
        Top-level parameters with type "boolean".
    required_params:
        The set of parameter names listed in the schema's "required" array.
    """

    name: str
    description: str
    input_schema: types.MappingProxyType
    string_params: tuple[str, ...]
    numeric_params: tuple[str, ...]
    boolean_params: tuple[str, ...]
    required_params: frozenset[str]


# ---------------------------------------------------------------------------
# Internal schema parsing helpers
# ---------------------------------------------------------------------------

def _parse_input_schema(
    schema: object,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], frozenset[str]]:
    """Extract parameter names by type from a JSON Schema properties dict.

    Returns (string_params, numeric_params, boolean_params, required_params).
    Only top-level properties are inspected — nested objects are out of scope.
    Property count is capped at _MAX_PROPERTIES before iteration.
    Returns empty containers on any parse failure.
    """
    if not isinstance(schema, dict):
        return (), (), (), frozenset()

    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return (), (), (), frozenset()

    # Cap property count before iteration — prevents oversize synthesis DoS.
    # A schema with 2800 single-char string properties (all within 64 KB) would
    # cause synthesis to allocate 2800 × 100 KB = 280 MB in the parent process.
    if len(properties) > _MAX_PROPERTIES:
        properties = dict(list(properties.items())[:_MAX_PROPERTIES])

    required_raw = schema.get("required", [])
    required_params: frozenset[str] = (
        frozenset(r for r in required_raw if isinstance(r, str))
        if isinstance(required_raw, list)
        else frozenset()
    )

    string_params: list[str] = []
    numeric_params: list[str] = []
    boolean_params: list[str] = []

    for name, prop in properties.items():
        if not isinstance(name, str) or not isinstance(prop, dict):
            continue
        typ = prop.get("type", "")
        if typ == "string":
            string_params.append(name)
        elif typ in ("integer", "number"):
            numeric_params.append(name)
        elif typ == "boolean":
            boolean_params.append(name)

    return tuple(string_params), tuple(numeric_params), tuple(boolean_params), required_params


def _tool_dict_to_discovered(tool_dict: object) -> DiscoveredTool | None:
    """Convert a single tools/list entry dict to a DiscoveredTool.

    Returns None on any parse failure — callers must handle None gracefully.

    Security checks applied at ingestion:
    - Tool name must match _SAFE_TOOL_NAME_RE (no template markers, no control chars)
    - inputSchema rejected if serialized size exceeds 64 KB
    - Properties count capped at _MAX_PROPERTIES (via _parse_input_schema)
    - Description capped at _MAX_DESCRIPTION_LEN
    """
    if not isinstance(tool_dict, dict):
        return None
    try:
        name = tool_dict.get("name", "")
        if not isinstance(name, str) or not name:
            return None

        # Validate tool name against allowlist (Sonnet P0 / Opus F3 fix).
        # Rejects names containing {{...}} which would be expanded by the template
        # substitution engine and could redirect probes to attacker-controlled URLs.
        if not _validate_tool_name(name):
            return None

        # Cap description to prevent large-body injection into reports (Opus F2)
        raw_desc = tool_dict.get("description") or ""
        description = str(raw_desc)[:_MAX_DESCRIPTION_LEN]

        raw_schema = tool_dict.get("inputSchema") or {}
        if not isinstance(raw_schema, dict):
            raw_schema = {}

        # Schema bombing protection — reject before parsing (Opus F1 layer 1)
        schema_bytes = json.dumps(raw_schema).encode()
        if len(schema_bytes) > _SCHEMA_SIZE_LIMIT_BYTES:
            return None  # silently skip oversized schema

        string_p, numeric_p, boolean_p, required_p = _parse_input_schema(raw_schema)

        return DiscoveredTool(
            name=name,
            description=description,
            input_schema=types.MappingProxyType(raw_schema),
            string_params=string_p,
            numeric_params=numeric_p,
            boolean_params=boolean_p,
            required_params=required_p,
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Async discovery — creates an ephemeral session
# ---------------------------------------------------------------------------

async def _discover_tools_async(
    target_url: str,
    config: ScanConfig,
) -> tuple[DiscoveredTool, ...]:
    """Open an ephemeral session, call tools/list, parse inputSchema for each tool.

    Returns empty tuple on any network or parse failure.
    Caps the manifest at _MAX_TOOLS_PER_MANIFEST to prevent iteration DoS.
    """
    from cosai_mcp.transport.streamable_http import StreamableHTTPTransport
    from cosai_mcp.session import MCPSession

    transport = StreamableHTTPTransport(target_url, config)
    try:
        await transport.connect()
        session = MCPSession(transport, config)
        info = await session.start()
        tool_list = info.tool_manifest or []

        # Cap manifest size (Opus F1 / F3 — prevents iteration DoS in parent)
        if len(tool_list) > _MAX_TOOLS_PER_MANIFEST:
            tool_list = tool_list[:_MAX_TOOLS_PER_MANIFEST]

        discovered: list[DiscoveredTool] = []
        for entry in tool_list:
            dt = _tool_dict_to_discovered(entry)
            if dt is not None:
                discovered.append(dt)
        return tuple(discovered)
    except Exception:
        return ()
    finally:
        try:
            await transport.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Public synchronous API
# ---------------------------------------------------------------------------

def discover_tools(target_url: str, config: ScanConfig) -> tuple[DiscoveredTool, ...]:
    """Synchronously discover all tools from a live MCP server.

    Opens an ephemeral HTTP session, calls tools/list, and parses each tool's
    inputSchema.  Returns a frozen tuple of DiscoveredTool objects — one per
    tool that could be parsed successfully.

    Returns empty tuple on any failure (network error, parse error, handshake
    failure).  This function is intentionally non-fatal: discovery failure must
    not abort the scan; it just means adaptive synthesis is unavailable.

    Parameters
    ----------
    target_url:
        Base URL of the MCP server (e.g. "http://localhost:8080").
    config:
        ScanConfig for auth, MCP path, and network constraints.
    """
    try:
        return asyncio.run(_discover_tools_async(target_url, config))
    except Exception:
        return ()
