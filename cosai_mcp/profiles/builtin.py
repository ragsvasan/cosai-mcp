"""Built-in server profiles — frozen at import, zero eval surface."""
from __future__ import annotations

import types

from cosai_mcp.profiles.models import ServerProfile

# ---------------------------------------------------------------------------
# Profile definitions
# ---------------------------------------------------------------------------

_FASTMCP = ServerProfile(
    name="fastmcp",
    description="FastMCP framework server — unauthenticated, standard MCP path.",
    mcp_path="/mcp",
    auth_header_format=None,
    tool_name_map=types.MappingProxyType({"ping": "ping", "echo": "echo"}),
    skip_categories=frozenset(),
    notes=(
        "Use for servers built with the FastMCP Python framework. "
        "No auth header is sent. Tool name map seeds common FastMCP defaults."
    ),
)

_MNEMO = ServerProfile(
    name="mnemo",
    description="Mnemo MCP memory server — Bearer auth, trailing-slash path, no SSRF surface.",
    mcp_path="/mcp/",
    auth_header_format="Bearer {token}",
    tool_name_map=types.MappingProxyType({
        "admin_delete": "purge_records",
        "read_file": "search_memories",
        "echo": "ping",
    }),
    skip_categories=frozenset({"T8"}),
    notes=(
        "Use for Mnemo (cosai-mnemo) servers. Requires --auth-token. "
        "T8 (Network Binding) skipped — Mnemo has no external fetch surface. "
        "MCP path uses trailing slash as required by the Mnemo router."
    ),
)

_OPENAI_PLUGIN = ServerProfile(
    name="openai-plugin",
    description="OpenAI plugin–style MCP adapter — Bearer auth, no session concept.",
    mcp_path="/mcp",
    auth_header_format="Bearer {token}",
    tool_name_map=types.MappingProxyType({}),
    skip_categories=frozenset({"T7"}),
    notes=(
        "Use for stateless OpenAI-plugin–style MCP adapters. "
        "T7 (Session Security) skipped — these servers are stateless by design."
    ),
)

_GENERIC_AUTH = ServerProfile(
    name="generic-auth",
    description="Generic authenticated MCP server — Bearer auth, standard path.",
    mcp_path="/mcp",
    auth_header_format="Bearer {token}",
    tool_name_map=types.MappingProxyType({}),
    skip_categories=frozenset(),
    notes=(
        "Use for any MCP server that requires a Bearer token. "
        "No tool name mappings — relies on adaptive discovery."
    ),
)

_GENERIC_NOAUTH = ServerProfile(
    name="generic-noauth",
    description="Generic unauthenticated MCP server — no auth, standard path.",
    mcp_path="/mcp",
    auth_header_format=None,
    tool_name_map=types.MappingProxyType({}),
    skip_categories=frozenset({"T1"}),
    notes=(
        "Use for internal or development MCP servers with no authentication. "
        "T1 (Authentication) skipped — auth is not applicable by design."
    ),
)

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

BUILTIN_PROFILES: types.MappingProxyType = types.MappingProxyType({
    p.name: p for p in [
        _FASTMCP,
        _MNEMO,
        _OPENAI_PLUGIN,
        _GENERIC_AUTH,
        _GENERIC_NOAUTH,
    ]
})
