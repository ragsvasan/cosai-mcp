"""ServerProfile frozen dataclass — schema-validated at import, no eval surface."""
from __future__ import annotations

import types
from dataclasses import dataclass


@dataclass(frozen=True)
class ServerProfile:
    """Immutable description of a known MCP server type.

    Attributes
    ----------
    name:
        Short identifier used with ``--profile``, e.g. ``"fastmcp"``.
    description:
        Human-readable summary shown by ``cosai profile list``.
    mcp_path:
        URL path of the MCP endpoint (default ``"/mcp"``).
    auth_header_format:
        Template for the ``Authorization`` header value.  ``{token}`` is
        substituted from ``--auth-token``.  ``None`` means no auth header.
    tool_name_map:
        Maps catalog placeholder tool names → real server tool names.
        Applied during template substitution so probes hit real endpoints.
    skip_categories:
        Categories that do not apply to this server type — filtered out
        before the prober loop so results stay meaningful.
    notes:
        Full detail shown by ``cosai profile info <name>``.
    """
    name: str
    description: str
    mcp_path: str
    auth_header_format: str | None
    tool_name_map: types.MappingProxyType
    skip_categories: frozenset
    notes: str

    def apply_tool_name(self, placeholder: str) -> str:
        """Return the real tool name for ``placeholder``, or ``placeholder`` unchanged."""
        return self.tool_name_map.get(placeholder, placeholder)  # type: ignore[no-any-return]
