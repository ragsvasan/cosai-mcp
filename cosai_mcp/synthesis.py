"""Adversarial probe payload synthesis.

Given a DiscoveredTool and a threat pattern, produces a tools/call payload
whose "arguments" dict conforms to the tool's real inputSchema — with an
adversarial value injected into the appropriate parameter.

This eliminates schema-mismatch INCONCLUSIVE results: instead of sending
{"cmd": "; cat /etc/passwd"} to a server that expects {"query": "..."}, we
send {"query": "; cat /etc/passwd"} which actually reaches the security logic.

Security constraints (non-negotiable):
- Pure function — no I/O, no subprocess, no network
- No "{{" allowed in the synthesized payload after expansion (template escape guard)
- Falls back to catalog payload when no suitable parameter exists
- All returned containers are frozen (MappingProxyType)
"""
from __future__ import annotations

import types
from typing import Any, Mapping

from cosai_mcp.discovery import DiscoveredTool

# ---------------------------------------------------------------------------
# Template escape guard constant
# ---------------------------------------------------------------------------

_TEMPLATE_ESCAPE = "{{"

# ---------------------------------------------------------------------------
# Adversarial value registry per pattern
# ---------------------------------------------------------------------------

# Fixed adversarial values for injection and traversal patterns.
_INJECTION_VALUE: str = "; cat /etc/passwd"
_TRAVERSAL_VALUE: str = "../../etc/passwd"
_OVERSIZE_VALUE: str = "A" * 100_000

# Parameter name substrings that suggest path/file-related inputs (case-insensitive)
_PATH_HINTS: tuple[str, ...] = ("path", "file", "dir", "url", "location", "dest", "src")

# Valid threat pattern values
_KNOWN_PATTERNS: frozenset[str] = frozenset(
    {"injection", "traversal", "oversize", "replay", "unknown_tool"}
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _safe_minimal_value(param_name: str, tool: DiscoveredTool) -> Any:
    """Return a type-appropriate safe minimal value for a required parameter."""
    if param_name in tool.string_params:
        return ""
    if param_name in tool.numeric_params:
        return 0
    if param_name in tool.boolean_params:
        return False
    return ""  # conservative default for unknown types


def _pick_traversal_param(tool: DiscoveredTool) -> str | None:
    """Return the best string param for a path-traversal injection.

    Prefers params with path-related names (path, file, dir, url, …).
    Falls back to the first string param when no path-hinted param exists.
    Returns None if the tool has no string parameters.
    """
    for param in tool.string_params:
        if any(hint in param.lower() for hint in _PATH_HINTS):
            return param
    return tool.string_params[0] if tool.string_params else None


def _extract_catalog_adversarial_value(catalog_payload: Mapping[str, Any]) -> str | None:
    """Extract the adversarial string value from a catalog probe payload.

    For tools/call payloads the catalog stores the adversarial value inside
    the "arguments" dict.  Returns the first non-empty string argument value
    that does not itself contain a template marker.
    """
    arguments = catalog_payload.get("arguments", {})
    if not isinstance(arguments, dict):
        return None
    for v in arguments.values():
        if isinstance(v, str) and v and _TEMPLATE_ESCAPE not in v:
            return v
    return None


def _check_template_escape(payload: dict[str, Any]) -> None:
    """Raise ValueError if any string value contains '{{' after synthesis.

    This guards against a case where a catalog value or a synthesized value
    contains an unresolved template variable, which would allow a crafted
    catalog entry to inject template markers into probe payloads.
    """
    for value in payload.values():
        if isinstance(value, str) and _TEMPLATE_ESCAPE in value:
            raise ValueError(
                f"Synthesized payload contains template escape {_TEMPLATE_ESCAPE!r} "
                f"in value {value[:80]!r}. Aborting synthesis."
            )


def _fill_required_params(
    args: dict[str, Any],
    tool: DiscoveredTool,
    skip: str | None = None,
) -> None:
    """Fill in safe minimal values for required params not already in args."""
    for param in tool.required_params:
        if param != skip and param not in args:
            args[param] = _safe_minimal_value(param, tool)


# ---------------------------------------------------------------------------
# Public synthesis API
# ---------------------------------------------------------------------------

def synthesize_probe_payload(
    tool: DiscoveredTool,
    threat_pattern: str,
    catalog_payload: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Synthesize a probe payload that conforms to a discovered tool's inputSchema.

    Injects an adversarial value into a parameter slot that the server will
    actually accept, replacing fictional parameter names from the catalog.

    Parameters
    ----------
    tool:
        The DiscoveredTool whose inputSchema guides synthesis.
    threat_pattern:
        One of "injection", "traversal", "oversize", "replay", "unknown_tool".
        Controls which adversarial value is injected and where.
    catalog_payload:
        The original catalog probe payload (full dict including "name" and
        "arguments" for tools/call probes).  Used as the adversarial value
        source for "injection" and as fallback when synthesis is impossible.

    Returns
    -------
    An immutable ``MappingProxyType`` ready for use as a probe payload.
    For tools/call probes the returned mapping has the shape
    ``{"name": tool.name, "arguments": {synthesized_args}}``.

    Raises
    ------
    ValueError
        If the synthesized payload contains ``{{`` after expansion — this
        indicates an unsafe template variable in synthesized content.
    """
    # "replay" and "unknown_tool" are structural, not content-injection patterns.
    if threat_pattern == "replay":
        # Return catalog payload verbatim — idempotency / replay test
        return types.MappingProxyType(dict(catalog_payload))

    if threat_pattern == "unknown_tool":
        # Substitute a tool name guaranteed to be absent from the manifest
        return types.MappingProxyType(
            {"name": "cosai_probe_nonexistent_tool", "arguments": {}}
        )

    # --- content-injection patterns ---

    if threat_pattern == "oversize":
        if not tool.string_params:
            # No string params to bloat — fall back to catalog
            return types.MappingProxyType(dict(catalog_payload))
        args: dict[str, Any] = {p: _OVERSIZE_VALUE for p in tool.string_params}
        _fill_required_params(args, tool)
        _check_template_escape(args)
        return types.MappingProxyType({"name": tool.name, "arguments": args})

    if threat_pattern == "traversal":
        target_param = _pick_traversal_param(tool)
        if target_param is None:
            return types.MappingProxyType(dict(catalog_payload))
        adv_value = _TRAVERSAL_VALUE
    else:
        # "injection" (default) — take adversarial value from catalog payload
        target_param = tool.string_params[0] if tool.string_params else None
        if target_param is None:
            # No string param to inject into — preserve catalog behavior
            return types.MappingProxyType(dict(catalog_payload))
        adv_value = _extract_catalog_adversarial_value(catalog_payload) or _INJECTION_VALUE

    # Validate: adversarial value must not contain template markers
    if _TEMPLATE_ESCAPE in adv_value:
        raise ValueError(
            f"Adversarial value contains template escape {_TEMPLATE_ESCAPE!r}: "
            f"{adv_value[:80]!r}"
        )

    args = {target_param: adv_value}
    _fill_required_params(args, tool, skip=target_param)
    _check_template_escape(args)

    return types.MappingProxyType({"name": tool.name, "arguments": args})


# ---------------------------------------------------------------------------
# Pattern derivation helper (used by ProbeRunner)
# ---------------------------------------------------------------------------

def threat_pattern_from_category(category: str) -> str:
    """Derive a synthesis threat pattern from a CoSAI threat category string.

    Used by ProbeRunner to select the right synthesis strategy for a probe
    retry without requiring a pattern field in the catalog.

    Returns one of: "injection", "traversal", "oversize", "unknown_tool".
    Defaults to "injection" for unknown or unhandled categories.
    """
    cat = category.upper().lstrip("T")
    _map: dict[str, str] = {
        "3":  "injection",
        "4":  "injection",
        "8":  "traversal",
        "10": "oversize",
        "11": "unknown_tool",
    }
    return _map.get(cat, "injection")
