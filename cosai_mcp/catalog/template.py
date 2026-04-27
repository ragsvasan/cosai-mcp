"""Safe template substitution operating on parsed Python dicts.

Rules:
- Substitution happens on the parsed dict BEFORE any JSON serialisation.
- Only the allowlisted variables may appear in templates.
- After substitution every string value is scanned for '{{'; any found →
  TemplateInjectionError (prevents double-expansion and blind injection).
- Probe destination (target host) is NOT templatable here.
"""
from __future__ import annotations

from typing import Any

from cosai_mcp.exceptions import TemplateInjectionError, UnknownVariableError

# Closed allowlist — no other variables accepted
_ALLOWED_VARS: frozenset[str] = frozenset(
    {"{{target_url}}", "{{session_id}}", "{{tool_name}}"}
)


def _find_templates(value: str) -> list[str]:
    """Return all {{...}} tokens found in a string."""
    tokens: list[str] = []
    start = 0
    while True:
        open_pos = value.find("{{", start)
        if open_pos == -1:
            break
        close_pos = value.find("}}", open_pos + 2)
        if close_pos == -1:
            break
        tokens.append(value[open_pos : close_pos + 2])
        start = close_pos + 2
    return tokens


def _substitute_str(s: str, variables: dict[str, str]) -> str:
    """Substitute template variables in a single string."""
    # Validate all tokens before substituting
    for token in _find_templates(s):
        if token not in _ALLOWED_VARS:
            raise UnknownVariableError(
                f"Template variable {token!r} is not in the allowed variable list: "
                f"{sorted(_ALLOWED_VARS)}"
            )

    # Validate variable values: double-brace sequences (template syntax) are forbidden.
    # If a value contained "{{session_id}}" and session_id was also in scope,
    # sequential str.replace would expand it in the next iteration.
    # Single braces (e.g. JSON content) are allowed — only {{ or }} are rejected.
    for bare_key, val in variables.items():
        if "{{" in val or "}}" in val:
            raise TemplateInjectionError(
                f"Template variable value for {bare_key!r} contains '{{{{' or '}}}}' — "
                f"injection rejected: {val!r}"
            )

    result = s
    for bare_key, replacement in variables.items():
        token = "{{" + bare_key + "}}"
        result = result.replace(token, replacement)

    # Post-substitution scan: no {{ may remain (defense-in-depth)
    if "{{" in result:
        raise TemplateInjectionError(
            f"Template injection detected: substituted value still contains '{{{{': {result!r}"
        )
    return result


def _substitute_value(value: Any, variables: dict[str, str]) -> Any:
    """Recursively substitute template variables in a value (dict / list / str)."""
    if isinstance(value, str):
        return _substitute_str(value, variables)
    if isinstance(value, dict):
        return {k: _substitute_value(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute_value(item, variables) for item in value]
    # int, bool, None, etc — pass through unchanged
    return value


def substitute_probe_payload(
    payload: dict[str, Any],
    variables: dict[str, str],
) -> dict[str, Any]:
    """Substitute template variables in a probe payload dict.

    Parameters
    ----------
    payload:
        The probe payload dict (parsed JSON, not serialised).
    variables:
        Mapping of variable name (without braces) to replacement value.
        E.g. ``{"tool_name": "list_files"}``.

    Returns
    -------
    dict
        New dict with substitutions applied.

    Raises
    ------
    UnknownVariableError
        A ``{{...}}`` token in the payload is not in the allowed variable list.
    TemplateInjectionError
        After substitution, a value still contains ``{{``.
    """
    # Normalise: caller passes bare names like "tool_name"; wrap to "{{tool_name}}"
    # but we store and match as "{{tool_name}}" internally, so build a flat map
    # keyed by the full token for _substitute_str.
    normalised: dict[str, str] = {}
    for key, val in variables.items():
        # Accept both "tool_name" and "{{tool_name}}"
        bare_key = key.strip("{}")
        normalised[bare_key] = val

    return _substitute_value(payload, normalised)  # type: ignore[return-value]
