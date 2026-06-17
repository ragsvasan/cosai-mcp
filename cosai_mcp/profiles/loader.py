"""Profile loader — resolves name → ServerProfile via built-in registry or sandboxed file."""
from __future__ import annotations

import ast
import re
import types
from pathlib import Path
from typing import Any

from cosai_mcp.profiles.builtin import BUILTIN_PROFILES
from cosai_mcp.profiles.models import ServerProfile

# ---------------------------------------------------------------------------
# Sandboxed user-profile parsing
#
# User-written profiles MUST NOT execute arbitrary code.  We parse them with
# ast.literal_eval so only Python literals (str, int, bool, dict, list, tuple,
# frozenset, None) are accepted.  Any attempt to embed function calls, imports,
# or os.system() assignments is rejected with ValueError before any code runs.
# ---------------------------------------------------------------------------

_SAFE_AST_TYPES = (
    ast.Constant,     # str, int, float, bool, None, bytes
    ast.Dict,
    ast.List,
    ast.Tuple,
    ast.Set,
    ast.UnaryOp,      # negative numbers: -1
    ast.USub,
    # Context nodes — structural markers attached to collection literals;
    # they carry no semantics and cannot be exploited.
    ast.Load,
    ast.Store,
    ast.Del,
)

_PROFILE_FIELD_TYPES: dict[str, Any] = {
    "name": str,
    "description": str,
    "mcp_path": str,
    "auth_header_format": (str, type(None)),
    "tool_name_map": dict,
    "skip_categories": (frozenset, set, list),
    "notes": str,
}


def _assert_literal_only(node: ast.AST) -> None:
    """Raise ValueError if ``node`` contains any non-literal AST nodes.

    This is a belt-and-suspenders check on top of ast.literal_eval.  We walk
    the parsed AST before passing it to literal_eval to catch any parser
    changes that might expand what literal_eval accepts.
    """
    for child in ast.walk(node):
        if not isinstance(child, _SAFE_AST_TYPES):
            raise ValueError(
                f"User profile contains disallowed AST node {type(child).__name__!r}. "
                "Only Python literals are permitted (str, dict, list, set, None, numbers)."
            )


def _parse_user_profile(path: Path) -> ServerProfile:
    """Parse a user-written profile file and return a validated ServerProfile.

    Security contract
    -----------------
    - ``path`` must already be confirmed to exist within an allowed directory
      (caller's responsibility).
    - File content is parsed with ``ast.parse`` + AST whitelist check +
      ``ast.literal_eval`` — no ``exec``, no ``eval``, no ``import``.
    - Unknown fields in the profile dict are rejected, not ignored.
    - ``tool_name_map`` values are restricted to str→str mappings.
    - ``skip_categories`` coerced to frozenset[str].
    """
    source = path.read_text(encoding="utf-8")

    # We expect the file to contain exactly one assignment: profile = {...}
    try:
        tree = ast.parse(source, filename=str(path), mode="exec")
    except SyntaxError as exc:
        raise ValueError(f"User profile has syntax error: {exc}") from exc

    # Must be a single Assign statement at module level
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.Assign):
        raise ValueError(
            "User profile must contain exactly one assignment: profile = ServerProfile(...) "
            "or profile = {...}"
        )

    assign = tree.body[0]

    # Target must be the bare name "profile"
    if (
        len(assign.targets) != 1
        or not isinstance(assign.targets[0], ast.Name)
        or assign.targets[0].id != "profile"
    ):
        raise ValueError("User profile assignment target must be 'profile'.")

    # Walk the RHS and reject any non-literal nodes
    _assert_literal_only(assign.value)

    # Now safe to literal_eval — produces a plain Python dict
    try:
        raw = ast.literal_eval(assign.value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"User profile value is not a valid literal: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError("User profile 'profile' value must be a dict.")

    return _dict_to_profile(raw, source_path=path)


def _dict_to_profile(raw: dict, source_path: Path) -> ServerProfile:
    """Convert a plain dict to a validated ServerProfile."""
    unknown = set(raw) - set(_PROFILE_FIELD_TYPES)
    if unknown:
        raise ValueError(
            f"User profile {source_path} contains unknown fields: {sorted(unknown)}. "
            "Remove them or update the profile schema."
        )

    missing = set(_PROFILE_FIELD_TYPES) - set(raw)
    if missing:
        raise ValueError(
            f"User profile {source_path} is missing required fields: {sorted(missing)}."
        )

    # name — must be str, no path-traversal chars
    name = raw["name"]
    if not isinstance(name, str) or not name.replace("-", "").replace("_", "").isalnum():
        raise ValueError(
            f"Profile 'name' must be an alphanumeric string (hyphens/underscores allowed), "
            f"got {name!r}."
        )

    # mcp_path — must start with /
    mcp_path = raw["mcp_path"]
    if not isinstance(mcp_path, str) or not mcp_path.startswith("/"):
        raise ValueError(f"Profile 'mcp_path' must be a string starting with '/', got {mcp_path!r}.")  # noqa: E501

    # auth_header_format
    ahf = raw["auth_header_format"]
    if ahf is not None and not isinstance(ahf, str):
        raise ValueError("Profile 'auth_header_format' must be a str or null.")
    if isinstance(ahf, str):
        if "{token}" not in ahf:
            raise ValueError("Profile 'auth_header_format' must contain '{token}' placeholder.")
        if re.search(r"[\r\n\x00]", ahf):
            raise ValueError(
                "Profile 'auth_header_format' must not contain CR, LF, or null bytes "
                "(would enable HTTP header injection)."
            )

    # tool_name_map — str→str only
    tnm_raw = raw["tool_name_map"]
    if not isinstance(tnm_raw, dict):
        raise ValueError("Profile 'tool_name_map' must be a dict.")
    for k, v in tnm_raw.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise ValueError(
                f"Profile 'tool_name_map' must contain only str→str pairs; "
                f"got {k!r}→{v!r}."
            )

    # skip_categories — coerce to frozenset[str], normalised to uppercase
    sc_raw = raw["skip_categories"]
    if isinstance(sc_raw, (list, set, frozenset)):
        for item in sc_raw:
            if not isinstance(item, str):
                raise ValueError(f"Profile 'skip_categories' must contain only strings; got {item!r}.")  # noqa: E501
        skip_categories: frozenset = frozenset(item.upper() for item in sc_raw)
    else:
        raise ValueError("Profile 'skip_categories' must be a list or set.")

    return ServerProfile(
        name=name,
        description=str(raw["description"]),
        mcp_path=mcp_path,
        auth_header_format=ahf,
        tool_name_map=types.MappingProxyType(tnm_raw),
        skip_categories=skip_categories,
        notes=str(raw["notes"]),
    )


# ---------------------------------------------------------------------------
# Public resolution function
# ---------------------------------------------------------------------------

def resolve_profile(
    name: str,
    *,
    allow_custom: bool = False,
    project_root: Path | None = None,
) -> ServerProfile:
    """Resolve ``name`` to a ServerProfile.

    Resolution order
    ----------------
    1. Built-in profiles (exact name match, case-sensitive).
    2. ``<project_root>/.cosai/profiles/<name>.py`` — requires ``allow_custom=True``.
    3. ``~/.cosai/profiles/<name>.py`` — requires ``allow_custom=True``.

    Raises
    ------
    ValueError
        If no matching profile is found, or a custom profile fails validation,
        or ``allow_custom=False`` and a file-based profile would be needed.
    """
    # 1. Built-in
    if name in BUILTIN_PROFILES:
        return BUILTIN_PROFILES[name]  # type: ignore[no-any-return]

    # 2/3. User-written — gated by --allow-custom-profiles
    if not allow_custom:
        raise ValueError(
            f"Unknown profile {name!r}. "
            f"Available built-in profiles: {', '.join(sorted(BUILTIN_PROFILES))}. "
            "To use a project-local profile, add --allow-custom-profiles."
        )

    search_dirs: list[Path] = []
    if project_root is not None:
        search_dirs.append(project_root / ".cosai" / "profiles")
    search_dirs.append(Path.home() / ".cosai" / "profiles")

    for directory in search_dirs:
        candidate = directory / f"{name}.py"
        if candidate.exists():
            # Confirm the resolved path is actually inside the allowed directory
            # (guards against symlink-based traversal)
            try:
                candidate.resolve().relative_to(directory.resolve())
            except ValueError as exc:
                raise ValueError(
                    f"Profile file {candidate} resolves outside allowed directory {directory}."
                ) from exc
            return _parse_user_profile(candidate)

    searched = " and ".join(str(d) for d in search_dirs)
    raise ValueError(
        f"Profile {name!r} not found in built-ins or {searched}. "
        f"Available built-in profiles: {', '.join(sorted(BUILTIN_PROFILES))}."
    )
