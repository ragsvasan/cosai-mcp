"""cosai_mcp.profiles — server profile system for zero-config scanning."""
from cosai_mcp.profiles.builtin import BUILTIN_PROFILES
from cosai_mcp.profiles.loader import resolve_profile
from cosai_mcp.profiles.models import ServerProfile

__all__ = ["ServerProfile", "BUILTIN_PROFILES", "resolve_profile"]
