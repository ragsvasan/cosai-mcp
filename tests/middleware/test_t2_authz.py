"""Tests for T2 middleware: AuthzEnforcer — RBAC and confused deputy prevention."""
from __future__ import annotations

import pytest

from cosai_mcp.middleware.authz import (
    AuthzContext,
    AuthzEnforcer,
    ConfusedDeputyError,
    InsufficientScopeError,
    ToolPolicy,
)


def _user_context(*scopes: str) -> AuthzContext:
    return AuthzContext(scopes=frozenset(scopes), has_user_claim=True)


def _machine_context(*scopes: str) -> AuthzContext:
    return AuthzContext(scopes=frozenset(scopes), has_user_claim=False)


# ===========================================================================
# ToolPolicy
# ===========================================================================

class TestToolPolicy:

    def test_from_dict(self):
        p = ToolPolicy.from_dict({"required_scopes": ["read", "write"], "user_only": True})
        assert p.required_scopes == frozenset({"read", "write"})
        assert p.user_only is True

    def test_defaults(self):
        p = ToolPolicy.from_dict({})
        assert p.required_scopes == frozenset()
        assert p.user_only is False


# ===========================================================================
# AuthzEnforcer
# ===========================================================================

class TestAuthzEnforcer:

    def _enforcer_with_tool(
        self,
        tool_name: str = "search",
        required_scopes: list[str] | None = None,
        user_only: bool = False,
    ) -> AuthzEnforcer:
        enforcer = AuthzEnforcer()
        enforcer.register_policy(
            tool_name,
            ToolPolicy(
                required_scopes=frozenset(required_scopes or []),
                user_only=user_only,
            ),
        )
        return enforcer

    # --- Passing cases ---

    def test_user_with_all_scopes_passes(self):
        enforcer = self._enforcer_with_tool(required_scopes=["read", "write"])
        enforcer.check("search", _user_context("read", "write"))  # no exception

    def test_user_with_extra_scopes_passes(self):
        enforcer = self._enforcer_with_tool(required_scopes=["read"])
        enforcer.check("search", _user_context("read", "write", "admin"))

    def test_no_scopes_required_user_passes(self):
        enforcer = self._enforcer_with_tool(required_scopes=[])
        enforcer.check("search", _user_context())

    def test_machine_caller_non_user_only_tool_passes(self):
        enforcer = self._enforcer_with_tool(required_scopes=["api"], user_only=False)
        enforcer.check("search", _machine_context("api"))

    # --- Confused deputy ---

    def test_machine_caller_user_only_tool_raises(self):
        """T2 gate fires from check() entry point for confused deputy."""
        enforcer = self._enforcer_with_tool(user_only=True)
        with pytest.raises(ConfusedDeputyError):
            enforcer.check("search", _machine_context())

    def test_confused_deputy_check_precedes_scope_check(self):
        """user_only violation is raised even when scopes are also missing."""
        enforcer = self._enforcer_with_tool(
            required_scopes=["admin"],
            user_only=True,
        )
        with pytest.raises(ConfusedDeputyError):
            enforcer.check("search", _machine_context())  # no scopes, no user claim

    # --- Scope violations ---

    def test_missing_single_scope_raises(self):
        enforcer = self._enforcer_with_tool(required_scopes=["write"])
        with pytest.raises(InsufficientScopeError) as exc_info:
            enforcer.check("search", _user_context("read"))
        assert "write" in exc_info.value.missing_scopes

    def test_missing_multiple_scopes_raises(self):
        enforcer = self._enforcer_with_tool(required_scopes=["read", "write", "delete"])
        with pytest.raises(InsufficientScopeError) as exc_info:
            enforcer.check("search", _user_context())
        assert exc_info.value.missing_scopes == frozenset({"read", "write", "delete"})

    # --- Unknown tool ---

    def test_unknown_tool_raises_by_default(self):
        enforcer = AuthzEnforcer()
        with pytest.raises(LookupError, match="No access policy"):
            enforcer.check("unlisted", _user_context("read"))

    def test_unknown_tool_allowed_when_flag_set(self):
        enforcer = AuthzEnforcer(allow_unconfigured=True)
        enforcer.check("unlisted", _user_context())  # no exception

    # --- Bulk registration ---

    def test_register_policies_bulk(self):
        enforcer = AuthzEnforcer()
        enforcer.register_policies({
            "search": {"required_scopes": ["read"]},
            "delete": {"required_scopes": ["write"], "user_only": True},
        })
        enforcer.check("search", _user_context("read"))  # passes
        with pytest.raises(ConfusedDeputyError):
            enforcer.check("delete", _machine_context("write"))  # blocked

    def test_regression_authorization_never_delegated_to_llm(self):
        """Policy check is deterministic — there is no 'maybe' path in check()."""
        enforcer = self._enforcer_with_tool(required_scopes=["admin"])
        # Even with a context that looks admin-ish by name, the scope must be explicit.
        ctx = AuthzContext(scopes=frozenset({"admin_like"}), has_user_claim=True)
        with pytest.raises(InsufficientScopeError):
            enforcer.check("search", ctx)
