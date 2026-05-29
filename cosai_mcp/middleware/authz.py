"""T2: Confused deputy prevention, per-tool RBAC."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ToolPolicy:
    """Static access policy for a single tool.

    Attributes:
        required_scopes: All scopes the caller must hold.
        user_only: True rejects server-to-server calls (no user claim in token).
    """
    required_scopes: frozenset[str]
    user_only: bool = False

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ToolPolicy":
        return cls(
            required_scopes=frozenset(d.get("required_scopes", [])),
            user_only=bool(d.get("user_only", False)),
        )


@dataclass(frozen=True)
class AuthzContext:
    """Describes the access context of a single request.

    Attributes:
        scopes: Token scopes the caller holds.
        has_user_claim: True if the token contains a ``sub`` user claim.
                        False for machine-to-machine calls.
    """
    scopes: frozenset[str]
    has_user_claim: bool

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AuthzContext":
        return cls(
            scopes=frozenset(d.get("scopes", [])),
            has_user_claim=bool(d.get("has_user_claim", False)),
        )


class ConfusedDeputyError(Exception):
    """Server-to-server caller attempted a user-only tool (T2 confused deputy)."""


class InsufficientScopeError(Exception):
    """Caller's scopes do not cover the tool's required scopes."""

    def __init__(self, tool_name: str, missing: frozenset[str]) -> None:
        super().__init__(
            f"Insufficient scope for tool '{tool_name}': "
            f"missing {sorted(missing)}"
        )
        self.tool_name = tool_name
        self.missing_scopes: frozenset[str] = missing


class AuthzEnforcer:
    """Enforce per-tool RBAC at dispatch time.

    Authorization decisions are deterministic server policy — never delegated
    to LLM judgment. Policies are registered statically at startup.

    Tools with no registered policy are denied by default unless
    ``allow_unconfigured=True``.
    """

    def __init__(self, allow_unconfigured: bool = False) -> None:
        self._policies: dict[str, ToolPolicy] = {}
        self._allow_unconfigured = allow_unconfigured

    def register_policy(self, tool_name: str, policy: ToolPolicy) -> None:
        """Register an access policy for *tool_name*."""
        self._policies[tool_name] = policy

    def register_policies(self, policies: dict[str, dict[str, Any]]) -> None:
        """Bulk-register policies from a config dict."""
        for tool_name, policy_dict in policies.items():
            self._policies[tool_name] = ToolPolicy.from_dict(policy_dict)

    def check(self, tool_name: str, context: AuthzContext) -> None:
        """Enforce the policy for *tool_name* against *context*.

        Raises:
            ``ConfusedDeputyError`` — tool is user_only but caller has no user claim.
            ``InsufficientScopeError`` — caller lacks required scopes.
            ``LookupError`` — no policy registered and allow_unconfigured is False.
        """
        if tool_name not in self._policies:
            if self._allow_unconfigured:
                return
            raise LookupError(
                f"No access policy registered for tool '{tool_name}'. "
                "Register a policy or set allow_unconfigured=True."
            )

        policy = self._policies[tool_name]

        # Confused deputy check — must precede scope check so the error is specific.
        if policy.user_only and not context.has_user_claim:
            raise ConfusedDeputyError(
                f"Tool '{tool_name}' is restricted to user-authenticated calls. "
                "Server-to-server requests (no user claim) are not permitted."
            )

        missing = policy.required_scopes - context.scopes
        if missing:
            raise InsufficientScopeError(tool_name, missing)
