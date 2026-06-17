"""CoSAI middleware stack — single entry point wiring all enforcement components."""
from __future__ import annotations

from typing import Any

from cosai_mcp.middleware.audit import AuditLogger
from cosai_mcp.middleware.authz import AuthzContext, AuthzEnforcer, ToolPolicy
from cosai_mcp.middleware.boundary import ResponseBoundaryGuard, ToolPoisoningDetector
from cosai_mcp.middleware.session import SessionManager
from cosai_mcp.middleware.supply_chain import SupplyChainEnforcer
from cosai_mcp.middleware.validation import ParameterValidator


class CoSAIStack:
    """Orchestrates all CoSAI middleware components for a single MCP server deployment.

    Enforces the check order on every request:
      validation (T3) → supply_chain (T11) → authz (T2) → session (T7) → audit (T12)

    Manifest-time (tools/list):
      supply_chain (T11) + tool poisoning detection (T4)

    Response-time (tools/call response):
      response boundary guard (T4/T9)

    All components are optional — omitting one silently skips that check.
    Provide the most restrictive configuration for production deployments.

    Usage::

        stack = CoSAIStack(
            supply_chain_enforcer=SupplyChainEnforcer(
                allowlist=frozenset({"search", "summarise"}),
            ),
            authz_enforcer=AuthzEnforcer(),
            session_manager=SessionManager(
                expected_issuer="https://auth.example.com",
                expected_audience="mcp-server",
            ),
        )

        # At startup after tools/list.
        stack.check_manifest(tools, session_id="ses-abc")

        # Per tools/call request.
        stack.check_tool_call(
            tool_name="search",
            arguments={"query": "hello"},
            authz_context=AuthzContext(
                scopes=frozenset(["read"]),
                has_user_claim=True,
            ),
            session_id="ses-abc",
        )
    """

    def __init__(
        self,
        *,
        parameter_validator: ParameterValidator | None = None,
        supply_chain_enforcer: SupplyChainEnforcer | None = None,
        authz_enforcer: AuthzEnforcer | None = None,
        session_manager: SessionManager | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.validator = parameter_validator or ParameterValidator(allow_unknown_tools=True)
        self.supply_chain = supply_chain_enforcer or SupplyChainEnforcer()
        self.authz = authz_enforcer or AuthzEnforcer(allow_unconfigured=True)
        self.session_manager = session_manager
        self.audit = audit_logger
        self._poisoning_detector = ToolPoisoningDetector()
        self._response_guard = ResponseBoundaryGuard()

    # -------------------------------------------------------------------------
    # Manifest-time checks — call once after tools/list
    # -------------------------------------------------------------------------

    def check_manifest(
        self,
        tools: list[dict[str, Any]],
        session_id: str = "startup",
    ) -> None:
        """Run T11 supply-chain and T4 tool-poisoning checks on a tools/list manifest.

        Raises ``SupplyChainError`` on allowlist violations.
        Logs poisoning findings to the audit log if one is configured.
        """
        # T11: allowlist + typosquat enforcement.
        self.supply_chain.check_tools(tools)

        # T4: prompt injection hidden in tool metadata.
        scan = self._poisoning_detector.scan(tools)
        if scan.flagged and self.audit:
            for finding in scan.findings:
                self.audit.log(
                    method="check_manifest:tool_poisoning",
                    session_id=session_id,
                    params={"location": finding.location, "pattern": finding.pattern},
                )

    # -------------------------------------------------------------------------
    # Per-request checks — call on every tools/call
    # -------------------------------------------------------------------------

    def check_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        authz_context: AuthzContext | None = None,
        session_id: str = "unknown",
        jwt_token: str | None = None,
        jwt_keyset: Any = None,
    ) -> None:
        """Run all per-request middleware checks.

        Enforcement order: validation (T3) → authz (T2) → session (T7) → audit (T12).

        Raises the first violation encountered.
        """
        # T3: parameter validation + injection guard.
        self.validator.validate(tool_name, arguments)

        # T2: RBAC + confused deputy.
        # If no context supplied, treat as unauthenticated machine call (no scopes,
        # no user claim) so user_only tools and scoped tools fail closed rather than
        # being silently skipped.
        effective_context = authz_context if authz_context is not None else AuthzContext(
            scopes=frozenset(), has_user_claim=False
        )
        self.authz.check(tool_name, effective_context)

        # T7: JWT bearer token validation.
        if jwt_token is not None and jwt_keyset is not None and self.session_manager is not None:
            self.session_manager.validate_token(jwt_token, jwt_keyset)

        # T12: audit every invocation.
        if self.audit is not None:
            self.audit.log(
                method="tools/call",
                session_id=session_id,
                params={"tool": tool_name, "args": arguments},
            )

    # -------------------------------------------------------------------------
    # Response checks — call after tool returns
    # -------------------------------------------------------------------------

    def check_response(self, body: str, session_id: str = "unknown") -> None:
        """Check a tool call response for indirect prompt injection (T4/T9).

        Logs findings to the audit log if one is configured.
        Does not raise — the caller decides whether to reject or redact.
        """
        scan = self._response_guard.check(body)
        if scan.flagged and self.audit is not None:
            for finding in scan.findings:
                self.audit.log(
                    method="check_response:injection",
                    session_id=session_id,
                    params={"location": finding.location, "severity": finding.severity},
                )


__all__ = [
    "CoSAIStack",
    "AuditLogger",
    "AuthzContext",
    "AuthzEnforcer",
    "ToolPolicy",
    "ResponseBoundaryGuard",
    "ToolPoisoningDetector",
    "SessionManager",
    "SupplyChainEnforcer",
    "ParameterValidator",
]
