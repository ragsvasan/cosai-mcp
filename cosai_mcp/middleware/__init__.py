"""CoSAI middleware stack — single entry point wiring all enforcement components."""
from __future__ import annotations

from typing import Any

from cosai_mcp.middleware.audit import AuditLogger
from cosai_mcp.middleware.authz import AuthzContext, AuthzEnforcer, ToolPolicy
from cosai_mcp.middleware.boundary import ResponseBoundaryGuard, ToolPoisoningDetector
from cosai_mcp.middleware.session import SessionManager
from cosai_mcp.middleware.supply_chain import SupplyChainEnforcer
from cosai_mcp.middleware.trust import SVRTrustGate
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
        svr_gate: SVRTrustGate | None = None,
    ) -> None:
        self.validator = parameter_validator or ParameterValidator(allow_unknown_tools=True)
        self.supply_chain = supply_chain_enforcer or SupplyChainEnforcer()
        self.authz = authz_enforcer or AuthzEnforcer(allow_unconfigured=True)
        self.session_manager = session_manager
        self.audit = audit_logger
        self._poisoning_detector = ToolPoisoningDetector()
        self._response_guard = ResponseBoundaryGuard()
        self._svr_gate = svr_gate

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

    def check_response(
        self,
        body: str,
        session_id: str = "unknown",
        svr_receipt: dict[str, Any] | None = None,
    ) -> None:
        """Check a tool call response for indirect prompt injection (T4/T9).

        Logs findings to the audit log if one is configured.
        Does not raise — the caller decides whether to reject or redact.

        Parameters
        ----------
        body:
            The raw text content of the tool call response.
        session_id:
            The MCP session identifier.
        svr_receipt:
            Optional Structural Verification Receipt dict attached to the
            response.  When ``svr_gate`` is configured on this stack, the
            gate runs regardless — a missing receipt counts as a gate
            failure and is logged to audit.
        """
        # T4/T9: injection pattern scan
        scan = self._response_guard.check(body)
        if scan.flagged and self.audit is not None:
            for finding in scan.findings:
                self.audit.log(
                    method="check_response:injection",
                    session_id=session_id,
                    params={"location": finding.location, "severity": finding.severity},
                )

        # T9: SVR structural verification gate (only runs when gate is configured)
        if self._svr_gate is not None:
            result = self._svr_gate.verify_before_chain(svr_receipt, body)
            if not result.verified and self.audit is not None:
                self.audit.log(
                    method="check_response:svr_gate",
                    session_id=session_id,
                    params={
                        "receipt_id": result.receipt_id or "",
                        "issues": list(result.issues[:3]),
                    },
                )

    # -------------------------------------------------------------------------
    # Resource-read audit hook — closes T12 resources/read gap
    # -------------------------------------------------------------------------

    def check_resource_read(
        self,
        uri: str,
        session_id: str = "unknown",
        parent_id: str | None = None,
    ) -> str | None:
        """Log a resources/read call for T12 audit completeness.

        Parameters
        ----------
        uri:
            The resource URI being read (e.g. ``"file:///workspace/data.csv"``).
        session_id:
            The MCP session identifier.
        parent_id:
            entry_id of the parent tool call (for DAG edge construction).
            Passing the tool-call's audit entry_id here links the resource
            read to the tool invocation that triggered it, closing the
            ``prompt_hash → context_refs → tool_invocation`` causal chain
            identified as a gap in THREAT_CATALOG.md T12.

        Returns
        -------
        str or None
            The audit entry_id if logged, ``None`` if no audit logger is
            configured.  The returned id can be used as ``parent_id`` for
            subsequent child calls.
        """
        if self.audit is not None:
            return self.audit.log(
                method="resources/read",
                session_id=session_id,
                params={"uri": uri},
                parent_id=parent_id,
            )
        return None


__all__ = ["CoSAIStack"]
