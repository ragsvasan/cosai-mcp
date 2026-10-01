"""CoSAI middleware stack — single entry point wiring all enforcement components."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from cosai_mcp.middleware.audit import AuditLogger
from cosai_mcp.middleware.authz import AuthzContext, AuthzEnforcer, ToolPolicy
from cosai_mcp.middleware.boundary import ResponseBoundaryGuard, ToolPoisoningDetector
from cosai_mcp.middleware.request_meta import (
    AuthenticatedPrincipal,
    HeaderInput,
    MetaTrustError,
    RequestMetadataError,
    reconcile_meta,
    validate_request_metadata,
)
from cosai_mcp.middleware.session import SessionManager
from cosai_mcp.middleware.state import (
    HandleError,
    HandleRegistry,
    RequestStateSealer,
    SpentStore,
    StateVerificationError,
    request_fingerprint,
)
from cosai_mcp.middleware.supply_chain import SupplyChainEnforcer
from cosai_mcp.middleware.validation import ParameterValidator

_AUDIT_LABELS = {-32020: "header_mismatch", -32022: "unsupported_version",
                 -32602: "invalid_params", -32600: "invalid_request"}


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
    # MCP 2026-07-28 envelope check — call FIRST on every Streamable HTTP request
    # -------------------------------------------------------------------------

    def check_request_envelope(
        self,
        headers: HeaderInput,
        body: Any,
        principal: AuthenticatedPrincipal,
        *,
        tool_schemas: Mapping[str, Any] | None = None,
        allowed_meta_keys: Iterable[str] | None = None,
        wsgi_environ: bool = False,
        session_id: str = "stateless",
    ) -> str:
        """Validate a modern request before routing, authorization, caching, or
        execution (CoSAI v2.0 TN-04, SD-02).

        1. ``MCP-Protocol-Version`` / ``Mcp-Method`` / ``Mcp-Name`` /
           ``Mcp-Param-*`` headers must agree with the body (-32020) and the
           version must be supported (-32022). Pass *tool_schemas* on
           ``tools/call`` or any ``Mcp-Param-*`` header is rejected.
        2. ``_meta`` identity/role claims must not conflict with *principal*
           and cannot expand its scopes.

        Only two rejections are legacy-fallback signals: -32602 with
        ``reason == "missing_meta"`` and -32600 with ``reason == "batch"``.
        By then the ``_meta`` of every message (params, result, error.data)
        has been reconciled. -32600 ``not_a_request`` / ``invalid_request``
        are never fallback-eligible.

        Failures are audited as security-relevant events — a fixed reason
        label, the authenticated subject, and offending key names; never
        claimed values — and re-raised. Returns the protocol version.
        """
        # Identity reconciliation runs FIRST and for every era: a legacy
        # (pre-2026-07-28) request is rejected below with -32602
        # ``missing_meta``, and a dual-era server that falls back on that error
        # must not thereby skip SD-02.
        def _log(keys: tuple[str, ...]) -> None:
            if self.audit is not None:
                self.audit.log(method="check_request_envelope:meta_mismatch",
                               session_id=session_id,
                               params={"keys": list(keys), "principal": principal.subject},
                               event={"principal": principal.subject, "keys": list(keys)})

        if not isinstance(body, (Mapping, list, tuple)):
            # Raw bytes/str (unparsed) would skip reconciliation; this is a
            # caller bug, never a legacy-fallback signal.
            if self.audit is not None:
                self.audit.log(method="check_request_envelope:invalid_body",
                               session_id=session_id,
                               params={"principal": principal.subject},
                               event={"principal": principal.subject,
                                      "check": "unparsed_body"})
            raise TypeError("check_request_envelope requires the parsed JSON-RPC body "
                            "(object or batch array)")
        # A JSON-RPC batch (legal in 2025-03-26) is rejected below with -32600
        # and may be handed to a legacy handler: reconcile every element too.
        messages = body if isinstance(body, (list, tuple)) else [body]
        for message in messages:
            if isinstance(body, (list, tuple)) and not isinstance(message, Mapping):
                _log(("<batch element>",))
                raise MetaTrustError(["<batch element>"])
            # _meta can ride on a request (params), a response (result) or an
            # error (error.data) — e.g. legacy sampling/elicitation replies.
            carriers: list[Any] = []
            if isinstance(message, Mapping):
                for field in ("params", "result"):
                    carriers.append(message.get(field))
                err = message.get("error")
                if isinstance(err, Mapping):
                    carriers.append(err.get("data"))
            for carrier in carriers:
                meta = carrier.get("_meta") if isinstance(carrier, Mapping) else None
                if meta is not None and not isinstance(meta, Mapping):
                    # A malformed _meta must not reach a loose legacy handler
                    # as an unreconciled claim via a fallback path.
                    _log(("_meta",))
                    raise MetaTrustError(["_meta"])
                reconcile_meta(meta if isinstance(meta, Mapping) else None, principal,
                               allowed_keys=allowed_meta_keys, on_mismatch=_log)
        try:
            return validate_request_metadata(headers, body, tool_schemas=tool_schemas,
                                             wsgi_environ=wsgi_environ)
        except TypeError:
            # Unsupported header representation: a caller bug, audited like
            # an unparsed body and never a fallback signal.
            if self.audit is not None:
                self.audit.log(method="check_request_envelope:invalid_headers",
                               session_id=session_id,
                               params={"principal": principal.subject},
                               event={"principal": principal.subject,
                                      "check": "unsupported_header_type"})
            raise
        except RequestMetadataError as exc:
            if self.audit is not None:
                label = _AUDIT_LABELS.get(exc.code, "invalid_request")
                self.audit.log(method=f"check_request_envelope:{label}",
                               session_id=session_id,
                               params={"code": exc.code, "check": exc.reason,
                                       "principal": principal.subject},
                               event={"principal": principal.subject, "code": exc.code,
                                      "check": exc.reason})
            raise

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
    # MCP 2026-07-28 / CoSAI v2.0
    "AuthenticatedPrincipal",
    "HandleError",
    "HandleRegistry",
    "MetaTrustError",
    "RequestMetadataError",
    "RequestStateSealer",
    "SpentStore",
    "StateVerificationError",
    "reconcile_meta",
    "request_fingerprint",
    "validate_request_metadata",
]
