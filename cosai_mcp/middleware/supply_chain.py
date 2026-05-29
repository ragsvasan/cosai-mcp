"""T11: Tool allowlist, registry signature check, typosquatting prevention."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cosai_mcp.middleware.integrity import levenshtein


@dataclass(frozen=True)
class AllowlistViolation:
    """A tool that failed the allowlist check."""
    tool_name: str
    reason: str          # "not_in_allowlist" | "typosquat"
    closest_match: str   # for typosquat; empty string otherwise
    distance: int        # Levenshtein distance; 0 for not_in_allowlist


class SupplyChainError(Exception):
    """Raised when one or more tools fail supply-chain checks."""

    def __init__(self, message: str, violations: list[AllowlistViolation]) -> None:
        super().__init__(message)
        self.violations: tuple[AllowlistViolation, ...] = tuple(violations)


class SignatureVerificationError(Exception):
    """Raised when a tool definition's Ed25519 signature cannot be verified."""


class AllowlistEnforcer:
    """Enforce an allowlist of permitted tool names with typosquat detection.

    Rules (evaluated per tool):
    - Exact match → allowed.
    - Not in allowlist AND distance > 1 from every allowlisted name → blocked (not_in_allowlist).
    - Not in allowlist AND distance ≤ 1 from an allowlisted name → blocked (typosquat).
    - Empty allowlist → all tools allowed (pass-through; no enforcement).
    """

    def __init__(self, allowlist: frozenset[str] | None = None) -> None:
        self._allowlist: frozenset[str] = allowlist or frozenset()

    def check_tools(self, tools: list[dict[str, Any]]) -> list[AllowlistViolation]:
        """Return violations for tools that fail the allowlist. Empty list means clean."""
        if not self._allowlist:
            return []

        violations: list[AllowlistViolation] = []
        for tool in tools:
            name = str(tool.get("name", ""))
            if name in self._allowlist:
                continue  # exact match — allowed

            # Check for typosquat (distance ≤ 1 from any allowlisted name).
            # CLAUDE.md T11 locked spec: block at distance ≤ 1. This differs from
            # integrity.py's TyposquatDetector which reports distance ≤ 2 for T6
            # awareness — supply chain enforcement uses the stricter T11 threshold.
            best_dist = 2  # sentinel: anything ≤ 1 triggers a typosquat violation
            best_match = ""
            for allowed in self._allowlist:
                d = levenshtein(name, allowed)
                if d < best_dist:
                    best_dist = d
                    best_match = allowed

            if best_match:
                violations.append(AllowlistViolation(
                    tool_name=name,
                    reason="typosquat",
                    closest_match=best_match,
                    distance=best_dist,
                ))
            else:
                violations.append(AllowlistViolation(
                    tool_name=name,
                    reason="not_in_allowlist",
                    closest_match="",
                    distance=0,
                ))

        return violations


class RegistrySignatureVerifier:
    """Verify Ed25519 signatures on tool definitions from an external registry.

    Protocol:
      The registry publishes tool definitions as JSON alongside a detached
      Ed25519 signature over ``SHA-256(canonical_json)``. Call ``verify()``
      at server startup before loading any external tool definition.
    """

    def __init__(self, public_key: Ed25519PublicKey) -> None:
        self._public_key = public_key

    @staticmethod
    def canonical_bytes(tool_def: dict[str, Any]) -> bytes:
        """Return deterministic JSON bytes used for signing (sorted keys, no whitespace)."""
        return json.dumps(tool_def, sort_keys=True, separators=(",", ":")).encode()

    def verify(self, tool_def: dict[str, Any], signature_bytes: bytes) -> None:
        """Verify *signature_bytes* over *tool_def*.

        Raises ``SignatureVerificationError`` if the signature is invalid.
        """
        message = self.canonical_bytes(tool_def)
        try:
            self._public_key.verify(signature_bytes, message)
        except InvalidSignature as exc:
            tool_name = tool_def.get("name", "<unknown>")
            raise SignatureVerificationError(
                f"Invalid Ed25519 signature for tool '{tool_name}'"
            ) from exc


class SupplyChainEnforcer:
    """Combine allowlist enforcement and optional registry signature verification.

    Call ``check_tools()`` at server startup (before the first tools/list
    response is acted upon) to block untrusted tools before they can execute.
    """

    def __init__(
        self,
        allowlist: frozenset[str] | None = None,
        registry_verifier: RegistrySignatureVerifier | None = None,
    ) -> None:
        self._allowlist_enforcer = AllowlistEnforcer(allowlist)
        self._verifier = registry_verifier

    def verify_tool_signature(
        self,
        tool_def: dict[str, Any],
        signature_bytes: bytes,
    ) -> None:
        """Verify *tool_def*'s registry signature.

        Raises ``SignatureVerificationError`` if no verifier is configured or
        the signature is invalid.
        """
        if self._verifier is None:
            raise SignatureVerificationError(
                "No registry verifier configured. "
                "Provide an Ed25519PublicKey to SupplyChainEnforcer."
            )
        self._verifier.verify(tool_def, signature_bytes)

    def check_tools(self, tools: list[dict[str, Any]]) -> None:
        """Check all tools against the allowlist.

        Raises ``SupplyChainError`` if any tool fails the check.
        """
        violations = self._allowlist_enforcer.check_tools(tools)
        if violations:
            names = ", ".join(v.tool_name for v in violations)
            raise SupplyChainError(
                f"Supply-chain check failed: {len(violations)} tool(s) blocked: {names}",
                violations,
            )
