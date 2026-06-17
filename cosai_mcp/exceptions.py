"""Custom exceptions for cosai-mcp."""
from __future__ import annotations


class CosaiMCPError(Exception):
    """Base exception for all cosai-mcp errors."""


class SessionIncompleteError(CosaiMCPError):
    """Raised when the MCP session handshake fails at any step."""


class SuspiciousRedirectError(CosaiMCPError):
    """Raised when a 3xx redirect response is received — never followed."""


class NetworkAllowlistError(CosaiMCPError):
    """Base for network-level allowlist violations."""


class PrivateAddressError(NetworkAllowlistError):
    """Raised when the target resolves to a private/loopback/link-local address."""


class DNSRebindingError(NetworkAllowlistError):
    """Raised when the resolved IP at connect time differs from the pinned IP."""


class OutputTruncatedWarning(UserWarning):
    """Issued when subprocess output is truncated at the 10 MB safety cap."""


# ---------------------------------------------------------------------------
# Catalog exceptions (Phase 2)
# ---------------------------------------------------------------------------

class SchemaValidationError(CosaiMCPError):
    """Raised when a catalog JSON file fails meta-schema validation."""


class SignatureVerificationError(CosaiMCPError):
    """Raised when an Ed25519 catalog signature is missing or invalid."""


class PathTraversalError(CosaiMCPError):
    """Raised when a catalog file path escapes the catalog root directory."""


class UnsafePatternError(CosaiMCPError):
    """Raised when a matches_regex pattern is rejected by RE2 (e.g. ReDoS risk)."""


class TemplateInjectionError(CosaiMCPError):
    """Raised when a substituted template value still contains '{{' (double-expansion attempt)."""


class UnknownVariableError(CosaiMCPError):
    """Raised when a template variable is not in the allowed variable allowlist."""


# ---------------------------------------------------------------------------
# CLI / scan orchestration exceptions (Phase 8)
# ---------------------------------------------------------------------------

class TargetUnreachableError(CosaiMCPError):
    """Raised when the target MCP server cannot be reached (TCP connect fails)."""


class ScannerInternalError(CosaiMCPError):
    """Raised when the scanner itself errors (not a target finding)."""
