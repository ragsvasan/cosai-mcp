"""MCP protocol-era constants and wire helpers (legacy + 2026-07-28 modern).

The 2026-07-28 MCP release removed the ``initialize`` handshake and
``Mcp-Session-Id``: every request is self-contained and carries its protocol
version, client identity, and client capabilities in ``params._meta``, and on
Streamable HTTP mirrors ``method`` / ``params.name`` into ``Mcp-Method`` /
``Mcp-Name`` headers.  Earlier revisions ("legacy") still use the handshake.

Everything here is pure (no I/O) so the session, transports, inventory
snapshot, and mock server share one definition of the wire format.

Spec: https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning
"""
from __future__ import annotations

import base64
import enum
import re
from typing import Any

# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------

MODERN_PROTOCOL_VERSION = "2026-07-28"
MODERN_VERSIONS: frozenset[str] = frozenset({MODERN_PROTOCOL_VERSION})

# Handshake-based revisions (initialize / initialized / Mcp-Session-Id).
LEGACY_VERSIONS: frozenset[str] = frozenset(
    {"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}
)

# ---------------------------------------------------------------------------
# _meta keys (params._meta on every modern request)
# ---------------------------------------------------------------------------

META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"

# ---------------------------------------------------------------------------
# JSON-RPC error codes defined by 2026-07-28 (reserved range -32020..-32099)
# ---------------------------------------------------------------------------

ERR_HEADER_MISMATCH = -32020
ERR_MISSING_CLIENT_CAPABILITY = -32021
ERR_UNSUPPORTED_PROTOCOL_VERSION = -32022
MODERN_ERROR_CODES: frozenset[int] = frozenset(
    {ERR_HEADER_MISMATCH, ERR_MISSING_CLIENT_CAPABILITY, ERR_UNSUPPORTED_PROTOCOL_VERSION}
)

# ---------------------------------------------------------------------------
# HTTP request-metadata headers (Streamable HTTP, modern only)
# ---------------------------------------------------------------------------

HEADER_PROTOCOL_VERSION = "MCP-Protocol-Version"
HEADER_METHOD = "Mcp-Method"
HEADER_NAME = "Mcp-Name"
HEADER_PARAM_PREFIX = "Mcp-Param-"

# Methods whose params.name / params.uri is mirrored into Mcp-Name.
_NAME_BEARING_METHODS: dict[str, str] = {
    "tools/call": "name",
    "prompts/get": "name",
    "resources/read": "uri",
}

_B64_PREFIX = "=?base64?"
_B64_SUFFIX = "?="
# RFC 9110 tchar — valid HTTP field-name token.
_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_JS_SAFE_INT = 2**53 - 1


class ProtocolEra(enum.StrEnum):
    """Which protocol era the scanner speaks to a target."""

    AUTO = "auto"      # probe modern first, fall back to legacy (dual-era client)
    MODERN = "modern"  # 2026-07-28 stateless only
    LEGACY = "legacy"  # initialize handshake only (pre-2026-07-28 behaviour)


class EraDetection(enum.Enum):
    """Outcome of classifying a ``server/discover`` probe response."""

    MODERN = "modern"              # server speaks a modern version we support
    LEGACY = "legacy"              # server is handshake-based → use initialize
    MODERN_INCOMPATIBLE = "modern_incompatible"  # modern, but no mutual version
    MODERN_ERROR = "modern_error"  # modern server rejected our request itself
    UNDETERMINED = "undetermined"  # auth/5xx/transport failure — era unknown


# ---------------------------------------------------------------------------
# Request construction
# ---------------------------------------------------------------------------

def build_request_meta(
    client_info: dict[str, str],
    client_capabilities: dict[str, Any],
    version: str = MODERN_PROTOCOL_VERSION,
) -> dict[str, Any]:
    """Return the required per-request ``_meta`` fields for a modern request."""
    return {
        META_PROTOCOL_VERSION: version,
        META_CLIENT_INFO: dict(client_info),
        META_CLIENT_CAPABILITIES: dict(client_capabilities),
    }


def with_request_meta(params: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *params* with the protocol ``_meta`` fields merged in.

    Keys already present in ``params['_meta']`` win: probes deliberately send
    spoofed or malformed ``_meta`` (T1 identity-claim tests), and the scanner
    must deliver exactly what the probe asked for.  A non-dict ``_meta`` is
    left untouched for the same reason.
    """
    out = dict(params)
    existing = out.get("_meta")
    if existing is None:
        out["_meta"] = dict(meta)
    elif isinstance(existing, dict):
        out["_meta"] = {**meta, **existing}
    return out


def encode_header_value(value: str) -> str:
    """Encode *value* for an ``Mcp-Name`` / ``Mcp-Param-*`` header.

    Plain visible ASCII passes through; anything else (non-ASCII, control
    characters, leading/trailing whitespace, or a value that itself matches
    the sentinel pattern) is carried as ``=?base64?<b64 of UTF-8>?=``.
    """
    safe = (
        value == value.strip()
        and all(c == "\t" or 0x20 <= ord(c) <= 0x7E for c in value)
        and not (value.startswith(_B64_PREFIX) and value.endswith(_B64_SUFFIX))
    )
    if safe:
        return value
    return _B64_PREFIX + base64.b64encode(value.encode("utf-8")).decode("ascii") + _B64_SUFFIX


def decode_header_value(value: str) -> str:
    """Inverse of :func:`encode_header_value` (used by the mock server)."""
    if value.startswith(_B64_PREFIX) and value.endswith(_B64_SUFFIX):
        inner = value[len(_B64_PREFIX):-len(_B64_SUFFIX)]
        return base64.b64decode(inner, validate=True).decode("utf-8")
    return value


def mcp_name_for(method: str, params: dict[str, Any]) -> str | None:
    """Return the body value mirrored into ``Mcp-Name`` for *method*, if any."""
    field = _NAME_BEARING_METHODS.get(method)
    if field is None:
        return None
    value = params.get(field)
    return value if isinstance(value, str) else None


def request_metadata_headers(
    method: str, params: dict[str, Any], version: str = MODERN_PROTOCOL_VERSION,
) -> dict[str, str]:
    """Return the standard modern Streamable-HTTP request headers."""
    headers = {HEADER_PROTOCOL_VERSION: version, HEADER_METHOD: method}
    name = mcp_name_for(method, params)
    if name is not None:
        headers[HEADER_NAME] = encode_header_value(name)
    return headers


def _header_param_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if abs(value) > _JS_SAFE_INT:
            return None
        return str(value)
    if isinstance(value, str):
        return encode_header_value(value)
    return None


def x_mcp_param_headers(input_schema: Any, arguments: Any) -> dict[str, str]:
    """Return ``Mcp-Param-{name}`` headers for ``x-mcp-header`` annotations.

    Only annotations reachable from the schema root through a chain of
    ``properties`` keys are honoured (spec constraint).  Annotations that
    violate the spec (non-token name, duplicate name, non-primitive target)
    are skipped: the scanner never *crashes* on a hostile schema, and the
    invalid annotation is left for a T3 manifest check to report.

    Deliberate protocol deviation: the spec says a conforming client MUST drop
    a tool with an invalid annotation from its ``tools/list`` view.  A security
    scanner must instead *see* hostile tool definitions, so the tool stays in
    the manifest and is probed; only the invalid header is withheld.
    """
    if not isinstance(input_schema, dict) or not isinstance(arguments, dict):
        return {}

    annotations: list[tuple[str, tuple[str, ...], Any]] = []

    def _walk(schema: dict[str, Any], path: tuple[str, ...], depth: int) -> None:
        if depth > 16:
            return
        props = schema.get("properties")
        if not isinstance(props, dict):
            return
        for key, sub in props.items():
            if not isinstance(sub, dict):
                continue
            ann = sub.get("x-mcp-header")
            if isinstance(ann, str):
                annotations.append((ann, (*path, key), sub.get("type")))
            _walk(sub, (*path, key), depth + 1)

    _walk(input_schema, (), 0)

    seen: set[str] = set()
    headers: dict[str, str] = {}
    for name, path, typ in annotations:
        lowered = name.lower()
        if not _TOKEN_RE.match(name) or lowered in seen:
            continue
        seen.add(lowered)
        if isinstance(typ, list):
            # e.g. ["string", "null"] — nullable primitive
            non_null = [t for t in typ if t != "null"]
            typ = non_null[0] if len(non_null) == 1 else None
        if typ not in ("string", "integer", "boolean"):
            continue
        node: Any = arguments
        for step in path:
            if not isinstance(node, dict) or step not in node:
                node = None
                break
            node = node[step]
        encoded = _header_param_value(node)
        if encoded is not None:
            headers[HEADER_PARAM_PREFIX + name] = encoded
    return headers


# ---------------------------------------------------------------------------
# Era detection
# ---------------------------------------------------------------------------

def _classify_versions(supported: Any) -> EraDetection:
    if not isinstance(supported, list):
        return EraDetection.MODERN_INCOMPATIBLE
    if any(v in MODERN_VERSIONS for v in supported):
        return EraDetection.MODERN
    if any(v in LEGACY_VERSIONS for v in supported):
        return EraDetection.LEGACY
    return EraDetection.MODERN_INCOMPATIBLE


def classify_discover_response(response: Any) -> EraDetection:
    """Classify the response to a modern ``server/discover`` probe.

    Implements the dual-era client rules from the 2026-07-28 spec: a
    ``DiscoverResult`` or a recognised modern JSON-RPC error identifies a
    modern server; anything else identifies a legacy one.  HTTP 401/403/429
    and 5xx are *undetermined* (auth or availability, not era) so a caller
    pinning the era for a whole scan does not pin the wrong one.
    """
    if not isinstance(response, dict) or not response:
        return EraDetection.LEGACY

    result = response.get("result")
    if isinstance(result, dict) and "supportedVersions" in result:
        return _classify_versions(result.get("supportedVersions"))

    error = response.get("error")
    if isinstance(error, dict):
        code = error.get("code")
        if code == ERR_UNSUPPORTED_PROTOCOL_VERSION:
            data = error.get("data")
            return _classify_versions(data.get("supported") if isinstance(data, dict) else None)
        if code in (ERR_HEADER_MISMATCH, ERR_MISSING_CLIENT_CAPABILITY):
            return EraDetection.MODERN_ERROR

    status = response.get("_status_code")
    if isinstance(status, int) and (status in (401, 403, 429) or status >= 500):
        return EraDetection.UNDETERMINED
    return EraDetection.LEGACY
