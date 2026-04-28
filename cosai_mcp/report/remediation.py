"""Static remediation registry — maps probe_id → RemediationBlock.

Content is spec-derived and framework-agnostic. Missing entries silently omit
the remediation tab in reports — they never crash the report builder.
"""
from __future__ import annotations

from dataclasses import dataclass


_VALID_LANGUAGES: frozenset[str] = frozenset({"python", "typescript", "pseudocode"})


@dataclass(frozen=True)
class RemediationBlock:
    """Actionable fix guidance for one probe finding.

    Attributes
    ----------
    threat_id:
        CoSAI threat ID (e.g. ``"T01-001"``).
    probe_id:
        Specific probe this block applies to (e.g. ``"T01-001-p1"``).
    spec_ref:
        Canonical spec citation (e.g. ``"MCP 2025-03-26 §4.3.1"``).
    what_spec_requires:
        Plain-text description of what the spec mandates (≤ 200 chars).
    fix_shape:
        Framework-agnostic pseudocode showing the shape of the fix (≤ 400 chars).
    fix_shape_language:
        Language hint for syntax highlighting: ``"python"``, ``"typescript"``,
        or ``"pseudocode"``.
    fastmcp_snippet:
        Optional FastMCP-specific Python snippet.
    typescript_snippet:
        Optional MCP SDK TypeScript snippet.
    verify_command_suffix:
        Appended to ``cosai scan <target>`` in the VERIFY section of the report.
    """
    threat_id: str
    probe_id: str
    spec_ref: str
    what_spec_requires: str
    fix_shape: str
    fix_shape_language: str
    fastmcp_snippet: str | None
    typescript_snippet: str | None
    verify_command_suffix: str = ""

    def __post_init__(self) -> None:
        if self.fix_shape_language not in _VALID_LANGUAGES:
            raise ValueError(
                f"fix_shape_language must be one of {sorted(_VALID_LANGUAGES)}, "
                f"got {self.fix_shape_language!r}."
            )


# ---------------------------------------------------------------------------
# Registry — keyed by probe_id
# ---------------------------------------------------------------------------

_BLOCKS: list[RemediationBlock] = [

    # ------------------------------------------------------------------
    # T01 — Improper Authentication
    # ------------------------------------------------------------------

    RemediationBlock(
        threat_id="T01-001",
        probe_id="T01-001-p1",
        spec_ref="MCP 2025-03-26 §4.1 (Authentication)",
        what_spec_requires=(
            "Servers that require authentication MUST reject initialize "
            "requests that lack a valid Bearer token with HTTP 401."
        ),
        fix_shape=(
            "# Guard at the transport layer, before the MCP dispatcher:\n"
            "if not request.headers.get('Authorization'):\n"
            "    return HTTP 401 Unauthorized\n"
            "token = request.headers['Authorization'].removeprefix('Bearer ')\n"
            "if not verify_token(token):\n"
            "    return HTTP 401 Unauthorized"
        ),
        fix_shape_language="python",
        fastmcp_snippet=(
            "# FastMCP: add auth middleware\n"
            "from fastmcp import FastMCP\n"
            "app = FastMCP('my-server')\n\n"
            "@app.middleware\n"
            "async def require_auth(request, call_next):\n"
            "    if not request.headers.get('Authorization'):\n"
            "        raise MCPError(INVALID_REQUEST, 'Authentication required')\n"
            "    return await call_next(request)"
        ),
        typescript_snippet=(
            "// MCP SDK: check Authorization in session handler\n"
            "server.onInitialize(async (params, extra) => {\n"
            "  const token = extra.headers?.authorization;\n"
            "  if (!token) throw new McpError(ErrorCode.InvalidRequest, 'Auth required');\n"
            "});"
        ),
        verify_command_suffix="--categories T1 --fail-on high",
    ),

    RemediationBlock(
        threat_id="T01-002",
        probe_id="T01-002-p1",
        spec_ref="MCP 2025-03-26 §4.1 (Authentication)",
        what_spec_requires=(
            "Bearer tokens MUST be validated cryptographically — not accepted "
            "unconditionally. Any non-empty string must not be treated as valid."
        ),
        fix_shape=(
            "# Validate signature, not just presence:\n"
            "import jwt\n"
            "try:\n"
            "    claims = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])\n"
            "except jwt.InvalidTokenError:\n"
            "    return HTTP 401 Unauthorized"
        ),
        fix_shape_language="python",
        fastmcp_snippet=None,
        typescript_snippet=None,
        verify_command_suffix="--categories T1 --fail-on high",
    ),

    RemediationBlock(
        threat_id="T01-002",
        probe_id="T01-002-p2",
        spec_ref="MCP 2025-03-26 §4.1 (Authentication)",
        what_spec_requires=(
            "Malformed or obviously invalid tokens (e.g. single characters) "
            "MUST be rejected with HTTP 401, not processed as valid auth."
        ),
        fix_shape=(
            "# Reject malformed tokens early:\n"
            "if len(token) < MINIMUM_TOKEN_LENGTH:\n"
            "    return HTTP 401 Unauthorized\n"
            "# Then validate signature as above."
        ),
        fix_shape_language="python",
        fastmcp_snippet=None,
        typescript_snippet=None,
        verify_command_suffix="--categories T1 --fail-on high",
    ),

    # ------------------------------------------------------------------
    # T02 — Missing Access Control
    # ------------------------------------------------------------------

    RemediationBlock(
        threat_id="T02-003",
        probe_id="T02-003-p1",
        spec_ref="CoSAI T2 §2.3 (Destructive tool authorization)",
        what_spec_requires=(
            "Destructive tools MUST implement a two-stage commit: a plan call "
            "returns a description and short-lived confirmation token; the execute "
            "call requires that token. One-shot destructive calls must be rejected."
        ),
        fix_shape=(
            "# Two-stage commit pattern:\n"
            "def delete_resource_plan(resource_id: str) -> dict:\n"
            "    token = secrets.token_hex(16)  # short-lived, single-use\n"
            "    store_pending(token, resource_id, ttl=60)\n"
            "    return {'description': f'Permanently delete {resource_id}', 'confirm_token': token}\n\n"
            "def delete_resource_execute(confirm_token: str) -> dict:\n"
            "    resource_id = consume_pending(confirm_token)  # raises if invalid/expired\n"
            "    actually_delete(resource_id)\n"
            "    return {'deleted': resource_id}"
        ),
        fix_shape_language="python",
        fastmcp_snippet=(
            "# FastMCP: separate plan and execute tools\n"
            "# WARNING: _pending is process-local. In multi-worker deployments\n"
            "# (gunicorn/uvicorn workers>1) use a shared store (Redis, DB) instead\n"
            "# — tokens issued by worker A are invisible to worker B.\n"
            "import secrets\n"
            "import time\n\n"
            "_pending: dict[str, tuple[str, float]] = {}  # token -> (resource_id, expires_at)\n\n"
            "@app.tool()\n"
            "def delete_plan(resource_id: str) -> dict:\n"
            "    # Prune expired entries to prevent unbounded growth\n"
            "    now = time.time()\n"
            "    for k in [k for k, (_, exp) in _pending.items() if exp < now]:\n"
            "        _pending.pop(k, None)\n"
            "    token = secrets.token_hex(16)\n"
            "    _pending[token] = (resource_id, now + 60)\n"
            "    return {'description': f'Permanently delete {resource_id}', 'confirm_token': token}\n\n"
            "@app.tool()\n"
            "def delete_execute(confirm_token: str) -> dict:\n"
            "    entry = _pending.pop(confirm_token, None)\n"
            "    if not entry or time.time() > entry[1]:\n"
            "        raise ValueError('Invalid or expired confirmation token')\n"
            "    return {'deleted': actually_delete(entry[0])}"
        ),
        typescript_snippet=(
            "// MCP SDK: plan + execute pattern\n"
            "server.tool('delete_plan', async ({ resource_id }) => {\n"
            "  const token = crypto.randomBytes(16).toString('hex');\n"
            "  pending.set(token, { resource_id, expires: Date.now() + 60_000 });\n"
            "  return { description: `Delete ${resource_id} permanently`, confirm_token: token };\n"
            "});\n"
            "server.tool('delete_execute', async ({ confirm_token }) => {\n"
            "  const entry = pending.get(confirm_token);\n"
            "  if (!entry || Date.now() > entry.expires)\n"
            "    throw new McpError(ErrorCode.InvalidParams, 'Invalid or expired token');\n"
            "  pending.delete(confirm_token);\n"
            "  return { deleted: await actuallyDelete(entry.resource_id) };\n"
            "});"
        ),
        verify_command_suffix="--categories T2 --fail-on critical",
    ),

    RemediationBlock(
        threat_id="T02-003",
        probe_id="T02-003-p2",
        spec_ref="CoSAI T2 §2.3 (Destructive tool authorization)",
        what_spec_requires=(
            "Tools that destroy resources without dry_run=true MUST require a "
            "prior confirmation token. Accepting operation=destroy, dry_run=false "
            "without a token is a one-shot destructive execution vulnerability."
        ),
        fix_shape=(
            "# Same two-stage commit applies — dry_run does not substitute for a token:\n"
            "# WRONG: if not dry_run: actually_destroy(target)\n"
            "# RIGHT: require confirm_token for any non-dry-run destructive path\n"
            "if not dry_run and not confirm_token:\n"
            "    raise McpError(INVALID_PARAMS, 'Confirmation token required for destructive operations')"
        ),
        fix_shape_language="python",
        fastmcp_snippet=None,
        typescript_snippet=None,
        verify_command_suffix="--categories T2 --fail-on critical",
    ),

    # ------------------------------------------------------------------
    # T03 — Input Validation Failures
    # ------------------------------------------------------------------

    RemediationBlock(
        threat_id="T03-001",
        probe_id="T03-001-p1",
        spec_ref="MCP 2025-03-26 §4.3 (Tool invocation)",
        what_spec_requires=(
            "Tool parameters MUST be validated against the declared JSON schema "
            "before execution. Command injection payloads must be rejected."
        ),
        fix_shape=(
            "# Validate against declared schema before calling implementation:\n"
            "from jsonschema import validate, ValidationError\n"
            "try:\n"
            "    validate(instance=arguments, schema=tool.inputSchema)\n"
            "except ValidationError as e:\n"
            "    raise McpError(INVALID_PARAMS, str(e))"
        ),
        fix_shape_language="python",
        fastmcp_snippet=(
            "# FastMCP: use typed parameters — validation is automatic\n"
            "from fastmcp import FastMCP\n"
            "import re\n\n"
            "@app.tool()\n"
            "def my_tool(filename: str) -> str:\n"
            "    # FastMCP validates type; add semantic check:\n"
            "    if not re.fullmatch(r'[\\w\\-\\.]+', filename):\n"
            "        raise ValueError('Invalid filename')\n"
            "    return open(filename).read()"
        ),
        typescript_snippet=None,
        verify_command_suffix="--categories T3 --fail-on high",
    ),

    RemediationBlock(
        threat_id="T03-001",
        probe_id="T03-001-p2",
        spec_ref="MCP 2025-03-26 §4.3 (Tool invocation)",
        what_spec_requires=(
            "Path traversal sequences (../../../) in file path parameters "
            "MUST be rejected before any filesystem access."
        ),
        fix_shape=(
            "# Canonicalize and assert path stays within allowed root:\n"
            "import pathlib\n"
            "allowed_root = pathlib.Path('/allowed/root').resolve()\n"
            "candidate = (allowed_root / user_path).resolve()\n"
            "if not str(candidate).startswith(str(allowed_root)):\n"
            "    raise McpError(INVALID_PARAMS, 'Path traversal rejected')"
        ),
        fix_shape_language="python",
        fastmcp_snippet=None,
        typescript_snippet=None,
        verify_command_suffix="--categories T3 --fail-on high",
    ),

    RemediationBlock(
        threat_id="T03-001",
        probe_id="T03-001-p3",
        spec_ref="MCP 2025-03-26 §4.3 (Tool invocation)",
        what_spec_requires=(
            "Oversized payloads MUST be rejected before deserialization to "
            "prevent memory exhaustion and denial-of-service."
        ),
        fix_shape=(
            "# Enforce payload size limit at transport layer:\n"
            "MAX_PAYLOAD_BYTES = 1_000_000  # 1 MB\n"
            "if len(request.body) > MAX_PAYLOAD_BYTES:\n"
            "    return HTTP 413 Content Too Large"
        ),
        fix_shape_language="python",
        fastmcp_snippet=None,
        typescript_snippet=None,
        verify_command_suffix="--categories T3 --fail-on medium",
    ),

    RemediationBlock(
        threat_id="T03-002",
        probe_id="T03-002-p1",
        spec_ref="MCP 2025-03-26 §4.3 (Tool invocation)",
        what_spec_requires=(
            "Integer parameters with defined bounds (min/max in schema) MUST "
            "be rejected when values exceed those bounds."
        ),
        fix_shape=(
            "# Use 'minimum'/'maximum' in your JSON schema:\n"
            '{"type": "integer", "minimum": 1, "maximum": 1000}\n'
            "# Then validate — do not just cast and clamp silently."
        ),
        fix_shape_language="pseudocode",
        fastmcp_snippet=None,
        typescript_snippet=None,
        verify_command_suffix="--categories T3 --fail-on medium",
    ),

    # ------------------------------------------------------------------
    # T05 — Inadequate Data Protection
    # ------------------------------------------------------------------

    RemediationBlock(
        threat_id="T05-001",
        probe_id="T05-001-p1",
        spec_ref="MCP 2025-03-26 §5.2 (Data protection)",
        what_spec_requires=(
            "Tool responses MUST NOT include credentials, secrets, or tokens "
            "in plaintext. Sensitive fields must be redacted before returning."
        ),
        fix_shape=(
            "# Scrub secrets from tool response before returning:\n"
            "import re\n"
            "REDACT_PATTERNS = [r'(?i)(password|secret|token|key)\\s*[:=]\\s*\\S+']\n"
            "def scrub(text):\n"
            "    for pat in REDACT_PATTERNS:\n"
            "        text = re.sub(pat, '[REDACTED]', text)\n"
            "    return text"
        ),
        fix_shape_language="python",
        fastmcp_snippet=None,
        typescript_snippet=None,
        verify_command_suffix="--categories T5 --fail-on high",
    ),

    # ------------------------------------------------------------------
    # T06 — Integrity / Verification Failures
    # ------------------------------------------------------------------

    RemediationBlock(
        threat_id="T06-001",
        probe_id="T06-001-p1",
        spec_ref="MCP 2025-03-26 §4.2.2 (Tool list stability)",
        what_spec_requires=(
            "The tools/list response MUST be stable within a session. "
            "Returning different tools after initialize is a T6 integrity violation."
        ),
        fix_shape=(
            "# Freeze the tool manifest at session start:\n"
            "session.tool_manifest = frozenset(tools.keys())\n\n"
            "# On each tools/list call:\n"
            "if set(tools.keys()) != session.tool_manifest:\n"
            "    raise McpError(INTERNAL_ERROR, 'Tool manifest changed mid-session')"
        ),
        fix_shape_language="python",
        fastmcp_snippet=None,
        typescript_snippet=None,
        verify_command_suffix="--categories T6 --fail-on high",
    ),

    # ------------------------------------------------------------------
    # T08 — Network Binding Failures
    # ------------------------------------------------------------------

    RemediationBlock(
        threat_id="T08-001",
        probe_id="T08-001-p1",
        spec_ref="MCP 2025-03-26 §6.1 (Network isolation)",
        what_spec_requires=(
            "MCP servers MUST NOT allow tool parameters to redirect HTTP "
            "requests to RFC1918 or loopback addresses (SSRF)."
        ),
        fix_shape=(
            "# Block RFC1918, loopback, link-local before fetching:\n"
            "import ipaddress, socket\n"
            "def is_safe(host):\n"
            "    ip = socket.gethostbyname(host)\n"
            "    addr = ipaddress.ip_address(ip)\n"
            "    return not (addr.is_private or addr.is_loopback or addr.is_link_local)\n"
            "if not is_safe(parsed_url.hostname):\n"
            "    raise McpError(INVALID_PARAMS, 'Disallowed target address')"
        ),
        fix_shape_language="python",
        fastmcp_snippet=None,
        typescript_snippet=None,
        verify_command_suffix="--categories T8 --fail-on critical",
    ),

    RemediationBlock(
        threat_id="T08-001",
        probe_id="T08-001-p2",
        spec_ref="MCP 2025-03-26 §6.1 (Network isolation)",
        what_spec_requires=(
            "IPv6 loopback (::1) and link-local addresses MUST be blocked "
            "in addition to IPv4 private ranges."
        ),
        fix_shape=(
            "# Include IPv6 checks:\n"
            "addr = ipaddress.ip_address(resolved_ip)\n"
            "if addr.is_loopback or addr.is_link_local or addr.is_private:\n"
            "    raise McpError(INVALID_PARAMS, 'Address not permitted')"
        ),
        fix_shape_language="python",
        fastmcp_snippet=None,
        typescript_snippet=None,
        verify_command_suffix="--categories T8 --fail-on critical",
    ),

    # ------------------------------------------------------------------
    # T10 — Resource Management
    # ------------------------------------------------------------------

    RemediationBlock(
        threat_id="T10-001",
        probe_id="T10-001-p1",
        spec_ref="MCP 2025-03-26 §7.1 (Rate limiting)",
        what_spec_requires=(
            "Servers MUST enforce per-session call budgets to prevent "
            "runaway agents from causing denial-of-wallet or resource exhaustion."
        ),
        fix_shape=(
            "# Enforce per-session rate limit at dispatcher:\n"
            "session.call_count += 1\n"
            "if session.call_count > MAX_CALLS_PER_SESSION:\n"
            "    raise McpError(INVALID_REQUEST, 'Session call budget exceeded')\n"
            "# Also enforce per-minute sliding window."
        ),
        fix_shape_language="python",
        fastmcp_snippet=None,
        typescript_snippet=None,
        verify_command_suffix="--categories T10 --fail-on high",
    ),

    # ------------------------------------------------------------------
    # T11 — Supply Chain / Lifecycle
    # ------------------------------------------------------------------

    RemediationBlock(
        threat_id="T11-001",
        probe_id="T11-001-p1",
        spec_ref="MCP 2025-03-26 §4.3.1 (Unknown tool names)",
        what_spec_requires=(
            "tools/call with an unknown tool name MUST return JSON-RPC error "
            "-32601 (Method not found) with isError:true. Returning isError:false "
            "for unknown tools is a supply-chain integrity failure."
        ),
        fix_shape=(
            "# Guard in your tool dispatcher:\n"
            "if tool_name not in registered_tools:\n"
            "    raise McpError(\n"
            "        METHOD_NOT_FOUND,\n"
            "        f'Unknown tool: {tool_name!r}'\n"
            "    )"
        ),
        fix_shape_language="python",
        fastmcp_snippet=(
            "# FastMCP raises METHOD_NOT_FOUND automatically for unknown tools.\n"
            "# If you are routing manually, add:\n"
            "@app.call_tool()\n"
            "async def call_tool(name: str, arguments: dict):\n"
            "    if name not in app.tools:\n"
            "        raise McpError(METHOD_NOT_FOUND, f'Unknown tool: {name!r}')\n"
            "    return await app.tools[name](arguments)"
        ),
        typescript_snippet=(
            "// MCP SDK TypeScript: guard in tool handler\n"
            "server.setRequestHandler(CallToolRequestSchema, async (request) => {\n"
            "  const { name } = request.params;\n"
            "  if (!tools[name]) {\n"
            "    throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);\n"
            "  }\n"
            "  return tools[name](request.params.arguments);\n"
            "});"
        ),
        verify_command_suffix="--categories T11 --fail-on high",
    ),

    RemediationBlock(
        threat_id="T11-001",
        probe_id="T11-001-p2",
        spec_ref="MCP 2025-03-26 §4.3.1 (Unknown tool names)",
        what_spec_requires=(
            "tools/call for an unregistered tool MUST set isError:true in the "
            "result object even when the server does not raise a JSON-RPC error."
        ),
        fix_shape=(
            "# Per spec, isError:true signals tool-level failure:\n"
            "return {\n"
            "    'isError': True,\n"
            "    'content': [{'type': 'text', 'text': f'Unknown tool: {name!r}'}]\n"
            "}"
        ),
        fix_shape_language="python",
        fastmcp_snippet=None,
        typescript_snippet=None,
        verify_command_suffix="--categories T11 --fail-on high",
    ),

    # ------------------------------------------------------------------
    # T12 — Insufficient Logging / Tool Description Transparency
    # ------------------------------------------------------------------

    RemediationBlock(
        threat_id="T12-002",
        probe_id="T12-002-p1",
        spec_ref="CoSAI T12 §12.2 (Observability and auditability)",
        what_spec_requires=(
            "tools/list MUST be accessible so operators can enumerate tool "
            "descriptions and audit which tools are exposed to agents."
        ),
        fix_shape=(
            "# Ensure tools/list is handled by your MCP server dispatcher:\n"
            "# Standard method — all MCP servers must implement it.\n"
            "# If returning 401/403, ensure scanner credentials can list tools."
        ),
        fix_shape_language="pseudocode",
        fastmcp_snippet=None,
        typescript_snippet=None,
        verify_command_suffix="--categories T12 --fail-on info",
    ),

    RemediationBlock(
        threat_id="T12-002",
        probe_id="T12-002-p2",
        spec_ref="CoSAI T12 §12.2 (Tool description transparency)",
        what_spec_requires=(
            "Tool descriptions for destructive operations MUST include explicit "
            "irreversibility disclosure so the LLM and operator know the action "
            "cannot be undone before a confirmation is issued."
        ),
        fix_shape=(
            "# Add irreversibility disclosure to destructive tool descriptions:\n"
            '# BEFORE: "Deletes the specified resource."\n'
            '# AFTER:  "Permanently deletes the specified resource. '
            'This action is irreversible and cannot be undone. '
            'Use delete_plan first to review what will be deleted."\n\n'
            "# Pair with T02-003 two-stage commit so the warning appears\n"
            "# in the plan response before the confirmation token is issued."
        ),
        fix_shape_language="pseudocode",
        fastmcp_snippet=(
            "# FastMCP: tool description in decorator\n"
            "@app.tool(\n"
            "    description=(\n"
            "        'Permanently deletes the specified resource. '\n"
            "        'THIS ACTION IS IRREVERSIBLE AND CANNOT BE UNDONE. '\n"
            "        'Call delete_plan first to obtain a confirmation token.'\n"
            "    )\n"
            ")\n"
            "def delete_execute(confirm_token: str) -> dict:\n"
            "    ..."
        ),
        typescript_snippet=(
            "// MCP SDK: description on tool registration\n"
            "server.tool(\n"
            "  'delete_execute',\n"
            "  'Permanently deletes the specified resource. '\n"
            "  + 'THIS ACTION IS IRREVERSIBLE AND CANNOT BE UNDONE. '\n"
            "  + 'Requires a confirmation token from delete_plan.',\n"
            "  { confirm_token: z.string() },\n"
            "  async ({ confirm_token }) => { ... }\n"
            ");"
        ),
        verify_command_suffix="--categories T12 --fail-on info",
    ),
]

# Public registry — keyed by probe_id for O(1) lookup at report time
REMEDIATION_REGISTRY: dict[str, RemediationBlock] = {b.probe_id: b for b in _BLOCKS}


def get_remediation(probe_id: str) -> RemediationBlock | None:
    """Return the RemediationBlock for *probe_id*, or None if not registered."""
    return REMEDIATION_REGISTRY.get(probe_id)
