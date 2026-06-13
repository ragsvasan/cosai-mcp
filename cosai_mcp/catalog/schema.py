"""JSON meta-schema validation for threat catalog entries."""
from __future__ import annotations

import jsonschema

from cosai_mcp.exceptions import SchemaValidationError

THREAT_META_SCHEMA: dict = {
    "type": "object",
    "required": [
        "schema_version", "id", "category", "severity", "cosai_ref",
        "owasp_ref", "cwe", "probes", "remediation", "references",
    ],
    "additionalProperties": False,
    "properties": {
        # 1.1 adds optional `confidence` (threat) + `corroboration` (probe).
        # 1.0 files remain valid and load unchanged (additive bump).
        "schema_version": {"type": "string", "enum": ["1.0", "1.1"]},
        # Standard threats: T##-###  (e.g. T01-001)
        # Adversarial threats: T##-ADV-### (e.g. T03-ADV-001)
        "id": {"type": "string", "pattern": "^T[0-9]{2}(-[A-Z]{2,5})?-[0-9]{3}$"},
        "category": {"type": "string", "pattern": "^T[0-9]+$"},
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low", "info"],
        },
        "cosai_ref": {"type": "string"},
        "owasp_ref": {"type": "string"},
        "cwe": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "probes": {
            "type": "array",
            "items": {"$ref": "#/$defs/probe"},
            "minItems": 0,
        },
        "remediation": {"type": "string"},
        "references": {"type": "array", "items": {"type": "string"}},
        # Schema 1.1 additive: reporting-only confidence label (never gates).
        "confidence": {
            "type": "string",
            "enum": ["low", "medium", "high"],
        },
        # Adversarial-only optional fields
        "adversarial": {"type": "boolean"},
        "mode": {"type": "string", "enum": ["read-only", "stateful"]},
        "description": {"type": "string"},
        "canary_placement": {"type": "string"},
    },
    "$defs": {
        "probe": {
            "type": "object",
            "required": ["id", "transport", "method", "payload", "assertions"],
            "additionalProperties": False,
            "properties": {
                "id": {"type": "string"},
                "transport": {"type": "string", "enum": ["http", "stdio"]},
                "method": {"type": "string"},
                "payload": {"type": "object"},
                "assertions": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/assertion"},
                    "minItems": 0,
                },
                # Schema 1.1 additive: positive-evidence assertions. When the
                # primary assertions FAIL but these do NOT all hold, the probe
                # is INCONCLUSIVE (uncorroborated) — not a finding. Suppresses
                # noise from incidental matches. Empty/absent = pre-1.1 behaviour.
                "corroboration": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/assertion"},
                    "minItems": 1,
                },
                # When True, a JSON-RPC protocol-validation error
                # (-32601/-32602/-32600/-32700) is an EXPECTED secure outcome
                # (the request was correctly rejected by a limit/allowlist) and
                # the probe is NOT downgraded to inconclusive. Used by T10/T11
                # reject-the-request probes. Default/absent = False.
                "protocol_error_is_expected": {"type": "boolean"},
                # Adversarial probe optional fields
                "description": {"type": "string"},
                "canary_detection": {"type": "boolean"},
                "session": {"type": "string"},
                "capture": {"type": "string"},
                "replay_token_from": {"type": "string"},
                "inconclusive_if_no_llm": {"type": "boolean"},
                "requires_discovered_tools": {"type": "boolean"},
                # Pentest-derived probe modifiers
                "probe_token": {"type": "string", "enum": ["read", "null_scope"]},
                "probe_count": {"type": "integer", "minimum": 1, "maximum": 100},
                "probe_headers": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                },
            },
        },
        "assertion": {
            "type": "object",
            "required": ["target", "operator", "value"],
            "additionalProperties": False,
            "properties": {
                "target": {"type": "string"},
                "operator": {
                    "type": "string",
                    "enum": [
                        "eq", "ne", "contains", "not_contains",
                        "matches_regex", "status_in", "error_code_in",
                    ],
                },
                "value": {},
                "description": {"type": "string"},
            },
        },
    },
}

_VALIDATOR = jsonschema.Draft202012Validator(THREAT_META_SCHEMA)


def validate_threat_json(data: dict) -> None:
    """Validate a parsed threat JSON dict against the meta-schema.

    Raises SchemaValidationError with a descriptive message on failure.
    """
    errors = list(_VALIDATOR.iter_errors(data))
    if errors:
        # Report the most specific (deepest) error first
        best = jsonschema.exceptions.best_match(errors)
        raise SchemaValidationError(
            f"Schema validation failed: {best.message} "
            f"(path: {'/'.join(str(p) for p in best.absolute_path)})"
        )
