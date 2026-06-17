"""T3: JSON schema strict mode, injection guards."""
from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import Any

import jsonschema

# RE2-compatible injection patterns — no backtracking constructs
_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("sql_injection",      re.compile(
        r"(?:union\s+select|drop\s+table|insert\s+into|delete\s+from|exec\s*\(|xp_cmdshell)",
        re.IGNORECASE,
    )),
    ("path_traversal",     re.compile(r"\.\.[\\/]")),
    ("null_byte",          re.compile(r"\x00")),
    ("shell_metachar",     re.compile(r"[;&|`]")),
    ("template_injection", re.compile(r"\{\{.{0,200}\}\}|\$\{.{0,200}\}")),
    ("script_injection",   re.compile(r"<\s*script\b", re.IGNORECASE)),
    ("crlf_injection",     re.compile(r"\r\n|\r(?!\n)")),
]


@dataclass(frozen=True)
class ValidationFinding:
    """A single validation failure."""
    parameter: str    # dot-path, e.g. "arguments.query"
    issue: str        # e.g. "injection:sql_injection" or "schema_violation:required"
    excerpt: str      # HTML-escaped context (safe to display)


class ParameterValidationError(Exception):
    """Raised when tool call parameters fail validation.

    ``findings`` contains all discovered issues so callers can log without
    leaking raw parameter values in error responses.
    """

    def __init__(self, tool_name: str, findings: list[ValidationFinding]) -> None:
        super().__init__(
            f"Parameter validation failed for tool '{tool_name}': "
            f"{len(findings)} finding(s)"
        )
        self.tool_name = tool_name
        self.findings: tuple[ValidationFinding, ...] = tuple(findings)


class InjectionGuard:
    """Recursively scan parameter values for injection patterns.

    Stops at the first matching pattern per parameter path (prevents probing
    the scanner's detection logic via partial matches).
    """

    def scan(
        self,
        params: dict[str, Any],
        path: str = "arguments",
    ) -> list[ValidationFinding]:
        """Return a list of findings; empty list means clean."""
        findings: list[ValidationFinding] = []
        self._scan_value(params, path, findings)
        return findings

    def _scan_value(
        self,
        value: Any,
        path: str,
        findings: list[ValidationFinding],
    ) -> None:
        if isinstance(value, str):
            for label, pattern in _INJECTION_PATTERNS:
                m = pattern.search(value)
                if m:
                    start = max(0, m.start() - 30)
                    end = min(len(value), m.end() + 30)
                    excerpt = html.escape(value[start:end], quote=True)
                    findings.append(ValidationFinding(
                        parameter=path,
                        issue=f"injection:{label}",
                        excerpt=excerpt,
                    ))
                    return  # one finding per path; stop on first match
        elif isinstance(value, dict):
            for k, v in value.items():
                self._scan_value(v, f"{path}.{k}", findings)
        elif isinstance(value, (list, tuple)):
            for i, v in enumerate(value):
                self._scan_value(v, f"{path}[{i}]", findings)


class ParameterValidator:
    """Validate tool call parameters against registered JSON Schemas.

    Schemas are registered per tool name. Unknown tools are rejected by default.
    Validation is strict: ``additionalProperties: false`` is enforced when the
    schema declares ``properties`` but omits ``additionalProperties``.

    After schema validation, InjectionGuard scans all string values.
    """

    def __init__(self, allow_unknown_tools: bool = False) -> None:
        self._schemas: dict[str, dict[str, Any]] = {}
        self._allow_unknown = allow_unknown_tools
        self._guard = InjectionGuard()

    def register_schema(self, tool_name: str, schema: dict[str, Any]) -> None:
        """Register a JSON Schema for a tool's ``arguments`` dict.

        Raises ``jsonschema.SchemaError`` if *schema* is not a valid JSON Schema.
        """
        jsonschema.Draft7Validator.check_schema(schema)
        self._schemas[tool_name] = schema

    def validate(self, tool_name: str, arguments: dict[str, Any]) -> None:
        """Validate *arguments* for *tool_name*.

        Raises ``ParameterValidationError`` if any check fails.
        """
        findings: list[ValidationFinding] = []

        # Injection scan runs first so injection findings are captured even when
        # the tool has no registered schema (audit signal preserved before early raise).
        findings.extend(self._guard.scan(arguments))

        if tool_name not in self._schemas:
            if not self._allow_unknown:
                findings.append(ValidationFinding(
                    parameter="tool_name",
                    issue="schema_not_registered",
                    excerpt=html.escape(tool_name[:120], quote=True),
                ))
                raise ParameterValidationError(tool_name, findings)
        else:
            schema = dict(self._schemas[tool_name])
            # Strict mode: reject extra properties when schema declares properties.
            if "properties" in schema and "additionalProperties" not in schema:
                schema["additionalProperties"] = False

            validator = jsonschema.Draft7Validator(schema)
            for err in validator.iter_errors(arguments):
                param_path = ".".join(str(p) for p in err.absolute_path) or "arguments"
                findings.append(ValidationFinding(
                    parameter=param_path,
                    issue=f"schema_violation:{err.validator}",
                    excerpt=html.escape(err.message[:120], quote=True),
                ))

        if findings:
            raise ParameterValidationError(tool_name, findings)
