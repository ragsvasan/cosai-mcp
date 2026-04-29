"""Frozen dataclass models for threat catalog entries."""
from __future__ import annotations

import types
from dataclasses import dataclass
from enum import Enum


class Provenance(Enum):
    OFFICIAL = "official"
    CUSTOM = "custom"  # reports mark as UNTRUSTED


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Operator(Enum):
    EQ = "eq"
    NE = "ne"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    MATCHES_REGEX = "matches_regex"
    STATUS_IN = "status_in"
    ERROR_CODE_IN = "error_code_in"


@dataclass(frozen=True)
class Assertion:
    target: str          # e.g. "response.error", "response.body", "response.error.code"
    operator: Operator
    value: object        # str | bool | int | tuple
    compiled_pattern: object = None  # re2 compiled pattern if operator == MATCHES_REGEX


@dataclass(frozen=True)
class Probe:
    id: str
    transport: str                   # "http", "stdio"
    method: str                      # JSON-RPC method name
    payload: types.MappingProxyType  # frozen dict
    assertions: tuple                # tuple[Assertion, ...]


@dataclass(frozen=True)
class ThreatDefinition:
    schema_version: str
    id: str
    category: str
    severity: Severity
    cosai_ref: str
    owasp_ref: str
    cwe: tuple           # tuple[str, ...]
    probes: tuple        # tuple[Probe, ...]
    remediation: str
    references: tuple    # tuple[str, ...]
    provenance: Provenance
    mode: str = "read-only"  # adversarial-only: "read-only" | "stateful"
