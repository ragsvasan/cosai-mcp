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


class Confidence(Enum):
    """How strongly a probe's signal corroborates a real finding.

    Confidence is a *reporting label only* — it never suppresses gating.
    A low-confidence finding still counts toward --fail-on / exit code 1
    (fail-closed contract, locked by crucible).
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


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
    probe_token: str | None = None   # "read" → use config.read_token instead of auth_token
    probe_count: int = 1             # >1 → repeat N times; passes if any response satisfies assertions
    probe_headers: types.MappingProxyType | None = None  # extra HTTP headers added to the request
    # Corroboration (schema 1.1, additive): positive-evidence assertions that
    # must ALL hold for a failed primary assertion to be reported as a finding.
    # When non-empty and the primary assertions FAIL but corroboration does NOT
    # all hold, the probe is downgraded to INCONCLUSIVE (uncorroborated) rather
    # than counted as a finding.  Empty tuple = pre-1.1 behaviour (no change).
    corroboration: tuple = ()        # tuple[Assertion, ...]
    # When True, a JSON-RPC protocol-validation error (-32601/-32602/-32600/
    # -32700) is an EXPECTED *secure* outcome for this probe rather than a sign
    # the security logic was never reached.  Set for probes whose security
    # control IS rejection of a malformed/oversized/typosquatted request (T10
    # resource limits, T11 tool-name allowlist), where a method-not-found or
    # invalid-params response means the allowlist/limit fired.  Default False:
    # for payload-injection probes (T03/T08) a protocol error is vacuous and the
    # probe is downgraded to INCONCLUSIVE (audit §2 / COV-06 / COV-08).
    protocol_error_is_expected: bool = False


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
    # Confidence (schema 1.1, additive): reporting label only — NEVER gates.
    # Defaults to MEDIUM so pre-1.1 catalog files behave identically.
    confidence: Confidence = Confidence.MEDIUM
