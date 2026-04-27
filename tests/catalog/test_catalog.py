"""Full test suite for cosai_mcp catalog: models, schema, loader, template.

All mocks use create_autospec to enforce real signatures.
Keypair is generated fresh per test session; COSAI_PUBKEY is set accordingly.
"""
from __future__ import annotations

import base64
import json
import os
import types
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cosai_mcp.catalog.loader import CatalogLoader
from cosai_mcp.catalog.models import Assertion, Operator, Probe, Provenance, ThreatDefinition
from cosai_mcp.catalog.template import substitute_probe_payload
from cosai_mcp.exceptions import (
    PathTraversalError,
    SchemaValidationError,
    SignatureVerificationError,
    TemplateInjectionError,
    UnsafePatternError,
    UnknownVariableError,
)

# ---------------------------------------------------------------------------
# Session-scoped keypair fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def test_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture(scope="session")
def test_public_key_bytes(test_private_key: Ed25519PrivateKey) -> bytes:
    return test_private_key.public_key().public_bytes_raw()


@pytest.fixture(scope="session")
def test_pubkey_b64(test_public_key_bytes: bytes) -> str:
    return base64.b64encode(test_public_key_bytes).decode()


def _sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    return base64.b64encode(private_key.sign(data))


# ---------------------------------------------------------------------------
# Helper: build a minimal valid threat JSON dict
# ---------------------------------------------------------------------------

_BASE_THREAT = {
    "schema_version": "1.0",
    "id": "T01-001",
    "category": "T1",
    "severity": "critical",
    "cosai_ref": "T1",
    "owasp_ref": "MCP-Top10-A01",
    "cwe": ["CWE-287"],
    "probes": [
        {
            "id": "T01-001-p1",
            "transport": "http",
            "method": "tools/call",
            "payload": {"name": "{{tool_name}}", "arguments": {}},
            "assertions": [
                {"target": "response.error", "operator": "eq", "value": True}
            ],
        }
    ],
    "remediation": "Enforce authentication on all MCP endpoints.",
    "references": ["https://cosai.org/T1"],
}


def _write_official_file(
    directory: Path,
    private_key: Ed25519PrivateKey,
    data: dict | None = None,
    filename: str = "T01-001.json",
    tamper_after_sign: bool = False,
) -> Path:
    """Write a JSON file + .sig sidecar to directory/official/."""
    official_dir = directory / "official"
    official_dir.mkdir(parents=True, exist_ok=True)
    payload = data or _BASE_THREAT
    raw = json.dumps(payload, indent=2).encode()
    sig = _sign(private_key, raw)
    json_path = official_dir / filename
    json_path.write_bytes(raw)
    sig_path = json_path.with_suffix(".json.sig")
    sig_path.write_bytes(sig + b"\n")
    if tamper_after_sign:
        # Mutate the file content AFTER signing to invalidate the signature
        tampered = json.loads(raw)
        tampered["severity"] = "low"
        json_path.write_bytes(json.dumps(tampered, indent=2).encode())
    return json_path


def _write_custom_file(
    directory: Path,
    data: dict | None = None,
    filename: str = "T99-001.json",
) -> Path:
    """Write a custom catalog JSON file (no sidecar)."""
    custom_dir = directory / "custom"
    custom_dir.mkdir(parents=True, exist_ok=True)
    payload = data or {**_BASE_THREAT, "id": "T99-001"}
    raw = json.dumps(payload, indent=2).encode()
    json_path = custom_dir / filename
    json_path.write_bytes(raw)
    return json_path


# ---------------------------------------------------------------------------
# Signature tests
# ---------------------------------------------------------------------------

def test_signature_valid(
    tmp_path: Path,
    test_private_key: Ed25519PrivateKey,
    test_pubkey_b64: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Valid Ed25519 signature: file loads cleanly."""
    monkeypatch.setenv("COSAI_PUBKEY", test_pubkey_b64)
    _write_official_file(tmp_path, test_private_key)
    loader = CatalogLoader(tmp_path)
    threats = loader.load_all()
    assert len(threats) == 1
    assert threats[0].id == "T01-001"
    assert threats[0].provenance == Provenance.OFFICIAL


def test_signature_tampered_content(
    tmp_path: Path,
    test_private_key: Ed25519PrivateKey,
    test_pubkey_b64: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Content modified after signing raises SignatureVerificationError."""
    monkeypatch.setenv("COSAI_PUBKEY", test_pubkey_b64)
    _write_official_file(tmp_path, test_private_key, tamper_after_sign=True)
    loader = CatalogLoader(tmp_path)
    with pytest.raises(SignatureVerificationError):
        loader.load_all()


def test_signature_wrong_pubkey_env(
    tmp_path: Path,
    test_private_key: Ed25519PrivateKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """COSAI_PUBKEY set to a different valid key raises SignatureVerificationError."""
    _write_official_file(tmp_path, test_private_key)
    # Generate a second keypair whose public key does NOT match the signer
    other_key = Ed25519PrivateKey.generate()
    other_pub_b64 = base64.b64encode(
        other_key.public_key().public_bytes_raw()
    ).decode()
    monkeypatch.setenv("COSAI_PUBKEY", other_pub_b64)
    loader = CatalogLoader(tmp_path)
    with pytest.raises(SignatureVerificationError):
        loader.load_all()


# ---------------------------------------------------------------------------
# Schema validation tests
# ---------------------------------------------------------------------------

def test_schema_unknown_field_rejected(
    tmp_path: Path,
    test_private_key: Ed25519PrivateKey,
    test_pubkey_b64: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Extra field in JSON raises SchemaValidationError."""
    monkeypatch.setenv("COSAI_PUBKEY", test_pubkey_b64)
    bad = {**_BASE_THREAT, "unexpected_field": "oops"}
    _write_official_file(tmp_path, test_private_key, data=bad)
    loader = CatalogLoader(tmp_path)
    with pytest.raises(SchemaValidationError):
        loader.load_all()


def test_schema_closed_operator_enum(
    tmp_path: Path,
    test_private_key: Ed25519PrivateKey,
    test_pubkey_b64: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid operator value raises SchemaValidationError."""
    monkeypatch.setenv("COSAI_PUBKEY", test_pubkey_b64)
    bad = {
        **_BASE_THREAT,
        "probes": [
            {
                **_BASE_THREAT["probes"][0],
                "assertions": [
                    {"target": "response.error", "operator": "regex", "value": True}
                ],
            }
        ],
    }
    _write_official_file(tmp_path, test_private_key, data=bad)
    loader = CatalogLoader(tmp_path)
    with pytest.raises(SchemaValidationError):
        loader.load_all()


def test_schema_version_must_be_1_0(
    tmp_path: Path,
    test_private_key: Ed25519PrivateKey,
    test_pubkey_b64: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """schema_version '2.0' raises SchemaValidationError."""
    monkeypatch.setenv("COSAI_PUBKEY", test_pubkey_b64)
    bad = {**_BASE_THREAT, "schema_version": "2.0"}
    _write_official_file(tmp_path, test_private_key, data=bad)
    loader = CatalogLoader(tmp_path)
    with pytest.raises(SchemaValidationError):
        loader.load_all()


# ---------------------------------------------------------------------------
# Path traversal tests
# ---------------------------------------------------------------------------

def test_path_traversal_absolute_rejected(tmp_path: Path) -> None:
    """Absolute path raises PathTraversalError."""
    loader = CatalogLoader(tmp_path)
    with pytest.raises(PathTraversalError):
        loader.load_file(Path("/etc/passwd"))


def test_path_traversal_dotdot_rejected(tmp_path: Path) -> None:
    """../../etc/passwd raises PathTraversalError."""
    loader = CatalogLoader(tmp_path)
    with pytest.raises(PathTraversalError):
        loader.load_file(Path("../../etc/passwd"))


# ---------------------------------------------------------------------------
# Custom catalog gating tests
# ---------------------------------------------------------------------------

def test_custom_catalog_disabled_by_default(
    tmp_path: Path,
    test_private_key: Ed25519PrivateKey,
    test_pubkey_b64: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without allow_custom, custom files are not loaded."""
    monkeypatch.setenv("COSAI_PUBKEY", test_pubkey_b64)
    _write_official_file(tmp_path, test_private_key)
    _write_custom_file(tmp_path)
    loader = CatalogLoader(tmp_path, allow_custom=False)
    threats = loader.load_all()
    ids = [t.id for t in threats]
    assert "T99-001" not in ids
    assert "T01-001" in ids


def test_custom_catalog_enabled_with_flag(
    tmp_path: Path,
    test_private_key: Ed25519PrivateKey,
    test_pubkey_b64: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """allow_custom=True loads custom file marked UNTRUSTED (CUSTOM provenance)."""
    monkeypatch.setenv("COSAI_PUBKEY", test_pubkey_b64)
    _write_official_file(tmp_path, test_private_key)
    _write_custom_file(tmp_path)
    loader = CatalogLoader(tmp_path, allow_custom=True)
    threats = loader.load_all()
    custom = next(t for t in threats if t.id == "T99-001")
    assert custom.provenance == Provenance.CUSTOM


# ---------------------------------------------------------------------------
# ReDoS / regex safety tests
# ---------------------------------------------------------------------------

def test_redos_pattern_rejected(
    tmp_path: Path,
    test_private_key: Ed25519PrivateKey,
    test_pubkey_b64: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RE2-invalid pattern (backreference \\1) raises UnsafePatternError at catalog load time.

    RE2 guarantees linear-time matching so it cannot suffer ReDoS; it rejects
    patterns that require backtracking semantics such as backreferences and
    lookbehind assertions.  Any pattern RE2 refuses to compile is surfaced as
    UnsafePatternError regardless of the specific RE2 rejection reason.
    """
    monkeypatch.setenv("COSAI_PUBKEY", test_pubkey_b64)
    bad = {
        **_BASE_THREAT,
        "probes": [
            {
                **_BASE_THREAT["probes"][0],
                "assertions": [
                    {
                        "target": "response.body",
                        "operator": "matches_regex",
                        "value": r"(?<=abc)def",  # lookbehind — RE2 rejects
                    }
                ],
            }
        ],
    }
    _write_official_file(tmp_path, test_private_key, data=bad)
    loader = CatalogLoader(tmp_path)
    with pytest.raises(UnsafePatternError):
        loader.load_all()


def test_regex_disabled_in_custom_without_flag(
    tmp_path: Path,
    test_private_key: Ed25519PrivateKey,
    test_pubkey_b64: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Custom file with matches_regex raises UnsafePatternError without allow_regex_in_custom."""
    monkeypatch.setenv("COSAI_PUBKEY", test_pubkey_b64)
    custom_data = {
        **_BASE_THREAT,
        "id": "T99-002",
        "probes": [
            {
                **_BASE_THREAT["probes"][0],
                "id": "T99-002-p1",
                "assertions": [
                    {
                        "target": "response.body",
                        "operator": "matches_regex",
                        "value": "^[a-z]+$",
                    }
                ],
            }
        ],
    }
    _write_custom_file(tmp_path, data=custom_data, filename="T99-002.json")
    loader = CatalogLoader(tmp_path, allow_custom=True, allow_regex_in_custom=False)
    with pytest.raises(UnsafePatternError):
        loader.load_all()


def test_regex_enabled_in_custom_with_flag(
    tmp_path: Path,
    test_private_key: Ed25519PrivateKey,
    test_pubkey_b64: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """allow_regex_in_custom=True: safe RE2 pattern compiles successfully."""
    monkeypatch.setenv("COSAI_PUBKEY", test_pubkey_b64)
    custom_data = {
        **_BASE_THREAT,
        "id": "T99-003",
        "probes": [
            {
                **_BASE_THREAT["probes"][0],
                "id": "T99-003-p1",
                "assertions": [
                    {
                        "target": "response.body",
                        "operator": "matches_regex",
                        "value": "^[a-z]+$",
                    }
                ],
            }
        ],
    }
    _write_custom_file(tmp_path, data=custom_data, filename="T99-003.json")
    loader = CatalogLoader(tmp_path, allow_custom=True, allow_regex_in_custom=True)
    threats = loader.load_all()
    custom = next(t for t in threats if t.id == "T99-003")
    assertion = custom.probes[0].assertions[0]
    assert assertion.operator == Operator.MATCHES_REGEX
    assert assertion.compiled_pattern is not None


# ---------------------------------------------------------------------------
# Template substitution tests
# ---------------------------------------------------------------------------

def test_template_no_double_expansion() -> None:
    """Variable value IS '{{target_url}}'; raises TemplateInjectionError on substitution."""
    payload = {"name": "{{tool_name}}", "url": "{{target_url}}"}
    # Substitute tool_name with a value that itself contains a template token
    with pytest.raises((TemplateInjectionError, UnknownVariableError)):
        substitute_probe_payload(
            payload,
            {"tool_name": "{{target_url}}"},  # double-expansion attempt
        )


def test_template_no_json_injection() -> None:
    """Value with JSON-injection characters does not add keys to result dict."""
    payload = {"name": "{{tool_name}}"}
    result = substitute_probe_payload(
        payload,
        {"tool_name": '"; "evil": true'},
    )
    # The injected string is just a string value, not a new key
    assert "evil" not in result
    assert result["name"] == '"; "evil": true'


def test_template_injection_detected() -> None:
    """Substituted value still contains '{{'; raises TemplateInjectionError."""
    payload = {"cmd": "{{tool_name}}"}
    with pytest.raises(TemplateInjectionError):
        substitute_probe_payload(
            payload,
            {"tool_name": "{{still_here}}"},
        )


def test_template_unknown_variable_rejected() -> None:
    """{{unknown_var}} in payload raises UnknownVariableError."""
    payload = {"cmd": "{{unknown_var}}"}
    with pytest.raises(UnknownVariableError):
        substitute_probe_payload(payload, {})


# ---------------------------------------------------------------------------
# Provenance tests
# ---------------------------------------------------------------------------

def test_provenance_official_from_load_path(
    tmp_path: Path,
    test_private_key: Ed25519PrivateKey,
    test_pubkey_b64: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """File loaded from catalog/official/ has provenance == Provenance.OFFICIAL."""
    monkeypatch.setenv("COSAI_PUBKEY", test_pubkey_b64)
    _write_official_file(tmp_path, test_private_key)
    loader = CatalogLoader(tmp_path)
    threats = loader.load_all()
    assert threats[0].provenance == Provenance.OFFICIAL


def test_provenance_custom_from_load_path(
    tmp_path: Path,
    test_private_key: Ed25519PrivateKey,
    test_pubkey_b64: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """File loaded from catalog/custom/ has provenance == Provenance.CUSTOM."""
    monkeypatch.setenv("COSAI_PUBKEY", test_pubkey_b64)
    _write_custom_file(tmp_path)
    loader = CatalogLoader(tmp_path, allow_custom=True)
    threats = loader.load_all()
    assert threats[0].provenance == Provenance.CUSTOM


# ---------------------------------------------------------------------------
# Frozen dataclass immutability tests
# ---------------------------------------------------------------------------

def test_frozen_dataclass_cwe_is_tuple(
    tmp_path: Path,
    test_private_key: Ed25519PrivateKey,
    test_pubkey_b64: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """threat.cwe is tuple, not list."""
    monkeypatch.setenv("COSAI_PUBKEY", test_pubkey_b64)
    _write_official_file(tmp_path, test_private_key)
    loader = CatalogLoader(tmp_path)
    threat = loader.load_all()[0]
    assert isinstance(threat.cwe, tuple)


def test_frozen_dataclass_no_list_mutation(
    tmp_path: Path,
    test_private_key: Ed25519PrivateKey,
    test_pubkey_b64: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """threat.cwe.append(...) raises AttributeError (tuples have no append)."""
    monkeypatch.setenv("COSAI_PUBKEY", test_pubkey_b64)
    _write_official_file(tmp_path, test_private_key)
    loader = CatalogLoader(tmp_path)
    threat = loader.load_all()[0]
    with pytest.raises(AttributeError):
        threat.cwe.append("CWE-999")  # type: ignore[attr-defined]


def test_frozen_dataclass_payload_is_mappingproxy(
    tmp_path: Path,
    test_private_key: Ed25519PrivateKey,
    test_pubkey_b64: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """probe.payload is MappingProxyType."""
    monkeypatch.setenv("COSAI_PUBKEY", test_pubkey_b64)
    _write_official_file(tmp_path, test_private_key)
    loader = CatalogLoader(tmp_path)
    threat = loader.load_all()[0]
    assert isinstance(threat.probes[0].payload, types.MappingProxyType)


# ---------------------------------------------------------------------------
# Regression tests (explicit regression tag)
# ---------------------------------------------------------------------------

def test_regression_redos_pattern_rejected(
    tmp_path: Path,
    test_private_key: Ed25519PrivateKey,
    test_pubkey_b64: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: patterns RE2 refuses must be rejected at catalog load time, not at scan time.

    Uses a lookbehind assertion which RE2 (correctly) refuses to compile.
    Backreferences and lookaheads require backtracking and are outside RE2's
    linear-time guarantee — they are rejected outright rather than compiled.
    """
    monkeypatch.setenv("COSAI_PUBKEY", test_pubkey_b64)
    bad = {
        **_BASE_THREAT,
        "probes": [
            {
                **_BASE_THREAT["probes"][0],
                "assertions": [
                    {
                        "target": "response.body",
                        "operator": "matches_regex",
                        "value": r"(?!abc)def",  # negative lookahead — RE2 rejects
                    }
                ],
            }
        ],
    }
    _write_official_file(tmp_path, test_private_key, data=bad)
    loader = CatalogLoader(tmp_path)
    with pytest.raises(UnsafePatternError):
        loader.load_all()


def test_regression_template_no_double_expansion() -> None:
    """Regression: template value containing '{{target_url}}' triggers injection guard."""
    payload = {"url": "{{target_url}}"}
    with pytest.raises((TemplateInjectionError, UnknownVariableError)):
        substitute_probe_payload(
            payload,
            {"target_url": "{{target_url}}"},  # double-expansion
        )


def test_regression_template_no_json_injection() -> None:
    """Regression: injected JSON special chars remain as string value, not parsed keys."""
    payload = {"name": "{{tool_name}}"}
    result = substitute_probe_payload(payload, {"tool_name": '{"injected": true}'})
    assert "injected" not in result
    assert isinstance(result["name"], str)


def test_regression_path_confinement_prefix_bypass(tmp_path: Path) -> None:
    """Regression: str.startswith() allowed /catalog_root_extra/ when catalog was
    /catalog_root — Path.is_relative_to() rejects it.

    A sibling directory whose name shares a string prefix with the catalog root
    was accessible via a ../<sibling_name>/file.json relative path with the old
    startswith check.
    """
    # Create a sibling whose resolved path shares a string prefix with tmp_path
    sibling = tmp_path.parent / (tmp_path.name + "sibling")
    sibling.mkdir(exist_ok=True)
    (sibling / "evil.json").write_text("{}")

    # Demonstrate the bug: old str.startswith would have returned True
    resolved = (sibling / "evil.json").resolve()
    catalog_resolved = tmp_path.resolve()
    assert str(resolved).startswith(str(catalog_resolved)), (
        "Test setup: sibling path must share a string prefix with catalog_root "
        "(otherwise this test doesn't prove the is_relative_to fix)"
    )
    # is_relative_to must correctly identify it's outside
    assert not resolved.is_relative_to(catalog_resolved)

    # And the loader must reject the traversal path
    loader = CatalogLoader(tmp_path)
    with pytest.raises(PathTraversalError):
        loader.load_file(Path("..") / (tmp_path.name + "sibling") / "evil.json")


def test_regression_template_brace_in_value_rejected() -> None:
    """Regression: double-brace sequence in a variable value must be rejected.

    A value of '{{session_id}}' could be double-expanded if session_id is also
    in scope. The value validation now rejects '{{' and '}}' in values.
    """
    payload = {"name": "{{tool_name}}"}
    # Double-brace in value — template syntax in a value is always injection
    with pytest.raises(TemplateInjectionError):
        substitute_probe_payload(payload, {"tool_name": "{{session_id}}"})


def test_regression_template_single_brace_allowed() -> None:
    """Regression: single-brace JSON content in values must NOT be rejected.

    Only double-braces (template syntax) are blocked; single braces in JSON
    strings are legitimate and must pass through unchanged.
    """
    payload = {"name": "{{tool_name}}"}
    result = substitute_probe_payload(payload, {"tool_name": '{"key": "value"}'})
    assert result["name"] == '{"key": "value"}'
