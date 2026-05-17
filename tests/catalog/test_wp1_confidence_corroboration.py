"""WP1 — confidence + corroboration (schema 1.1).

Covers:
- Schema 1.1 additive: confidence enum + probe corroboration parse.
- Corroboration semantics: a failed primary assertion WITHOUT corroborating
  positive evidence is INCONCLUSIVE, not a finding (noise suppression).
- Corroboration semantics: a failed primary assertion WITH all corroborating
  evidence present is still a FINDING.
- Low-confidence findings STILL gate (fail-closed, locked by crucible).
- Catalog hash binds corroboration + confidence (H-2 content-binding).
- Adversarial: bad confidence enum rejected; corroboration regex obeys the
  custom-catalog RE2 policy; SARIF survives schema 1.1 + confidence property.
- Real official catalog loads under the project signing path after re-sign.
"""
from __future__ import annotations

import base64
import json
import types
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cosai_mcp.api import _catalog_hash, _determine_exit_code
from cosai_mcp.catalog.loader import CatalogLoader
from cosai_mcp.catalog.models import (
    Assertion,
    Confidence,
    Operator,
    Probe,
    Provenance,
    Severity,
    ThreatDefinition,
)
from cosai_mcp.exceptions import SchemaValidationError, UnsafePatternError
from cosai_mcp.harness.result import ProbeResult

CATALOG_ROOT = Path(__file__).parent.parent.parent / "catalog"


# ---------------------------------------------------------------------------
# Real official catalog: signed + 1.1 + corroboration round-trips
# ---------------------------------------------------------------------------

def test_official_catalog_loads_after_resign() -> None:
    """Every official file verifies under the project signing path (post WP1)."""
    threats = CatalogLoader(CATALOG_ROOT).load_all()
    assert len(threats) >= 17
    t1 = next(t for t in threats if t.id == "T01-001")
    assert t1.schema_version == "1.1"
    assert t1.confidence == Confidence.HIGH
    assert len(t1.probes[0].corroboration) == 1
    t3 = next(t for t in threats if t.id == "T03-001")
    assert t3.schema_version == "1.1"
    assert all(len(p.corroboration) >= 1 for p in t3.probes)


def test_old_1_0_file_still_parses(tmp_path: Path) -> None:
    """Additive bump: a 1.0 file with no confidence/corroboration still loads."""
    base = {
        "schema_version": "1.0",
        "id": "T99-001",
        "category": "T99",
        "severity": "low",
        "cosai_ref": "T9",
        "owasp_ref": "x",
        "cwe": ["CWE-1"],
        "probes": [
            {
                "id": "p1",
                "transport": "http",
                "method": "tools/call",
                "payload": {"name": "{{tool_name}}", "arguments": {}},
                "assertions": [
                    {"target": "response.error", "operator": "eq", "value": True}
                ],
            }
        ],
        "remediation": "x",
        "references": [],
    }
    custom = tmp_path / "custom"
    custom.mkdir()
    (custom / "T99-001.json").write_text(json.dumps(base))
    loader = CatalogLoader(tmp_path, allow_custom=True)
    threats = loader.load_all()
    assert len(threats) == 1
    assert threats[0].confidence == Confidence.MEDIUM  # default
    assert threats[0].probes[0].corroboration == ()


# ---------------------------------------------------------------------------
# Corroboration semantics — entry at ProbeContext.execute_probe
# ---------------------------------------------------------------------------

def _make_threat_with_corro(corro: tuple) -> ThreatDefinition:
    probe = Probe(
        id="P-001-p1",
        transport="http",
        method="tools/call",
        payload=types.MappingProxyType({"name": "echo", "arguments": {}}),
        assertions=(
            Assertion(target="response.body", operator=Operator.NOT_CONTAINS, value="root:"),
        ),
        corroboration=corro,
    )
    return ThreatDefinition(
        schema_version="1.1",
        id="P-001",
        category="T3",
        severity=Severity.CRITICAL,
        cosai_ref="T3",
        owasp_ref="x",
        cwe=("CWE-78",),
        probes=(probe,),
        remediation="x",
        references=(),
        provenance=Provenance.OFFICIAL,
        confidence=Confidence.HIGH,
    )


@pytest.mark.asyncio
async def test_uncorroborated_failure_is_inconclusive() -> None:
    """Primary fails but corroboration absent → INCONCLUSIVE, not a finding."""
    from cosai_mcp.harness.mock_server import MockMCPServer
    from tests.probes.conftest import run_probe

    # Body contains "root:" (primary not_contains FAILS) but the corroboration
    # requires an independent ":/" marker that is NOT present.
    threat = _make_threat_with_corro(
        (Assertion(target="response.body", operator=Operator.CONTAINS, value=":/"),)
    )
    resp = {
        "jsonrpc": "2.0",
        "id": 0,
        "result": {"content": [{"type": "text", "text": "root:"}], "isError": False},
    }
    with MockMCPServer(tools_call_response=resp) as server:
        server.wait_ready()
        result = await run_probe(threat.probes[0], threat, server)
    assert result.passed is False
    assert result.inconclusive_reason is not None
    assert "corroborating" in result.inconclusive_reason.lower()


@pytest.mark.asyncio
async def test_corroborated_failure_is_finding() -> None:
    """Primary fails AND corroboration present → genuine finding (not inconclusive)."""
    from cosai_mcp.harness.mock_server import MockMCPServer
    from tests.probes.conftest import run_probe

    threat = _make_threat_with_corro(
        (Assertion(target="response.body", operator=Operator.CONTAINS, value=":/"),)
    )
    resp = {
        "jsonrpc": "2.0",
        "id": 0,
        "result": {"content": [{"type": "text", "text": "root:x:0:0:/root:/bin/sh"}], "isError": False},
    }
    with MockMCPServer(tools_call_response=resp) as server:
        server.wait_ready()
        result = await run_probe(threat.probes[0], threat, server)
    assert result.passed is False
    assert result.inconclusive_reason is None  # corroborated → real finding


@pytest.mark.asyncio
async def test_secure_server_still_passes_with_corroboration() -> None:
    """Corroboration never converts a PASS into a finding."""
    from cosai_mcp.harness.mock_server import MockMCPServer
    from tests.probes.conftest import run_probe

    threat = _make_threat_with_corro(
        (Assertion(target="response.body", operator=Operator.CONTAINS, value=":/"),)
    )
    resp = {
        "jsonrpc": "2.0",
        "id": 0,
        "result": {"content": [{"type": "text", "text": "access denied"}], "isError": False},
    }
    with MockMCPServer(tools_call_response=resp) as server:
        server.wait_ready()
        result = await run_probe(threat.probes[0], threat, server)
    assert result.passed is True
    assert result.inconclusive_reason is None


# ---------------------------------------------------------------------------
# Integration: end-to-end _run_scan, low-confidence still gates (fail-closed)
# ---------------------------------------------------------------------------

def test_low_confidence_finding_still_gates_exit_1() -> None:
    """Locked: a low-confidence finding STILL counts toward exit code 1."""
    low_conf_threat_sev = {"T01-001": Severity.LOW}
    failing = ProbeResult(
        probe_id="T01-001-p1",
        threat_id="T01-001",
        passed=False,
        status_code=200,
        response_body="",
        error=None,
        assertions=(),
        duration_seconds=0.0,
        inconclusive_reason=None,
    )
    # fail_on=low → low-severity finding gates. Confidence is irrelevant to
    # the exit code by design (reporting-only label).
    code = _determine_exit_code([failing], [], "low", low_conf_threat_sev)
    assert code == 1


def test_inconclusive_uncorroborated_does_not_gate() -> None:
    """An uncorroborated (inconclusive) probe must NOT trigger exit 1."""
    inconclusive = ProbeResult(
        probe_id="T03-001-p1",
        threat_id="T03-001",
        passed=False,
        status_code=200,
        response_body="",
        error=None,
        assertions=(),
        duration_seconds=0.0,
        inconclusive_reason="uncorroborated",
    )
    code = _determine_exit_code(
        [inconclusive], [], "low", {"T03-001": Severity.CRITICAL}
    )
    assert code == 0


# ---------------------------------------------------------------------------
# H-2: catalog hash binds corroboration + confidence
# ---------------------------------------------------------------------------

def _threat(corro=(), confidence=Confidence.MEDIUM) -> ThreatDefinition:
    probe = Probe(
        id="X-001-p1",
        transport="http",
        method="tools/call",
        payload=types.MappingProxyType({}),
        assertions=(Assertion(target="response.error", operator=Operator.EQ, value=True),),
        corroboration=corro,
    )
    return ThreatDefinition(
        schema_version="1.1", id="X-001", category="T1", severity=Severity.HIGH,
        cosai_ref="T1", owasp_ref="x", cwe=("CWE-1",), probes=(probe,),
        remediation="x", references=(), provenance=Provenance.OFFICIAL,
        confidence=confidence,
    )


def test_catalog_hash_changes_when_corroboration_changes() -> None:
    h1 = _catalog_hash([_threat(corro=())])
    h2 = _catalog_hash([
        _threat(corro=(Assertion(target="response.body", operator=Operator.CONTAINS, value="x"),))
    ])
    assert h1 != h2


def test_catalog_hash_changes_when_confidence_changes() -> None:
    h1 = _catalog_hash([_threat(confidence=Confidence.LOW)])
    h2 = _catalog_hash([_threat(confidence=Confidence.HIGH)])
    assert h1 != h2


# ---------------------------------------------------------------------------
# Adversarial inputs
# ---------------------------------------------------------------------------

def _sign(priv: Ed25519PrivateKey, data: bytes) -> bytes:
    return base64.b64encode(priv.sign(data))


def _write_official(d: Path, priv: Ed25519PrivateKey, payload: dict) -> None:
    od = d / "official"
    od.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(payload, indent=2).encode()
    (od / "T01-001.json").write_bytes(raw)
    (od / "T01-001.json.sig").write_bytes(_sign(priv, raw) + b"\n")


def test_bad_confidence_enum_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A catalog 'confidence' outside the closed enum raises SchemaValidationError."""
    priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    monkeypatch.setenv("COSAI_PUBKEY", pub_b64)
    bad = {
        "schema_version": "1.1",
        "id": "T01-001",
        "category": "T1",
        "severity": "critical",
        "cosai_ref": "T1",
        "owasp_ref": "x",
        "cwe": ["CWE-287"],
        "confidence": "certain",  # not in {low,medium,high}
        "probes": [
            {
                "id": "p1",
                "transport": "http",
                "method": "tools/call",
                "payload": {"name": "{{tool_name}}", "arguments": {}},
                "assertions": [
                    {"target": "response.error", "operator": "eq", "value": True}
                ],
            }
        ],
        "remediation": "x",
        "references": [],
    }
    _write_official(tmp_path, priv, bad)
    with pytest.raises(SchemaValidationError):
        CatalogLoader(tmp_path).load_all()


def test_corroboration_regex_blocked_in_custom_catalog(tmp_path: Path) -> None:
    """matches_regex inside a corroboration block obeys the custom RE2 policy."""
    payload = {
        "schema_version": "1.1",
        "id": "T99-001",
        "category": "T99",
        "severity": "low",
        "cosai_ref": "T9",
        "owasp_ref": "x",
        "cwe": ["CWE-1"],
        "probes": [
            {
                "id": "p1",
                "transport": "http",
                "method": "tools/call",
                "payload": {"name": "{{tool_name}}", "arguments": {}},
                "assertions": [
                    {"target": "response.error", "operator": "eq", "value": True}
                ],
                "corroboration": [
                    {"target": "response.body", "operator": "matches_regex", "value": "secret"}
                ],
            }
        ],
        "remediation": "x",
        "references": [],
    }
    custom = tmp_path / "custom"
    custom.mkdir()
    (custom / "T99-001.json").write_text(json.dumps(payload))
    # allow_regex_in_custom defaults False → corroboration regex must be rejected
    with pytest.raises(UnsafePatternError):
        CatalogLoader(tmp_path, allow_custom=True).load_all()


def test_synthesized_retry_probe_keeps_corroboration() -> None:
    """A synthesized adaptive-retry probe must NOT drop corroboration (§4)."""
    from unittest.mock import MagicMock, patch

    from cosai_mcp.harness.runner import _synthesize_probe

    corro = (Assertion(target="response.body", operator=Operator.CONTAINS, value="root:"),)
    probe = Probe(
        id="T03-001-p1",
        transport="http",
        method="tools/call",
        payload=types.MappingProxyType({"name": "{{tool_name}}", "arguments": {}}),
        assertions=(
            Assertion(target="response.body", operator=Operator.NOT_CONTAINS, value="root:"),
        ),
        corroboration=corro,
    )
    threat = _make_threat_with_corro(corro)
    threat = ThreatDefinition(
        schema_version="1.1", id="T03-001", category="T3", severity=Severity.CRITICAL,
        cosai_ref="T3", owasp_ref="x", cwe=("CWE-78",), probes=(probe,),
        remediation="x", references=(), provenance=Provenance.OFFICIAL,
        confidence=Confidence.HIGH,
    )
    fake_tool = MagicMock()
    with patch(
        "cosai_mcp.synthesis.synthesize_probe_payload",
        return_value=types.MappingProxyType({"name": "echo", "arguments": {"q": "x"}}),
    ), patch(
        "cosai_mcp.synthesis.threat_pattern_from_category", return_value="injection"
    ):
        synth = _synthesize_probe(probe, threat, fake_tool)
    assert synth is not None
    assert synth.corroboration == corro  # propagated, not dropped


def test_sarif_survives_schema_1_1_and_confidence_property() -> None:
    """Full pipeline: a 1.1 threat with confidence flows into SARIF cleanly."""
    from cosai_mcp.report.sarif import SarifBuilder, ScanContext

    ctx = ScanContext(target_url="http://t", scan_timestamp="2026-05-17", catalog_hash="h")
    b = SarifBuilder(ctx)
    failing = ProbeResult(
        probe_id="T01-001-p1", threat_id="T01-001", passed=False,
        status_code=200, response_body="", error=None, assertions=(),
        duration_seconds=0.0, inconclusive_reason=None,
    )
    b.add_result(
        result=failing, severity=Severity.CRITICAL, rule_id="T01-001",
        rule_name="T01-001", rule_description="x", owasp_ref="MCP-Top10-A01",
        cwe=("CWE-287",), confidence="high",
    )
    doc = json.loads(b.build_json())
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["confidence"] == "high"
    assert doc["runs"][0]["results"][0]["ruleId"] == "T01-001"
