"""Integration tests for adversarial probe infrastructure.

Covers the Opus panel ARCH findings:
- ARCH [1]: {{canary}} template variable now in allowlist
- ARCH [2]: adversarial catalog loads without .sig sidecars
- ARCH [3]: T04-ADV-001 removed (T4 locked architecture violation)
- ARCH [4]: canary_detected flows from probe result through to report
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from cosai_mcp.catalog.template import _ALLOWED_VARS, substitute_probe_payload

# ---------------------------------------------------------------------------
# ARCH [1]: {{canary}} in template allowlist
# ---------------------------------------------------------------------------

class TestCanaryTemplateVariable:

    def test_canary_in_allowed_vars(self):
        """{{canary}} must be in the template allowlist.

        ARCH [1]: adversarial probes use {{canary}} in both payload and
        assertion values. Without this, every adversarial probe fails at
        template substitution with UnknownVariableError.
        """
        assert "{{canary}}" in _ALLOWED_VARS

    def test_canary_substitution_in_payload(self):
        """{{canary}} substitution must succeed in a probe payload dict."""
        payload = {"name": "my_tool", "arguments": {"input": "{{canary}}"}}
        result = substitute_probe_payload(payload, {"canary": "COSAI_PROBE_TEST_00000000_deadbeef"})
        assert result["arguments"]["input"] == "COSAI_PROBE_TEST_00000000_deadbeef"

    def test_canary_substitution_in_nested_assertion(self):
        """{{canary}} substitution must succeed in assertion value (nested dict)."""
        assertion = {"value": "{{canary}}", "operator": "not_contains"}
        result = substitute_probe_payload(assertion, {"canary": "COSAI_PROBE_T03-ADV-001_DEADBEEF_abc123"})  # noqa: E501
        assert result["value"] == "COSAI_PROBE_T03-ADV-001_DEADBEEF_abc123"

    def test_canary_value_cannot_inject_secondary_template(self):
        """A canary value containing {{...}} must be rejected as injection.

        Defense against an adversarial server returning a response that contains
        a template token which could expand in a second pass.
        """
        from cosai_mcp.exceptions import TemplateInjectionError
        with pytest.raises(TemplateInjectionError):
            substitute_probe_payload(
                {"input": "{{canary}}"},
                {"canary": "COSAI_PROBE_{{tool_name}}_00000000_deadbeef"},
            )


# ---------------------------------------------------------------------------
# ARCH [2]: adversarial catalog loads without .sig sidecars
# ---------------------------------------------------------------------------

class TestAdversarialCatalogLoading:

    def test_adversarial_catalog_requires_sig(self, tmp_path):
        """Adversarial catalog files must have Ed25519 .sig sidecars.

        FIX [Codex P1]: Previously _load_adversarial() skipped signature verification
        (ARCH [2] rationalized dual opt-in as a substitute). The Codex review found
        this allows tampered official files to load. The fix: _load_adversarial now
        delegates to _load_official which enforces the sig check.

        Test: file without .sig raises SignatureVerificationError.
        """
        from cosai_mcp.catalog.loader import CatalogLoader
        from cosai_mcp.exceptions import SignatureVerificationError

        catalog_root = tmp_path
        adv_dir = catalog_root / "official" / "adversarial"
        adv_dir.mkdir(parents=True)

        adv_file = adv_dir / "T03-TEST-001.json"
        adv_file.write_text(json.dumps({
            "schema_version": "1.0",
            "id": "T03-TEST-001",
            "category": "T3",
            "severity": "high",
            "cosai_ref": "T3",
            "owasp_ref": "MCP-Top10-A03",
            "cwe": ["CWE-74"],
            "probes": [
                {
                    "id": "T03-TEST-001-p1",
                    "transport": "http",
                    "method": "tools/call",
                    "payload": {"name": "ping", "arguments": {}},
                    "assertions": [
                        {"target": "response.error", "operator": "eq", "value": False}
                    ]
                }
            ],
            "remediation": "Test only.",
            "references": []
        }))

        # No .sig sidecar — must raise
        loader = CatalogLoader(catalog_root, allow_adversarial=True)
        with pytest.raises(SignatureVerificationError):
            loader.load_all()

    def test_adversarial_catalog_not_loaded_without_flag(self, tmp_path):
        """Adversarial catalog must be skipped when allow_adversarial=False (default)."""
        from cosai_mcp.catalog.loader import CatalogLoader

        catalog_root = tmp_path
        adv_dir = catalog_root / "official" / "adversarial"
        adv_dir.mkdir(parents=True)
        (adv_dir / "T03-TEST-001.json").write_text(json.dumps({
            "schema_version": "1.0", "id": "T03-TEST-001", "category": "T3",
            "severity": "high", "cosai_ref": "T3", "owasp_ref": "MCP-Top10-A03",
            "cwe": ["CWE-74"],
            "probes": [], "remediation": "test", "references": []
        }))

        loader = CatalogLoader(catalog_root, allow_adversarial=False)
        threats = loader.load_all()
        assert not any(t.id == "T03-TEST-001" for t in threats)

    def test_shipped_adversarial_catalog_files_are_valid_json(self):
        """Every shipped adversarial JSON must be parseable and schema-valid.

        ARCH [1]+[2] regression: catches malformed catalog entries that would
        cause adversarial mode to fail at load time.
        """
        from cosai_mcp.catalog.schema import validate_threat_json

        catalog_root = Path(__file__).parents[2] / "catalog" / "official" / "adversarial"
        if not catalog_root.is_dir():
            pytest.skip("No adversarial catalog directory found")

        files = list(catalog_root.glob("*.json"))
        assert files, "Expected at least one adversarial catalog file"

        for f in files:
            data = json.loads(f.read_text())
            validate_threat_json(data)  # must not raise


# ---------------------------------------------------------------------------
# ARCH [3]: T04-ADV-001 removed (locked architecture violation)
# ---------------------------------------------------------------------------

class TestT4AdversarialRemoved:

    def test_t04_adv_001_not_in_shipped_catalog(self):
        """T04-ADV-001 must not exist in the shipped adversarial catalog.

        ARCH [3]: T4 (data/control boundary / prompt injection) can only be
        tested via middleware instrumentation per the locked three-engine
        architecture. Black-box canary reflection is not a valid T4 test.
        """
        catalog_root = Path(__file__).parents[2] / "catalog" / "official" / "adversarial"
        t04_adv = catalog_root / "T04-ADV-001.json"
        assert not t04_adv.exists(), (
            "T04-ADV-001.json must not exist — T4 detection requires middleware "
            "instrumentation, not black-box canary probing (locked architecture)."
        )


# ---------------------------------------------------------------------------
# ARCH [4]: canary_detected on ProbeResult
# ---------------------------------------------------------------------------

class TestCanaryDetectedField:

    def test_probe_result_has_canary_detected_field(self):
        """ProbeResult must have canary_detected field defaulting to False.

        ARCH [4]: without this field, the adversarial report cannot distinguish
        canary-hit results from ordinary failures.
        """
        from cosai_mcp.harness.result import make_probe_result

        result = make_probe_result(
            probe_id="T03-ADV-001-p1",
            threat_id="T03-ADV-001",
            passed=False,
            assertions=(),
        )
        assert hasattr(result, "canary_detected")
        assert result.canary_detected is False

    def test_probe_result_canary_detected_in_to_dict(self):
        """ProbeResult.to_dict() must include canary_detected for serialization."""
        from cosai_mcp.harness.result import make_probe_result

        result = make_probe_result(
            probe_id="T03-ADV-001-p1",
            threat_id="T03-ADV-001",
            passed=False,
            assertions=(),
        )
        d = result.to_dict()
        assert "canary_detected" in d
        assert d["canary_detected"] is False
