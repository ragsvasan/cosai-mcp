"""Catalog schema 1.3 — CoSAI MCP Security v2.0 labels (mcp_t_ref, threat_refs).

Every official entry (including adversarial) carries its MCP-Tn label and the
numbered v2.0 threats it tests, each number constrained to the v2.0 §3.1 threat
table for the entry's category. Labels reach SARIF rule properties.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from cosai_mcp.catalog.loader import CatalogLoader
from cosai_mcp.catalog.schema import validate_threat_json
from cosai_mcp.exceptions import SchemaValidationError
from cosai_mcp.harness.mock_server import MockMCPServer

CATALOG_ROOT = Path(__file__).resolve().parents[2] / "catalog"

# CoSAI MCP Security v2.0 §3.1 threat table: threats listed per category
# (MCP-specific, contextualized, and conventional columns).
V2_THREATS_BY_CATEGORY: dict[str, set[int]] = {
    "T1": {1, 8, 16, 17, 18, 19},
    "T2": {8, 9, 10, 20},
    "T3": {21, 22, 23},
    "T4": {2, 3, 4, 11, 21},
    "T5": {22, 24},
    "T6": {4, 5, 6, 25},
    "T7": {12, 17, 19, 23, 26, 27, 28, 29, 30},
    "T8": {6, 10, 26, 31, 32},
    "T9": {7, 13},
    "T10": {14, 33},
    "T11": {6, 25},
    "T12": {15, 34},
}


def _official_files() -> list[dict[str, Any]]:
    return [json.loads(p.read_text()) for p in sorted((CATALOG_ROOT / "official").rglob("*.json"))]


def test_every_official_entry_is_labelled() -> None:
    docs = _official_files()
    assert len(docs) >= 50
    for d in docs:
        assert d["schema_version"] == "1.3", d["id"]
        assert d["mcp_t_ref"] == "MCP-" + d["category"], d["id"]
        assert d["threat_refs"], d["id"]


def test_threat_refs_follow_v2_category_table() -> None:
    for d in _official_files():
        allowed = V2_THREATS_BY_CATEGORY[d["category"]]
        assert set(d["threat_refs"]) <= allowed, (d["id"], d["threat_refs"], allowed)


def test_loaded_definitions_expose_labels_and_tiers() -> None:
    threats = {t.id: t for t in CatalogLoader(CATALOG_ROOT).load_all()}
    t = threats["T01-001"]
    assert t.mcp_t_ref == "MCP-T1" and t.threat_refs == (1, 18)
    assert t.threat_tiers == (1, 3)          # 1 = MCP-specific, 18 = conventional
    assert threats["T02-003"].threat_tiers == (2,)


def _base_doc() -> dict[str, Any]:
    return copy.deepcopy(json.loads((CATALOG_ROOT / "official" / "T01-001.json").read_text()))


@pytest.mark.parametrize(("field", "value"), [
    ("mcp_t_ref", "MCP-T13"),
    ("mcp_t_ref", "T1"),
    ("threat_refs", []),
    ("threat_refs", [0]),
    ("threat_refs", [35]),
    ("threat_refs", [1, 1]),
    ("threat_refs", ["1"]),
])
def test_schema_rejects_bad_labels(field: str, value: Any) -> None:
    doc = _base_doc()
    doc[field] = value
    with pytest.raises(SchemaValidationError):
        validate_threat_json(doc)


def test_older_schema_without_labels_still_validates() -> None:
    doc = _base_doc()
    doc["schema_version"] = "1.0"
    del doc["mcp_t_ref"], doc["threat_refs"]
    validate_threat_json(doc)


def test_labels_reach_sarif_rule_properties(tmp_path: Path) -> None:
    from cosai_mcp.cli import main

    sarif = tmp_path / "out.sarif"
    with MockMCPServer() as server:
        server.wait_ready()
        CliRunner().invoke(main, [
            "scan", f"http://127.0.0.1:{server.port}", "--allow-private-targets",
            "--categories", "T8", "--engine", "prober", "--no-report",
            "--report-sarif", str(sarif),
        ])
    rules = json.loads(sarif.read_text())["runs"][0]["tool"]["driver"]["rules"]
    t8 = [r for r in rules if r["id"].startswith("T08-")]
    assert t8, rules
    for rule in t8:
        props = rule["properties"]
        assert props["cosai_mcp_t"] == "MCP-T8"
        assert props["cosai_threats"] == [26]
        assert props["cosai_threat_tiers"] == [3]
