"""docs/EVIDENCE_PER_LEVEL.md is generated from the control catalog and must
stay in sync with it (CoSAI v2.0 evidence-per-level annex)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

from cosai_mcp.assurance.controls import CONTROLS

ROOT = Path(__file__).resolve().parent.parent


def _gen():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(
        "gen_evidence_annex", ROOT / "scripts" / "gen_evidence_annex.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_regression_evidence_annex_in_sync_with_control_catalog() -> None:
    doc = (ROOT / "docs" / "EVIDENCE_PER_LEVEL.md").read_text(encoding="utf-8")
    assert doc == _gen().render(), "run: python scripts/gen_evidence_annex.py"


def test_evidence_annex_covers_every_control_and_level_requirement() -> None:
    doc = (ROOT / "docs" / "EVIDENCE_PER_LEVEL.md").read_text(encoding="utf-8")
    for c in CONTROLS:
        assert f"### {c.control_id} — {c.title}" in doc
        for lvl in (1, 2, 3, 4):
            req = c.requirement(lvl)
            if req is not None:
                assert req.text in doc


def test_evidence_annex_reference_impls_name_real_controls() -> None:
    ids = {c.control_id for c in CONTROLS}
    assert set(_gen().REFERENCE_IMPL) <= ids


def test_regression_readme_assurance_matrix_in_sync() -> None:
    gen = _gen()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert gen.render_readme_block() in readme, "run: python scripts/gen_evidence_annex.py"


def _pr(threat_id: str):  # type: ignore[no-untyped-def]
    from cosai_mcp.harness.result import ProbeResult

    return ProbeResult(probe_id=f"{threat_id}-p1", threat_id=threat_id, passed=True,
                       status_code=200, response_body="", error=None, assertions=(),
                       duration_seconds=0.0)


def test_regression_annex_verdict_semantics_match_evaluate() -> None:
    from cosai_mcp.assurance.controls import CONTROLS_BY_ID
    from cosai_mcp.assurance.evaluate import _control_verdict
    from cosai_mcp.assurance.models import EvidenceItem, Verdict

    tn04 = CONTROLS_BY_ID["TN-04"]
    probes = [_pr("T07-004"), _pr("T07-005")]
    assert _control_verdict(tn04, 3, probes, [], {}).verdict is Verdict.PASS
    ev = {"TN-04": EvidenceItem("TN-04", "x.txt", "0" * 64)}
    assert _control_verdict(tn04, 3, probes, [], ev).verdict is Verdict.ATTESTED
    assert _control_verdict(tn04, 4, probes, [], {}).verdict is Verdict.UNVERIFIED
    sd02 = CONTROLS_BY_ID["SD-02"]
    promoted = frozenset(sd02.optional_probes)
    sd02_ev = {"SD-02": EvidenceItem("SD-02", "x.txt", "0" * 64)}
    # promoted optional disproof test absent -> UNVERIFIED even with evidence
    assert _control_verdict(sd02, 2, [], [], sd02_ev, promoted).verdict is Verdict.UNVERIFIED
    doc = (ROOT / "docs" / "EVIDENCE_PER_LEVEL.md").read_text(encoding="utf-8")
    for phrase in ("takes precedence over a passing proof", "`not_required`",
                   "`unverified` (default)", "required when the target exposes that surface"):
        assert phrase in doc


def test_regression_annex_reference_impls_resolve() -> None:
    import importlib

    gen = _gen()
    for module, attr in gen.COSAI_SYMBOLS:
        obj = importlib.import_module(module)
        for part in attr.split("."):
            obj = getattr(obj, part)
    doc = (ROOT / "docs" / "EVIDENCE_PER_LEVEL.md").read_text(encoding="utf-8")
    assert "not yet in a released version" in doc and "opt-in" in doc


def test_annex_mentions_every_linked_test_id() -> None:
    doc = (ROOT / "docs" / "EVIDENCE_PER_LEVEL.md").read_text(encoding="utf-8")
    for c in CONTROLS:
        for tid in (*c.probe_threats, *c.verify_with, *c.optional_probes):
            assert f"`{tid}`" in doc, (c.control_id, tid)


def test_regression_readme_matrix_counts_match_annex_semantics() -> None:
    block = _gen().render_readme_block()
    assert "TN-04 (≤L3)" in block and "surface-dependent" in block


def test_regression_gen_check_mode_detects_stale_and_missing_markers(
        tmp_path: Path) -> None:
    import pytest

    gen = _gen()
    mp = pytest.MonkeyPatch()
    try:
        doc, readme = tmp_path / "doc.md", tmp_path / "README.md"
        mp.setattr(gen, "DOC", doc)
        mp.setattr(gen, "README", readme)
        readme.write_text(f"x\n{gen._START}\n{gen._END}\n", encoding="utf-8")
        doc.write_text("stale", encoding="utf-8")
        assert gen.main(["--check"]) == 1
        assert gen.main([]) == 0 and gen.main(["--check"]) == 0
        readme.write_text("no markers", encoding="utf-8")
        assert gen.main(["--check"]) == 2
    finally:
        mp.undo()
