"""WP4 — honest coverage matrix reconciliation.

`cosai_mcp.api.COVERAGE_MATRIX` is the single source of truth. These tests
fail if:

- The README / ANALYSIS_AND_RATIONALE narrative drifts back to an
  "all 12 categories implemented" headline that the engines do not deliver.
- A middleware module flips between stub and implemented without the docs
  being updated (the doc list of not-implemented modules is asserted against
  the actual import behaviour).
- `COVERAGE_MATRIX` and `MIDDLEWARE_ONLY_CATEGORIES` disagree.
"""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from cosai_mcp.api import COVERAGE_MATRIX, MIDDLEWARE_ONLY_CATEGORIES

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"
ANALYSIS = REPO_ROOT / "docs" / "ANALYSIS_AND_RATIONALE.md"

# Locked truth (CLAUDE.md): T4/T9/T12 are middleware-only; black-box probing
# is structurally wrong for them.
_EXPECTED_MIDDLEWARE_ONLY = frozenset({"T4", "T9", "T12"})

# Locked truth: these four middleware modules are not-yet-implemented stubs.
_STUB_MODULES = ("authz", "validation", "session", "supply_chain")
_IMPLEMENTED_MODULES = (
    "auth", "boundary", "protection", "integrity",
    "network", "trust", "resources", "audit",
)


class TestMatrixInternalConsistency:
    def test_all_twelve_categories_present(self) -> None:
        assert set(COVERAGE_MATRIX) == {f"T{i}" for i in range(1, 13)}

    def test_middleware_only_set_matches_matrix(self) -> None:
        derived = {
            cat for cat, eng in COVERAGE_MATRIX.items()
            if eng == "middleware-only"
        }
        assert derived == MIDDLEWARE_ONLY_CATEGORIES == _EXPECTED_MIDDLEWARE_ONLY

    def test_zero_config_count_is_nine(self) -> None:
        zero_config = [
            c for c, e in COVERAGE_MATRIX.items() if e != "middleware-only"
        ]
        assert len(zero_config) == 9


class TestMiddlewareStubStatusMatchesDocs:
    @pytest.mark.parametrize("mod", _STUB_MODULES)
    def test_stub_module_raises_not_implemented(self, mod: str) -> None:
        import sys

        sys.modules.pop(f"cosai_mcp.middleware.{mod}", None)
        with pytest.raises(NotImplementedError):
            importlib.import_module(f"cosai_mcp.middleware.{mod}")

    @pytest.mark.parametrize("mod", _IMPLEMENTED_MODULES)
    def test_implemented_module_imports(self, mod: str) -> None:
        # Must not raise NotImplementedError on import.
        importlib.import_module(f"cosai_mcp.middleware.{mod}")

    def test_readme_lists_every_stub_module_as_not_implemented(self) -> None:
        txt = README.read_text()
        for mod in _STUB_MODULES:
            assert mod in txt, f"README must disclose stub module {mod!r}"
        assert "NotImplementedError" in txt

    def test_analysis_lists_every_stub_module_as_not_implemented(self) -> None:
        txt = ANALYSIS.read_text()
        for mod in _STUB_MODULES:
            assert mod in txt, f"ANALYSIS must disclose stub module {mod!r}"
        assert "NotImplementedError" in txt


class TestNoOverclaimingHeadline:
    """The README headline / status line must not assert that all 12
    categories are implemented or zero-config — that is the exact dishonest
    framing WP4 removes."""

    def test_readme_no_all_twelve_implemented_claim(self) -> None:
        txt = README.read_text().lower()
        assert "all t1–t12 categories implemented" not in txt
        assert "all 12 cosai threat categories implemented" not in txt
        # The status line must state the honest split.
        assert "zero-config" in txt
        assert "middleware" in txt

    def test_readme_states_nine_zero_config(self) -> None:
        txt = README.read_text()
        assert "9 categories" in txt or "9 categories" in txt.lower()

    def test_analysis_no_all_twelve_engine_claim(self) -> None:
        txt = ANALYSIS.read_text()
        # The engines section must not claim three engines cover "all 12".
        assert "three scan engines** against all 12 CoSAI categories" not in txt
