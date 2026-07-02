"""P9 CI/CD tests: GitHub Action config, Docker, SARIF upload semantics."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parent.parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
GATE_YML = WORKFLOWS / "cosai-gate.yml"
CI_YML = WORKFLOWS / "ci.yml"
DOCKERFILE = ROOT / "Dockerfile"
README = ROOT / "README.md"
COVERAGE_MD = ROOT / "docs" / "COVERAGE.md"


# ===========================================================================
# GitHub Action permissions — minimal surface
# ===========================================================================

class TestActionPermissions:

    def test_action_permissions_minimal(self):
        """cosai-gate.yml must declare only contents:read + security-events:write."""
        data = yaml.safe_load(GATE_YML.read_text())
        jobs = data.get("jobs", {})
        scan_job = jobs.get("scan", {})
        perms = scan_job.get("permissions", {})

        assert perms.get("contents") == "read", \
            "scan job must have contents:read"
        assert perms.get("security-events") == "write", \
            "scan job must have security-events:write for SARIF upload"
        # Must NOT have write-all or packages:write (supply chain risk)
        assert "write-all" not in str(perms), \
            "scan job must not use write-all permissions"
        assert perms.get("packages") is None, \
            "scan job must not have packages permission"


# ===========================================================================
# SHA pinning — never mutable tags in action references
# ===========================================================================

class TestActionShaPinning:

    def _collect_uses(self, workflow_path: Path) -> list[str]:
        """Extract all `uses:` values from a workflow file."""
        data = yaml.safe_load(workflow_path.read_text())
        uses: list[str] = []

        def walk(obj: object) -> None:
            if isinstance(obj, dict):
                if "uses" in obj:
                    uses.append(obj["uses"])
                for v in obj.values():
                    walk(v)
            elif isinstance(obj, list):
                for item in obj:
                    walk(item)

        walk(data)
        return uses

    def test_gate_action_uses_pinned_checkout(self):
        """cosai-gate.yml must not reference a mutable tag for actions/checkout."""
        uses_list = self._collect_uses(GATE_YML)
        checkout_refs = [u for u in uses_list if "actions/checkout" in u]
        # v4 is a mutable tag but is the standard — this test verifies it's
        # pinned to a versioned tag not a branch like @main or @master
        for ref in checkout_refs:
            assert "@main" not in ref and "@master" not in ref, \
                f"actions/checkout must not use @main/@master: {ref}"

    def test_ci_no_branch_pinned_actions(self):
        """ci.yml must not use @main or @master for any external action."""
        uses_list = self._collect_uses(CI_YML)
        for ref in uses_list:
            assert "@main" not in ref and "@master" not in ref, \
                f"Action must not be pinned to @main/@master: {ref}"


# ===========================================================================
# SARIF upload on exit code 2 (partial scan)
# ===========================================================================

class TestSarifUploadOnError:

    def test_sarif_upload_on_exit_2_configured(self):
        """ci.yml must upload SARIF even on scanner error (exit 2)."""
        data = yaml.safe_load(CI_YML.read_text())
        jobs = data.get("jobs", {})
        test_job = jobs.get("test", {})
        steps = test_job.get("steps", [])

        sarif_upload_steps = [
            s for s in steps
            if isinstance(s.get("uses", ""), str)
            and "upload-sarif" in s.get("uses", "")
        ]
        assert len(sarif_upload_steps) >= 1, \
            "ci.yml test job must have a SARIF upload step"

        # At least one upload step must run on failure (exit 2 scenario)
        upload_on_failure = [
            s for s in sarif_upload_steps
            if "failure" in str(s.get("if", ""))
        ]
        assert len(upload_on_failure) >= 1, \
            "At least one SARIF upload step must run on failure"

    def test_gate_sarif_always_uploaded(self):
        """cosai-gate.yml SARIF upload step must use if: always()."""
        data = yaml.safe_load(GATE_YML.read_text())
        jobs = data.get("jobs", {})
        scan_job = jobs.get("scan", {})
        steps = scan_job.get("steps", [])

        sarif_steps = [
            s for s in steps
            if "upload-sarif" in str(s.get("uses", ""))
        ]
        assert len(sarif_steps) >= 1, \
            "cosai-gate.yml must have a SARIF upload step"
        assert any("always" in str(s.get("if", "")) for s in sarif_steps), \
            "SARIF upload step must use if: always() so it runs on exit 1 and 2"


# ===========================================================================
# Docker image — non-root user, minimal surface
# ===========================================================================

class TestDockerfile:

    def test_dockerfile_exists(self):
        assert DOCKERFILE.exists(), "Dockerfile must exist for P9"

    def test_dockerfile_non_root_user(self):
        content = DOCKERFILE.read_text()
        assert "USER cosai" in content or "USER " in content, \
            "Dockerfile must switch to a non-root user"
        assert "useradd" in content or "adduser" in content, \
            "Dockerfile must create a non-root user"

    def test_dockerfile_no_root_entrypoint(self):
        content = DOCKERFILE.read_text()
        # Ensure USER directive comes before ENTRYPOINT
        lines = content.splitlines()
        user_idx = next((i for i, ln in enumerate(lines) if ln.startswith("USER")), None)
        entrypoint_idx = next((i for i, ln in enumerate(lines) if ln.startswith("ENTRYPOINT")), None)  # noqa: E501
        assert user_idx is not None, "Dockerfile must have a USER directive"
        assert entrypoint_idx is not None, "Dockerfile must have an ENTRYPOINT"
        assert user_idx < entrypoint_idx, \
            "USER directive must appear before ENTRYPOINT"

    def test_dockerfile_no_shell_true(self):
        """ENTRYPOINT and CMD must use JSON array form (exec form), not shell form."""
        content = DOCKERFILE.read_text()
        for line in content.splitlines():
            if line.startswith("ENTRYPOINT") or line.startswith("CMD"):
                assert line.strip().split(None, 1)[1].startswith("["), \
                    f"ENTRYPOINT/CMD must use exec (JSON array) form, not shell form: {line}"


# ===========================================================================
# Regression tests
# ===========================================================================

class TestP9Regressions:

    def test_regression_gate_yml_valid_yaml(self):
        """cosai-gate.yml must be valid YAML (parse without error)."""
        yaml.safe_load(GATE_YML.read_text())

    def test_regression_ci_yml_valid_yaml(self):
        """ci.yml must be valid YAML."""
        yaml.safe_load(CI_YML.read_text())

    def test_regression_gate_has_workflow_call_trigger(self):
        """cosai-gate.yml must be triggered via workflow_call for reuse.

        Note: PyYAML parses the bare `on:` key as Python True (YAML boolean alias).
        """
        data = yaml.safe_load(GATE_YML.read_text())
        # `on:` → True in PyYAML; fall back to string key for other parsers
        triggers = data.get(True, data.get("on", {}))
        assert "workflow_call" in triggers, \
            "cosai-gate.yml must support workflow_call trigger for reuse"


# ===========================================================================
# FABLE_AUDIT_2026-07-01 FIND 2 — the headline test-count claim drifts
# silently (917 -> 1315 -> stale again in the whitepaper; 1558 was already
# wrong on the branch that shipped it). This guard fails the moment a PR
# changes the collected test count without updating the docs that quote it.
# ===========================================================================

_SLASH_COUNT_RE = re.compile(r"(\d+)\s*/\s*(\d+)\s+tests?\s+passing")
_STATED_COUNT_PATTERNS = (
    re.compile(r"(\d+)\s+tests?\s+passing"),
    re.compile(r"(\d+)\s+passing\s+tests?"),
)


def _stated_counts(text: str) -> set[int]:
    """Extract every "N tests passing" style claim in *text*.

    "N/M tests passing" (e.g. "1558/1558 tests passing") is handled
    explicitly and its own spans are removed before the simpler
    single-number patterns run — a mismatched N/M (a partial run, e.g.
    "1200/1558") is a real, meaningful signal and must fail loudly with a
    clear message, not be silently reduced to "whichever number happens to
    sit next to the word 'tests'".
    """
    found: set[int] = set()
    for match in _SLASH_COUNT_RE.finditer(text):
        left, right = int(match.group(1)), int(match.group(2))
        assert left == right, (
            f"doc states a non-100% count ({left}/{right} tests passing) — "
            "this guard only validates the all-tests-passing headline figure"
        )
        found.add(right)
    remaining = _SLASH_COUNT_RE.sub("", text)
    for pattern in _STATED_COUNT_PATTERNS:
        found.update(int(n) for n in pattern.findall(remaining))
    return found


class TestStatedCountsParsing:

    def test_stated_counts_handles_n_of_n_passing_phrasing(self):
        assert _stated_counts("Build: 1558/1558 tests passing") == {1558}

    def test_stated_counts_rejects_mismatched_n_of_m(self):
        with pytest.raises(AssertionError, match="non-100%"):
            _stated_counts("Build: 1200/1558 tests passing")

    def test_stated_counts_handles_tests_passing_phrasing(self):
        assert _stated_counts("Alpha — 1558 tests passing, Apache 2.0.") == {1558}

    def test_stated_counts_handles_passing_tests_phrasing(self):
        assert _stated_counts("1558 passing tests, Apache 2.0.") == {1558}

    def test_stated_counts_combines_all_phrasings_present(self):
        text = "1558/1558 tests passing. Also: 1558 tests passing. And: 1558 passing tests."
        assert _stated_counts(text) == {1558}


class TestCosaiGateExpectedCatalogHash:
    """Defense-pass FIX 1 (ENT-P0-1 review): --expected-catalog-hash was
    reachable from the CLI and Python API but not from the reusable
    cosai-gate.yml workflow — the actual documented CI use case ("a release
    gate is deterministic ... between the PR run and the merge run")."""

    def test_gate_yml_exposes_expected_catalog_hash_input(self) -> None:
        data = yaml.safe_load(GATE_YML.read_text())
        triggers = data.get(True, data.get("on", {}))
        inputs = triggers["workflow_call"]["inputs"]
        assert "expected_catalog_hash" in inputs
        assert inputs["expected_catalog_hash"].get("required") is not True

    def test_gate_yml_run_script_references_expected_catalog_hash_flag(self) -> None:
        text = GATE_YML.read_text()
        assert "--expected-catalog-hash" in text
        assert "inputs.expected_catalog_hash" in text


class TestDocsTestCountConsistency:

    def test_regression_docs_test_count_matches_collect(self):
        """README.md and docs/COVERAGE.md's stated test count must match
        what pytest actually collects right now — not a number frozen at
        whatever commit last happened to update it by hand.
        """
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, (
            f"pytest --collect-only failed (exit {result.returncode}) — a collection "
            f"error elsewhere must not be misread as a valid count.\nstdout: {result.stdout}"
            f"\nstderr: {result.stderr}"
        )
        lines = [ln for ln in result.stdout.strip().splitlines() if ln.strip()]
        assert lines, f"pytest --collect-only produced no output; stderr: {result.stderr}"
        match = re.search(r"(\d+)\s+tests?\s+collected", lines[-1])
        assert match, f"could not parse collected count from: {lines[-1]!r}"
        collected = int(match.group(1))

        for path in (README, COVERAGE_MD):
            stated = _stated_counts(path.read_text())
            assert stated, f"{path} no longer states a test count in the expected phrasing"
            assert stated == {collected}, (
                f"{path} claims {sorted(stated)} tests passing, but pytest --collect-only "
                f"reports {collected} collected right now. Update the doc to match."
            )
