"""Smoke test for the bundled example MCP servers.

The example servers under ``examples/`` are deliberately vulnerable demo
targets for ``cosai scan``. They depend on optional packages (fastmcp /
fastapi / uvicorn) that are NOT cosai-mcp dependencies, so we cannot import
them in CI. Instead we assert each file exists and is syntactically valid
Python (compiles), so they don't silently rot.
"""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
EXAMPLES = ROOT / "examples"

EXAMPLE_SERVERS = [
    EXAMPLES / "fastmcp" / "server.py",
    EXAMPLES / "fastapi-mcp" / "server.py",
]


@pytest.mark.parametrize("server_path", EXAMPLE_SERVERS, ids=lambda p: p.parent.name)
def test_example_server_exists_and_compiles(server_path: Path) -> None:
    assert server_path.is_file(), f"missing example server: {server_path}"
    source = server_path.read_text(encoding="utf-8")
    # Raises SyntaxError if the file is not valid Python.
    compile(source, str(server_path), "exec")


@pytest.mark.parametrize("server_path", EXAMPLE_SERVERS, ids=lambda p: p.parent.name)
def test_example_server_advertises_vulnerable_tools(server_path: Path) -> None:
    """The demo servers must keep their intentionally vulnerable tools so the
    scanner has something to flag (T3 command injection, T4 tool poisoning)."""
    source = server_path.read_text(encoding="utf-8")
    assert "run_command" in source, "T3 demo tool (run_command) missing"
    assert "read_notes" in source, "T4 demo tool (read_notes) missing"
    assert "Ignore all previous instructions" in source, \
        "T4 prompt-injection description missing"


def test_examples_readme_exists() -> None:
    readme = EXAMPLES / "README.md"
    assert readme.is_file(), "examples/README.md missing"
    text = readme.read_text(encoding="utf-8")
    assert "cosai scan" in text, "README must show the scan command"
    assert "intentionally insecure" in text.lower() or "for testing only" in text.lower(), \
        "README must warn the servers are insecure"
