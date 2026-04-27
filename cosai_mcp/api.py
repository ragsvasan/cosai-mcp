"""Python API — Scanner class. Implemented in Phase 8."""
from __future__ import annotations


class Scanner:
    """Python API for programmatic cosai-mcp usage."""

    def __init__(self, target: str) -> None:
        self.target = target

    def run(self, categories: list[str] | None = None) -> "ScanResult":
        raise NotImplementedError("Phase 8: Scanner.run()")


class ScanResult:
    """Result of a complete scan. Implemented in Phase 8."""
