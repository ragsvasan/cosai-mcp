"""cosai CLI — scan + audit commands. Implemented in Phase 8."""
from __future__ import annotations

import click


@click.group()
def main() -> None:
    """cosai-mcp: MCP security scanner covering all 12 CoSAI threat categories."""


@main.command()
@click.argument("target")
@click.option("--categories", default="all", help="Comma-separated list of T-categories (e.g. T1,T3)")
@click.option("--engine", type=click.Choice(["prober", "stateful", "all"]), default="all")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default="critical")
@click.option("--allow-custom-catalog", is_flag=True, default=False)
@click.option("--report-sarif", type=click.Path(), default=None)
@click.option("--report-html", type=click.Path(), default=None)
def scan(target: str, categories: str, engine: str, fail_on: str,
         allow_custom_catalog: bool, report_sarif: str | None, report_html: str | None) -> None:
    """Scan a target MCP server."""
    raise NotImplementedError("Phase 8: cosai scan")


@main.command()
@click.argument("report", type=click.Path(exists=True))
def audit(report: str) -> None:
    """Verify audit chain integrity of a scan report."""
    raise NotImplementedError("Phase 8: cosai audit verify")


if __name__ == "__main__":
    main()
