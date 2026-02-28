"""
Ybe Check CLI — typer-based interface.
"""

import json
from pathlib import Path

import typer

from . import __version__
from .core import filter_findings, load_report, run_scan

app = typer.Typer(
    name="ybe-check",
    help="Production-readiness gatekeeper for vibe-coded apps.",
)


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Path to the repository to scan"),
    modules: list[str] = typer.Option(
        None,
        "--modules",
        "-m",
        help="Specific modules to run (e.g. secrets, dependencies). Omit to run all.",
    ),
    categories: list[str] = typer.Option(
        None,
        "--categories",
        "-c",
        help="Categories to run: static, dynamic, infra. Omit to run all.",
    ),
    output: Path = typer.Option(
        Path("ybe-report.json"),
        "--output",
        "-o",
        help="Output JSON report path",
    ),
) -> None:
    """Run a Ybe Check scan and write the report to a JSON file."""
    path_str = str(path.resolve())
    if not path.is_dir():
        typer.echo(f"Error: {path_str} is not a directory.", err=True)
        raise typer.Exit(1)

    report = run_scan(path_str, modules=modules or None, categories=categories or None)

    if "error" in report:
        typer.echo(f"Error: {report['error']}", err=True)
        raise typer.Exit(1)

    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    score = report.get("overall_score", 0)
    verdict = report.get("verdict", "UNKNOWN")
    count = len(report.get("findings", []))
    typer.echo(f"Scan complete. Score: {score}/100 — {verdict}. {count} findings written to {output}")


@app.command()
def report(
    file: Path = typer.Option(
        Path("ybe-report.json"),
        "--file",
        "-f",
        help="Path to the JSON report file",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        "-F",
        help="Output format: json or table",
    ),
    severity: str = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter findings by severity: info, low, medium, high, critical",
    ),
    category: str = typer.Option(
        None,
        "--category",
        help="Filter findings by category: static, dynamic, infra",
    ),
) -> None:
    """Load a report and display findings (optionally filtered)."""
    if not file.exists():
        typer.echo(f"Error: Report file not found: {file}", err=True)
        raise typer.Exit(1)

    report = load_report(str(file))
    findings = filter_findings(
        report,
        severity=severity,
        category=category,
    )

    if format == "json":
        typer.echo(json.dumps({"findings": findings, "report_meta": {k: v for k, v in report.items() if k != "findings"}}, indent=2))
        return

    # Table format
    if not findings:
        typer.echo("No findings (or none match the filters).")
        return

    # Simple table: id | source | type | severity | location
    rows = []
    for f in findings:
        loc = f.get("location", {}) or {}
        path_str = loc.get("path") or "-"
        line_str = str(loc.get("line")) if loc.get("line") else "-"
        location = f"{path_str}:{line_str}"
        rows.append(
            (
                f.get("id", "-")[:20],
                f.get("source", "-"),
                (f.get("type", "-") or "-")[:30],
                f.get("severity", "-"),
                location[:50],
            )
        )

    col_widths = [max(len(r[i]) for r in rows) for i in range(5)]
    header = ("ID", "Source", "Type", "Severity", "Location")
    col_widths = [max(col_widths[i], len(header[i])) for i in range(5)]
    sep = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(header))
    typer.echo(sep)
    typer.echo("-" * len(sep))
    for row in rows:
        typer.echo(" | ".join(str(row[i]).ljust(col_widths[i])[:col_widths[i]] for i in range(5)))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
