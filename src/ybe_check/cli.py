"""
Ybe Check CLI — typer-based interface.
"""

import json
import os
import re
import shutil
import subprocess
import webbrowser
from pathlib import Path

import typer

from . import __version__
from .ai import CONFIG_DIR, CONFIG_FILE, load_config, save_config
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


@app.command()
def setup(
    skip_extension: bool = typer.Option(False, "--skip-extension", help="Skip VS Code/Cursor extension install"),
    custom_keys: bool = typer.Option(False, "--custom-keys", help="Provide your own API keys"),
) -> None:
    """One-time setup: install extension, register MCP. AI works out of the box."""
    typer.echo(f"Ybe Check v{__version__} — Setup\n")

    if not skip_extension:
        _install_extension()

    _write_mcp_config()

    if custom_keys:
        _collect_api_keys()
    else:
        typer.echo("[ai] No API keys configured — AI falls back to static remediation until keys are added.")

    typer.echo("\nSetup complete. Reload your Cursor/VS Code window to activate the MCP server.")


def _version_key_from_vsix(path: Path) -> tuple[int, ...]:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", path.name)
    if not m:
        return (0, 0, 0)
    return tuple(int(part) for part in m.groups())


def _select_vsix(vsix_files: list[Path]) -> Path:
    # Prefer latest modified artifact (typical release flow), tie-break by semantic version.
    return max(vsix_files, key=lambda p: (p.stat().st_mtime, _version_key_from_vsix(p)))


def _install_extension() -> None:
    assets_dir = Path(__file__).parent / "assets"
    vsix_files = list(assets_dir.glob("ybe-check-*.vsix")) if assets_dir.exists() else []

    if not vsix_files:
        typer.echo("[extension] No bundled .vsix found — skipping extension install.")
        typer.echo("           Install manually: cursor --install-extension <path-to-vsix>")
        return

    vsix = _select_vsix(vsix_files)
    ide_cmd = None
    for cmd in ("cursor", "code"):
        if shutil.which(cmd):
            ide_cmd = cmd
            break

    if not ide_cmd:
        typer.echo(f"[extension] Neither 'cursor' nor 'code' CLI found on PATH.")
        typer.echo(f"           Install manually: cursor --install-extension {vsix}")
        return

    typer.echo(f"[extension] Installing {vsix.name} via '{ide_cmd}'...")
    try:
        subprocess.run(
            [ide_cmd, "--install-extension", str(vsix)],
            check=True,
            capture_output=True,
            text=True,
        )
        typer.echo(f"[extension] Installed successfully.")
    except subprocess.CalledProcessError as e:
        typer.echo(f"[extension] Install failed: {e.stderr.strip()}")


def _write_mcp_config() -> None:
    """Write MCP server config to both .vscode/mcp.json and .cursor/mcp.json."""
    python_cmd = "python3"
    mcp_entry = {
        "command": python_cmd,
        "args": ["-m", "ybe_check.mcp_server"],
    }

    targets = [
        (Path.cwd() / ".vscode", "VS Code"),
        (Path.cwd() / ".cursor", "Cursor"),
    ]

    for target_dir, label in targets:
        mcp_file = target_dir / "mcp.json"

        config: dict = {"mcpServers": {}}
        if mcp_file.exists():
            try:
                config = json.loads(mcp_file.read_text("utf-8"))
            except (json.JSONDecodeError, OSError):
                config = {"mcpServers": {}}
        if "mcpServers" not in config:
            config["mcpServers"] = {}

        existing = config["mcpServers"].get("ybe-check")
        if existing and existing.get("command") == python_cmd:
            typer.echo(f"[mcp] {mcp_file.relative_to(Path.cwd())} already configured — skipping.")
            continue

        config["mcpServers"]["ybe-check"] = mcp_entry

        target_dir.mkdir(parents=True, exist_ok=True)
        mcp_file.write_text(json.dumps(config, indent=2), encoding="utf-8")
        typer.echo(f"[mcp] Wrote MCP server config to {mcp_file.relative_to(Path.cwd())} ({label})")


def _collect_api_keys() -> None:
    config = load_config()
    typer.echo("")

    blackbox_key = typer.prompt(
        "Blackbox AI API key (primary LLM — press Enter to skip)",
        default=config.get("blackbox_api_key", ""),
        show_default=False,
    )
    if blackbox_key:
        config["blackbox_api_key"] = blackbox_key

    google_key = typer.prompt(
        "Google Gemini API key (fallback LLM — press Enter to skip)",
        default=config.get("google_api_key", ""),
        show_default=False,
    )
    if google_key:
        config["google_api_key"] = google_key

    if blackbox_key or google_key:
        save_config(config)
        typer.echo(f"[keys] Saved to {CONFIG_FILE}")
    else:
        typer.echo("[keys] No keys provided — AI analysis will use static fallback.")


@app.command()
def init(
    path: Path = typer.Argument(Path("."), help="Repository path to scan"),
    port: int = typer.Option(7474, "--port", "-p", help="Dashboard port"),
    skip_extension: bool = typer.Option(False, "--skip-extension", help="Skip VS Code/Cursor extension install"),
    custom_keys: bool = typer.Option(False, "--custom-keys", help="Provide your own API keys"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Don't auto-open browser"),
) -> None:
    """All-in-one: install extension, configure MCP, run scan, launch dashboard."""
    typer.echo(f"\n  Ybe Check v{__version__} — Full Init\n")

    if not skip_extension:
        typer.echo("━━━ Step 1/4: Extension ━━━")
        _install_extension()

    typer.echo("\n━━━ Step 2/4: MCP Server ━━━")
    _write_mcp_config()

    if custom_keys:
        typer.echo("\n━━━ Step 3/4: API Keys ━━━")
        _collect_api_keys()
    else:
        typer.echo("\n━━━ Step 3/4: AI ━━━")
        typer.echo("[ai] No API keys configured — static remediation fallback is active.")

    typer.echo("\n━━━ Step 4/4: Scan + Dashboard ━━━")
    repo = str(path.resolve())
    if not path.is_dir():
        typer.echo(f"Error: {repo} is not a directory.", err=True)
        raise typer.Exit(1)

    report_path = Path(repo) / "ybe-report.json"
    if report_path.exists():
        typer.echo(f"[scan] Found existing report at {report_path}")
        try:
            existing = json.loads(report_path.read_text("utf-8"))
            score = existing.get("overall_score", "?")
            count = len(existing.get("findings", []))
            typer.echo(f"[scan] Score: {score}/100 — {count} findings. Skipping re-scan.")
            typer.echo("       Run 'ybe-check scan .' to force a fresh scan.")
        except Exception:
            typer.echo("[scan] Could not read existing report, running fresh scan...")
            _run_scan_and_save(repo, report_path)
    else:
        _run_scan_and_save(repo, report_path)

    # Launch dashboard
    typer.echo(f"\n[dashboard] Starting at http://127.0.0.1:{port}")
    typer.echo("            Press Ctrl+C to stop.\n")

    if not no_browser:
        import threading
        threading.Timer(1.5, lambda: webbrowser.open(f"http://127.0.0.1:{port}")).start()

    from .dashboard import start_server
    start_server(port=port)


def _run_scan_and_save(repo: str, report_path: Path) -> None:
    typer.echo(f"[scan] Scanning {repo} (this may take a few minutes)...")
    rpt = run_scan(repo)
    if "error" in rpt:
        typer.echo(f"[scan] Error: {rpt['error']}", err=True)
        raise typer.Exit(1)
    report_path.write_text(json.dumps(rpt, indent=2), encoding="utf-8")
    score = rpt.get("overall_score", 0)
    verdict = rpt.get("verdict", "UNKNOWN")
    count = len(rpt.get("findings", []))
    typer.echo(f"[scan] Done. Score: {score}/100 — {verdict}. {count} findings.")


@app.command()
def dashboard(
    port: int = typer.Option(7474, "--port", "-p", help="Port for the dashboard server"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Don't auto-open browser"),
) -> None:
    """Launch the local web dashboard to view scan results."""
    report_path = Path.cwd() / "ybe-report.json"

    if not report_path.exists():
        typer.echo("No ybe-report.json found — running scan first...")
        rpt = run_scan(str(Path.cwd()))
        report_path.write_text(json.dumps(rpt, indent=2), encoding="utf-8")
        typer.echo(f"Scan complete. Score: {rpt.get('overall_score', 0)}/100\n")

    typer.echo(f"Starting dashboard at http://127.0.0.1:{port}")

    if not no_browser:
        import threading
        threading.Timer(1.5, lambda: webbrowser.open(f"http://127.0.0.1:{port}")).start()

    from .dashboard import start_server
    start_server(port=port)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
