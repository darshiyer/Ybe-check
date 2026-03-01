"""
Ybe Check MCP Server — exposes scan tools to MCP clients.

Tools:
  ybe.scan_repo       – Run a full security + production-readiness scan.
  ybe.list_findings   – List / filter findings from a scan report.
  ybe.get_remediation – Get remediation guidance for a specific finding.

Run with:
  python -m ybe_check.mcp_server
"""

import json
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

from .ai import enrich_finding, load_config
from .core import filter_findings, load_report, run_scan

mcp = FastMCP(
    "ybe-check",
    json_response=True,
)

REPORT_FILENAME = "ybe-report.json"


def _load_or_scan(path: str) -> dict:
    """Load an existing report or run a fresh scan.

    Resolution order:
      1. ``ybe-report.json`` inside *path* if it exists.
      2. Run a fresh scan on *path*.
    """
    default = Path(path) / REPORT_FILENAME
    if default.exists():
        return load_report(str(default))
    return run_scan(path)


# ---------------------------------------------------------------------------
# Tool: ybe.scan_repo
#   Maps to -> core.run_scan(path, modules, categories)
#   Always runs a fresh scan; returns the full unified report dict.
# ---------------------------------------------------------------------------

@mcp.tool(name="ybe.scan_repo")
def scan_repo(
    path: str,
    modules: Optional[list[str]] = None,
    categories: Optional[list[str]] = None,
) -> str:
    """Scan a repository for security and production-readiness issues.

    Runs all enabled Ybe Check modules (secrets, prompt injection, PII,
    dependencies, auth guards, IaC, SBOM, etc.) and returns a unified
    JSON report including findings, scores, and a verdict.

    Args:
        path: Absolute or relative path to the repository root.
        modules: Optional subset of module names (e.g. ["secrets", "dependencies"]).
        categories: Optional subset of ["static", "dynamic", "infra"].
    """
    report = run_scan(path, modules=modules, categories=categories)
    return json.dumps(report, indent=2)


# ---------------------------------------------------------------------------
# Tool: ybe.list_findings
#   Maps to -> core.filter_findings(report, severity, category)
#   Loads ybe-report.json from <path> when available; otherwise runs a scan.
# ---------------------------------------------------------------------------

@mcp.tool(name="ybe.list_findings")
def list_findings(
    path: str,
    severity: Optional[str] = None,
    category: Optional[str] = None,
) -> str:
    """List findings from a previous or fresh scan, optionally filtered.

    If a ``ybe-report.json`` file exists inside *path* it is loaded
    instead of running a new scan.  Findings can be narrowed by severity
    and/or category.

    Args:
        path: Path to the repository (or directory containing a report).
        severity: Filter by severity level (info | low | medium | high | critical).
        category: Filter by category (static | dynamic | infra).
    """
    report = _load_or_scan(path)
    findings = filter_findings(report, severity=severity, category=category)
    return json.dumps(findings, indent=2)


# ---------------------------------------------------------------------------
# Tool: ybe.get_remediation
#   Loads a report for *path*, finds the matching finding, and returns
#   its ai_analysis block (or a minimal impact/remediation stub).
# ---------------------------------------------------------------------------

@mcp.tool(name="ybe.get_remediation")
def get_remediation(
    path: str,
    finding_id: str,
) -> str:
    """Return AI-powered remediation guidance for a single finding.

    Loads the report for *path* (from ``ybe-report.json`` if present,
    otherwise runs a fresh scan), locates the finding by *finding_id*,
    and returns its ``ai_analysis`` block.  When ``ai_analysis`` is
    absent it is generated via the LLM chain (Blackbox AI -> Gemini ->
    static fallback) and cached back to the report file.

    Args:
        path: Path to the repository.
        finding_id: The finding ID (e.g. "secrets:0", "deps:3").
    """
    report = _load_or_scan(path)
    findings = report.get("findings", [])
    match = next((f for f in findings if f.get("id") == finding_id), None)

    if not match:
        return json.dumps({
            "error": f"Finding '{finding_id}' not found.",
            "impact": None,
            "remediation": None,
        })

    ai = match.get("ai_analysis")
    if not ai:
        config = load_config()
        ai = enrich_finding(match, config)
        match["ai_analysis"] = ai
        _cache_report(path, report)

    return json.dumps({"finding_id": finding_id, **ai}, indent=2)


def _cache_report(path: str, report: dict) -> None:
    """Write enriched report back to ybe-report.json for future loads."""
    report_path = Path(path) / REPORT_FILENAME
    try:
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    except OSError:
        pass


def main() -> None:
    """Entry-point: stdio (local) or HTTP (remote/demo) transport.

    Usage:
      python -m ybe_check.mcp_server           # stdio — for Cursor/VS Code local
      python -m ybe_check.mcp_server --remote  # HTTP on port 8000 — for ngrok/demo
    """
    import sys
    if "--remote" in sys.argv:
        port = int(next(
            (sys.argv[sys.argv.index("--port") + 1] for _ in ["x"] if "--port" in sys.argv),
            8000,
        ))
        mcp.run(transport="streamable-http", host="0.0.0.0", port=port)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
