"""
Ybe Check MCP Server — security context provider for AI coding assistants.

Tools (7):
  ybe.scan_repo          – Run a full security + production-readiness scan.
  ybe.list_findings      – List / filter findings from a scan report.
  ybe.get_remediation    – Get remediation guidance for a specific finding.
  ybe.get_security_context – Get a structured security summary for the workspace.
  ybe.enhance_prompt     – Wrap any user prompt with security-aware context.
  ybe.get_fix_prompt     – Generate a ready-to-use fix prompt for a finding.
  ybe.get_review_prompt  – Generate a security-aware code review prompt.

Prompt Templates (3):
  security-audit   – Comprehensive security review prompt.
  fix-critical     – Fix all critical/high findings prompt.
  review-file      – Security-focused file review prompt.

Run with:
  python -m ybe_check.mcp_server
"""

import json
import os
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

# ── Severity weight for sorting findings by urgency ──────────────────────
_SEV_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _load_or_scan(path: str) -> dict:
    """Load an existing report or run a fresh scan."""
    default = Path(path) / REPORT_FILENAME
    if default.exists():
        return load_report(str(default))
    return run_scan(path)


def _build_security_summary(report: dict, max_findings: int = 15) -> dict:
    """Distil a full report into a compact security context block."""
    findings = report.get("findings", [])
    sorted_f = sorted(findings, key=lambda f: _SEV_WEIGHT.get(f.get("severity", "medium"), 3), reverse=True)
    top = sorted_f[:max_findings]

    by_sev: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "medium")
        by_sev[s] = by_sev.get(s, 0) + 1

    modules = report.get("module_results", [])
    weak_modules = [m["name"] for m in modules if (m.get("score") or 100) < 50]

    return {
        "overall_score": report.get("overall_score", 0),
        "verdict": report.get("verdict", "UNKNOWN"),
        "total_findings": len(findings),
        "severity_breakdown": by_sev,
        "weakest_modules": weak_modules[:5],
        "top_fixes": report.get("top_fixes", [])[:5],
        "top_findings": [
            {
                "id": f.get("id"),
                "type": f.get("type"),
                "severity": f.get("severity"),
                "file": (f.get("location") or {}).get("path", ""),
                "line": (f.get("location") or {}).get("line"),
                "summary": f.get("summary", "")[:200],
            }
            for f in top
        ],
    }


# =====================================================================
# TOOL 1: ybe.scan_repo
# =====================================================================

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


# =====================================================================
# TOOL 2: ybe.list_findings
# =====================================================================

@mcp.tool(name="ybe.list_findings")
def list_findings(
    path: str,
    severity: Optional[str] = None,
    category: Optional[str] = None,
) -> str:
    """List findings from a previous or fresh scan, optionally filtered.

    Args:
        path: Path to the repository (or directory containing a report).
        severity: Filter by severity level (info | low | medium | high | critical).
        category: Filter by category (static | dynamic | infra).
    """
    report = _load_or_scan(path)
    findings = filter_findings(report, severity=severity, category=category)
    return json.dumps(findings, indent=2)


# =====================================================================
# TOOL 3: ybe.get_remediation
# =====================================================================

@mcp.tool(name="ybe.get_remediation")
def get_remediation(
    path: str,
    finding_id: str,
) -> str:
    """Return AI-powered remediation guidance for a single finding.

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


# =====================================================================
# TOOL 4: ybe.get_security_context   (NEW – prompt engineering core)
# =====================================================================

@mcp.tool(name="ybe.get_security_context")
def get_security_context(
    path: str,
    file: Optional[str] = None,
) -> str:
    """Return a structured security context for the workspace.

    This is the primary context injection tool. AI assistants should call
    this FIRST to understand the security posture before answering any
    code-related question. The response includes:
      - Overall score & verdict
      - Severity breakdown
      - Weakest modules
      - Top critical/high findings (optionally filtered to a single file)
      - Recommended priority fixes

    Args:
        path: Path to the repository root.
        file: Optional relative file path to narrow findings to that file only.
    """
    report = _load_or_scan(path)
    ctx = _build_security_summary(report)

    if file:
        all_findings = report.get("findings", [])
        file_findings = [
            f for f in all_findings
            if file in ((f.get("location") or {}).get("path") or "")
        ]
        file_findings.sort(key=lambda f: _SEV_WEIGHT.get(f.get("severity", "medium"), 3), reverse=True)
        ctx["file_filter"] = file
        ctx["file_findings"] = [
            {
                "id": f.get("id"),
                "type": f.get("type"),
                "severity": f.get("severity"),
                "line": (f.get("location") or {}).get("line"),
                "summary": f.get("summary", "")[:200],
            }
            for f in file_findings[:20]
        ]

    return json.dumps(ctx, indent=2)


# =====================================================================
# TOOL 5: ybe.enhance_prompt   (NEW – prompt engineering wrapper)
# =====================================================================

@mcp.tool(name="ybe.enhance_prompt")
def enhance_prompt(
    path: str,
    user_prompt: str,
    file: Optional[str] = None,
) -> str:
    """Wrap a user's prompt with security-aware context from the latest scan.

    Takes the raw user prompt and returns an enhanced version that
    includes the security context, relevant findings, and instructions
    for the AI to consider security implications in its response.

    This ensures every AI interaction is informed by actual scan data.

    Args:
        path: Path to the repository root.
        user_prompt: The original prompt the user typed.
        file: Optional file path to focus the security context on.
    """
    report = _load_or_scan(path)
    ctx = _build_security_summary(report)

    # Build the file-specific context if a file is given
    file_section = ""
    if file:
        all_findings = report.get("findings", [])
        file_findings = [
            f for f in all_findings
            if file in ((f.get("location") or {}).get("path") or "")
        ]
        if file_findings:
            file_findings.sort(key=lambda f: _SEV_WEIGHT.get(f.get("severity", "medium"), 3), reverse=True)
            file_items = "\n".join(
                f"  - [{f.get('severity','medium').upper()}] Line {(f.get('location') or {}).get('line', '?')}: "
                f"{f.get('type', 'issue')} — {f.get('summary', '')[:120]}"
                for f in file_findings[:10]
            )
            file_section = f"\n\n### Known Issues in `{file}`:\n{file_items}"

    # Build severity summary
    sev = ctx.get("severity_breakdown", {})
    sev_line = ", ".join(f"{k}: {v}" for k, v in sorted(sev.items(), key=lambda x: _SEV_WEIGHT.get(x[0], 0), reverse=True))

    # Top fixes
    fixes = ctx.get("top_fixes", [])
    fixes_section = ""
    if fixes:
        fixes_items = "\n".join(f"  {i+1}. {fix}" for i, fix in enumerate(fixes[:5]))
        fixes_section = f"\n\n### Priority Fixes:\n{fixes_items}"

    enhanced = f"""## Security Context (Ybe Check Scan)
**Score: {ctx.get('overall_score', 0)}/100 — {ctx.get('verdict', 'UNKNOWN')}**
Findings: {ctx.get('total_findings', 0)} total ({sev_line})
Weakest modules: {', '.join(ctx.get('weakest_modules', [])) or 'none'}{file_section}{fixes_section}

---

## User Request:
{user_prompt}

---

**IMPORTANT**: When responding, you MUST:
1. Consider the security findings above in your answer.
2. If the user's request touches code with known vulnerabilities, warn them and suggest the secure approach.
3. Never introduce patterns that would lower the security score.
4. Reference specific finding IDs (e.g. secrets:0) when relevant.
5. If suggesting code changes, ensure they address or at least don't worsen the listed issues."""

    return json.dumps({"enhanced_prompt": enhanced, "context": ctx}, indent=2)


# =====================================================================
# TOOL 6: ybe.get_fix_prompt   (NEW – one-click fix prompt generator)
# =====================================================================

@mcp.tool(name="ybe.get_fix_prompt")
def get_fix_prompt(
    path: str,
    finding_id: str,
) -> str:
    """Generate a ready-to-use prompt for fixing a specific security finding.

    Returns a carefully engineered prompt that can be pasted directly
    into an AI assistant (Copilot Chat, etc.) to get a targeted fix.

    Args:
        path: Path to the repository root.
        finding_id: The finding ID (e.g. "secrets:0", "deps:3").
    """
    report = _load_or_scan(path)
    findings = report.get("findings", [])
    match = next((f for f in findings if f.get("id") == finding_id), None)

    if not match:
        return json.dumps({"error": f"Finding '{finding_id}' not found."})

    loc = match.get("location") or {}
    file_path = loc.get("path") or "unknown"
    line = loc.get("line") or "?"
    sev = (match.get("severity") or "medium").upper()
    ftype = match.get("type", "issue")
    summary = match.get("summary", "Security issue detected")
    evidence = match.get("evidence") or {}
    snippet = evidence.get("snippet") or evidence.get("match") or ""

    # Get AI analysis if available
    ai = match.get("ai_analysis") or {}
    remediation_hint = ai.get("remediation", "")

    prompt = f"""Fix this {sev} security finding in my codebase:

**Finding ID**: {finding_id}
**Type**: {ftype}
**Severity**: {sev}
**File**: {file_path}
**Line**: {line}
**Issue**: {summary}
{f'**Evidence**: `{snippet[:200]}`' if snippet else ''}
{f'**Suggested Fix**: {remediation_hint}' if remediation_hint else ''}

Please:
1. Show me the exact code change needed to fix this issue.
2. Explain why the current code is vulnerable.
3. Ensure the fix doesn't break existing functionality.
4. If there are related issues in the same file, mention them."""

    return json.dumps({"finding_id": finding_id, "prompt": prompt.strip()}, indent=2)


# =====================================================================
# TOOL 7: ybe.get_review_prompt   (NEW – file review prompt)
# =====================================================================

@mcp.tool(name="ybe.get_review_prompt")
def get_review_prompt(
    path: str,
    file: str,
) -> str:
    """Generate a security-focused code review prompt for a specific file.

    Gathers all known findings for the file and builds a prompt that
    asks the AI to review the file with those issues in mind.

    Args:
        path: Path to the repository root.
        file: Relative path to the file to review.
    """
    report = _load_or_scan(path)
    all_findings = report.get("findings", [])
    file_findings = [
        f for f in all_findings
        if file in ((f.get("location") or {}).get("path") or "")
    ]
    file_findings.sort(key=lambda f: _SEV_WEIGHT.get(f.get("severity", "medium"), 3), reverse=True)

    if not file_findings:
        prompt = f"""Review `{file}` for security issues.

No known findings from the last Ybe Check scan, but please check for:
- Hardcoded secrets or API keys
- SQL injection or command injection
- Missing input validation
- Insecure authentication patterns
- PII/sensitive data logging
- Missing error handling"""
    else:
        issues_text = "\n".join(
            f"  {i+1}. [{(f.get('severity','medium')).upper()}] Line {(f.get('location') or {}).get('line', '?')}: "
            f"{f.get('type', 'issue')} — {f.get('summary', '')[:150]}"
            for i, f in enumerate(file_findings[:15])
        )
        prompt = f"""Review `{file}` for security issues.

Ybe Check found {len(file_findings)} issue(s) in this file:
{issues_text}

Please:
1. Read through the file and validate each finding above.
2. Provide the exact code fix for each confirmed issue.
3. Check for any additional security problems not caught by the scanner.
4. Rate the overall security quality of this file (1-10).
5. Suggest any architectural improvements for better security."""

    ctx = _build_security_summary(report)
    return json.dumps({
        "file": file,
        "known_issues": len(file_findings),
        "prompt": prompt.strip(),
        "workspace_score": ctx["overall_score"],
    }, indent=2)


# =====================================================================
# MCP PROMPT TEMPLATES — appear in Copilot / Cursor prompt picker
# =====================================================================

@mcp.prompt(name="security-audit")
def prompt_security_audit() -> str:
    """Comprehensive security audit prompt for the current workspace."""
    return """You are a senior security engineer performing a production-readiness audit.

Use the ybe.get_security_context tool to get the current scan results for this workspace,
then provide a comprehensive security review covering:

1. **Critical Issues** — List all critical/high findings that must be fixed before deployment.
2. **Quick Wins** — Issues that are easy to fix and improve the score significantly.
3. **Architecture Concerns** — Structural security problems (auth flow, data handling, etc.).
4. **Compliance Gaps** — Missing security controls for production (HTTPS, CSP, rate limiting, etc.).
5. **Prioritized Action Plan** — Ordered list of what to fix first for maximum score improvement.

Reference specific finding IDs from the scan. Be specific with file names and line numbers."""


@mcp.prompt(name="fix-critical")
def prompt_fix_critical() -> str:
    """Fix all critical and high severity findings."""
    return """You are a security remediation specialist.

Use the ybe.get_security_context tool to get all findings, then focus on CRITICAL and HIGH severity issues.

For each critical/high finding:
1. Show the exact file and line.
2. Explain the vulnerability in one sentence.
3. Provide the complete fixed code (not just a diff — show the full corrected function/block).
4. Verify the fix doesn't introduce new issues.

Start with the most severe issues first. Use ybe.get_fix_prompt for detailed context on each finding.
After all fixes, estimate what the new security score would be."""


@mcp.prompt(name="review-file")
def prompt_review_file() -> str:
    """Security-focused review of the currently open file."""
    return """You are a code reviewer focused on security.

Use the ybe.get_review_prompt tool with the path to the currently open file to get
known issues, then perform a thorough security review:

1. Validate each finding from the scan — is it a true positive?
2. Check for issues the scanner may have missed.
3. Rate the security quality (1-10).
4. Provide specific code fixes for each confirmed issue.
5. Suggest hardening improvements.

Be precise — reference exact line numbers and show corrected code blocks."""


# =====================================================================
# Internal helpers
# =====================================================================

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
