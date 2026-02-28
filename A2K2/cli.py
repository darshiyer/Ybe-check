#!/usr/bin/env python3
"""
Ybe Check CLI — orchestrator.
Usage: python cli.py <repo_path> [--json]
"""
import sys
import os
import json
import argparse
import importlib

# Add the extension directory to path so modules/ is found
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# All available scan modules
ALL_MODULES = [
    "modules.secrets",
    "modules.prompt_injection",
    "modules.pii_logging",
    "modules.dependencies",
    "modules.auth_guards"
]

# Static-only modules (no network calls, no dynamic analysis)
STATIC_MODULES = [
    "modules.secrets",
    "modules.prompt_injection",
    "modules.pii_logging",
    "modules.auth_guards"
]

def load_modules(static_only=False):
    module_list = STATIC_MODULES if static_only else ALL_MODULES
    loaded = []
    for name in module_list:
        try:
            mod = importlib.import_module(name)
            loaded.append(mod)
        except ImportError as e:
            print(f"Warning: Could not load {name}: {e}", 
                  file=sys.stderr)
    return loaded

def extract_top_fixes(results):
    fixes = []
    for module in results:
        for detail in module.get("details", []):
            if detail.get("severity") in ["critical", "high"]:
                reason = detail.get("reason", "")
                if reason and reason not in fixes:
                    fixes.append(reason)
    return fixes[:5]

def run_scan(repo_path, static_only=False):
    modules = load_modules(static_only=static_only)
    results = []
    
    for mod in modules:
        try:
            result = mod.scan(repo_path)
            results.append(result)
        except Exception as e:
            results.append({
                "name": getattr(mod, "NAME", mod.__name__),
                "score": None,
                "issues": 0,
                "details": [],
                "warning": str(e)
            })
    
    scores = [r["score"] for r in results 
              if r.get("score") is not None]
    
    if scores:
        overall = round(
            0.7 * (sum(scores) / len(scores)) + 
            0.3 * min(scores)
        )
    else:
        overall = 0
    
    overall = max(0, min(100, overall))
    
    verdict = (
        "PRODUCTION READY" if overall >= 80
        else "NEEDS ATTENTION" if overall >= 40
        else "NOT READY"
    )
    
    return {
        "overall_score": overall,
        "verdict": verdict,
        "modules": results,
        "top_fixes": extract_top_fixes(results)
    }

def format_plain_text(report):
    """Format report as human-readable plain text."""
    lines = []
    lines.append("=" * 60)
    lines.append(f"  Ybe Check — Production Readiness Report")
    lines.append("=" * 60)
    lines.append(f"  Overall Score: {report['overall_score']}/100")
    lines.append(f"  Verdict:       {report['verdict']}")
    lines.append("")

    if report.get("top_fixes"):
        lines.append("  Top Fixes:")
        for i, fix in enumerate(report["top_fixes"], 1):
            lines.append(f"    {i}. {fix}")
        lines.append("")

    for mod in report.get("modules", []):
        score_str = f"{mod['score']}/100" if mod.get("score") is not None else "N/A"
        lines.append(f"  [{score_str}] {mod['name']} — {mod.get('issues', 0)} issue(s)")
        if mod.get("warning"):
            lines.append(f"         ⚠ {mod['warning']}")
        for detail in mod.get("details", [])[:10]:
            file_info = detail.get("file", "?")
            line_num = detail.get("line", "?")
            dtype = detail.get("type", "issue")
            severity = detail.get("severity", "?")
            lines.append(f"         [{severity.upper()}] {file_info}:{line_num} — {dtype}")
        remaining = mod.get("issues", 0) - 10
        if remaining > 0:
            lines.append(f"         ... and {remaining} more")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Ybe Check CLI")
    parser.add_argument("repo_path", help="Path to repo to scan")
    parser.add_argument("--json", action="store_true", 
                        help="Output as JSON (default: human-readable text)")
    parser.add_argument("--static", action="store_true",
                        help="Run static analysis only (skip network-dependent checks)")
    args = parser.parse_args()
    
    repo_path = os.path.abspath(args.repo_path)
    
    if not os.path.isdir(repo_path):
        error_msg = f"Not a directory: {repo_path}"
        if args.json:
            print(json.dumps({"error": error_msg}))
        else:
            print(f"Error: {error_msg}", file=sys.stderr)
        sys.exit(1)
    
    report = run_scan(repo_path, static_only=args.static)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(format_plain_text(report))

if __name__ == "__main__":
    main()
