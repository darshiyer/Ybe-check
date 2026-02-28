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

MODULES = [
    "modules.secrets",
    "modules.prompt_injection",
    "modules.pii_logging",
    "modules.dependencies",
    "modules.auth_guards"
]

def load_modules():
    loaded = []
    for name in MODULES:
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

def run_scan(repo_path):
    modules = load_modules()
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

def main():
    parser = argparse.ArgumentParser(description="Ybe Check CLI")
    parser.add_argument("repo_path", help="Path to repo to scan")
    parser.add_argument("--json", action="store_true", 
                        help="Output as JSON")
    args = parser.parse_args()
    
    repo_path = os.path.abspath(args.repo_path)
    
    if not os.path.isdir(repo_path):
        print(json.dumps({
            "error": f"Not a directory: {repo_path}"
        }))
        sys.exit(1)
    
    report = run_scan(repo_path)
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
