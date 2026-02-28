"""
Ybe Check core — scan orchestration and unified report generation.
Wraps existing A2K2 modules, adapts their output to the unified findings schema.
"""

import importlib
import json
import os
import time
from pathlib import Path
from typing import Any, Optional

from . import __version__
from .schema import CATEGORY_DYNAMIC, CATEGORY_INFRA, CATEGORY_STATIC, detail_to_finding

# Module name (for --modules) -> (import_path, category)
MODULE_MAP: dict[str, tuple[str, str]] = {
    "secrets": ("A2K2.modules.secrets", CATEGORY_STATIC),
    "prompt_injection": ("A2K2.modules.prompt_injection", CATEGORY_STATIC),
    "pii_logging": ("A2K2.modules.pii_logging", CATEGORY_STATIC),
    "dependencies": ("A2K2.modules.dependencies", CATEGORY_INFRA),
    "auth_guards": ("A2K2.modules.auth_guards", CATEGORY_STATIC),
    "iac_security": ("A2K2.modules.iac_security", CATEGORY_INFRA),
    "license_compliance": ("A2K2.modules.license_compliance", CATEGORY_INFRA),
    "ai_traceability": ("A2K2.modules.ai_traceability", CATEGORY_STATIC),
    "test_coverage": ("A2K2.modules.test_coverage", CATEGORY_STATIC),
    "container_scan": ("A2K2.modules.container_scan", CATEGORY_INFRA),
    "sbom": ("A2K2.modules.sbom", CATEGORY_INFRA),
    "config_env": ("A2K2.modules.config_env", CATEGORY_INFRA),
    "load_testing": ("A2K2.modules.load_testing", CATEGORY_DYNAMIC),
    "web_attacks": ("A2K2.modules.web_attacks", CATEGORY_DYNAMIC),
    "api_fuzzing": ("A2K2.modules.api_fuzzing", CATEGORY_DYNAMIC),
    "prompt_live": ("A2K2.modules.prompt_live", CATEGORY_DYNAMIC),
}

# Category -> default module list (when --categories is used)
CATEGORY_MODULES: dict[str, list[str]] = {
    CATEGORY_STATIC: [
        "secrets", "prompt_injection", "pii_logging", "auth_guards",
        "iac_security", "license_compliance", "ai_traceability", "test_coverage",
    ],
    CATEGORY_DYNAMIC: ["load_testing", "web_attacks", "api_fuzzing", "prompt_live"],
    CATEGORY_INFRA: ["dependencies", "container_scan", "sbom", "config_env"],
}


def _resolve_modules(modules: Optional[list[str]], categories: Optional[list[str]]) -> list[str]:
    """Resolve which modules to run from --modules and/or --categories."""
    if modules:
        return [m for m in modules if m in MODULE_MAP]
    if categories:
        result: list[str] = []
        for cat in categories:
            if cat in CATEGORY_MODULES:
                result.extend(CATEGORY_MODULES[cat])
        return list(dict.fromkeys(result))  # dedupe, preserve order
    return list(MODULE_MAP.keys())


def _source_name(mod_name: str) -> str:
    """Short source name for findings (e.g. secrets, deps, trivy)."""
    aliases = {
        "secrets": "secrets",
        "prompt_injection": "prompt_injection",
        "pii_logging": "pii",
        "dependencies": "deps",
        "auth_guards": "auth",
        "iac_security": "iac",
        "license_compliance": "license",
        "ai_traceability": "ai_trace",
        "test_coverage": "test_cov",
        "container_scan": "trivy",
        "sbom": "syft",
        "config_env": "config_env",
        "load_testing": "artillery",
        "web_attacks": "zap",
        "api_fuzzing": "ffuf",
        "prompt_live": "vigil",
    }
    return aliases.get(mod_name, mod_name)


def run_scan(
    path: str,
    modules: Optional[list[str]] = None,
    categories: Optional[list[str]] = None,
) -> dict[str, Any]:
    """
    Run selected scan modules and return a unified report.

    Returns:
        {
            "tool": "ybe-check",
            "version": "0.1.0",
            "scan_path": str,
            "scan_time": str (ISO),
            "modules_run": list[str],
            "overall_score": int,
            "verdict": str,
            "findings": list[dict],  # unified schema
            "module_results": list[dict],  # raw per-module (score, issues, warning)
        }
    """
    repo_path = os.path.abspath(path)
    if not os.path.isdir(repo_path):
        return {
            "tool": "ybe-check",
            "version": __version__,
            "scan_path": repo_path,
            "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "error": f"Not a directory: {repo_path}",
            "modules_run": [],
            "findings": [],
            "module_results": [],
        }

    to_run = _resolve_modules(modules, categories)
    start = time.time()
    all_findings: list[dict] = []
    module_results: list[dict] = []
    global_finding_idx = 0

    for mod_name in to_run:
        import_path, category = MODULE_MAP[mod_name]
        source = _source_name(mod_name)
        try:
            mod = importlib.import_module(import_path)
            result = mod.scan(repo_path)
        except Exception as e:
            module_results.append({
                "name": mod_name,
                "score": None,
                "issues": 0,
                "warning": str(e),
            })
            continue

        module_results.append({
            "name": result.get("name", mod_name),
            "score": result.get("score"),
            "issues": result.get("issues", 0),
            "warning": result.get("warning"),
        })

        for i, detail in enumerate(result.get("details") or []):
            finding = detail_to_finding(detail, source, category, global_finding_idx)
            finding["id"] = f"{source}:{global_finding_idx}"
            all_findings.append(finding)
            global_finding_idx += 1

    elapsed = time.time() - start
    scores = [r["score"] for r in module_results if r.get("score") is not None]
    overall = (
        max(0, min(100, round(0.7 * (sum(scores) / len(scores)) + 0.3 * min(scores))))
        if scores
        else 0
    )
    verdict = (
        "PRODUCTION READY" if overall >= 80
        else "NEEDS ATTENTION" if overall >= 40
        else "NOT READY"
    )

    return {
        "tool": "ybe-check",
        "version": __version__,
        "scan_path": repo_path,
        "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scan_duration_seconds": round(elapsed, 2),
        "modules_run": to_run,
        "overall_score": overall,
        "verdict": verdict,
        "findings": all_findings,
        "module_results": module_results,
        "top_fixes": _extract_top_fixes(all_findings),
    }


def _extract_top_fixes(findings: list[dict]) -> list[str]:
    """Extract top remediation hints from findings (critical/high first)."""
    seen: set[str] = set()
    fixes: list[str] = []
    for sev in ("critical", "high", "medium"):
        for f in findings:
            if f.get("severity") != sev:
                continue
            s = (f.get("summary") or "").strip()
            if s and s not in seen:
                seen.add(s)
                fixes.append(s)
    return fixes[:5]


def load_report(path: str) -> dict[str, Any]:
    """Load a JSON report file."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def filter_findings(
    report: dict,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    source: Optional[str] = None,
) -> list[dict]:
    """Filter findings by severity, category, or source."""
    findings = report.get("findings", [])
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if category:
        findings = [f for f in findings if f.get("category") == category]
    if source:
        findings = [f for f in findings if f.get("source") == source]
    return findings
