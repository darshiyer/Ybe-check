#!/usr/bin/env python3
"""
Ybe Check MCP Server — self-contained, zero external dependencies.

Bundled inside the VS Code extension. Implements MCP (Model Context Protocol)
over stdio transport using JSON-RPC 2.0. Uses the extension's bundled cli.py
and modules/ for scanning — no pip install needed.

Requirements: Python 3.10+ (stdlib only)

Run:
    python3 mcp_server.py          # stdio mode (default — for VS Code / Cursor)
    python3 mcp_server.py --list   # print available tools and exit
"""
import sys
import os
import json
import logging
from pathlib import Path
from typing import Any, Optional

# ── Setup: add extension directory to Python path ────────────────
EXT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EXT_DIR))

# Import bundled scanner
from cli import run_scan as _cli_run_scan, _persist_to_store, get_changed_files  # noqa: E402

logger = logging.getLogger("ybe-check-mcp")

REPORT_FILENAME = "ybe-report.json"
SEV_WEIGHT: dict[str, int] = {
    "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
}

# Source name mapping for finding IDs (module display name → short key)
_SOURCE_NAMES: dict[str, str] = {
    "Secrets Detection": "secrets",
    "Prompt Injection": "prompt_inj",
    "PII & Logging": "pii",
    "Dependencies": "deps",
    "Auth Guards": "auth",
    "IaC Security": "iac",
    "License Compliance": "license",
    "AI Traceability": "ai_trace",
    "Test & Coverage": "test_cov",
    "Container Security": "trivy",
    "SBOM": "syft",
    "Config & Env": "config_env",
    "Load Testing": "artillery",
    "Web Attacks": "zap",
    "API Fuzzing": "ffuf",
    "Live Prompt Testing": "vigil",
}


# ================================================================
# Report adaptation — cli.py format → flat findings format
# ================================================================

# Directories that indicate test/fixture/example code (not production)
_TEST_PATH_EXACT: set[str] = {
    "test", "tests", "__tests__", "spec", "fixture", "fixtures",
    "mock", "mocks", "example", "examples", "sample", "samples",
    "demo", "testdata", "test_data", "e2e", "benchmark",
}
# Patterns: segments ending with -test, _test, or starting with test-, test_
_TEST_PATH_AFFIXES = ("test-", "test_", "-test", "_test")


def _is_test_fixture(fpath: str) -> bool:
    """Return True if the file path looks like test/fixture/example code."""
    parts = fpath.lower().replace("\\", "/").split("/")
    for part in parts:
        if part in _TEST_PATH_EXACT:
            return True
        # Match *-test, test-*, *_test, test_* directory names
        for affix in _TEST_PATH_AFFIXES:
            if part.startswith(affix) or part.endswith(affix):
                return True
    return False


def _flatten_findings(report: dict) -> list[dict]:
    """Convert cli.py module-nested details into a flat findings list."""
    findings: list[dict] = []
    idx = 0
    for mod in report.get("modules", []):
        source = _SOURCE_NAMES.get(mod.get("name", ""), "unknown")
        for detail in mod.get("details", []):
            fpath = detail.get("file", "")
            entry: dict = {
                "id": f"{source}:{idx}",
                "type": detail.get("type", "issue"),
                "severity": (detail.get("severity") or "medium").lower(),
                "source": mod.get("name", "unknown"),
                "category": "static",
                "summary": detail.get("reason") or detail.get("type", ""),
                "details": detail.get("remediation") or "",
                "location": {
                    "path": fpath,
                    "line": detail.get("line"),
                },
                "evidence": {
                    "snippet": detail.get("snippet", ""),
                    "match": detail.get("match", ""),
                },
            }
            # Carry over enrichment fields from cli.py dedup/CWE pass
            if detail.get("confidence"):
                entry["confidence"] = detail["confidence"]
            if detail.get("cwe"):
                entry["cwe"] = detail["cwe"]
            if detail.get("owasp"):
                entry["owasp"] = detail["owasp"]
            if detail.get("occurrences"):
                entry["occurrences"] = detail["occurrences"]
            # Tag test fixtures
            if _is_test_fixture(fpath):
                entry["test_fixture"] = True
                entry["confidence"] = "low"
            findings.append(entry)
            idx += 1
    return findings


def _adapt_report(cli_report: dict) -> dict:
    """Transform cli.py report to the flat-findings format MCP tools expect."""
    # Already in MCP format (has "findings" at top level, no "modules")
    if "findings" in cli_report and "modules" not in cli_report:
        return cli_report

    findings = _flatten_findings(cli_report)
    return {
        "overall_score": cli_report.get("overall_score", 0),
        "verdict": cli_report.get("verdict", "UNKNOWN"),
        "findings": findings,
        "module_results": [
            {
                "name": m.get("name", ""),
                "score": m.get("score"),
                "issues": m.get("issues", 0),
                "warning": m.get("warning"),
            }
            for m in cli_report.get("modules", [])
        ],
        "top_fixes": [
            f.get("action", "") for f in cli_report.get("top_fixes", [])
        ],
    }


# ================================================================
# Report loading / scanning
# ================================================================

def _load_or_scan(repo_path: str) -> dict:
    """Load existing report or run a fresh scan."""
    report_file = Path(repo_path) / REPORT_FILENAME
    if report_file.exists():
        try:
            raw = json.loads(report_file.read_text("utf-8"))
            return _adapt_report(raw)
        except (json.JSONDecodeError, OSError):
            pass
    return _run_scan(repo_path)


def _run_scan(
    repo_path: str,
    include_paths: Optional[list[str]] = None,
) -> dict:
    """Run a scan via the bundled cli.py and return adapted report."""
    cli_report = _cli_run_scan(
        repo_path,
        static_only=True,
        dynamic_only=False,
        include_paths=set(include_paths) if include_paths is not None else None,
    )

    # Persist for sidebar
    try:
        _persist_to_store(repo_path, cli_report)
    except Exception:
        pass

    # Cache as ybe-report.json for subsequent loads
    try:
        (Path(repo_path) / REPORT_FILENAME).write_text(
            json.dumps(cli_report, indent=2), "utf-8",
        )
    except OSError:
        pass

    return _adapt_report(cli_report)


# ================================================================
# Security summary builder
# ================================================================

def _build_security_summary(report: dict, max_findings: int = 15) -> dict:
    findings = report.get("findings", [])
    sorted_f = sorted(
        findings,
        key=lambda f: SEV_WEIGHT.get(f.get("severity", "medium"), 3),
        reverse=True,
    )

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
            for f in sorted_f[:max_findings]
        ],
    }


# ================================================================
# ROOT-CAUSE GROUPING — collapse N findings into distinct problems
# ================================================================

# Map finding types to broad root causes
_ROOT_CAUSE_MAP: dict[str, str] = {
    "hardcoded api key": "secrets_in_source",
    "hardcoded secret": "secrets_in_source",
    "hardcoded password": "secrets_in_source",
    "secret keyword": "secrets_in_source",
    "json web token": "secrets_in_source",
    "base64 high entropy string": "secrets_in_source",
    "hex high entropy string": "secrets_in_source",
    "private key": "secrets_in_source",
    "aws access key": "secrets_in_source",
    "slack token": "secrets_in_source",
    "stripe api key": "secrets_in_source",
    "github token": "secrets_in_source",
    "basic auth credentials": "secrets_in_source",
    "secret in env file": "secrets_in_source",
    "hardcoded email": "pii_in_source",
    "hardcoded phone number": "pii_in_source",
    "hardcoded aadhaar": "pii_in_source",
    "hardcoded pan": "pii_in_source",
    "hardcoded credit card": "pii_in_source",
    "unsafe prompt template": "prompt_injection_risk",
    "missing prompt guardrails": "prompt_injection_risk",
    "jailbreak vulnerable prompt": "prompt_injection_risk",
    "unsafe logging": "unsafe_logging",
    "unprotected route": "missing_auth",
    "debug mode enabled": "insecure_config",
    "wildcard cors": "insecure_config",
    "unresolvable dependency": "dependency_risk",
    "license risk": "dependency_risk",
    "bare except": "code_quality",
    "no subprocess timeout": "code_quality",
    "no path validation": "code_quality",
    "eval/exec on variable": "code_quality",
    # Multi-word variants the scanner produces
    "unsafe prompt template (multiline)": "prompt_injection_risk",
    "unsafe prompt template (f-string)": "prompt_injection_risk",
    "unsafe prompt template (format)": "prompt_injection_risk",
    "unprotected sensitive route": "missing_auth",
    "unprotected admin route": "missing_auth",
    "hardcoded secret in docker-compose": "secrets_in_source",
    "dangerous default in env": "insecure_config",
    "missing .env.example": "insecure_config",
    "config drift": "insecure_config",
    "ai generation marker": "ai_traceability",
    "ai generated code marker": "ai_traceability",
    "prompt artifact": "ai_traceability",
    "markdown artifact": "ai_traceability",
    "no test files found": "missing_tests",
    "no test framework detected": "missing_tests",
    "low test-to-code ratio": "missing_tests",
    # auth / url patterns
    "basic auth in url": "secrets_in_source",
    "basic auth credentials in url": "secrets_in_source",
    # IaC / checkov findings (CKV_* pattern)
}

_ROOT_CAUSE_LABELS: dict[str, str] = {
    "secrets_in_source": "Secrets committed to source code",
    "pii_in_source": "PII / personal data hardcoded in source",
    "prompt_injection_risk": "LLM prompt injection vulnerabilities",
    "unsafe_logging": "Sensitive data in log output",
    "missing_auth": "Missing authentication on routes",
    "insecure_config": "Insecure configuration (debug, CORS, etc.)",
    "dependency_risk": "Dependency vulnerabilities or license issues",
    "code_quality": "Code quality / architectural issues",
    "ai_traceability": "AI-generated code markers (informational)",
    "missing_tests": "Missing or insufficient test coverage",
}

_ROOT_CAUSE_FIXES: dict[str, str] = {
    "secrets_in_source": "Move all secrets to .env (add to .gitignore), rotate any committed credentials, use os.getenv() to read them.",
    "pii_in_source": "Move hardcoded personal data to a database or environment config. Never store emails, phones, or IDs in source code.",
    "prompt_injection_risk": "Sanitize user input before injecting into prompts. Add system-level guardrails ('You must not...') and validate LLM output.",
    "unsafe_logging": "Log only specific fields (request.method, request.path) — never log full request/response objects that may contain PII.",
    "missing_auth": "Add authentication middleware to all sensitive routes. Use @login_required or equivalent before handlers.",
    "insecure_config": "Set DEBUG=False in production. Restrict CORS to specific origins. Remove default passwords.",
    "dependency_risk": "Pin all dependency versions. Run pip-audit / npm audit. Replace packages with restrictive licenses.",
    "code_quality": "Add timeouts to subprocess calls. Replace bare except: with specific exception types. Validate all file paths.",
    "ai_traceability": "Review AI-generated code for correctness. Remove @generated markers if code has been human-reviewed. Low priority.",
    "missing_tests": "Add test files for critical modules. Install pytest/jest. Aim for coverage on auth, data, and API paths first.",
}


def _infer_root_cause(ftype: str) -> str:
    """Infer root cause for unmapped types via keyword matching."""
    t = ftype.lower()
    if any(k in t for k in ("secret", "key", "token", "credential", "password", "auth in url")):
        return "secrets_in_source"
    if any(k in t for k in ("prompt", "jailbreak", "injection", "guardrail")):
        return "prompt_injection_risk"
    if any(k in t for k in ("pii", "email", "phone", "aadhaar", "pan", "credit card")):
        return "pii_in_source"
    if any(k in t for k in ("route", "auth", "login", "admin")):
        return "missing_auth"
    if any(k in t for k in ("debug", "cors", "config", "env", "default")):
        return "insecure_config"
    if any(k in t for k in ("except", "timeout", "eval", "exec", "subprocess")):
        return "code_quality"
    if any(k in t for k in ("ckv", "misconfiguration", "iac")):
        return "insecure_config"
    if any(k in t for k in ("license", "dependency", "vulnerable")):
        return "dependency_risk"
    return ftype or "other"


def _group_by_root_cause(findings: list[dict]) -> list[dict]:
    """Group findings into distinct root causes ranked by impact."""
    groups: dict[str, list[dict]] = {}
    for f in findings:
        ftype = (f.get("type") or "").lower().strip()
        cause = _ROOT_CAUSE_MAP.get(ftype) or _infer_root_cause(ftype)
        groups.setdefault(cause, []).append(f)

    result = []
    for cause, items in groups.items():
        # Worst severity in the group
        worst = min(items, key=lambda f: SEV_WEIGHT.get(f.get("severity", "info"), 0))
        worst_sev = worst.get("severity", "medium")
        files = sorted(set(
            (f.get("location") or {}).get("path", "?") for f in items
        ))
        test_count = sum(1 for f in items if f.get("test_fixture"))
        prod_count = len(items) - test_count

        result.append({
            "root_cause": cause,
            "label": _ROOT_CAUSE_LABELS.get(cause, cause.replace("_", " ").title()),
            "worst_severity": worst_sev,
            "total": len(items),
            "production": prod_count,
            "test_fixture": test_count,
            "files": files[:10],
            "fix": _ROOT_CAUSE_FIXES.get(cause, "Review and fix the identified issues."),
            "cwe": worst.get("cwe"),
            "example_id": items[0].get("id"),
        })

    # Sort by impact: highest severity first, then most production findings
    result.sort(key=lambda g: (
        -SEV_WEIGHT.get(g["worst_severity"], 0),
        -g["production"],
    ))
    return result


# ================================================================
# DELTA SCAN — compare current findings with store
# ================================================================

def _compute_delta(repo_path: str) -> dict:
    """Compare current scan findings with the persistent store to get deltas."""
    store_path = Path(repo_path) / ".ybe-check" / "store.json"
    if not store_path.exists():
        return {"available": False}

    try:
        store = json.loads(store_path.read_text("utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"available": False}

    findings = store.get("findings", [])
    new = [f for f in findings if f.get("isNew")]
    resolved = [f for f in findings if f.get("status") in ("fixed", "resolved")]
    ignored = [f for f in findings if f.get("status") == "ignored"]
    open_f = [f for f in findings if f.get("status") == "open"]

    history = store.get("history", [])
    prev_score = history[-2]["score"] if len(history) >= 2 else None
    curr_score = store.get("currentScore")

    return {
        "available": True,
        "current_score": curr_score,
        "previous_score": prev_score,
        "score_delta": (curr_score - prev_score) if curr_score is not None and prev_score is not None else None,
        "open": len(open_f),
        "new_since_last": len(new),
        "resolved": len(resolved),
        "ignored": len(ignored),
        "total_scans": len(history),
    }


# ================================================================
# MCP TOOLS — 7 tools: scan, triage, get_finding, fix, resolve, delta, status
# ================================================================

def tool_ybe_scan(args: dict) -> str:
    """Run a scan (full, changed files, or specific path)."""
    repo_path = args.get("path", ".")
    scope = args.get("scope", "full")
    path_filter = args.get("path_filter", "")

    include_paths: Optional[list[str]] = None
    if scope == "changed":
        try:
            changed = get_changed_files(repo_path)
            include_paths = list(changed) if changed else []
        except Exception:
            include_paths = []
    elif scope == "path" and path_filter:
        # Resolve to absolute
        p = path_filter if os.path.isabs(path_filter) else str(Path(repo_path) / path_filter)
        include_paths = [p]

    report = _run_scan(repo_path, include_paths=include_paths)
    return json.dumps(_build_security_summary(report, max_findings=20), indent=2)


def tool_ybe_triage(args: dict) -> str:
    """Top N distinct root-cause problems ranked by impact, with one fix each.
    Call this first when starting a session — gives the highest-leverage view."""
    repo_path = args.get("path", ".")
    limit = args.get("limit", 5)
    report = _load_or_scan(repo_path)
    findings = report.get("findings", [])
    groups = _group_by_root_cause(findings)

    delta = _compute_delta(repo_path)
    output: dict = {
        "score": report.get("overall_score", 0),
        "verdict": report.get("verdict", "UNKNOWN"),
        "total_findings": len(findings),
        "root_causes": len(groups),
        "triage": groups[:limit],
    }
    if delta.get("available"):
        output["delta"] = {
            "score_change": delta.get("score_delta"),
            "new": delta.get("new_since_last", 0),
            "resolved": delta.get("resolved", 0),
            "open": delta.get("open", 0),
        }
    return json.dumps(output, indent=2)


def tool_ybe_get_finding(args: dict) -> str:
    """Get full details and remediation for a specific finding by ID."""
    repo_path = args.get("path", ".")
    finding_id = args.get("finding_id", "")
    report = _load_or_scan(repo_path)
    match = next(
        (f for f in report.get("findings", []) if f.get("id") == finding_id),
        None,
    )
    if not match:
        return json.dumps({"error": f"Finding '{finding_id}' not found."})

    severity = match.get("severity", "medium")
    summary = match.get("summary", "")
    details_text = match.get("details", "")
    cwe = match.get("cwe")
    owasp = match.get("owasp")
    loc = match.get("location") or {}
    evidence = match.get("evidence") or {}

    references = []
    if owasp:
        references.append(owasp)
    if cwe:
        references.append(f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html")

    return json.dumps({
        "finding_id": finding_id,
        "type": match.get("type", "issue"),
        "severity": severity,
        "confidence": match.get("confidence", "medium"),
        "file": loc.get("path", ""),
        "line": loc.get("line"),
        "summary": summary,
        "snippet": evidence.get("snippet") or evidence.get("match") or "",
        "remediation": details_text or f"Address: {summary[:200]}. Review {loc.get('path', 'the file')} and apply the fix.",
        "cwe": cwe,
        "owasp": owasp,
        "references": references,
        "test_fixture": match.get("test_fixture", False),
    }, indent=2)


def tool_ybe_fix(args: dict) -> str:
    """Generate a ready-to-use fix prompt for a specific finding."""
    repo_path = args.get("path", ".")
    finding_id = args.get("finding_id", "")
    report = _load_or_scan(repo_path)
    match = next(
        (f for f in report.get("findings", []) if f.get("id") == finding_id),
        None,
    )
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

    evidence_line = f"**Evidence**: `{snippet[:200]}`\n" if snippet else ""
    prompt = (
        f"Fix this {sev} security finding in my codebase:\n\n"
        f"**Finding ID**: {finding_id}\n"
        f"**Type**: {ftype}\n"
        f"**Severity**: {sev}\n"
        f"**File**: {file_path}\n"
        f"**Line**: {line}\n"
        f"**Issue**: {summary}\n"
        f"{evidence_line}\n"
        "Please:\n"
        "1. Show me the exact code change needed to fix this issue.\n"
        "2. Explain why the current code is vulnerable.\n"
        "3. Ensure the fix doesn't break existing functionality.\n"
        "4. If there are related issues in the same file, mention them."
    )
    return json.dumps({"finding_id": finding_id, "prompt": prompt.strip()}, indent=2)


def tool_ybe_resolve(args: dict) -> str:
    """Mark a finding as fixed, ignored, or reopen it."""
    repo_path = args.get("path", ".")
    finding_id = args.get("finding_id", "")
    # Accept 'resolution' (spec) or legacy 'status'
    resolution = args.get("resolution") or args.get("status", "fixed")
    note = args.get("note", "")

    if resolution not in ("fixed", "ignored", "open"):
        return json.dumps({"error": f"Invalid resolution '{resolution}'. Use fixed, ignored, or open."})

    store_path = Path(repo_path) / ".ybe-check" / "store.json"
    if not store_path.exists():
        return json.dumps({"error": "No store found. Run a scan first."})

    try:
        store = json.loads(store_path.read_text("utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return json.dumps({"error": f"Failed to read store: {e}"})

    findings = store.get("findings", [])
    match = next((f for f in findings if f.get("id") == finding_id), None)
    if not match:
        return json.dumps({"error": f"Finding '{finding_id}' not found in store."})

    old_status = match.get("status", "open")
    match["status"] = resolution
    if note:
        match["note"] = note

    try:
        store_path.write_text(json.dumps(store, indent=2), "utf-8")
    except OSError as e:
        return json.dumps({"error": f"Failed to write store: {e}"})

    return json.dumps({
        "finding_id": finding_id,
        "old_status": old_status,
        "new_status": resolution,
        "note": note or None,
        "type": match.get("type", ""),
        "file": (match.get("location") or {}).get("path") or match.get("file", ""),
    }, indent=2)


def tool_ybe_delta(args: dict) -> str:
    """What changed since the last scan: new issues, resolved, score change."""
    repo_path = args.get("path", ".")
    delta = _compute_delta(repo_path)
    if not delta.get("available"):
        return json.dumps({"error": "No scan history. Run at least 2 scans to see deltas."})
    return json.dumps(delta, indent=2)


def tool_ybe_status(args: dict) -> str:
    """Current security status: score, open/fixed/ignored counts, last scan time."""
    repo_path = args.get("path", ".")
    store_path = Path(repo_path) / ".ybe-check" / "store.json"
    if not store_path.exists():
        return json.dumps({"scanned": False, "message": "No scan data. Run ybe_scan first."})

    try:
        store = json.loads(store_path.read_text("utf-8"))
    except (json.JSONDecodeError, OSError):
        return json.dumps({"scanned": False, "message": "Could not read store."})

    findings = store.get("findings", [])
    open_f   = [f for f in findings if f.get("status") == "open"]
    fixed_f  = [f for f in findings if f.get("status") == "fixed"]
    ign_f    = [f for f in findings if f.get("status") == "ignored"]

    by_sev: dict[str, int] = {}
    for f in open_f:
        s = f.get("severity", "medium")
        by_sev[s] = by_sev.get(s, 0) + 1

    history = store.get("history", [])
    prev_score = history[-2]["score"] if len(history) >= 2 else None

    return json.dumps({
        "scanned": True,
        "score": store.get("currentScore"),
        "previous_score": prev_score,
        "verdict": store.get("verdict", "UNKNOWN"),
        "last_scan": store.get("lastScan"),
        "open": len(open_f),
        "fixed": len(fixed_f),
        "ignored": len(ign_f),
        "total": len(findings),
        "open_by_severity": by_sev,
    }, indent=2)


# ================================================================
# TOOL & PROMPT REGISTRIES
# ================================================================

TOOLS: dict[str, dict[str, Any]] = {
    "ybe_scan": {
        "handler": tool_ybe_scan,
        "schema": {
            "name": "ybe_scan",
            "description": (
                "Scan a repository for security issues. "
                "scope='full' scans everything (default); "
                "scope='changed' scans only git-modified files; "
                "scope='path' scans a specific file or folder (supply path_filter). "
                "Returns a summary with score, severity breakdown, and top findings."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute path to the repository root."},
                    "scope": {
                        "type": "string",
                        "enum": ["full", "changed", "path"],
                        "description": "Scan scope. Default: full.",
                        "default": "full",
                    },
                    "path_filter": {
                        "type": "string",
                        "description": "File or folder to scan when scope='path' (relative to repo root).",
                    },
                },
                "required": ["path"],
            },
        },
    },
    "ybe_triage": {
        "handler": tool_ybe_triage,
        "schema": {
            "name": "ybe_triage",
            "description": (
                "Top N distinct root-cause problems ranked by impact, each with a concrete one-step fix. "
                "Call this first when starting a session — gives the highest-leverage view of the repo."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute path to the repository root."},
                    "limit": {"type": "integer", "description": "Max root causes to return (default 5).", "default": 5},
                },
                "required": ["path"],
            },
        },
    },
    "ybe_get_finding": {
        "handler": tool_ybe_get_finding,
        "schema": {
            "name": "ybe_get_finding",
            "description": "Get full details, evidence, and remediation guidance for a specific finding by ID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute path to the repository root."},
                    "finding_id": {"type": "string", "description": 'Finding ID (e.g. "secrets:0").'},
                },
                "required": ["path", "finding_id"],
            },
        },
    },
    "ybe_fix": {
        "handler": tool_ybe_fix,
        "schema": {
            "name": "ybe_fix",
            "description": "Generate a ready-to-use fix prompt for a specific finding. Returns a structured prompt you can act on directly.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute path to the repository root."},
                    "finding_id": {"type": "string", "description": 'Finding ID (e.g. "secrets:0").'},
                },
                "required": ["path", "finding_id"],
            },
        },
    },
    "ybe_resolve": {
        "handler": tool_ybe_resolve,
        "schema": {
            "name": "ybe_resolve",
            "description": "Mark a finding as fixed, ignored, or reopen it in the persistent security store.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute path to the repository root."},
                    "finding_id": {"type": "string", "description": "Finding ID."},
                    "resolution": {
                        "type": "string",
                        "enum": ["fixed", "ignored", "open"],
                        "description": "New status for the finding.",
                        "default": "fixed",
                    },
                    "note": {"type": "string", "description": "Optional note explaining the resolution."},
                },
                "required": ["path", "finding_id"],
            },
        },
    },
    "ybe_delta": {
        "handler": tool_ybe_delta,
        "schema": {
            "name": "ybe_delta",
            "description": "What changed since the last scan: new issues introduced, resolved, remaining open, and score change.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute path to the repository root."},
                },
                "required": ["path"],
            },
        },
    },
    "ybe_status": {
        "handler": tool_ybe_status,
        "schema": {
            "name": "ybe_status",
            "description": "Current security status: score, open/fixed/ignored counts, severity breakdown, and last scan time. Fast — reads from store without rescanning.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute path to the repository root."},
                },
                "required": ["path"],
            },
        },
    },
}

# ── Prompt templates ─────────────────────────────────────────────

PROMPTS: dict[str, dict] = {
    "security-audit": {
        "name": "security-audit",
        "description": "Comprehensive security audit of the current workspace.",
        "arguments": [],
    },
    "fix-critical": {
        "name": "fix-critical",
        "description": "Fix all critical and high severity findings.",
        "arguments": [],
    },
}

PROMPT_CONTENT: dict[str, str] = {
    "security-audit": (
        "You are a senior security engineer performing a production-readiness audit.\n\n"
        "1. Call ybe_triage to get the top root-cause problems ranked by impact.\n"
        "2. Call ybe_status for the current score and counts.\n"
        "Then provide a comprehensive security review covering:\n\n"
        "- **Critical Issues** — findings that must be fixed before deployment.\n"
        "- **Quick Wins** — easy fixes that improve the score significantly.\n"
        "- **Architecture Concerns** — structural problems (auth flow, data handling, etc.).\n"
        "- **Prioritized Action Plan** — ordered list of what to fix first.\n\n"
        "Reference specific finding IDs. Be specific with file names and line numbers."
    ),
    "fix-critical": (
        "You are a security remediation specialist.\n\n"
        "1. Call ybe_triage to identify the highest-impact root causes.\n"
        "2. For each critical/high finding, call ybe_fix to get the fix prompt.\n"
        "3. Apply the fix, then call ybe_resolve with resolution='fixed'.\n\n"
        "For each fix:\n"
        "- Show the exact file and line.\n"
        "- Explain the vulnerability in one sentence.\n"
        "- Provide the complete corrected code block.\n"
        "- Verify the fix doesn't introduce new issues.\n\n"
        "Start with the most severe issues. After all fixes, call ybe_status to show the new score."
    ),
}


# ================================================================
# JSON-RPC 2.0 / MCP PROTOCOL OVER STDIO
# ================================================================

def _jsonrpc_result(msg_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _jsonrpc_error(msg_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def handle_initialize(msg_id: Any, params: dict) -> dict:
    return _jsonrpc_result(msg_id, {
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {"listChanged": False},
            "prompts": {"listChanged": False},
        },
        "serverInfo": {
            "name": "ybe-check",
            "version": "1.0.0",
        },
    })


def handle_tools_list(msg_id: Any, params: dict) -> dict:
    tools = [t["schema"] for t in TOOLS.values()]
    return _jsonrpc_result(msg_id, {"tools": tools})


def handle_tools_call(msg_id: Any, params: dict) -> dict:
    name = params.get("name", "")
    arguments = params.get("arguments", {})

    tool = TOOLS.get(name)
    if not tool:
        return _jsonrpc_error(msg_id, -32601, f"Unknown tool: {name}")

    try:
        result_text = tool["handler"](arguments)
        return _jsonrpc_result(msg_id, {
            "content": [{"type": "text", "text": result_text}],
        })
    except Exception as e:
        logger.exception("Tool %s failed", name)
        return _jsonrpc_result(msg_id, {
            "content": [{"type": "text", "text": json.dumps({"error": str(e)})}],
            "isError": True,
        })


def handle_prompts_list(msg_id: Any, params: dict) -> dict:
    return _jsonrpc_result(msg_id, {"prompts": list(PROMPTS.values())})


def handle_prompts_get(msg_id: Any, params: dict) -> dict:
    name = params.get("name", "")
    content = PROMPT_CONTENT.get(name)
    if not content:
        return _jsonrpc_error(msg_id, -32602, f"Unknown prompt: {name}")
    return _jsonrpc_result(msg_id, {
        "description": PROMPTS[name]["description"],
        "messages": [
            {"role": "user", "content": {"type": "text", "text": content}},
        ],
    })


def handle_ping(msg_id: Any, params: dict) -> dict:
    return _jsonrpc_result(msg_id, {})


# ── Dispatch table ───────────────────────────────────────────────

_METHODS: dict[str, Any] = {
    "initialize": handle_initialize,
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
    "prompts/list": handle_prompts_list,
    "prompts/get": handle_prompts_get,
    "ping": handle_ping,
}

_NOTIFICATIONS: set[str] = {
    "notifications/initialized",
    "notifications/cancelled",
}


# ================================================================
# MAIN LOOP
# ================================================================

def main() -> None:
    """MCP stdio server — reads newline-delimited JSON-RPC from stdin."""
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)

    if "--list" in sys.argv:
        for name, tool in TOOLS.items():
            print(f"  {name:30s} {tool['schema']['description'][:70]}")
        return

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue

        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Invalid JSON on stdin: %s", line[:200])
            continue

        method = msg.get("method", "")
        msg_id = msg.get("id")
        params = msg.get("params", {})

        # Notifications — no response expected
        if method in _NOTIFICATIONS:
            continue

        # Requests need an id
        if msg_id is None:
            continue

        handler = _METHODS.get(method)
        if handler:
            try:
                response = handler(msg_id, params)
            except Exception as e:
                logger.exception("Handler for %s failed", method)
                response = _jsonrpc_error(msg_id, -32603, f"Internal error: {e}")
        else:
            response = _jsonrpc_error(msg_id, -32601, f"Method not found: {method}")

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
