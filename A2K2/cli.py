#!/usr/bin/env python3
"""Ybe Check CLI — self-contained audit script bundled with the VS Code extension.
Multi-layer security scanner: detect-secrets, keyword patterns, .env audit,
hardcoded credentials, dangerous configs, and dependency checks.
"""
import argparse
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional


# ===================================================================
# SHARED UTILS
# ===================================================================

SKIP_DIRS: Set[str] = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", ".next",
    ".ybe-check", ".secret-stack", ".eggs", "*.egg-info",
}

SKIP_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".zip", ".gz", ".tar", ".bz2", ".7z", ".rar",
    ".pyc", ".pyo", ".exe", ".dll", ".so", ".dylib",
    ".bin", ".lock", ".vsix", ".pdf", ".doc", ".docx",
    ".sqlite", ".db", ".sqlite3",
}

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB — skip huge files


def _walk_files(root: str) -> List[str]:
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in SKIP_EXTENSIONS:
                continue
            full = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(full) > MAX_FILE_SIZE:
                    continue
                if os.path.islink(full):
                    continue
            except OSError:
                continue
            files.append(full)
    return files


def _read_file(fpath: str) -> Optional[str]:
    try:
        with open(fpath, "r", errors="ignore") as f:
            return f.read()
    except Exception:
        return None


# ===================================================================
# MODULE 1: detect-secrets (external tool)
# ===================================================================

def _ensure_detect_secrets() -> bool:
    try:
        subprocess.run(
            [sys.executable, "-m", "detect_secrets", "--version"],
            capture_output=True, check=True,
        )
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    sys.stderr.write("detect-secrets not found — installing automatically...\n")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "detect-secrets", "-q"],
            check=True, capture_output=True,
        )
        return True
    except subprocess.CalledProcessError as e:
        sys.stderr.write(
            f"Failed to install detect-secrets: "
            f"{e.stderr.decode() if e.stderr else 'unknown error'}\n"
        )
        return False


def run_detect_secrets(target_path: str) -> Dict:
    if not _ensure_detect_secrets():
        return {
            "name": "detect-secrets",
            "score": 0, "issues": 0, "details": [],
            "warning": "Could not install detect-secrets. Run: pip install detect-secrets",
        }

    try:
        result = subprocess.run(
            [sys.executable, "-m", "detect_secrets", "scan", "--all-files", target_path],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        return {
            "name": "detect-secrets",
            "score": 0, "issues": 0, "details": [],
            "warning": "detect-secrets not found after install attempt",
        }

    if result.returncode != 0 and not result.stdout:
        return {
            "name": "detect-secrets",
            "score": 0, "issues": 0, "details": [],
            "error": result.stderr.strip() if result.stderr else "Unknown error",
        }

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "name": "detect-secrets",
            "score": 0, "issues": 0, "details": [],
            "error": "Invalid JSON from detect-secrets",
        }

    results_dict = data.get("results", {})
    details: List[Dict] = []
    for filename, findings in results_dict.items():
        for item in findings:
            details.append({
                "file": filename,
                "line": item.get("line_number"),
                "type": item.get("type"),
                "reason": item.get("reason"),
            })

    issues = len(details)
    return {
        "name": "detect-secrets",
        "score": max(0, 100 - 5 * issues),
        "issues": issues,
        "details": details,
    }


# ===================================================================
# MODULE 2: Keyword & Pattern Secret Scanner
# ===================================================================

TOKEN_PATTERNS: List[Tuple[str, str, re.Pattern]] = [
    # Cloud providers
    ("AWS Access Key",         "high",   re.compile(r'AKIA[0-9A-Z]{12,}')),
    ("AWS MFA Serial",         "medium", re.compile(r'arn:aws:iam::\d{12}:mfa/\S+')),
    ("GCP API Key",            "high",   re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("GCP Service Account",    "high",   re.compile(r'"type"\s*:\s*"service_account"')),
    ("Azure Storage Key",      "high",   re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{60,}')),
    ("Heroku API Key",         "high",   re.compile(r'[hH]eroku[a-zA-Z0-9_-]*[=:]\s*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}')),

    # AI providers
    ("OpenAI API Key",         "high",   re.compile(r'sk-[A-Za-z0-9_-]{20,}')),
    ("Anthropic API Key",      "high",   re.compile(r'sk-ant-[A-Za-z0-9_-]{20,}')),
    ("Hugging Face Token",     "high",   re.compile(r'hf_[A-Za-z0-9]{20,}')),

    # Version control
    ("GitHub Token",           "high",   re.compile(r'(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}')),
    ("GitLab Token",           "high",   re.compile(r'(glpat|gldt|glft)-[A-Za-z0-9_-]{20,}')),
    ("Bitbucket App Password", "high",   re.compile(r'ATBB[A-Za-z0-9]{32,}')),

    # Communication
    ("Slack Token",            "high",   re.compile(r'xox[bpors]-[0-9A-Za-z\-]{10,}')),
    ("Slack Webhook",          "high",   re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_/]+')),
    ("Discord Token",          "high",   re.compile(r'[MNO][a-zA-Z\d_-]{23,}\.[a-zA-Z\d_-]{6}\.[a-zA-Z\d_-]{27,}')),
    ("Telegram Bot Token",     "high",   re.compile(r'\d{8,10}:[0-9A-Za-z_-]{35}')),

    # Payment
    ("Stripe Key",             "high",   re.compile(r'[sr]k_(test|live)_[0-9a-zA-Z]{10,}')),
    ("Stripe Restricted Key",  "high",   re.compile(r'rk_(test|live)_[0-9a-zA-Z]{10,}')),
    ("PayPal Braintree Token", "high",   re.compile(r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}')),
    ("Square OAuth",           "medium", re.compile(r'sq0csp-[0-9A-Za-z\-_]{43}')),

    # Email / messaging
    ("SendGrid Key",           "high",   re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}')),
    ("Mailgun Key",            "high",   re.compile(r'key-[0-9a-zA-Z]{32}')),
    ("Mailchimp Key",          "medium", re.compile(r'[0-9a-z]{32}-us\d{1,2}')),
    ("Twilio Key",             "high",   re.compile(r'(AC|SK)[a-f0-9]{32}', re.IGNORECASE)),

    # Crypto / auth
    ("Private Key Block",      "high",   re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----')),
    ("JWT Token",              "medium", re.compile(r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+')),

    # Package managers
    ("NPM Token",              "high",   re.compile(r'npm_[A-Za-z0-9-_]{20,}')),
    ("PyPI Token",             "high",   re.compile(r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,}')),

    # Databases
    ("MongoDB URI",            "high",   re.compile(r'mongodb(\+srv)?://[^\s"\'<>]{10,}')),
    ("PostgreSQL URI",         "high",   re.compile(r'postgres(ql)?://[^\s"\'<>]{10,}')),
    ("MySQL URI",              "high",   re.compile(r'mysql://[^\s"\'<>]{10,}')),
    ("Redis URI",              "high",   re.compile(r'redis://[^\s"\'<>]{10,}')),

    # URLs with credentials
    ("Basic Auth in URL",      "high",   re.compile(r'https?://[^\s:@]+:[^\s:@]+@[^\s]+')),

    # Firebase
    ("Firebase URL",           "medium", re.compile(r'https?://[a-z0-9-]+\.firebaseio\.com')),
]

ASSIGNMENT_PATTERN = re.compile(
    r'''(?i)'''
    r'''(?:'''
    r'''api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?key[_-]?(?:id)?|'''
    r'''auth[_-]?token|bearer[_-]?token|'''
    r'''password|passwd|pwd|'''
    r'''private[_-]?key|client[_-]?secret|app[_-]?secret|'''
    r'''token|credentials|signing[_-]?key|encryption[_-]?key|'''
    r'''db[_-]?password|database[_-]?(?:url|password)|connection[_-]?string|'''
    r'''openai[_-]?(?:api[_-]?)?key|'''
    r'''aws[_-]?secret[_-]?access[_-]?key|aws[_-]?access[_-]?key[_-]?id|'''
    r'''gcp[_-]?(?:api[_-]?)?key|azure[_-]?(?:api[_-]?)?key|'''
    r'''stripe[_-]?(?:secret|publishable)[_-]?key|'''
    r'''sendgrid[_-]?(?:api[_-]?)?key|twilio[_-]?(?:auth[_-]?)?token|'''
    r'''slack[_-]?(?:bot[_-]?)?token|discord[_-]?(?:bot[_-]?)?token|'''
    r'''github[_-]?token|gitlab[_-]?token|'''
    r'''jwt[_-]?secret|session[_-]?secret|cookie[_-]?secret|'''
    r'''smtp[_-]?password|mail[_-]?password|email[_-]?password'''
    r''')'''
    r'''\s*[=:]\s*["'][^"'\s]{8,}["']''',
    re.MULTILINE,
)

ENV_ASSIGNMENT_PATTERN = re.compile(
    r'''(?i)^'''
    r'''(?:export\s+)?'''
    r'''(?:'''
    r'''[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH)[A-Z_]*'''
    r''')'''
    r'''\s*=\s*[^\s#]{8,}''',
    re.MULTILINE,
)


def run_keyword_scan(target_path: str) -> Dict:
    details: List[Dict] = []
    seen: Set[str] = set()

    for fpath in _walk_files(target_path):
        content = _read_file(fpath)
        if content is None:
            continue

        rel_path = os.path.relpath(fpath, target_path)
        fname = os.path.basename(fpath).lower()
        is_env_file = fname.startswith(".env") or fname == "env"
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") and not is_env_file:
                continue

            for pattern_name, severity, pattern in TOKEN_PATTERNS:
                for match in pattern.finditer(line):
                    key = f"{rel_path}:{line_num}:{pattern_name}"
                    if key not in seen:
                        seen.add(key)
                        matched_text = match.group()
                        details.append({
                            "file": rel_path,
                            "line": line_num,
                            "type": pattern_name,
                            "severity": severity,
                            "reason": f"{matched_text[:45]}{'...' if len(matched_text) > 45 else ''}",
                        })

            for match in ASSIGNMENT_PATTERN.finditer(line):
                key = f"{rel_path}:{line_num}:Hardcoded Secret"
                if key not in seen:
                    seen.add(key)
                    matched_text = match.group()
                    details.append({
                        "file": rel_path,
                        "line": line_num,
                        "type": "Hardcoded Secret",
                        "severity": "high",
                        "reason": f"{matched_text[:50]}{'...' if len(matched_text) > 50 else ''}",
                    })

            if is_env_file:
                for match in ENV_ASSIGNMENT_PATTERN.finditer(line):
                    key = f"{rel_path}:{line_num}:Env Secret"
                    if key not in seen:
                        seen.add(key)
                        matched_text = match.group()
                        details.append({
                            "file": rel_path,
                            "line": line_num,
                            "type": "Env File Secret",
                            "severity": "high",
                            "reason": f"{matched_text[:50]}{'...' if len(matched_text) > 50 else ''}",
                        })

    issues = len(details)
    high = sum(1 for d in details if d.get("severity") == "high")
    med = sum(1 for d in details if d.get("severity") == "medium")
    score = max(0, 100 - (10 * high) - (5 * med))

    return {
        "name": "keyword-secrets",
        "score": score,
        "issues": issues,
        "details": details,
    }


# ===================================================================
# MODULE 3: Dangerous Configuration Scanner
# ===================================================================

DANGEROUS_CONFIGS: List[Tuple[str, str, str, re.Pattern]] = [
    ("Debug Mode Enabled",    "medium", "*.py",  re.compile(r'(?i)\bDEBUG\s*=\s*True\b')),
    ("Debug Mode Enabled",    "medium", "*.py",  re.compile(r'(?i)app\.run\([^)]*debug\s*=\s*True')),
    ("Wildcard CORS",         "high",   "*",     re.compile(r'''(?i)(?:CORS|cors|Access-Control-Allow-Origin)[^=]*[=:]\s*["']\*["']''')),
    ("Binding to 0.0.0.0",   "medium", "*",     re.compile(r'''(?:host|bind|listen)[^=]*[=:]\s*["']0\.0\.0\.0["']''')),
    ("S3 Public Read ACL",    "high",   "*.tf",  re.compile(r'acl\s*=\s*"public-read"')),
    ("S3 Public RW ACL",      "high",   "*.tf",  re.compile(r'acl\s*=\s*"public-read-write"')),
    ("Versioning Disabled",   "medium", "*.tf",  re.compile(r'enabled\s*=\s*false', re.IGNORECASE)),
    ("SSL Verify Disabled",   "high",   "*.py",  re.compile(r'verify\s*=\s*False')),
    ("Insecure HTTP",         "medium", "*",     re.compile(r'(?i)https?\s*=\s*False|SECURE_SSL_REDIRECT\s*=\s*False')),
    ("No Auth Middleware",    "medium", "*.py",  re.compile(r'''@app\.route\([^)]*\)\s*\n\s*def\s+(?:admin|dashboard|internal|manage|config)''')),
    ("Eval Usage",            "high",   "*.py",  re.compile(r'\beval\s*\(')),
    ("Exec Usage",            "high",   "*.py",  re.compile(r'\bexec\s*\(')),
    ("Shell=True",            "high",   "*.py",  re.compile(r'shell\s*=\s*True')),
    ("Pickle Load",           "medium", "*.py",  re.compile(r'pickle\.loads?\(')),
    ("YAML Unsafe Load",      "medium", "*.py",  re.compile(r'yaml\.load\([^)]*(?!Loader)')),
    ("Logging PII/Secrets",   "medium", "*.py",  re.compile(r'''(?i)log(?:ger)?\.(?:info|debug|warning)\([^)]*(?:request|payload|body|password|token|key|secret)''')),
    ("Exposed System Prompt", "medium", "*.py",  re.compile(r'''(?i)system_prompt\s*=\s*["'][^"']{20,}["']''')),
    ("Prompt Injection Risk",  "medium", "*.yaml", re.compile(r'(?i)ignore\s+previous\s+instructions')),
    ("Prompt Injection Risk",  "medium", "*.yml",  re.compile(r'(?i)ignore\s+previous\s+instructions')),
    ("Prompt Injection Risk",  "medium", "*.py",   re.compile(r'(?i)ignore\s+previous\s+instructions')),
]


def _matches_file_filter(rel_path: str, file_filter: str) -> bool:
    if file_filter == "*":
        return True
    ext = file_filter.replace("*", "")
    return rel_path.lower().endswith(ext)


def run_config_scan(target_path: str) -> Dict:
    details: List[Dict] = []
    seen: Set[str] = set()

    for fpath in _walk_files(target_path):
        content = _read_file(fpath)
        if content is None:
            continue

        rel_path = os.path.relpath(fpath, target_path)

        for rule_name, severity, file_filter, pattern in DANGEROUS_CONFIGS:
            if not _matches_file_filter(rel_path, file_filter):
                continue

            for match in pattern.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                key = f"{rel_path}:{line_num}:{rule_name}"
                if key not in seen:
                    seen.add(key)
                    matched_text = match.group()
                    details.append({
                        "file": rel_path,
                        "line": line_num,
                        "type": rule_name,
                        "severity": severity,
                        "reason": f"{matched_text[:50]}{'...' if len(matched_text) > 50 else ''}",
                    })

    issues = len(details)
    high = sum(1 for d in details if d.get("severity") == "high")
    med = sum(1 for d in details if d.get("severity") == "medium")
    score = max(0, 100 - (10 * high) - (5 * med))

    return {
        "name": "dangerous-config",
        "score": score,
        "issues": issues,
        "details": details,
    }


# ===================================================================
# MODULE 4: Dependency Risk Scanner
# ===================================================================

KNOWN_VULNERABLE: Dict[str, Dict[str, str]] = {
    "flask": {"below": "2.0.0", "reason": "Flask <2.0 has known security issues"},
    "django": {"below": "3.2.0", "reason": "Django <3.2 is end-of-life"},
    "requests": {"below": "2.25.0", "reason": "requests <2.25 has CVEs"},
    "urllib3": {"below": "1.26.0", "reason": "urllib3 <1.26 has known vulnerabilities"},
    "pyjwt": {"below": "2.0.0", "reason": "PyJWT <2.0 has algorithm confusion vulnerability"},
    "cryptography": {"below": "3.3.0", "reason": "cryptography <3.3 has known CVEs"},
    "pillow": {"below": "9.0.0", "reason": "Pillow <9.0 has multiple CVEs"},
    "numpy": {"below": "1.22.0", "reason": "numpy <1.22 has buffer overflow CVEs"},
    "express": {"below": "4.18.0", "reason": "express <4.18 has prototype pollution risk"},
    "lodash": {"below": "4.17.21", "reason": "lodash <4.17.21 has prototype pollution CVE"},
    "axios": {"below": "1.0.0", "reason": "axios <1.0 has SSRF vulnerability"},
}


def _parse_version(v: str) -> List[int]:
    parts = []
    for p in re.split(r'[^0-9]', v):
        if p:
            try:
                parts.append(int(p))
            except ValueError:
                break
    return parts or [0]


def _version_below(current: str, threshold: str) -> bool:
    c = _parse_version(current)
    t = _parse_version(threshold)
    for i in range(max(len(c), len(t))):
        cv = c[i] if i < len(c) else 0
        tv = t[i] if i < len(t) else 0
        if cv < tv:
            return True
        if cv > tv:
            return False
    return False


def run_dependency_scan(target_path: str) -> Dict:
    details: List[Dict] = []

    req_path = os.path.join(target_path, "requirements.txt")
    if os.path.exists(req_path):
        content = _read_file(req_path) or ""
        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r'^([a-zA-Z0-9_-]+)\s*(?:[=<>!~]+)\s*([0-9][0-9.]*)', line)
            if match:
                pkg, ver = match.group(1).lower(), match.group(2)
                if pkg in KNOWN_VULNERABLE:
                    vuln = KNOWN_VULNERABLE[pkg]
                    if _version_below(ver, vuln["below"]):
                        details.append({
                            "file": "requirements.txt",
                            "line": line_num,
                            "type": f"Vulnerable: {pkg}=={ver}",
                            "severity": "high",
                            "reason": vuln["reason"],
                        })

    pkg_path = os.path.join(target_path, "package.json")
    if os.path.exists(pkg_path):
        content = _read_file(pkg_path) or ""
        try:
            pkg_data = json.loads(content)
        except json.JSONDecodeError:
            pkg_data = {}

        for dep_section in ["dependencies", "devDependencies"]:
            deps = pkg_data.get(dep_section, {})
            for pkg_name, ver_str in deps.items():
                clean_ver = re.sub(r'^[\^~>=<! ]+', '', ver_str)
                pkg_lower = pkg_name.lower()
                if pkg_lower in KNOWN_VULNERABLE:
                    vuln = KNOWN_VULNERABLE[pkg_lower]
                    if _version_below(clean_ver, vuln["below"]):
                        details.append({
                            "file": "package.json",
                            "line": 0,
                            "type": f"Vulnerable: {pkg_name}@{ver_str}",
                            "severity": "high",
                            "reason": vuln["reason"],
                        })

    issues = len(details)
    score = max(0, 100 - 15 * issues)

    return {
        "name": "dependencies",
        "score": score,
        "issues": issues,
        "details": details,
    }


# ===================================================================
# ORCHESTRATOR
# ===================================================================

def run_static_modules(target_path: str) -> List[Dict]:
    return [
        run_detect_secrets(target_path),
        run_keyword_scan(target_path),
        run_config_scan(target_path),
        run_dependency_scan(target_path),
    ]


def aggregate_results(module_results: List[Dict]) -> Dict:
    scores = [m.get("score", 0) for m in module_results]
    count = len(scores) or 1
    avg = round(sum(scores) / count)
    worst = min(scores) if scores else 0

    # Weighted: 70% average + 30% worst module (one bad module drags the score)
    overall = round(0.7 * avg + 0.3 * worst)

    total_issues = sum(m.get("issues", 0) for m in module_results)

    return {
        "modules": module_results,
        "modules_count": len(module_results),
        "total_issues": total_issues,
        "overall_score": overall,
    }


def main():
    parser = argparse.ArgumentParser(description="Ybe Check CLI")
    parser.add_argument("path", help="Path to the repository to audit")
    parser.add_argument("--json", action="store_true", help="Output report as JSON")
    args = parser.parse_args()

    target_path = os.path.abspath(args.path)
    module_results = run_static_modules(target_path)
    report = aggregate_results(module_results)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for mod in module_results:
            status = "PASS" if mod["score"] >= 80 else "WARN" if mod["score"] >= 40 else "FAIL"
            print(f"  [{status}] {mod['name']}: {mod['score']}/100 ({mod['issues']} issues)")
        print(f"\n  Overall Score: {report['overall_score']}/100")
        print(f"  Total Issues:  {report['total_issues']}")


if __name__ == "__main__":
    main()
