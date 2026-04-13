"""
Secrets Detection module: detect-secrets + keyword/pattern scanning.
Contract: scan(repo_path) -> { name, score, issues, details[, warning] }
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional, Set, Tuple

NAME = "Secrets Detection"

# Self-exclusion: don't scan the scanner's own source tree
_SCANNER_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------------
# File walk (shared within this module)
# ---------------------------------------------------------------------------

SKIP_DIRS: Set[str] = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", ".next",
    ".ybe-check", ".secret-stack", ".eggs", "*.egg-info",
    "site-packages", ".antigravity", ".cursor", ".claude",
    "graphify-out", "coverage_html", ".terraform",
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

# ---------------------------------------------------------------------------
# Path-based suppression — skip findings in known infrastructure / test paths.
# These are legitimate key files (TLS certs, test fixtures) not leaked secrets.
# ---------------------------------------------------------------------------

SUPPRESSED_PATH_SEGMENTS: Set[str] = {
    'tls',
    'crypto-config',
    'crypto_config',
    'x509',
    'certs',
    'certificates',
    'test-fixtures',
    'fixtures',
    '__fixtures__',
    'testdata',
    'test_data',
    'mock',
    'mocks',
    '__mocks__',
    'migrations',
    'node_modules',
}

SUPPRESSED_FILENAME_PATTERNS: List[re.Pattern] = [
    re.compile(r'.*\.pem$',           re.IGNORECASE),
    re.compile(r'.*\.crt$',           re.IGNORECASE),
    re.compile(r'.*\.cer$',           re.IGNORECASE),
    re.compile(r'server\.key$',       re.IGNORECASE),
    re.compile(r'client\.key$',       re.IGNORECASE),
    re.compile(r'ca\.key$',           re.IGNORECASE),
    re.compile(r'.*_test\.go$',       re.IGNORECASE),
    re.compile(r'.*\.test\.(js|ts)$', re.IGNORECASE),
]


def _is_suppressed(rel_path: str) -> bool:
    """
    Return True if a file should be excluded from secret scanning.
    Checks path segments and filename patterns against the suppression lists.
    """
    # Normalise separators so both / and os.sep work
    parts = set(rel_path.replace('\\', '/').split('/'))
    if parts & SUPPRESSED_PATH_SEGMENTS:
        return True
    fname = os.path.basename(rel_path)
    return any(pat.match(fname) for pat in SUPPRESSED_FILENAME_PATTERNS)

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB


def _walk_files(root: str) -> List[str]:
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        _real = os.path.realpath(dirpath)
        if _real == _SCANNER_ROOT or _real.startswith(_SCANNER_ROOT + os.sep):
            dirnames.clear(); continue
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in SKIP_EXTENSIONS:
                continue
            full = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(full) > MAX_FILE_SIZE or os.path.islink(full):
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


def _score_from_details(details: List[Dict]) -> int:
    critical = len([d for d in details if d.get("severity") == "critical"])
    high = len([d for d in details if d.get("severity") == "high"])
    medium = len([d for d in details if d.get("severity") == "medium"])
    return max(0, 100 - (critical * 15) - (high * 10) - (medium * 5))


# ---------------------------------------------------------------------------
# detect-secrets (external tool)
# ---------------------------------------------------------------------------

def _ensure_detect_secrets() -> bool:
    try:
        subprocess.run(
            [sys.executable, "-m", "detect_secrets", "--version"],
            capture_output=True,
            check=True,
        )
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass
    # Try install strategies in order: plain → --user → --break-system-packages
    for extra in [[], ["--user"], ["--break-system-packages"]]:
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "detect-secrets", "-q"] + extra,
                check=True,
                capture_output=True,
            )
            return True
        except subprocess.CalledProcessError:
            continue
    return False


_DS_TIMEOUT = 45  # seconds — prevents hanging on large repos

# Directories and file extensions that detect-secrets should skip.
# Binary, generated, and package directories never contain real secrets.
_DS_EXCLUDE_DIRS = [
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", "out", ".next", "graphify-out", "coverage",
]
_DS_EXCLUDE_EXTS = [
    ".vsix", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf",
    ".zip", ".tar", ".gz", ".bin", ".pyc", ".map",
]


def _run_detect_secrets(repo_path: str) -> Tuple[List[Dict], Optional[str]]:
    """Returns (details, warning_or_none)."""
    if not _ensure_detect_secrets():
        return [], "Could not install detect-secrets. Run: pip install detect-secrets"

    # Build exclude flags so detect-secrets skips binary/generated paths
    exclude_args: List[str] = []
    exclude_pattern = "|".join(
        [rf"(^|/){d}(/|$)" for d in _DS_EXCLUDE_DIRS] +
        [rf"\.{ext.lstrip('.')}$" for ext in _DS_EXCLUDE_EXTS]
    )
    if exclude_pattern:
        exclude_args = ["--exclude-files", exclude_pattern]

    try:
        result = subprocess.run(
            [sys.executable, "-m", "detect_secrets", "scan", "--all-files", repo_path]
            + exclude_args,
            capture_output=True,
            text=True,
            check=False,
            timeout=_DS_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return [], f"detect-secrets timed out after {_DS_TIMEOUT}s — repo may be too large"
    except FileNotFoundError:
        return [], "detect-secrets not found after install attempt"
    if result.returncode != 0 and not result.stdout:
        return [], (result.stderr.strip() if result.stderr else "Unknown error")
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return [], "Invalid JSON from detect-secrets"
    results_dict = data.get("results", {})
    details: List[Dict] = []
    for filename, findings in results_dict.items():
        try:
            rel = os.path.relpath(filename, repo_path)
        except ValueError:
            rel = filename
        # Filter out findings from skipped directories
        parts = rel.replace("\\", "/").split("/")
        if any(p in SKIP_DIRS for p in parts):
            continue
        for item in findings:
            details.append({
                "file": rel,
                "line": item.get("line_number"),
                "type": item.get("type", "Secret"),
                "severity": "high",
                "reason": "Move this secret to an environment variable and add it to .env.example",
            })
    return details, None


# ---------------------------------------------------------------------------
# Keyword & pattern secret scanner
# ---------------------------------------------------------------------------

# (pattern_name, severity, regex). Use "critical" for private keys / highest risk.
TOKEN_PATTERNS: List[Tuple[str, str, re.Pattern]] = [
    ("Private Key Block", "critical", re.compile(
        r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
    )),
    ("AWS Access Key", "high", re.compile(r"AKIA[0-9A-Z]{12,}")),
    ("AWS MFA Serial", "medium", re.compile(r"arn:aws:iam::\d{12}:mfa/\S+")),
    ("GCP API Key", "high", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("GCP Service Account", "high", re.compile(r'"type"\s*:\s*"service_account"')),
    ("Azure Storage Key", "high", re.compile(
        r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{60,}"
    )),
    ("Heroku API Key", "high", re.compile(
        r"[hH]eroku[a-zA-Z0-9_-]*[=:]\s*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}"
    )),
    ("OpenAI API Key", "high", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("Anthropic API Key", "high", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("Hugging Face Token", "high", re.compile(r"hf_[A-Za-z0-9]{20,}")),
    ("GitHub Token", "high", re.compile(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}")),
    ("GitLab Token", "high", re.compile(r"(glpat|gldt|glft)-[A-Za-z0-9_-]{20,}")),
    ("Bitbucket App Password", "high", re.compile(r"ATBB[A-Za-z0-9]{32,}")),
    ("Slack Token", "high", re.compile(r"xox[bpors]-[0-9A-Za-z\-]{10,}")),
    ("Slack Webhook", "high", re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_/]+")),
    ("Discord Token", "high", re.compile(
        r"[MNO][a-zA-Z\d_-]{23,}\.[a-zA-Z\d_-]{6}\.[a-zA-Z\d_-]{27,}"
    )),
    ("Telegram Bot Token", "high", re.compile(r"\d{8,10}:[0-9A-Za-z_-]{35}")),
    ("Stripe Key", "high", re.compile(r"[sr]k_(test|live)_[0-9a-zA-Z]{10,}")),
    ("Stripe Restricted Key", "high", re.compile(r"rk_(test|live)_[0-9a-zA-Z]{10,}")),
    ("PayPal Braintree Token", "high", re.compile(
        r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"
    )),
    ("Square OAuth", "medium", re.compile(r"sq0csp-[0-9A-Za-z\-_]{43}")),
    ("SendGrid Key", "high", re.compile(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}")),
    ("Mailgun Key", "high", re.compile(r"key-[0-9a-zA-Z]{32}")),
    ("Mailchimp Key", "medium", re.compile(r"[0-9a-z]{32}-us\d{1,2}")),
    ("Twilio Key", "high", re.compile(r"(AC|SK)[a-f0-9]{32}", re.IGNORECASE)),
    ("JWT Token", "medium", re.compile(
        r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+"
    )),
    ("NPM Token", "high", re.compile(r"npm_[A-Za-z0-9-_]{20,}")),
    ("PyPI Token", "high", re.compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,}")),
    ("MongoDB URI", "high", re.compile(r"mongodb(\+srv)?://[^\s\"'<>]{10,}")),
    ("PostgreSQL URI", "high", re.compile(r"postgres(ql)?://[^\s\"'<>]{10,}")),
    ("MySQL URI", "high", re.compile(r"mysql://[^\s\"'<>]{10,}")),
    ("Redis URI", "high", re.compile(r"redis://[^\s\"'<>]{10,}")),
    ("Basic Auth in URL", "high", re.compile(r"https?://[^\s:@]+:[^\s:@]+@[^\s]+")),
    ("Firebase URL", "medium", re.compile(r"https?://[a-z0-9-]+\.firebaseio\.com")),
]

ASSIGNMENT_PATTERN = re.compile(
    r"""(?i)"""
    r"""(?:"""
    r"""api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?key[_-]?(?:id)?|"""
    r"""auth[_-]?token|bearer[_-]?token|"""
    r"""password|passwd|pwd|"""
    r"""private[_-]?key|client[_-]?secret|app[_-]?secret|"""
    r"""token|credentials|signing[_-]?key|encryption[_-]?key|"""
    r"""db[_-]?password|database[_-]?(?:url|password)|connection[_-]?string|"""
    r"""openai[_-]?(?:api[_-]?)?key|"""
    r"""aws[_-]?secret[_-]?access[_-]?key|aws[_-]?access[_-]?key[_-]?id|"""
    r"""gcp[_-]?(?:api[_-]?)?key|azure[_-]?(?:api[_-]?)?key|"""
    r"""stripe[_-]?(?:secret|publishable)[_-]?key|"""
    r"""sendgrid[_-]?(?:api[_-]?)?key|twilio[_-]?(?:auth[_-]?)?token|"""
    r"""slack[_-]?(?:bot[_-]?)?token|discord[_-]?(?:bot[_-]?)?token|"""
    r"""github[_-]?token|gitlab[_-]?token|"""
    r"""jwt[_-]?secret|session[_-]?secret|cookie[_-]?secret|"""
    r"""smtp[_-]?password|mail[_-]?password|email[_-]?password"""
    r""")"""
    r"""\s*[=:]\s*["'][^"'\s]{8,}["']""",
    re.MULTILINE,
)

ENV_ASSIGNMENT_PATTERN = re.compile(
    r"""(?i)^"""
    r"""(?:export\s+)?"""
    r"""(?:"""
    r"""[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH)[A-Z_]*"""
    r""")"""
    r"""\s*=\s*[^\s#]{8,}""",
    re.MULTILINE,
)


def _run_keyword_scan(repo_path: str) -> Tuple[List[Dict], int]:
    """Returns (details, suppressed_count)."""
    details: List[Dict] = []
    seen: Set[str] = set()
    suppressed_count = 0
    for fpath in _walk_files(repo_path):
        content = _read_file(fpath)
        if content is None:
            continue
        rel_path = os.path.relpath(fpath, repo_path)

        # --- Path suppression check ---
        if _is_suppressed(rel_path):
            suppressed_count += 1
            continue

        fname = os.path.basename(fpath).lower()
        is_env_file = fname.startswith(".env") or fname == "env"
        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or (stripped.startswith("#") and not is_env_file):
                continue
            for pattern_name, severity, pattern in TOKEN_PATTERNS:
                for match in pattern.finditer(line):
                    key = f"{rel_path}:{line_num}:{pattern_name}"
                    if key not in seen:
                        seen.add(key)
                        reason = (
                            f"{pattern_name} found in {rel_path}:{line_num}. "
                            "Remove from source code — store in environment variable or secrets manager."
                        )
                        details.append({
                            "file": rel_path,
                            "line": line_num,
                            "type": pattern_name,
                            "severity": severity,
                            "reason": reason,
                        })
            for match in ASSIGNMENT_PATTERN.finditer(line):
                key = f"{rel_path}:{line_num}:Hardcoded Secret"
                if key not in seen:
                    seen.add(key)
                    details.append({
                        "file": rel_path,
                        "line": line_num,
                        "type": "Hardcoded Secret",
                        "severity": "high",
                        "reason": "Move this hardcoded secret to an environment variable and add it to .env.example",
                    })
            if is_env_file:
                for match in ENV_ASSIGNMENT_PATTERN.finditer(line):
                    key = f"{rel_path}:{line_num}:Env Secret"
                    if key not in seen:
                        seen.add(key)
                        details.append({
                            "file": rel_path,
                            "line": line_num,
                            "type": "Env File Secret",
                            "severity": "high",
                            "reason": "Do not commit .env with real values; use .env.example with placeholders and load secrets at runtime.",
                        })
    return details, suppressed_count


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan(repo_path: str) -> Dict:
    repo_path = os.path.abspath(repo_path)
    if not os.path.isdir(repo_path):
        return {
            "name": NAME,
            "score": None,
            "issues": 0,
            "suppressed": 0,
            "details": [],
            "warning": "Path is not a directory",
        }
    ds_details, ds_warning = _run_detect_secrets(repo_path)
    kw_details, suppressed_count = _run_keyword_scan(repo_path)

    # Also suppress detect-secrets findings from infrastructure paths
    ds_details_filtered = []
    for d in ds_details:
        if _is_suppressed(d.get("file", "")):
            suppressed_count += 1
        else:
            ds_details_filtered.append(d)

    # Merge and dedupe by file:line:type
    seen: Set[str] = set()
    details: List[Dict] = []
    for d in ds_details_filtered + kw_details:
        f, ln, t = d.get("file"), d.get("line"), d.get("type")
        key = f"{f}:{ln}:{t}"
        if key in seen:
            continue
        seen.add(key)
        details.append({
            "file": d.get("file", ""),
            "line": d.get("line"),
            "type": d.get("type", "Secret"),
            "severity": d.get("severity", "high"),
            "reason": d.get("reason", ""),
        })
    if not details and ds_warning:
        return {
            "name": NAME,
            "score": None,
            "issues": 0,
            "suppressed": suppressed_count,
            "details": [],
            "warning": ds_warning,
        }
    score = _score_from_details(details)
    result: Dict = {
        "name": NAME,
        "score": score,
        "issues": len(details),
        "suppressed": suppressed_count,
        "details": details,
    }
    if ds_warning:
        result["warning"] = ds_warning
    return result
