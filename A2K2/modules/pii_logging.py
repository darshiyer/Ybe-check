"""
PII & Logging Detection Module — Ybe Check
Author: Darsh
Status: IN PROGRESS

CONTRACT:
- Input: repo_path (string, absolute path)
- Output: dict matching module contract
- Test: cd A2K2 && python -c "
    import sys,json; sys.path.insert(0,'.')
    from modules.pii_logging import scan
    print(json.dumps(scan('../A2K2-test'),indent=2))"

MUST DETECT IN A2K2-test/:
  app.py: admin@company.com (email)
  app.py: 9876543210 (phone)
  app.py: logger.info(request) (unsafe logging)
"""

import os
import re

NAME = "PII & Logging"

SKIP_DIRS = {
    '.git', 'node_modules', '__pycache__', '.venv',
    'venv', 'dist', 'build', '.next', 'out'
}
SKIP_PATH_KEYWORDS = {'test', 'spec', '__mock__', 'fixture'}

TARGET_EXTENSIONS = {'.py', '.js', '.ts'}

# ── PII REGEX PATTERNS ───────────────────────────────────────
PII_PATTERNS = [
    {
        "pattern": re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
        "type": "Hardcoded Email",
        "severity": "high",
        "reason": "Hardcoded email address in code — move to config or environment variable"
    },
    {
        "pattern": re.compile(r'\b[6-9]\d{9}\b'),
        "type": "Hardcoded Phone Number",
        "severity": "high",
        "reason": "Hardcoded Indian phone number — remove from source code"
    },
    {
        "pattern": re.compile(r'\b\d{4}[\s-]\d{4}[\s-]\d{4}\b'),
        "type": "Hardcoded Aadhaar",
        "severity": "critical",
        "reason": "Hardcoded Aadhaar number — critical PII violation, remove immediately"
    },
    {
        "pattern": re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'),
        "type": "Hardcoded PAN",
        "severity": "critical",
        "reason": "Hardcoded PAN number — critical PII violation, remove immediately"
    },
    {
        "pattern": re.compile(r'\b(?:\d[ -]?){13,16}\b'),
        "type": "Possible Credit Card Number",
        "severity": "critical",
        "reason": "Possible hardcoded credit card number detected"
    }
]

# ── UNSAFE LOGGING PATTERNS ──────────────────────────────────
LOG_FUNCTIONS = [
    "logger.info", "logger.debug", "logger.warning",
    "logger.error", "logging.info", "logging.debug",
    "logging.warning", "console.log", "console.error",
    "console.warn", "print"
]

SENSITIVE_ARGS = {
    "request", "response", "user", "password",
    "token", "body", "data", "payload", "req",
    "res", "credentials", "secret", "auth"
}

# Matches: logger.info(request) but NOT logger.info(request.id)
LOG_PATTERN = re.compile(
    r'(' + '|'.join(re.escape(fn) for fn in LOG_FUNCTIONS) + r')\s*\(\s*(\w+)\s*\)',
    re.IGNORECASE
)


def should_skip(fpath):
    parts = fpath.lower().replace('\\', '/').split('/')
    return any(kw in parts for kw in SKIP_PATH_KEYWORDS)


def walk_files(repo_path):
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in TARGET_EXTENSIONS:
                fpath = os.path.join(root, fname)
                if not should_skip(fpath):
                    yield fpath


def read_lines(fpath):
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except Exception:
        return []


def rel(fpath, repo_path):
    return os.path.relpath(fpath, repo_path)


def scan(repo_path: str) -> dict:
    details = []
    seen = set()

    for fpath in walk_files(repo_path):
        lines = read_lines(fpath)
        relative = rel(fpath, repo_path)

        for i, line in enumerate(lines):
            line_num = i + 1
            stripped = line.strip()

            # Skip comment lines
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            # ── DETECT PII ────────────────────────────────────
            # YOUR CODE HERE ↓
            for pii in PII_PATTERNS:
                if pii["pattern"].search(stripped):
                    key = (relative, line_num, pii["type"])
                    if key not in seen:
                        seen.add(key)
                        details.append({
                            "file": relative,
                            "line": line_num,
                            "type": pii["type"],
                            "severity": pii["severity"],
                            "reason": pii["reason"]
                        })

            # ── DETECT UNSAFE LOGGING ─────────────────────────
            # YOUR CODE HERE ↓
            match = LOG_PATTERN.search(stripped)
            if match:
                arg = match.group(2).lower()
                if arg in SENSITIVE_ARGS:
                    key = (relative, line_num, "Unsafe Logging")
                    if key not in seen:
                        seen.add(key)
                        details.append({
                            "file": relative,
                            "line": line_num,
                            "type": "Unsafe Logging",
                            "severity": "high",
                            "reason": "Full object logged — may expose PII or secrets in application logs"
                        })

    # ── SCORING ──────────────────────────────────────────────
    critical = len([d for d in details if d["severity"] == "critical"])
    high = len([d for d in details if d["severity"] == "high"])
    medium = len([d for d in details if d["severity"] == "medium"])
    score = max(0, 100 - (critical * 15) - (high * 10) - (medium * 5))

    return {
        "name": NAME,
        "score": score,
        "issues": len(details),
        "details": details
    }
