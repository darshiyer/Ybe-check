import os
import re

NAME = "PII & Logging"

SKIP_DIRS = {
    '.git', 'node_modules', '__pycache__', '.venv',
    'venv', 'dist', 'build', '.next', 'out'
}
SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.ttf', '.eot', '.zip', '.tar', '.gz',
    '.pyc', '.lock', '.vsix', '.db'
}

# --- PII Patterns ---
PII_PATTERNS = [
    {
        "pattern": re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
        "type": "Hardcoded Email",
        "severity": "high",
        "reason": "Hardcoded email address found — move to environment config"
    },
    {
        "pattern": re.compile(r'\b[6-9]\d{9}\b'),
        "type": "Hardcoded Phone Number",
        "severity": "high",
        "reason": "Hardcoded Indian phone number found — remove from source code"
    },
    {
        "pattern": re.compile(r'\b\d{4}[\s-]\d{4}[\s-]\d{4}\b'),
        "type": "Hardcoded Aadhaar",
        "severity": "critical",
        "reason": "Hardcoded Aadhaar number — critical PII violation under DPDP Act"
    },
    {
        "pattern": re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'),
        "type": "Hardcoded PAN",
        "severity": "critical",
        "reason": "Hardcoded PAN number — critical PII violation under DPDP Act"
    },
    {
        "pattern": re.compile(r'\b(?:\d[ -]?){13,16}\b'),
        "type": "Hardcoded Credit Card",
        "severity": "critical",
        "reason": "Possible hardcoded credit card number — critical financial PII"
    }
]

# --- Unsafe Logging ---
LOG_FUNCTIONS = [
    "logger.info",
    "logger.debug",
    "logger.warning",
    "logger.error",
    "logger.critical",
    "logging.info",
    "logging.debug",
    "logging.warning",
    "logging.error",
    "console.log",
    "console.error",
    "console.warn",
    "console.debug",
    "print",
]

SENSITIVE_ARGS = [
    "request", "response", "user", "password",
    "token", "body", "data", "payload", "req", "res",
    "credentials", "secret", "auth", "headers", "session",
    "user_data", "userdata", "form", "params"
]

# Build one compiled regex per log function
# Matches: logger.info(request) but NOT logger.info(request.id) or logger.info("string")
# Pattern: log_func(\s*SENSITIVE_VAR\s*[,)] 
# The key: after the variable name, we allow only whitespace, comma, or closing paren — NOT a dot
def _build_log_patterns():
    patterns = []
    sensitive_group = '|'.join(re.escape(s) for s in SENSITIVE_ARGS)
    for fn in LOG_FUNCTIONS:
        # Escape the function name (e.g. logger.info → logger\.info)
        escaped_fn = re.escape(fn)
        # Match: logger.info(  sensitive_var  ) or logger.info(sensitive_var, ...)
        # Negative lookahead (?![.\w]) ensures we don't match request.id or request_data
        pat = re.compile(
            escaped_fn + r'\s*\(\s*(' + sensitive_group + r')\s*(?![.\w])',
        )
        patterns.append((fn, pat))
    return patterns

LOG_PATTERNS = _build_log_patterns()


def walk_files(repo_path, extensions):
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in extensions and ext not in SKIP_EXTENSIONS:
                fpath = os.path.join(root, fname)
                yield fpath


def read_file(fpath):
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except:
        return []


def rel(fpath, repo_path):
    return os.path.relpath(fpath, repo_path)


def should_skip_file(rpath):
    """Skip test/spec/mock files based on relative path."""
    lower = rpath.lower()
    skip_markers = ['test', 'spec', '__mock__', '__tests__', 'fixtures']
    return any(marker in lower for marker in skip_markers)


def is_comment_line(line):
    """Returns True if the line is a comment (Python or JS style)."""
    stripped = line.strip()
    return stripped.startswith('#') or stripped.startswith('//')


def scan_file(fpath, repo_path, details, seen):
    lines = read_file(fpath)
    rpath = rel(fpath, repo_path)

    for i, line in enumerate(lines):
        line_no = i + 1

        # Skip comment lines entirely
        if is_comment_line(line):
            continue

        stripped = line.strip()

        # --- Part 1: PII Pattern Detection ---
        for pii in PII_PATTERNS:
            if pii["pattern"].search(stripped):
                dedup_key = (rpath, line_no, pii["type"])
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    details.append({
                        "file": rpath,
                        "line": line_no,
                        "snippet": stripped,
                        "type": pii["type"],
                        "severity": pii["severity"],
                        "reason": pii["reason"]
                    })

        # --- Part 2: Unsafe Logging Detection ---
        for fn_name, pattern in LOG_PATTERNS:
            if pattern.search(stripped):
                dedup_key = (rpath, line_no, "Unsafe Logging")
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    details.append({
                        "file": rpath,
                        "line": line_no,
                        "snippet": stripped,
                        "type": "Unsafe Logging",
                        "severity": "high",
                        "reason": f"Full object passed to {fn_name}() — may expose PII or secrets in logs"
                    })
                break  # Only flag once per line even if multiple patterns match


def scan(repo_path: str) -> dict:
    try:
        details = []
        seen = set()

        for fpath in walk_files(repo_path, {'.py', '.js', '.ts'}):
            rpath = rel(fpath, repo_path)
            if should_skip_file(rpath):
                continue
            scan_file(fpath, repo_path, details, seen)

        # Scoring formula — contract law, do not change
        critical = len([d for d in details if d["severity"] == "critical"])
        high     = len([d for d in details if d["severity"] == "high"])
        medium   = len([d for d in details if d["severity"] == "medium"])
        score    = max(0, 100 - (critical * 15) - (high * 10) - (medium * 5))

        return {
            "name": NAME,
            "score": score,
            "issues": len(details),
            "details": details
        }

    except Exception as e:
        return {
            "name": NAME,
            "score": None,
            "issues": 0,
            "details": [],
            "warning": f"Could not run: {str(e)}"
        }
