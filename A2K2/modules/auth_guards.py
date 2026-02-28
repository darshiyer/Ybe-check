"""
Auth Guards Detection Module — Ybe Check
Author: Kartikeya
Status: IN PROGRESS

CONTRACT:
- Input: repo_path (string, absolute path)
- Output: dict matching module contract
- Test: cd A2K2 && python -c "
    import sys,json; sys.path.insert(0,'.')
    from modules.auth_guards import scan
    print(json.dumps(scan('../A2K2-test'),indent=2))"

MUST DETECT IN A2K2-test/:
  app.py: @app.route('/admin') with no auth
  Any DEBUG = True
  Any wildcard CORS
"""

import os
import re

NAME = "Auth Guards"

SKIP_DIRS = {
    '.git', 'node_modules', '__pycache__', '.venv',
    'venv', 'dist', 'build', '.next', 'out'
}

# ── ROUTE PATTERNS ───────────────────────────────────────────
PYTHON_ROUTE_PATTERN = re.compile(
    r'@(?:app|router|blueprint)\.'
    r'(get|post|put|delete|patch|route)\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE
)

JS_ROUTE_PATTERN = re.compile(
    r'(?:app|router)\.'
    r'(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE
)

# ── SENSITIVE PATH KEYWORDS ──────────────────────────────────
SENSITIVE_PATHS = {
    'admin', 'internal', 'config', 'secret', 'dashboard',
    'delete', 'reset', 'sudo', 'manage', 'panel', 'private',
    'superuser', 'root', 'system', 'debug', 'staff'
}

# ── AUTH PATTERNS ────────────────────────────────────────────
PYTHON_AUTH_PATTERNS = [
    'Depends(', 'require_auth', 'get_current_user',
    'login_required', 'jwt', 'bearer', 'authenticate',
    'Security(', 'verify_token', 'current_user',
    'auth_required', 'token_required', 'HTTPBearer',
    '@login_required'
]

JS_AUTH_PATTERNS = [
    'authenticate', 'authorize', 'verifyToken',
    'requireAuth', 'passport', 'jwt.verify',
    'isAuthenticated', 'checkAuth', 'authMiddleware',
    'requireLogin', 'ensureAuth'
]

# ── ALWAYS-FLAG PATTERNS ─────────────────────────────────────
WILDCARD_CORS_PATTERNS = [
    re.compile(r'cors\s*\(\s*\{\s*origin\s*:\s*["\'\`]\*["\'\`]', re.IGNORECASE),
    re.compile(r'CORS\s*\(\s*origins\s*=\s*["\'\[]\s*\*', re.IGNORECASE),
    re.compile(r'allow_origins\s*=\s*\[\s*["\'\`]\*["\'\`]', re.IGNORECASE),
    re.compile(r'Access-Control-Allow-Origin\s*:\s*\*', re.IGNORECASE),
]

DEBUG_PATTERN = re.compile(r'\bDEBUG\s*=\s*True\b')
NODE_DEBUG_PATTERN = re.compile(r'NODE_ENV\s*=\s*["\']development["\']')


def is_sensitive_path(path_str):
    parts = path_str.lower().strip('/').split('/')
    return any(part in SENSITIVE_PATHS for part in parts)


def walk_files(repo_path, extensions):
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in extensions:
                yield os.path.join(root, fname)


def read_lines(fpath):
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except Exception:
        return []


def rel(fpath, repo_path):
    return os.path.relpath(fpath, repo_path)


def check_auth_in_window(lines, center_idx, auth_patterns, window=15):
    """Return True if any auth pattern found near center_idx."""
    start = max(0, center_idx - window)
    end = min(len(lines), center_idx + window)
    window_text = ' '.join(lines[start:end])
    return any(p in window_text for p in auth_patterns)


def scan(repo_path: str) -> dict:
    details = []
    seen = set()

    # ── SCAN PYTHON FILES ─────────────────────────────────────
    for fpath in walk_files(repo_path, {'.py'}):
        lines = read_lines(fpath)
        relative = rel(fpath, repo_path)
        full_text = ''.join(lines)

        # TODO: Kartikeya — UNPROTECTED ROUTES (Python)
        # YOUR CODE HERE ↓
        for i, line in enumerate(lines):
            match = PYTHON_ROUTE_PATTERN.search(line)
            if match:
                path_str = match.group(2)
                if is_sensitive_path(path_str):
                    has_auth = check_auth_in_window(lines, i, PYTHON_AUTH_PATTERNS)
                    if not has_auth:
                        key = (relative, i + 1, "Unprotected Sensitive Route")
                        if key not in seen:
                            seen.add(key)
                            details.append({
                                "file": relative,
                                "line": i + 1,
                                "type": "Unprotected Sensitive Route",
                                "severity": "critical",
                                "reason": f"Route '{path_str}' has no authentication middleware — accessible without login"
                            })

        # TODO: Kartikeya — DEBUG MODE
        # YOUR CODE HERE ↓
        if DEBUG_PATTERN.search(full_text):
            match = DEBUG_PATTERN.search(full_text)
            line_num = full_text[:match.start()].count('\n') + 1
            key = (relative, line_num, "Debug Mode Enabled")
            if key not in seen:
                seen.add(key)
                details.append({
                    "file": relative,
                    "line": line_num,
                    "type": "Debug Mode Enabled",
                    "severity": "high",
                    "reason": "DEBUG=True exposes stack traces and internal info in production"
                })

        # TODO: Kartikeya — WILDCARD CORS
        # YOUR CODE HERE ↓
        for pattern in WILDCARD_CORS_PATTERNS:
            match = pattern.search(full_text)
            if match:
                line_num = full_text[:match.start()].count('\n') + 1
                key = (relative, line_num, "Wildcard CORS")
                if key not in seen:
                    seen.add(key)
                    details.append({
                        "file": relative,
                        "line": line_num,
                        "type": "Wildcard CORS",
                        "severity": "high",
                        "reason": "CORS allows all origins — exposes API to requests from any website"
                    })
                break

    # ── SCAN JS/TS FILES ──────────────────────────────────────
    for fpath in walk_files(repo_path, {'.js', '.ts'}):
        lines = read_lines(fpath)
        relative = rel(fpath, repo_path)
        full_text = ''.join(lines)

        # TODO: Kartikeya — same as Python but for JS/TS
        # YOUR CODE HERE ↓
        for i, line in enumerate(lines):
            match = JS_ROUTE_PATTERN.search(line)
            if match:
                path_str = match.group(2)
                if is_sensitive_path(path_str):
                    has_auth = check_auth_in_window(lines, i, JS_AUTH_PATTERNS)
                    if not has_auth:
                        key = (relative, i + 1, "Unprotected Sensitive Route")
                        if key not in seen:
                            seen.add(key)
                            details.append({
                                "file": relative,
                                "line": i + 1,
                                "type": "Unprotected Sensitive Route",
                                "severity": "critical",
                                "reason": f"Route '{path_str}' has no authentication middleware — accessible without login"
                            })

        if NODE_DEBUG_PATTERN.search(full_text):
            match = NODE_DEBUG_PATTERN.search(full_text)
            line_num = full_text[:match.start()].count('\n') + 1
            key = (relative, line_num, "Debug Mode Enabled")
            if key not in seen:
                seen.add(key)
                details.append({
                    "file": relative,
                    "line": line_num,
                    "type": "Debug Mode Enabled",
                    "severity": "high",
                    "reason": "NODE_ENV=development in production code"
                })

        for pattern in WILDCARD_CORS_PATTERNS:
            match = pattern.search(full_text)
            if match:
                line_num = full_text[:match.start()].count('\n') + 1
                key = (relative, line_num, "Wildcard CORS")
                if key not in seen:
                    seen.add(key)
                    details.append({
                        "file": relative,
                        "line": line_num,
                        "type": "Wildcard CORS",
                        "severity": "high",
                        "reason": "CORS allows all origins — exposes API to requests from any website"
                    })
                break

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
