"""
Auth Guards Detection Module — Ybe Check
Author: Kartikeya
Status: COMPLETE

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

SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.ttf', '.eot', '.zip', '.tar', '.gz',
    '.pyc', '.lock', '.vsix', '.db'
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
    'superuser', 'root', 'system', 'debug'
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
    'requireAuth', 'passport', 'middleware',
    'jwt.verify', 'isAuthenticated', 'checkAuth',
    'authMiddleware', 'requireLogin', 'ensureAuth'
]

# ── ALWAYS-FLAG PATTERNS ─────────────────────────────────────
WILDCARD_CORS_PATTERNS = [
    re.compile(r'cors\s*\(\s*\{\s*origin\s*:\s*["\'\`]\*["\'\`]', re.IGNORECASE),
    re.compile(r'cors\s*\(\s*\{origin\s*:\s*["\'\`]\*["\'\`]', re.IGNORECASE),
    re.compile(r'CORS\s*\(\s*origins\s*=\s*["\'\[]\s*\*', re.IGNORECASE),
    re.compile(r'allow_origins\s*=\s*\[\s*["\'\`]\*["\'\`]', re.IGNORECASE),
    re.compile(r'Access-Control-Allow-Origin\s*:\s*\*', re.IGNORECASE),
    # Simple variable assignment patterns: CORS_ORIGIN = "*" or cors_origin = '*'
    re.compile(r'(?:CORS|cors)[_-]?(?:ORIGIN|origin|ORIGINS|origins)\s*=\s*["\'\`]\*["\'\`]'),
    # ALLOWED_ORIGINS = ["*"] or allowed_origins = ['*']
    re.compile(r'(?:ALLOWED|allowed)[_-]?(?:ORIGINS|origins|HOSTS|hosts)\s*=\s*\[\s*["\'\`]\*["\'\`]'),
]

DEBUG_PATTERN = re.compile(r'\bDEBUG\s*=\s*True\b')
NODE_DEBUG_PATTERN = re.compile(r'NODE_ENV\s*=\s*["\']development["\']')


def is_sensitive_path(path_str):
    """Check if any segment in the route path is a sensitive keyword."""
    parts = path_str.lower().strip('/').split('/')
    return any(part in SENSITIVE_PATHS for part in parts)


def walk_files(repo_path, extensions):
    """Walk repo yielding files matching given extensions, skipping ignored dirs & binary extensions."""
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in extensions and ext not in SKIP_EXTENSIONS:
                yield os.path.join(root, fname)


def read_lines(fpath):
    """Read file lines safely. Returns empty list on failure."""
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except Exception:
        return []


def rel(fpath, repo_path):
    """Return path relative to repo root."""
    return os.path.relpath(fpath, repo_path)


def check_auth_in_window(lines, center_idx, auth_patterns, before=5, after=20):
    """Return True if any auth pattern found in window around center_idx."""
    start = max(0, center_idx - before)
    end = min(len(lines), center_idx + after)
    window_text = ' '.join(lines[start:end])
    return any(p.lower() in window_text.lower() for p in auth_patterns)


def scan(repo_path: str) -> dict:
    try:
        details = []
        seen = set()

        # ── SCAN PYTHON FILES ─────────────────────────────────
        for fpath in walk_files(repo_path, {'.py'}):
            lines = read_lines(fpath)
            if not lines:
                continue
            relative = rel(fpath, repo_path)
            full_text = ''.join(lines)

            # UNPROTECTED ROUTES (Python)
            for i, line in enumerate(lines):
                match = PYTHON_ROUTE_PATTERN.search(line)
                if match:
                    path_str = match.group(2)
                    if is_sensitive_path(path_str):
                        has_auth = check_auth_in_window(
                            lines, i, PYTHON_AUTH_PATTERNS,
                            before=5, after=20
                        )
                        if not has_auth:
                            key = (relative, i + 1, "Unprotected Sensitive Route")
                            if key not in seen:
                                seen.add(key)
                                details.append({
                                    "file": relative,
                                    "line": i + 1,
                                    "type": "Unprotected Sensitive Route",
                                    "severity": "critical",
                                    "reason": f"Route '{path_str}' has no authentication — accessible without login"
                                })

            # DEBUG MODE
            for m in DEBUG_PATTERN.finditer(full_text):
                line_num = full_text[:m.start()].count('\n') + 1
                key = (relative, line_num, "Debug Mode Enabled")
                if key not in seen:
                    seen.add(key)
                    details.append({
                        "file": relative,
                        "line": line_num,
                        "type": "Debug Mode Enabled",
                        "severity": "high",
                        "reason": "Debug mode enabled in code — exposes stack traces and internal info in production"
                    })

            # WILDCARD CORS
            for pattern in WILDCARD_CORS_PATTERNS:
                m = pattern.search(full_text)
                if m:
                    line_num = full_text[:m.start()].count('\n') + 1
                    key = (relative, line_num, "Wildcard CORS")
                    if key not in seen:
                        seen.add(key)
                        details.append({
                            "file": relative,
                            "line": line_num,
                            "type": "Wildcard CORS",
                            "severity": "high",
                            "reason": "CORS allows all origins — exposes API to any website"
                        })
                    break

        # ── SCAN JS/TS FILES ──────────────────────────────────
        for fpath in walk_files(repo_path, {'.js', '.ts'}):
            lines = read_lines(fpath)
            if not lines:
                continue
            relative = rel(fpath, repo_path)
            full_text = ''.join(lines)

            # UNPROTECTED ROUTES (JS/TS)
            for i, line in enumerate(lines):
                match = JS_ROUTE_PATTERN.search(line)
                if match:
                    path_str = match.group(2)
                    if is_sensitive_path(path_str):
                        has_auth = check_auth_in_window(
                            lines, i, JS_AUTH_PATTERNS,
                            before=15, after=15
                        )
                        if not has_auth:
                            key = (relative, i + 1, "Unprotected Sensitive Route")
                            if key not in seen:
                                seen.add(key)
                                details.append({
                                    "file": relative,
                                    "line": i + 1,
                                    "type": "Unprotected Sensitive Route",
                                    "severity": "critical",
                                    "reason": f"Route '{path_str}' has no authentication — accessible without login"
                                })

            # NODE DEBUG
            for m in NODE_DEBUG_PATTERN.finditer(full_text):
                line_num = full_text[:m.start()].count('\n') + 1
                key = (relative, line_num, "Debug Mode Enabled")
                if key not in seen:
                    seen.add(key)
                    details.append({
                        "file": relative,
                        "line": line_num,
                        "type": "Debug Mode Enabled",
                        "severity": "high",
                        "reason": "NODE_ENV=development hardcoded — exposes stack traces and internal info in production"
                    })

            # WILDCARD CORS (JS/TS)
            for pattern in WILDCARD_CORS_PATTERNS:
                m = pattern.search(full_text)
                if m:
                    line_num = full_text[:m.start()].count('\n') + 1
                    key = (relative, line_num, "Wildcard CORS")
                    if key not in seen:
                        seen.add(key)
                        details.append({
                            "file": relative,
                            "line": line_num,
                            "type": "Wildcard CORS",
                            "severity": "high",
                            "reason": "CORS allows all origins — exposes API to any website"
                        })
                    break

        # ── SCORING ───────────────────────────────────────────
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

    except Exception as e:
        return {
            "name": NAME,
            "score": None,
            "issues": 0,
            "details": [],
            "warning": f"Could not run: {e}"
        }
