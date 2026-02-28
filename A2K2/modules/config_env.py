"""
Ybe Check — Config & Env Module
Validates environment configuration hygiene across the repository:

  1. .env.example completeness — every key in .env should also appear in
     .env.example (ensures new teammates know what to set).

  2. Secret exposure — real secrets committed in .env files (not .example).

  3. Missing .env.example — if a .env file exists but no .env.example, the
     team has no onboarding guide and secrets may leak.

  4. Config drift — keys present in .env.example but missing from the actual
     .env (could cause silent runtime errors).

  5. Production vs development mismatch — DEBUG=True, localhost URLs, or
     dev database strings found in .env.production / .env.prod.

  6. Dangerous defaults — weak secrets, default passwords, empty values for
     security-sensitive keys.

No external tools required — pure Python static analysis.
"""

import os
import re
from typing import Optional

NAME = "Config & Env"

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv',
             'dist', 'build', '.next', 'out', '.ybe-check'}

# Files that are "example / template" — must NOT contain real secrets
EXAMPLE_FILES = {
    ".env.example", ".env.sample", ".env.template",
    ".env.dist", "env.example", "sample.env",
}

# Files that should contain real values (not committed to git in a healthy repo)
REAL_ENV_FILES = {
    ".env", ".env.local", ".env.development.local",
    ".env.production.local", ".env.test.local",
}

# Production env files — stricter rules
PRODUCTION_ENV_FILES = {
    ".env.production", ".env.prod", ".env.staging",
    ".env.live", ".env.release",
}

# All env files
ALL_ENV_PATTERNS = EXAMPLE_FILES | REAL_ENV_FILES | PRODUCTION_ENV_FILES | {
    ".env.development", ".env.test", ".env.ci",
}

# ── SECRET DETECTION ──────────────────────────────────────────────────────────
# Applied to committed .env files (real values, not examples)

SECRET_PATTERNS = [
    (re.compile(r'sk-[A-Za-z0-9\-_]{20,}'),                        "OpenAI API Key"),
    (re.compile(r'sk-ant-[A-Za-z0-9\-_]{20,}'),                    "Anthropic API Key"),
    (re.compile(r'sk_live_[A-Za-z0-9]{24,}'),                      "Stripe Live Key"),
    (re.compile(r'AKIA[0-9A-Z]{16}'),                              "AWS Access Key"),
    (re.compile(r'AIza[A-Za-z0-9\-_]{35,}'),                      "Google API Key"),
    (re.compile(r'ghp_[A-Za-z0-9]{36,}'),                         "GitHub Personal Access Token"),
    (re.compile(r'xoxb-[0-9A-Za-z\-]{50,}'),                      "Slack Bot Token"),
    (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),      "Private Key"),
    (re.compile(r'[0-9a-f]{32,}', re.IGNORECASE),                 "High-Entropy Hex String"),
]

# Keys that should never have weak/default/empty values
SENSITIVE_KEY_PATTERNS = re.compile(
    r'(?:SECRET|PASSWORD|PASSWD|TOKEN|KEY|PRIVATE|SALT|SIGNING|JWT)',
    re.IGNORECASE
)

WEAK_VALUES = {
    "secret", "password", "123456", "admin", "test", "default",
    "changeme", "change_me", "your_secret_here", "supersecret",
    "development", "dev", "replace_me", "todo", "fixme",
    "letmein", "qwerty", "abc123", "pass", "pass123",
}

# Production danger signals
PRODUCTION_DANGER_PATTERNS = [
    (re.compile(r'DEBUG\s*=\s*(?:True|true|1|yes)',   re.IGNORECASE), "DEBUG=True in production config",       "critical"),
    (re.compile(r'localhost|127\.0\.0\.1',             re.IGNORECASE), "localhost URL in production config",    "high"),
    (re.compile(r'sqlite',                             re.IGNORECASE), "SQLite database in production config",  "high"),
    (re.compile(r'(?:DATABASE_URL|DB_HOST)\s*=.*local',re.IGNORECASE), "Local DB connection in production",     "high"),
    (re.compile(r'ALLOWED_HOSTS\s*=\s*\*',            re.IGNORECASE), "Wildcard ALLOWED_HOSTS in production",  "high"),
    (re.compile(r'CORS_ORIGINS?\s*=\s*\*',            re.IGNORECASE), "Wildcard CORS in production config",    "high"),
    (re.compile(r'HTTPS\s*=\s*(?:False|false|0|no)',   re.IGNORECASE), "HTTPS disabled in production",         "high"),
]


# ── ENV FILE PARSING ──────────────────────────────────────────────────────────

def parse_env_file(fpath: str) -> dict[str, str]:
    """
    Parse an .env file and return a {KEY: value} dict.
    Handles: KEY=value, KEY="value", KEY='value', # comments, multiline (basic).
    """
    result = {}
    try:
        with open(fpath, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, raw_value = line.partition("=")
                key       = key.strip()
                raw_value = raw_value.strip()
                # Strip surrounding quotes
                if len(raw_value) >= 2 and raw_value[0] in ('"', "'") and raw_value[-1] == raw_value[0]:
                    raw_value = raw_value[1:-1]
                # Strip inline comments
                if " #" in raw_value:
                    raw_value = raw_value.split(" #")[0].strip()
                result[key] = raw_value
    except OSError:
        pass
    return result


def is_placeholder_value(value: str) -> bool:
    """Return True if a value looks like a placeholder, not a real secret."""
    if not value:
        return True
    lower = value.lower()
    placeholder_signals = [
        "your_", "my_", "replace", "change_me", "example", "sample",
        "insert_", "add_your", "paste_", "fill_in", "<", ">",
        "xxxxxxx", "...", "todo", "fixme",
    ]
    return any(s in lower for s in placeholder_signals)


def looks_like_real_secret(value: str) -> bool:
    """Heuristic: does this value look like a real credential (not a placeholder)?"""
    if not value or len(value) < 8:
        return False
    if is_placeholder_value(value):
        return False
    # Check against known secret patterns
    for pattern, _ in SECRET_PATTERNS:
        if pattern.search(value):
            return True
    # High entropy string: mostly hex or base64, len > 20
    if len(value) > 20:
        hex_ratio = sum(1 for c in value if c in "0123456789abcdefABCDEF") / len(value)
        b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        b64_ratio = sum(1 for c in value if c in b64_chars) / len(value)
        if hex_ratio > 0.85 or b64_ratio > 0.90:
            return True
    return False


# ── FILE DISCOVERY ────────────────────────────────────────────────────────────

def find_env_files(repo_path: str) -> dict[str, str]:
    """
    Walk repo root (not subdirectories, env files live at root or in config/).
    Returns {filename: absolute_path}.
    """
    found = {}
    search_dirs = [repo_path]

    # Also check common config subdirectories
    for subdir in ["config", "env", "envs", ".config"]:
        d = os.path.join(repo_path, subdir)
        if os.path.isdir(d):
            search_dirs.append(d)

    for search_dir in search_dirs:
        for dirpath, dirnames, filenames in os.walk(search_dir):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in filenames:
                lower = fname.lower()
                if lower in ALL_ENV_PATTERNS or lower.startswith(".env"):
                    rel = os.path.relpath(os.path.join(dirpath, fname), repo_path)
                    found[rel] = os.path.join(dirpath, fname)
            # Only go one level deep in config subdirs
            if search_dir != repo_path:
                break

    return found


# ── ANALYSIS FUNCTIONS ────────────────────────────────────────────────────────

def check_example_completeness(
    example_path: str,
    real_path: str,
    repo_path: str,
) -> list[dict]:
    """
    Check that all keys in the real .env are documented in .env.example.
    """
    details = []
    example_keys = set(parse_env_file(example_path).keys())
    real_keys    = set(parse_env_file(real_path).keys())

    # Keys in .env but missing from .env.example
    undocumented = real_keys - example_keys
    for key in sorted(undocumented):
        rel_real = os.path.relpath(real_path, repo_path)
        rel_ex   = os.path.relpath(example_path, repo_path)
        details.append({
            "file":     rel_real,
            "line":     0,
            "type":     "Undocumented Env Key",
            "severity": "medium",
            "reason":   (
                f"Key '{key}' exists in '{rel_real}' but is missing from '{rel_ex}' — "
                "new developers won't know to set this. Add it to .env.example with a placeholder value."
            ),
            "key": key,
        })

    # Keys in .env.example but missing from .env (possible runtime error)
    unconfigured = example_keys - real_keys
    for key in sorted(unconfigured):
        if SENSITIVE_KEY_PATTERNS.search(key):
            rel_real = os.path.relpath(real_path, repo_path)
            rel_ex   = os.path.relpath(example_path, repo_path)
            details.append({
                "file":     rel_real,
                "line":     0,
                "type":     "Missing Required Security Key",
                "severity": "high",
                "reason":   (
                    f"Security-sensitive key '{key}' is documented in '{rel_ex}' "
                    f"but not set in '{rel_real}' — this may cause auth/crypto failures at runtime."
                ),
                "key": key,
            })

    return details


def check_secret_exposure(fpath: str, keys: dict[str, str], repo_path: str) -> list[dict]:
    """
    Check for real secrets committed in env files.
    """
    details = []
    rel = os.path.relpath(fpath, repo_path)

    fname_lower = os.path.basename(fpath).lower()
    is_example  = fname_lower in EXAMPLE_FILES

    try:
        with open(fpath, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []

    for i, line in enumerate(lines, 1):
        line_stripped = line.strip()
        if line_stripped.startswith("#") or "=" not in line_stripped:
            continue

        key, _, value = line_stripped.partition("=")
        key   = key.strip()
        value = value.strip().strip('"\'')

        # In example files, real secrets are extra bad (they get committed to git)
        if is_example and looks_like_real_secret(value):
            # Find which pattern matched
            for pattern, secret_type in SECRET_PATTERNS:
                if pattern.search(value):
                    details.append({
                        "file":     rel,
                        "line":     i,
                        "type":     f"Real Secret in Example File: {secret_type}",
                        "severity": "critical",
                        "reason":   (
                            f"Key '{key}' in '{rel}' contains what appears to be a real {secret_type}. "
                            "Example files are committed to git — replace with a placeholder immediately."
                        ),
                        "key": key,
                    })
                    break

        # Weak/default values for sensitive keys
        if SENSITIVE_KEY_PATTERNS.search(key):
            if value.lower() in WEAK_VALUES or (value and len(value) < 8 and not is_placeholder_value(value)):
                details.append({
                    "file":     rel,
                    "line":     i,
                    "type":     "Weak Secret Value",
                    "severity": "high" if not is_example else "medium",
                    "reason":   (
                        f"Security key '{key}' has a weak value '{value}' — "
                        "use a cryptographically random value (e.g. openssl rand -hex 32)."
                    ),
                    "key": key,
                })

        # Empty sensitive keys
        if SENSITIVE_KEY_PATTERNS.search(key) and not value and not is_example:
            details.append({
                "file":     rel,
                "line":     i,
                "type":     "Empty Security Key",
                "severity": "high",
                "reason":   (
                    f"Security key '{key}' is set but has no value — "
                    "this will likely cause auth failures or insecure defaults at runtime."
                ),
                "key": key,
            })

    return details


def check_production_config(fpath: str, keys: dict[str, str], repo_path: str) -> list[dict]:
    """
    Check production env files for development-mode or dangerous settings.
    """
    details = []
    rel = os.path.relpath(fpath, repo_path)

    try:
        with open(fpath, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("#"):
            continue
        for pattern, msg, severity in PRODUCTION_DANGER_PATTERNS:
            if pattern.search(line):
                details.append({
                    "file":     rel,
                    "line":     i,
                    "type":     msg,
                    "severity": severity,
                    "reason":   (
                        f"{msg} at {rel}:{i} — "
                        "this setting is dangerous in a production environment."
                    ),
                })
                break  # one finding per line

    return details


# ── SCORE CALCULATION ─────────────────────────────────────────────────────────

def compute_score(details: list) -> int:
    critical = sum(1 for d in details if d["severity"] == "critical")
    high     = sum(1 for d in details if d["severity"] == "high")
    medium   = sum(1 for d in details if d["severity"] == "medium")
    return max(0, 100 - (critical * 15) - (high * 10) - (medium * 5))


# ── MAIN ENTRY POINT ──────────────────────────────────────────────────────────

def scan(repo_path: str) -> dict:
    """
    Entry point called by cli.py.
    Validates all .env* files in the repo for completeness, security, and
    production-readiness.
    """
    env_files = find_env_files(repo_path)

    if not env_files:
        return {
            "name": NAME, "score": 100, "issues": 0, "details": [],
            "warning": "No .env files found — add a .env.example to document required configuration."
        }

    all_details: list[dict] = []

    # Categorise found files
    example_files    = {k: v for k, v in env_files.items()
                        if os.path.basename(k).lower() in EXAMPLE_FILES}
    real_files       = {k: v for k, v in env_files.items()
                        if os.path.basename(k).lower() in REAL_ENV_FILES}
    production_files = {k: v for k, v in env_files.items()
                        if os.path.basename(k).lower() in PRODUCTION_ENV_FILES}

    # ── Check 1: missing .env.example ─────────────────────────────────────
    if real_files and not example_files:
        all_details.append({
            "file":     list(real_files.keys())[0],
            "line":     0,
            "type":     "Missing .env.example",
            "severity": "high",
            "reason":   (
                ".env file exists but no .env.example was found — "
                "create .env.example with placeholder values for every key so "
                "teammates can onboard without guessing required configuration."
            ),
        })

    # ── Check 2: example completeness + config drift ───────────────────────
    if example_files:
        ex_path = list(example_files.values())[0]
        for rel_real, real_path in real_files.items():
            completeness_issues = check_example_completeness(ex_path, real_path, repo_path)
            all_details.extend(completeness_issues)

    # ── Check 3: secret exposure in all env files ──────────────────────────
    for rel_path, abs_path in env_files.items():
        keys    = parse_env_file(abs_path)
        secrets = check_secret_exposure(abs_path, keys, repo_path)
        all_details.extend(secrets)

    # ── Check 4: production config sanity ─────────────────────────────────
    for rel_path, abs_path in production_files.items():
        keys    = parse_env_file(abs_path)
        prod_issues = check_production_config(abs_path, keys, repo_path)
        all_details.extend(prod_issues)

    # ── Check 5: .env files in git (check .gitignore) ─────────────────────
    gitignore_path = os.path.join(repo_path, ".gitignore")
    env_in_gitignore = False
    if os.path.exists(gitignore_path):
        try:
            with open(gitignore_path, encoding="utf-8", errors="ignore") as f:
                gitignore_content = f.read()
            env_in_gitignore = bool(re.search(r'^\.env\b', gitignore_content, re.MULTILINE))
        except OSError:
            pass

    if real_files and not env_in_gitignore:
        all_details.append({
            "file":     ".gitignore",
            "line":     0,
            "type":     ".env Not in .gitignore",
            "severity": "critical",
            "reason":   (
                ".env file exists but '.env' is not listed in .gitignore — "
                "real secrets could be accidentally committed to git. "
                "Add '.env' and '.env.*' to .gitignore immediately."
            ),
        })

    # Deduplicate
    seen: set[tuple] = set()
    deduped = []
    for d in all_details:
        key = (d.get("type"), d.get("file"), d.get("line"), d.get("key", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(d)

    # Sort: critical first
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    deduped.sort(key=lambda d: sev_order.get(d["severity"], 4))

    score = compute_score(deduped)

    return {
        "name":    NAME,
        "score":   score,
        "issues":  len(deduped),
        "details": deduped,
        "meta": {
            "env_files_found":        list(env_files.keys()),
            "example_files_found":    list(example_files.keys()),
            "production_files_found": list(production_files.keys()),
        }
    }
