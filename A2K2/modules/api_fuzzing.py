"""
Ybe Check — API Fuzzing Module
Uses ffuf (https://github.com/ffuf/ffuf) to discover undocumented or
accidentally exposed API endpoints and flag sensitive ones (admin, debug,
internal, config) that should not be publicly reachable.

Requires: ffuf binary in PATH
          brew install ffuf  OR  go install github.com/ffuf/ffuf/v2@latest
Target:   set YBECK_TARGET_URL env var, or auto-detected from repo config.
"""

import os
import re
import json
import shutil
import subprocess
import tempfile
from typing import Optional

NAME = "API Fuzzing"

# ── WORDLIST ──────────────────────────────────────────────────────────────────
# Curated list of common API paths to fuzz — covers REST conventions, admin
# panels, debug endpoints, health checks, and common framework routes.

WORDLIST = [
    # Health & status
    "health", "healthz", "ready", "readyz", "live", "livez",
    "status", "ping", "version", "info",

    # API versioning
    "api", "api/v1", "api/v2", "api/v3",
    "v1", "v2", "v3",

    # Auth & users
    "auth", "login", "logout", "register", "signup", "token",
    "refresh", "oauth", "oauth2", "callback", "verify",
    "users", "user", "profile", "me", "account", "accounts",
    "password", "reset", "forgot-password",

    # Admin — high value targets
    "admin", "admin/login", "admin/dashboard", "admin/users",
    "administrator", "administration",
    "superadmin", "super-admin",
    "manage", "management", "manager",
    "panel", "control-panel", "cp",
    "console", "dashboard",

    # Debug & internals — should never be exposed in production
    "debug", "debug/pprof", "debug/vars",
    "metrics", "prometheus", "actuator", "actuator/health",
    "actuator/env", "actuator/beans", "actuator/info",
    "internal", "internal/metrics", "internal/debug",
    "private", "hidden",

    # Config & secrets
    "config", "settings", "setup", "install",
    "env", ".env", "environment",
    "secrets",

    # Docs & specs
    "docs", "doc", "swagger", "swagger-ui", "openapi",
    "openapi.json", "swagger.json", "api-docs",
    "redoc", "graphql", "graphiql", "playground",

    # Files & uploads
    "upload", "uploads", "files", "file", "media",
    "static", "assets", "download", "downloads",
    "backup", "backups", "dump",

    # Database & cache
    "db", "database", "redis", "cache",
    "sql", "mongo", "elastic",

    # Monitoring
    "logs", "log", "errors", "error",
    "trace", "tracing", "jaeger",

    # Common framework routes
    "rails/info", "rails/info/properties",
    "wp-admin", "wp-login.php",
    "phpmyadmin", "adminer",
    ".git", ".git/config",
    "server-status", "server-info",
]

# Paths that are expected and not security concerns
BENIGN_PATHS = {"/", "/health", "/healthz", "/ping", "/status",
                "/version", "/info", "/docs", "/swagger-ui",
                "/openapi.json", "/swagger.json", "/api-docs",
                "/redoc", "/graphql", "/graphiql", "/playground",
                "/api", "/api/v1", "/api/v2", "/api/v3",
                "/v1", "/v2", "/v3"}

# Paths that are high-severity exposures
CRITICAL_PATHS = {
    "/admin", "/administrator", "/superadmin", "/super-admin",
    "/.env", "/config", "/secrets", "/internal", "/private",
    "/debug", "/actuator/env", "/actuator/beans",
    "/.git/config", "/backup", "/dump",
}

HIGH_SEVERITY_PATHS = {
    "/admin/login", "/admin/dashboard", "/admin/users",
    "/manage", "/management", "/control-panel", "/cp",
    "/panel", "/console", "/dashboard",
    "/metrics", "/prometheus",
    "/actuator", "/actuator/health",
    "/db", "/database", "/redis", "/cache",
    "/logs", "/log", "/errors",
    "/phpmyadmin", "/adminer", "/wp-admin",
}

# Status codes that indicate something interesting was found
INTERESTING_CODES = {200, 201, 204, 301, 302, 401, 403}
# 200/201/204 = found and accessible
# 301/302 = redirect (endpoint exists)
# 401 = requires auth but exists
# 403 = exists but forbidden — still interesting
SKIP_CODES = {404, 410, 400, 405}


# ── TARGET URL RESOLUTION ─────────────────────────────────────────────────────

ENV_KEYS = ["BASE_URL", "API_URL", "APP_URL", "NEXT_PUBLIC_API_URL",
            "SERVER_URL", "BACKEND_URL", "HOST", "PUBLIC_URL"]


def resolve_target_url(repo_path: str) -> Optional[str]:
    url = os.environ.get("YBECK_TARGET_URL", "").strip()
    if url:
        return url.rstrip("/")

    for fname in [".env", ".env.local", ".env.development", ".env.example"]:
        fpath = os.path.join(repo_path, fname)
        if not os.path.exists(fpath):
            continue
        try:
            with open(fpath, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    if key.strip() in ENV_KEYS:
                        val = val.strip().strip('"\'')
                        if val.startswith("http"):
                            return val.rstrip("/")
        except OSError:
            continue

    dc_path = os.path.join(repo_path, "docker-compose.yml")
    if os.path.exists(dc_path):
        try:
            with open(dc_path, encoding="utf-8", errors="ignore") as f:
                content = f.read()
            port_match = re.search(r'["\']?(\d{2,5}):\d{2,5}["\']?', content)
            if port_match:
                return f"http://localhost:{port_match.group(1)}"
        except OSError:
            pass

    return None


# ── FFUF HELPERS ──────────────────────────────────────────────────────────────

def check_ffuf() -> bool:
    return shutil.which("ffuf") is not None


def write_wordlist(path: str) -> None:
    with open(path, "w") as f:
        f.write("\n".join(WORDLIST))


def run_ffuf(target_url: str, wordlist_path: str, output_path: str) -> tuple[bool, str]:
    """
    Run ffuf against target_url/FUZZ.
    -mc all    : match all status codes
    -fc 404,410: filter out 404/410 (not found)
    -t 10      : 10 concurrent threads (respectful)
    -rate 50   : max 50 req/s
    -timeout 10: 10s per request timeout
    -of json   : JSON output
    -s         : silent (no banner)
    """
    try:
        cmd = [
            "ffuf",
            "-u", f"{target_url}/FUZZ",
            "-w", wordlist_path,
            "-o", output_path,
            "-of", "json",
            "-mc", "all",
            "-fc", ",".join(str(c) for c in SKIP_CODES),
            "-t", "10",
            "-rate", "50",
            "-timeout", "10",
            "-s",                   # silent
            "-noninteractive",      # no prompts
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )

        if not os.path.exists(output_path):
            return False, f"ffuf produced no output. stderr: {result.stderr[:300]}"
        return True, ""

    except subprocess.TimeoutExpired:
        return False, "ffuf timed out after 2 minutes"
    except FileNotFoundError:
        return False, "ffuf not found — install with: brew install ffuf"
    except Exception as e:
        return False, str(e)


# ── RESULTS PARSING ───────────────────────────────────────────────────────────

def classify_path(path: str) -> tuple[str, str]:
    """
    Classify a discovered path into (severity, reason).
    """
    normalized = "/" + path.strip("/").lower()

    # Exact match against critical set
    for critical in CRITICAL_PATHS:
        if normalized == critical or normalized.startswith(critical + "/"):
            return "critical", (
                f"Sensitive path '{normalized}' is publicly reachable — "
                "this endpoint must be access-controlled or removed in production"
            )

    # High severity set
    for high in HIGH_SEVERITY_PATHS:
        if normalized == high or normalized.startswith(high + "/"):
            return "high", (
                f"Administrative or internal path '{normalized}' is accessible — "
                "ensure proper authentication is enforced"
            )

    # Benign
    if normalized in BENIGN_PATHS:
        return "low", f"Standard endpoint '{normalized}' is accessible"

    return "medium", (
        f"Undocumented endpoint '{normalized}' discovered — "
        "verify this should be publicly accessible"
    )


def parse_ffuf_output(output_path: str) -> list[dict]:
    """
    Parse ffuf JSON output into our details[] format.
    ffuf output structure:
      { "results": [{ "input": {"FUZZ": "admin"}, "status": 200,
                      "length": 1234, "url": "http://...", "redirectlocation": "" }] }
    """
    details = []

    try:
        with open(output_path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []

    results = data.get("results", [])
    if not results:
        return []

    for item in results:
        fuzz_val  = item.get("input", {}).get("FUZZ", "")
        status    = item.get("status", 0)
        url       = item.get("url", "")
        length    = item.get("length", 0)
        redirect  = item.get("redirectlocation", "")

        if not fuzz_val:
            continue

        severity, reason = classify_path(fuzz_val)

        # Skip clearly benign low-severity endpoints to reduce noise
        if severity == "low":
            continue

        # Annotate status code context
        status_context = {
            200: "returns 200 OK (fully accessible)",
            201: "returns 201 Created",
            204: "returns 204 No Content",
            301: f"redirects to {redirect}" if redirect else "returns 301 redirect",
            302: f"redirects to {redirect}" if redirect else "returns 302 redirect",
            401: "returns 401 Unauthorized (endpoint exists but requires auth)",
            403: "returns 403 Forbidden (endpoint exists, access denied)",
        }.get(status, f"returns HTTP {status}")

        details.append({
            "file":      f"/{fuzz_val}",
            "line":      0,
            "type":      f"Exposed Endpoint [{status}]",
            "severity":  severity,
            "reason":    f"{reason} — {status_context}",
            "url":       url,
            "status":    status,
            "size":      length,
        })

    # Sort critical first
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    details.sort(key=lambda d: sev_order.get(d["severity"], 4))

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
    Runs ffuf against the target URL and reports discovered sensitive endpoints.
    """
    # 1. Check ffuf is installed
    if not check_ffuf():
        return {
            "name": NAME, "score": None, "issues": 0, "details": [],
            "warning": "ffuf not found — install with: brew install ffuf  OR  go install github.com/ffuf/ffuf/v2@latest"
        }

    # 2. Resolve target URL
    target_url = resolve_target_url(repo_path)
    if not target_url:
        return {
            "name": NAME, "score": None, "issues": 0, "details": [],
            "warning": (
                "No target URL found. Set YBECK_TARGET_URL env var or add "
                "BASE_URL/APP_URL to a .env file in the repo."
            )
        }

    # 3. Write wordlist and run ffuf
    with tempfile.TemporaryDirectory(prefix="ybe-ffuf-") as tmp:
        wordlist_path = os.path.join(tmp, "wordlist.txt")
        output_path   = os.path.join(tmp, "ffuf-output.json")

        write_wordlist(wordlist_path)

        success, error = run_ffuf(target_url, wordlist_path, output_path)
        if not success:
            return {
                "name": NAME, "score": None, "issues": 0, "details": [],
                "warning": f"ffuf failed: {error}"
            }

        # 4. Parse results
        details = parse_ffuf_output(output_path)

    score = compute_score(details)

    return {
        "name":    NAME,
        "score":   score,
        "issues":  len(details),
        "details": details,
        "meta": {
            "target":       target_url,
            "paths_tested": len(WORDLIST),
        }
    }
