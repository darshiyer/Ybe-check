"""
Ybe Check — Load Testing Module
Uses Artillery (https://artillery.io) to benchmark HTTP endpoints discovered
in the repository and report latency, error rate, and throughput findings.

Requires: npm install -g artillery
Target:   set YBECK_TARGET_URL env var, or auto-detected from repo config.
"""

import os
import re
import json
import subprocess
import tempfile
import shutil
from typing import Optional

NAME = "Load Testing"

# ── TARGET URL RESOLUTION ────────────────────────────────────────────────────

ENV_KEYS = ["BASE_URL", "API_URL", "APP_URL", "NEXT_PUBLIC_API_URL",
            "SERVER_URL", "BACKEND_URL", "HOST", "PUBLIC_URL"]

COMMON_PORTS = [3000, 8000, 8080, 5000, 4000, 3001]


def resolve_target_url(repo_path: str) -> Optional[str]:
    """
    Resolve the target URL from:
      1. YBECK_TARGET_URL environment variable
      2. .env / .env.local / .env.example files in the repo
      3. docker-compose.yml port mappings
      4. README.md URL patterns
    Returns the URL string or None if not found.
    """
    # 1. Explicit override
    url = os.environ.get("YBECK_TARGET_URL", "").strip()
    if url:
        return url.rstrip("/")

    # 2. .env files
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

    # 3. docker-compose.yml — grab first published port on the app service
    dc_path = os.path.join(repo_path, "docker-compose.yml")
    if os.path.exists(dc_path):
        try:
            with open(dc_path, encoding="utf-8", errors="ignore") as f:
                content = f.read()
            # Look for "- '3000:3000'" or "- 8080:8080" patterns
            port_match = re.search(r'["\']?(\d{2,5}):\d{2,5}["\']?', content)
            if port_match:
                return f"http://localhost:{port_match.group(1)}"
        except OSError:
            pass

    # 4. README.md — look for localhost or 127.0.0.1 URLs
    for readme in ["README.md", "readme.md", "README.rst"]:
        rpath = os.path.join(repo_path, readme)
        if not os.path.exists(rpath):
            continue
        try:
            with open(rpath, encoding="utf-8", errors="ignore") as f:
                text = f.read()
            m = re.search(r'https?://(?:localhost|127\.0\.0\.1):\d+', text)
            if m:
                return m.group(0).rstrip("/")
        except OSError:
            pass

    return None


# ── ENDPOINT DISCOVERY ───────────────────────────────────────────────────────

ROUTE_PATTERNS = [
    # Flask / FastAPI / Django
    (r'@(?:app|router|blueprint)\.\w+\(["\']([/][^"\']*)["\']', "python"),
    # Express.js
    (r'(?:app|router)\.\w+\(["\']([/][^"\']*)["\']', "js"),
    # Next.js API routes — infer from file path structure
    # (handled separately via filesystem walk)
]

CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx"}


def discover_endpoints(repo_path: str) -> list[str]:
    """
    Walk source files and extract HTTP route paths.
    Also infers Next.js API routes from filesystem.
    Returns a deduplicated list of paths like ['/api/users', '/health'].
    """
    found = set()

    # Regex-based extraction from source files
    skip = {'.git', 'node_modules', '__pycache__', '.venv', 'venv',
            'dist', 'build', '.next', 'out', '.ybe-check'}

    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in CODE_EXTENSIONS:
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue

            for pattern, _ in ROUTE_PATTERNS:
                for m in re.finditer(pattern, content):
                    path = m.group(1)
                    # Skip paths with dynamic params unresolved — replace with literal
                    path = re.sub(r'<[^>]+>', '1', path)
                    path = re.sub(r'\{[^}]+\}', '1', path)
                    path = re.sub(r':[a-zA-Z_]+', '1', path)
                    found.add(path)

    # Next.js API routes — infer from pages/api or app/api directory structure
    for api_root in ["pages/api", "app/api", "src/pages/api", "src/app/api"]:
        api_dir = os.path.join(repo_path, api_root)
        if not os.path.isdir(api_dir):
            continue
        for dirpath, _, filenames in os.walk(api_dir):
            for fname in filenames:
                if os.path.splitext(fname)[1] in {".js", ".ts"}:
                    rel = os.path.relpath(
                        os.path.join(dirpath, fname), repo_path
                    )
                    # Convert pages/api/users/index.ts → /api/users
                    route = "/" + "/".join(rel.split(os.sep))
                    route = re.sub(r'/(index)?\.(js|ts|jsx|tsx)$', '', route)
                    route = re.sub(r'\[[^\]]+\]', '1', route)  # [id] → 1
                    found.add(route)

    # Always include standard health/base endpoints
    found.update(["/", "/health", "/api", "/api/health"])

    return sorted(found)[:30]  # Cap at 30 endpoints to keep test duration bounded


# ── ARTILLERY CONFIG GENERATION ──────────────────────────────────────────────

def generate_artillery_config(target_url: str, endpoints: list[str]) -> str:
    """
    Generate an Artillery YAML load test config.
    Runs a 30-second warm-up then a 60-second sustained load phase.
    """
    flows = []
    for path in endpoints:
        flows.append(f"      - get:\n          url: \"{path}\"")

    flow_block = "\n".join(flows) if flows else '      - get:\n          url: "/"'

    return f"""config:
  target: "{target_url}"
  http:
    timeout: 10
  phases:
    - name: warm_up
      duration: 20
      arrivalRate: 2
    - name: sustained_load
      duration: 60
      arrivalRate: 10
    - name: spike
      duration: 20
      arrivalRate: 30
  defaults:
    headers:
      Content-Type: application/json
      Accept: application/json

scenarios:
  - name: endpoint_benchmark
    flow:
{flow_block}
"""


# ── ARTILLERY EXECUTION ───────────────────────────────────────────────────────

def check_artillery() -> bool:
    return shutil.which("artillery") is not None


def run_artillery(config_path: str, report_path: str) -> tuple[dict | None, str | None]:
    """
    Execute Artillery and return the parsed JSON report.
    Returns (report_dict, error_string).
    """
    try:
        result = subprocess.run(
            ["artillery", "run", config_path,
             "--output", report_path],
            capture_output=True,
            text=True,
            timeout=180,  # 3 min max
        )
        if not os.path.exists(report_path):
            stderr_snippet = result.stderr[-500:] if result.stderr else "no output"
            return None, f"Artillery produced no report file. stderr: {stderr_snippet}"

        with open(report_path, encoding="utf-8") as f:
            return json.load(f), None

    except subprocess.TimeoutExpired:
        return None, "Artillery timed out after 3 minutes"
    except FileNotFoundError:
        return None, "artillery not found — run: npm install -g artillery"
    except Exception as e:
        return None, str(e)


# ── RESULTS PARSING ───────────────────────────────────────────────────────────

def parse_artillery_report(report: dict, target_url: str) -> list[dict]:
    """
    Extract findings from Artillery's aggregate stats.
    Flags slow p95/p99 latency, high error rates, and low throughput.
    """
    details = []

    aggregate = report.get("aggregate", {})
    latency   = aggregate.get("latency", {})
    counters  = aggregate.get("counters", {})
    rates     = aggregate.get("rates", {})

    p95 = latency.get("p95", 0)
    p99 = latency.get("p99", 0)
    p50 = latency.get("median", latency.get("p50", 0))

    total_requests = counters.get("http.requests", 0)
    total_errors   = (
        counters.get("http.request_rate", 0)  # sometimes structured differently
        + sum(v for k, v in counters.items() if "error" in k.lower())
    )
    codes_5xx = sum(v for k, v in counters.items()
                    if re.match(r"http\.codes\.5\d\d", k))
    codes_4xx = sum(v for k, v in counters.items()
                    if re.match(r"http\.codes\.4\d\d", k))

    rps = rates.get("http.request_rate", 0)

    # ── Latency findings ──
    if p95 > 3000:
        details.append({
            "file": target_url, "line": 0,
            "type": "Critical Latency",
            "severity": "critical",
            "reason": f"p95 response time is {p95:.0f}ms — exceeds 3s threshold. Profile and optimize hot paths.",
            "metric": f"p95={p95:.0f}ms p99={p99:.0f}ms median={p50:.0f}ms",
        })
    elif p95 > 1500:
        details.append({
            "file": target_url, "line": 0,
            "type": "High Latency",
            "severity": "high",
            "reason": f"p95 response time is {p95:.0f}ms — exceeds 1.5s production target. Consider caching or query optimization.",
            "metric": f"p95={p95:.0f}ms p99={p99:.0f}ms median={p50:.0f}ms",
        })
    elif p95 > 800:
        details.append({
            "file": target_url, "line": 0,
            "type": "Elevated Latency",
            "severity": "medium",
            "reason": f"p95 response time is {p95:.0f}ms — watch this under higher load.",
            "metric": f"p95={p95:.0f}ms p99={p99:.0f}ms median={p50:.0f}ms",
        })

    # ── Error rate findings ──
    if total_requests > 0:
        error_rate = (codes_5xx / total_requests) * 100
        if error_rate > 5:
            details.append({
                "file": target_url, "line": 0,
                "type": "High 5xx Error Rate",
                "severity": "critical",
                "reason": f"{error_rate:.1f}% of requests returned 5xx — service is unstable under load. "
                          f"({codes_5xx}/{total_requests} requests failed)",
                "metric": f"5xx_rate={error_rate:.1f}%",
            })
        elif error_rate > 1:
            details.append({
                "file": target_url, "line": 0,
                "type": "Elevated 5xx Error Rate",
                "severity": "high",
                "reason": f"{error_rate:.1f}% of requests returned 5xx. ({codes_5xx}/{total_requests})",
                "metric": f"5xx_rate={error_rate:.1f}%",
            })

        client_error_rate = (codes_4xx / total_requests) * 100
        if client_error_rate > 20:
            details.append({
                "file": target_url, "line": 0,
                "type": "High 4xx Rate",
                "severity": "medium",
                "reason": f"{client_error_rate:.1f}% of requests returned 4xx — check endpoint paths and auth handling.",
                "metric": f"4xx_rate={client_error_rate:.1f}%",
            })

    # ── Throughput findings ──
    if rps > 0 and rps < 5:
        details.append({
            "file": target_url, "line": 0,
            "type": "Low Throughput",
            "severity": "high",
            "reason": f"Throughput is only {rps:.1f} req/s — service cannot handle production traffic levels.",
            "metric": f"rps={rps:.1f}",
        })

    # ── Connection errors ──
    conn_errors = sum(v for k, v in counters.items()
                      if any(x in k.lower() for x in ["econnrefused", "etimedout", "enotfound"]))
    if conn_errors > 0:
        details.append({
            "file": target_url, "line": 0,
            "type": "Connection Errors",
            "severity": "critical",
            "reason": f"{conn_errors} connection errors during load test — service became unreachable under load.",
            "metric": f"conn_errors={conn_errors}",
        })

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
    Discovers endpoints, runs Artillery load test, returns structured findings.
    """
    # 1. Check Artillery is installed
    if not check_artillery():
        return {
            "name": NAME, "score": None, "issues": 0, "details": [],
            "warning": "artillery not found — run: npm install -g artillery"
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

    # 3. Discover endpoints
    endpoints = discover_endpoints(repo_path)

    # 4. Generate Artillery config and run test
    with tempfile.TemporaryDirectory(prefix="ybe-artillery-") as tmp:
        config_path = os.path.join(tmp, "artillery.yml")
        report_path = os.path.join(tmp, "report.json")

        with open(config_path, "w") as f:
            f.write(generate_artillery_config(target_url, endpoints))

        report, error = run_artillery(config_path, report_path)

    if error:
        return {
            "name": NAME, "score": None, "issues": 0, "details": [],
            "warning": f"Artillery failed: {error}"
        }

    # 5. Parse and score
    details = parse_artillery_report(report, target_url)
    score   = compute_score(details)

    return {
        "name":    NAME,
        "score":   score,
        "issues":  len(details),
        "details": details,
        "meta": {
            "target":    target_url,
            "endpoints": endpoints,
        }
    }
