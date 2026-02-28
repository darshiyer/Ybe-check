"""
Ybe Check — Web Attack Surface Module
Uses OWASP ZAP (via Docker: owasp/zap2docker-stable) to run a baseline
vulnerability scan against a live target and report findings by severity.

Requires: Docker running locally
Target:   set YBECK_TARGET_URL env var, or auto-detected from repo config.

ZAP Baseline scan checks for ~100+ OWASP Top 10 issues including:
  SQL Injection, XSS, CSRF, insecure headers, open redirects,
  sensitive data exposure, security misconfigurations, and more.
"""

import os
import re
import json
import subprocess
import tempfile
import shutil
from typing import Optional

NAME = "Web Attack Surface"

ZAP_IMAGE = "owasp/zap2docker-stable"

# ZAP risk codes → our severity
ZAP_RISK_MAP = {
    "3": "critical",   # High
    "2": "high",       # Medium
    "1": "medium",     # Low
    "0": "low",        # Informational
}

# ZAP alert IDs that are too noisy for vibe-coded apps
SKIP_ALERT_IDS = {
    "10027",   # Information Disclosure - Suspicious Comments (too broad)
    "10096",   # Timestamp Disclosure
}

# ── TARGET URL RESOLUTION (shared logic with other dynamic modules) ───────────

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


# ── DOCKER HELPERS ────────────────────────────────────────────────────────────

def check_docker() -> tuple[bool, str]:
    """Returns (available, error_message)."""
    if not shutil.which("docker"):
        return False, "docker not found — install Docker Desktop"
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return False, "Docker daemon is not running — start Docker Desktop"
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "Docker daemon is not responding"
    except Exception as e:
        return False, str(e)


def pull_zap_image() -> tuple[bool, str]:
    """Pull ZAP Docker image if not already present. Returns (success, error)."""
    try:
        # Check if image already exists locally
        result = subprocess.run(
            ["docker", "image", "inspect", ZAP_IMAGE],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return True, ""  # Already present

        # Pull it
        result = subprocess.run(
            ["docker", "pull", ZAP_IMAGE],
            capture_output=True, text=True, timeout=300
        )
        return result.returncode == 0, result.stderr[:300] if result.returncode != 0 else ""
    except subprocess.TimeoutExpired:
        return False, "Docker pull timed out — check network connection"
    except Exception as e:
        return False, str(e)


# ── ZAP SCAN EXECUTION ────────────────────────────────────────────────────────

def run_zap_baseline(target_url: str, report_path: str) -> tuple[bool, str]:
    """
    Run ZAP baseline scan against target_url.
    Writes JSON report to report_path.

    ZAP baseline scan is passive + active rules that don't attack the target —
    safe to run against staging/dev environments.
    """
    try:
        cmd = [
            "docker", "run", "--rm",
            "--network", "host",                      # reach localhost targets
            "-v", f"{os.path.dirname(report_path)}:/zap/wrk:rw",
            ZAP_IMAGE,
            "zap-baseline.py",
            "-t", target_url,
            "-J", os.path.basename(report_path),      # JSON output file
            "-l", "WARN",                             # only WARN and above in logs
            "-I",                                     # ignore warnings (don't fail on them)
            "--auto",                                 # use auto mode for modern apps
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 min max
        )
        # ZAP exits with 1 when it finds issues — that's normal
        report_exists = os.path.exists(report_path)
        if not report_exists:
            return False, f"ZAP produced no report. stderr: {result.stderr[-400:]}"
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "ZAP scan timed out after 10 minutes"
    except Exception as e:
        return False, str(e)


# ── REPORT PARSING ────────────────────────────────────────────────────────────

def parse_zap_report(report_path: str, target_url: str) -> list[dict]:
    """
    Parse ZAP JSON report into our details[] format.
    ZAP report structure:
      { "site": [{ "alerts": [{ "riskcode": "3", "alert": "...", ... }] }] }
    """
    details = []
    seen = set()

    try:
        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return []

    # ZAP wraps everything in a "site" array
    sites = data if isinstance(data, list) else data.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        alerts = site.get("alerts", [])
        if isinstance(alerts, dict):
            alerts = [alerts]

        for alert in alerts:
            alert_id   = str(alert.get("pluginid", alert.get("alertRef", "0")))
            if alert_id in SKIP_ALERT_IDS:
                continue

            risk_code  = str(alert.get("riskcode", "1"))
            severity   = ZAP_RISK_MAP.get(risk_code, "medium")
            alert_name = alert.get("alert", alert.get("name", "Unknown Vulnerability"))
            description = alert.get("desc", "")
            solution    = alert.get("solution", "")
            reference   = alert.get("reference", "")

            # Each alert can have multiple instances (URL + method + evidence)
            instances = alert.get("instances", [])
            if isinstance(instances, dict):
                instances = [instances]
            if not instances:
                instances = [{"uri": target_url, "method": "GET", "evidence": ""}]

            for instance in instances[:5]:  # cap at 5 instances per alert type
                uri      = instance.get("uri", target_url)
                method   = instance.get("method", "GET")
                evidence = instance.get("evidence", "")[:100]

                # Path from URI
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(uri)
                    path = parsed.path or "/"
                except Exception:
                    path = uri

                dedup_key = (alert_id, path)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                reason_parts = [f"[ZAP-{alert_id}] {alert_name}"]
                if solution:
                    # Strip HTML tags from ZAP's HTML-formatted solution
                    clean_solution = re.sub(r'<[^>]+>', '', solution).strip()
                    reason_parts.append(f"Fix: {clean_solution[:150]}")

                details.append({
                    "file":       path,
                    "line":       0,
                    "type":       alert_name,
                    "severity":   severity,
                    "reason":     " — ".join(reason_parts),
                    "evidence":   evidence,
                    "method":     method,
                    "alert_id":   alert_id,
                    "reference":  reference[:100] if reference else "",
                })

    # Sort: critical first, then high, medium, low
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
    Runs OWASP ZAP Docker baseline scan against the target URL.
    """
    # 1. Resolve target URL
    target_url = resolve_target_url(repo_path)
    if not target_url:
        return {
            "name": NAME, "score": None, "issues": 0, "details": [],
            "warning": (
                "No target URL found. Set YBECK_TARGET_URL env var or add "
                "BASE_URL/APP_URL to a .env file in the repo."
            )
        }

    # 2. Check Docker
    docker_ok, docker_err = check_docker()
    if not docker_ok:
        return {
            "name": NAME, "score": None, "issues": 0, "details": [],
            "warning": f"Docker unavailable: {docker_err}"
        }

    # 3. Pull ZAP image
    pull_ok, pull_err = pull_zap_image()
    if not pull_ok:
        return {
            "name": NAME, "score": None, "issues": 0, "details": [],
            "warning": f"Could not pull {ZAP_IMAGE}: {pull_err}"
        }

    # 4. Run scan
    with tempfile.TemporaryDirectory(prefix="ybe-zap-") as tmp:
        report_filename = "zap-report.json"
        report_path     = os.path.join(tmp, report_filename)

        success, error = run_zap_baseline(target_url, report_path)
        if not success:
            return {
                "name": NAME, "score": None, "issues": 0, "details": [],
                "warning": f"ZAP scan failed: {error}"
            }

        # 5. Parse report
        details = parse_zap_report(report_path, target_url)

    score = compute_score(details)

    return {
        "name":    NAME,
        "score":   score,
        "issues":  len(details),
        "details": details,
        "meta": {
            "target":     target_url,
            "zap_image":  ZAP_IMAGE,
            "scan_type":  "baseline",
        }
    }
