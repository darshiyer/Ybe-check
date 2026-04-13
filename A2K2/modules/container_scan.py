"""
Ybe Check — Container Scan Module
Uses Trivy (https://trivy.dev) to audit container images and Dockerfiles
found in the repository for OS/library CVEs, secrets, misconfigurations,
and license violations.

Two scan modes (both run automatically):
  1. Dockerfile scan  — trivy config   (static, no image pull needed)
  2. Image scan       — trivy image    (dynamic, pulls image from registry or
                                        reads image name from Dockerfile/compose)

Requires: trivy in PATH
  brew install trivy          (macOS)
  apt install trivy           (Debian/Ubuntu)
  OR  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
"""

import os
import re
import json
import shutil
import subprocess
from typing import Optional

NAME = "Container Scan"

_SCANNER_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv',
             'dist', 'build', '.next', 'out', '.ybe-check'}

# Trivy severity → our severity
SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "UNKNOWN":  "low",
}

# CVE IDs to skip (false positives or irrelevant in dev context)
SKIP_CVE_IDS: set[str] = set()

# Trivy vuln types to include
VULN_TYPES = "os,library"

# Trivy security checks to include
SECURITY_CHECKS = "vuln,secret,config"


# ── FILE DISCOVERY ────────────────────────────────────────────────────────────

def find_dockerfiles(repo_path: str) -> list[str]:
    """Return all Dockerfile and docker-compose files in the repo."""
    found = []
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        _real = os.path.realpath(dirpath)
        if _real == _SCANNER_ROOT or _real.startswith(_SCANNER_ROOT + os.sep):
            dirnames.clear(); continue
        for fname in filenames:
            lower = fname.lower()
            if (lower == "dockerfile"
                    or lower.startswith("dockerfile.")
                    or lower in {"docker-compose.yml", "docker-compose.yaml",
                                  "docker-compose.prod.yml", "docker-compose.production.yml"}):
                found.append(os.path.join(dirpath, fname))
    return found


def extract_image_names(repo_path: str) -> list[str]:
    """
    Extract Docker image names from:
      - Dockerfile FROM directives
      - docker-compose.yml image: fields
      - .github/workflows/*.yml image: or container: fields
    Returns a deduplicated list of image references.
    """
    images = set()

    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        _real = os.path.realpath(dirpath)
        if _real == _SCANNER_ROOT or _real.startswith(_SCANNER_ROOT + os.sep):
            dirnames.clear(); continue
        for fname in filenames:
            lower = fname.lower()
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue

            # Dockerfile FROM directives
            if lower == "dockerfile" or lower.startswith("dockerfile."):
                for m in re.finditer(r'^FROM\s+([^\s]+)', content, re.MULTILINE | re.IGNORECASE):
                    img = m.group(1).strip()
                    if img.lower() not in {"scratch", "buildenv"} and not img.startswith("$"):
                        images.add(img)

            # docker-compose image: fields
            if lower in {"docker-compose.yml", "docker-compose.yaml"}:
                for m in re.finditer(r'^\s+image:\s+["\']?([^\s"\'#]+)["\']?',
                                     content, re.MULTILINE):
                    img = m.group(1).strip()
                    if img and not img.startswith("$"):
                        images.add(img)

            # GitHub Actions container: or image: inside jobs
            if dirpath.endswith((".github/workflows", ".github/workflows")) and fname.endswith(".yml"):
                for m in re.finditer(r'(?:container|image):\s+["\']?([a-zA-Z0-9._/:\-]+)["\']?',
                                     content):
                    img = m.group(1).strip()
                    if "/" in img or ":" in img:
                        images.add(img)

    return sorted(images)


# ── TRIVY HELPERS ─────────────────────────────────────────────────────────────

def check_trivy() -> bool:
    return shutil.which("trivy") is not None


def run_trivy(args: list[str], timeout: int = 120) -> tuple[dict | None, str | None]:
    """
    Run trivy with --format json and return parsed output.
    Returns (parsed_dict, error_string).
    """
    cmd = ["trivy", "--format", "json", "--quiet"] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout.strip()
        if not output:
            return None, f"trivy produced no output. stderr: {result.stderr[:300]}"
        return json.loads(output), None
    except subprocess.TimeoutExpired:
        return None, f"trivy timed out after {timeout}s"
    except json.JSONDecodeError as e:
        return None, f"Could not parse trivy JSON: {e}"
    except FileNotFoundError:
        return None, "trivy not found — install with: brew install trivy"
    except Exception as e:
        return None, str(e)


# ── RESULT PARSING ────────────────────────────────────────────────────────────

def parse_trivy_results(data: dict, source_label: str, repo_path: str) -> list[dict]:
    """
    Parse trivy JSON output into our details[] format.
    Trivy output structure:
      { "Results": [{ "Target": "...", "Vulnerabilities": [...], "Misconfigurations": [...] }] }
    """
    details = []
    seen: set[str] = set()

    results = data.get("Results", [])
    if not results:
        return []

    for result in results:
        target = result.get("Target", source_label)
        # Make target relative if it's an absolute path inside repo
        if os.path.isabs(target) and target.startswith(repo_path):
            target = os.path.relpath(target, repo_path)

        # ── Vulnerabilities (CVEs) ──────────────────────────────────────────
        for vuln in result.get("Vulnerabilities") or []:
            cve_id    = vuln.get("VulnerabilityID", "UNKNOWN")
            if cve_id in SKIP_CVE_IDS:
                continue
            pkg       = vuln.get("PkgName", "unknown")
            installed = vuln.get("InstalledVersion", "?")
            fixed     = vuln.get("FixedVersion", "no fix available")
            title     = vuln.get("Title") or vuln.get("Description", "")[:80]
            severity  = SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN").upper(), "medium")
            score_v   = vuln.get("CVSS", {})
            cvss_str  = ""
            for _, cvss_data in score_v.items():
                v3 = cvss_data.get("V3Score")
                if v3:
                    cvss_str = f" CVSS={v3}"
                    break

            dedup = (cve_id, pkg, target)
            if dedup in seen:
                continue
            seen.add(dedup)

            fix_msg = f"Upgrade {pkg} from {installed} to {fixed}" if fixed != "no fix available" \
                      else f"No fix available yet for {pkg}@{installed}"

            details.append({
                "file":     target,
                "line":     0,
                "type":     f"CVE: {cve_id} in {pkg}",
                "severity": severity,
                "reason":   f"[{cve_id}{cvss_str}] {title} — {fix_msg}",
                "cve_id":   cve_id,
                "package":  pkg,
                "installed_version": installed,
                "fixed_version":     fixed,
            })

        # ── Misconfigurations ───────────────────────────────────────────────
        for misconf in result.get("Misconfigurations") or []:
            check_id  = misconf.get("ID", "UNKNOWN")
            title     = misconf.get("Title", "Security Misconfiguration")
            desc      = misconf.get("Description", "")[:120]
            resolution= misconf.get("Resolution", "")[:120]
            severity  = SEVERITY_MAP.get(misconf.get("Severity", "MEDIUM").upper(), "medium")

            dedup = (check_id, target)
            if dedup in seen:
                continue
            seen.add(dedup)

            reason = f"[{check_id}] {title}"
            if resolution:
                reason += f" — Fix: {resolution}"

            details.append({
                "file":     target,
                "line":     misconf.get("CauseMetadata", {}).get("StartLine", 0),
                "type":     f"Misconfiguration: {title}",
                "severity": severity,
                "reason":   reason,
                "check_id": check_id,
            })

        # ── Secrets ──────────────────────────────────────────────────────────
        for secret in result.get("Secrets") or []:
            rule_id   = secret.get("RuleID", "UNKNOWN")
            title     = secret.get("Title", "Secret Detected")
            severity  = SEVERITY_MAP.get(secret.get("Severity", "HIGH").upper(), "high")
            line_no   = secret.get("StartLine", 0)
            match_str = secret.get("Match", "")[:60]

            dedup = (rule_id, target, line_no)
            if dedup in seen:
                continue
            seen.add(dedup)

            details.append({
                "file":     target,
                "line":     line_no,
                "type":     f"Secret in Container: {title}",
                "severity": severity,
                "reason":   (f"[{rule_id}] Secret baked into container image at line {line_no}. "
                             "Remove from Dockerfile and use build-time secrets (--secret) instead."),
                "match":    match_str,
            })

    # Sort: critical → high → medium → low
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
    1. Scan Dockerfiles (static — no network needed).
    2. Scan extracted image names (dynamic — pulls from registry).
    """
    if not check_trivy():
        return {
            "name": NAME, "score": None, "issues": 0, "details": [],
            "warning": "trivy not found — install with: brew install trivy"
        }

    dockerfiles = find_dockerfiles(repo_path)
    image_names = extract_image_names(repo_path)

    if not dockerfiles and not image_names:
        return {
            "name": NAME, "score": 100, "issues": 0, "details": [],
            "warning": "No Dockerfiles or container images found in this repo."
        }

    all_details: list[dict] = []
    warnings: list[str] = []

    # ── 1. Dockerfile / docker-compose config scan ────────────────────────
    for dockerfile in dockerfiles:
        rel = os.path.relpath(dockerfile, repo_path)
        data, error = run_trivy(
            ["config", "--skip-dirs", ",".join(SKIP_DIRS), dockerfile],
            timeout=60,
        )
        if error:
            warnings.append(f"Dockerfile scan failed for {rel}: {error}")
            continue
        if data:
            details = parse_trivy_results(data, rel, repo_path)
            all_details.extend(details)

    # ── 2. Image vulnerability scan ───────────────────────────────────────
    for image in image_names:
        # Skip obviously local/build-stage images
        if image in {"node", "python", "ubuntu", "debian", "alpine",
                      "scratch", "busybox"} or image.startswith("${"):
            continue

        data, error = run_trivy(
            [
                "image",
                "--vuln-type", VULN_TYPES,
                "--security-checks", SECURITY_CHECKS,
                "--ignore-unfixed",    # only report CVEs with available fixes
                image,
            ],
            timeout=180,
        )
        if error:
            # If the image doesn't exist locally and we can't pull, note it
            if "unable to find" in error.lower() or "not found" in error.lower():
                all_details.append({
                    "file":     "Dockerfile",
                    "line":     0,
                    "type":     "Unverifiable Image",
                    "severity": "medium",
                    "reason":   (f"Image '{image}' could not be pulled for scanning. "
                                 "Pin to a specific digest to prevent supply chain attacks."),
                })
            else:
                warnings.append(f"Image scan failed for {image}: {error}")
            continue

        if data:
            details = parse_trivy_results(data, image, repo_path)
            all_details.extend(details)

    score   = compute_score(all_details)
    warning = " | ".join(warnings) if warnings else None

    result = {
        "name":    NAME,
        "score":   score,
        "issues":  len(all_details),
        "details": all_details,
        "meta": {
            "dockerfiles_scanned": len(dockerfiles),
            "images_scanned":      len(image_names),
        }
    }
    if warning:
        result["warning"] = warning
    return result
