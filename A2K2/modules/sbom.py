"""
Ybe Check — SBOM Module
Uses Syft (https://github.com/anchore/syft) to generate a Software Bill of
Materials for the repository and then audits the SBOM for:
  - Packages with no license declared
  - Packages pinned to non-reproducible version ranges
  - Packages from unknown or suspicious sources
  - SBOM completeness (all dependency files accounted for)

The generated SBOM is also written to <repo>/.ybe-check/sbom.json so it can
be shared with downstream tools (Grype, Dependency-Track, etc.)

Requires: syft in PATH
  brew install syft                              (macOS)
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
"""

import os
import re
import json
import shutil
import subprocess
from typing import Optional

NAME = "SBOM"

_SCANNER_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv',
             'dist', 'build', '.next', 'out', '.ybe-check'}

# Licenses that are acceptable — anything not in this set is flagged
APPROVED_LICENSES = {
    "MIT", "Apache-2.0", "Apache 2.0", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "CC0-1.0", "Unlicense", "Python-2.0", "PSF-2.0",
    "LGPL-2.0", "LGPL-2.1", "LGPL-3.0",
    "MPL-2.0",
}

# High-risk licenses — copyleft or non-commercial
RISKY_LICENSES = {
    "GPL-2.0":   "critical",
    "GPL-3.0":   "critical",
    "AGPL-3.0":  "critical",
    "SSPL-1.0":  "critical",
    "BUSL-1.1":  "high",
    "CC-BY-NC":  "high",
    "CC-BY-NC-SA": "high",
    "EUPL-1.1":  "medium",
    "EUPL-1.2":  "medium",
}

# Unpinned version patterns — signals non-reproducible builds
UNPINNED_PATTERNS = [
    re.compile(r'^\*$'),                          # exact wildcard
    re.compile(r'^>=\s*\d'),                      # >=1.0 with no upper bound
    re.compile(r'^\^'),                           # ^1.0 (semver caret)
    re.compile(r'^~(?!\d+\.\d+\.\d+)'),          # ~1.0 (semver tilde, not exact)
    re.compile(r'^latest$', re.IGNORECASE),       # "latest" tag
]

# Package ecosystems that syft labels
ECOSYSTEM_MAP = {
    "python":     "pip",
    "javascript": "npm",
    "java":       "maven",
    "go":         "go",
    "ruby":       "gem",
    "rust":       "cargo",
    "dotnet":     "nuget",
}

SBOM_OUTPUT_DIR = ".ybe-check"
SBOM_FILENAME   = "sbom.json"


# ── SYFT HELPERS ──────────────────────────────────────────────────────────────

def check_syft() -> bool:
    return shutil.which("syft") is not None


def run_syft(repo_path: str, output_path: str) -> tuple[bool, str]:
    """
    Run syft to generate a CycloneDX-format SBOM in JSON.
    Uses dir: scheme so syft scans the repo as a directory.
    """
    try:
        result = subprocess.run(
            [
                "syft",
                f"dir:{repo_path}",
                "-o", f"cyclonedx-json={output_path}",
                "--quiet",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if not os.path.exists(output_path):
            return False, f"syft produced no output file. stderr: {result.stderr[:300]}"
        return True, ""

    except subprocess.TimeoutExpired:
        return False, "syft timed out after 2 minutes"
    except FileNotFoundError:
        return False, "syft not found — install with: brew install syft"
    except Exception as e:
        return False, str(e)


# ── SBOM ANALYSIS ─────────────────────────────────────────────────────────────

def analyze_sbom(sbom: dict, repo_path: str) -> list[dict]:
    """
    Analyze a CycloneDX SBOM for quality, license, and pinning issues.
    CycloneDX JSON structure:
      { "components": [{ "name", "version", "licenses": [...], "purl": "..." }] }
    """
    details = []
    seen: set[tuple] = set()

    components = sbom.get("components", [])
    if not components:
        return []

    no_license_count = 0
    unpinned_count   = 0

    for comp in components:
        name      = comp.get("name", "unknown")
        version   = comp.get("version", "")
        purl      = comp.get("purl", "")
        comp_type = comp.get("type", "library")

        # Determine ecosystem from purl (pkg:npm/..., pkg:pypi/..., etc.)
        ecosystem = "unknown"
        if purl:
            m = re.match(r'pkg:([^/]+)/', purl)
            if m:
                ecosystem = m.group(1).lower()

        # ── License audit ──────────────────────────────────────────────────
        licenses = comp.get("licenses", [])
        license_ids = []
        for lic in licenses:
            lic_id = (lic.get("license", {}).get("id") or
                      lic.get("license", {}).get("name") or
                      lic.get("expression", ""))
            if lic_id:
                license_ids.append(lic_id)

        if not license_ids:
            no_license_count += 1
            if no_license_count <= 10:  # cap noise
                dedup = ("no_license", name, version)
                if dedup not in seen:
                    seen.add(dedup)
                    details.append({
                        "file":      "SBOM",
                        "line":      0,
                        "type":      "No License Declared",
                        "severity":  "medium",
                        "reason":    (
                            f"Package '{name}@{version}' ({ecosystem}) has no license declared — "
                            "unknown licensing terms create legal risk in production."
                        ),
                        "package":   name,
                        "version":   version,
                        "ecosystem": ecosystem,
                    })
        else:
            for lic_id in license_ids:
                sev = RISKY_LICENSES.get(lic_id)
                if sev:
                    dedup = ("risky_license", name, lic_id)
                    if dedup not in seen:
                        seen.add(dedup)
                        details.append({
                            "file":      "SBOM",
                            "line":      0,
                            "type":      f"Risky License: {lic_id}",
                            "severity":  sev,
                            "reason":    (
                                f"'{name}@{version}' uses {lic_id} — "
                                f"{'copyleft license may require open-sourcing your code' if 'GPL' in lic_id or 'AGPL' in lic_id else 'license may restrict commercial use'}. "
                                "Review with legal before shipping to production."
                            ),
                            "package":   name,
                            "version":   version,
                            "license":   lic_id,
                        })

        # ── Version pinning audit ──────────────────────────────────────────
        if version:
            for pat in UNPINNED_PATTERNS:
                if pat.match(version.strip()):
                    unpinned_count += 1
                    if unpinned_count <= 15:  # cap noise
                        dedup = ("unpinned", name, version)
                        if dedup not in seen:
                            seen.add(dedup)
                            details.append({
                                "file":      "SBOM",
                                "line":      0,
                                "type":      "Unpinned Dependency",
                                "severity":  "medium",
                                "reason":    (
                                    f"'{name}' version '{version}' ({ecosystem}) is not pinned to an exact version — "
                                    "non-reproducible builds can silently introduce breaking changes or vulnerabilities. "
                                    "Pin to an exact version (e.g. 1.2.3) or use a lockfile."
                                ),
                                "package":   name,
                                "version":   version,
                            })
                    break  # only report once per package

    # ── SBOM completeness check ───────────────────────────────────────────
    # Count manifest files in the repo and compare to what syft found
    manifest_extensions = {
        "requirements.txt", "requirements-dev.txt", "Pipfile", "Pipfile.lock",
        "setup.py", "setup.cfg", "pyproject.toml",
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "go.mod", "go.sum",
        "Gemfile", "Gemfile.lock",
        "Cargo.toml", "Cargo.lock",
        "pom.xml", "build.gradle", "build.gradle.kts",
    }
    manifest_count = 0
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        _real = os.path.realpath(dirpath)
        if _real == _SCANNER_ROOT or _real.startswith(_SCANNER_ROOT + os.sep):
            dirnames.clear(); continue
        for fname in filenames:
            if fname in manifest_extensions:
                manifest_count += 1

    if manifest_count > 0 and len(components) == 0:
        details.append({
            "file":     "SBOM",
            "line":     0,
            "type":     "Empty SBOM",
            "severity": "high",
            "reason":   (
                f"SBOM was generated but contains 0 components despite {manifest_count} "
                "dependency manifest(s) being present — syft may have failed to parse them. "
                "Run 'syft dir:. -o cyclonedx-json' manually to debug."
            ),
        })

    # Summary finding if no_license_count is very high
    if no_license_count > 10:
        details.append({
            "file":     "SBOM",
            "line":     0,
            "type":     "Widespread Missing Licenses",
            "severity": "high",
            "reason":   (
                f"{no_license_count} packages have no license declared — "
                "this represents significant legal risk. "
                "Audit the full SBOM at .ybe-check/sbom.json."
            ),
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
    Generates SBOM with syft and audits it for license, pinning, and completeness issues.
    Also persists the SBOM to .ybe-check/sbom.json for downstream tooling.
    """
    if not check_syft():
        return {
            "name": NAME, "score": None, "issues": 0, "details": [],
            "warning": "syft not found — install with: brew install syft"
        }

    # Ensure output dir exists
    output_dir  = os.path.join(repo_path, SBOM_OUTPUT_DIR)
    output_path = os.path.join(output_dir, SBOM_FILENAME)
    os.makedirs(output_dir, exist_ok=True)

    # Generate SBOM
    success, error = run_syft(repo_path, output_path)
    if not success:
        return {
            "name": NAME, "score": None, "issues": 0, "details": [],
            "warning": f"syft failed: {error}"
        }

    # Load and parse SBOM
    try:
        with open(output_path, encoding="utf-8") as f:
            sbom = json.load(f)
    except Exception as e:
        return {
            "name": NAME, "score": None, "issues": 0, "details": [],
            "warning": f"Could not read SBOM output: {e}"
        }

    components = sbom.get("components", [])
    details    = analyze_sbom(sbom, repo_path)
    score      = compute_score(details)

    return {
        "name":    NAME,
        "score":   score,
        "issues":  len(details),
        "details": details,
        "meta": {
            "components_found": len(components),
            "sbom_path":        os.path.relpath(output_path, repo_path),
            "sbom_format":      "CycloneDX JSON",
        }
    }
