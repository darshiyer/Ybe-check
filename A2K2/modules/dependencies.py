"""
Dependencies Detection Module — Ybe Check
Author: Kartikeya
Status: COMPLETE

CONTRACT:
- Input: repo_path (string, absolute path)
- Output: dict matching module contract
- Test: cd A2K2 && python -c "
    import sys,json; sys.path.insert(0,'.')
    from modules.dependencies import scan
    print(json.dumps(scan('../A2K2-test'),indent=2))"

MUST DETECT IN A2K2-test/:
  requirements.txt: Pillow==9.0.0 (vulnerable)
  requirements.txt: pyjwt==1.7.0 (vulnerable)
  requirements.txt: fastapi-utils-pro (hallucinated)
"""

import os
import re
import json
import urllib.request
import concurrent.futures

NAME = "Dependencies"

# ── KNOWN VULNERABLE VERSIONS ────────────────────────────────
# Format: "package": ("min_safe_version", "fix message")
PYTHON_VULNERABLE = {
    "flask": ("2.0.0", "Upgrade to flask>=2.0.0 (fixes CVE-2023-30861)"),
    "django": ("3.2.0", "Upgrade to django>=3.2.0 (multiple CVEs)"),
    "requests": ("2.25.0", "Upgrade to requests>=2.25.0 (CVE-2023-32681)"),
    "pyjwt": ("2.0.0", "Upgrade to pyjwt>=2.0.0 (CVE-2022-29217)"),
    "pillow": ("9.3.0", "Upgrade to pillow>=9.3.0 (CVE-2022-45199)"),
    "numpy": ("1.24.0", "Upgrade to numpy>=1.24.0"),
    "urllib3": ("1.26.5", "Upgrade to urllib3>=1.26.5 (CVE-2021-33503)"),
    "cryptography": ("39.0.0", "Upgrade to cryptography>=39.0.0"),
    "paramiko": ("2.10.0", "Upgrade to paramiko>=2.10.0 (CVE-2022-24302)"),
    "werkzeug": ("2.3.0", "Upgrade to werkzeug>=2.3.0 (CVE-2023-25577)"),
    "sqlalchemy": ("1.4.0", "Upgrade to sqlalchemy>=1.4.0"),
    "starlette": ("0.27.0", "Upgrade to starlette>=0.27.0 (CVE-2023-29159)"),
    "aiohttp": ("3.8.5", "Upgrade to aiohttp>=3.8.5 (CVE-2023-37276)"),
    "fastapi": ("0.99.0", "Upgrade to fastapi>=0.99.0"),
}

NPM_VULNERABLE = {
    "lodash": ("4.17.21", "Upgrade to lodash>=4.17.21 (CVE-2021-23337)"),
    "axios": ("1.0.0", "Upgrade to axios>=1.0.0 (CVE-2023-45857)"),
    "express": ("4.18.0", "Upgrade to express>=4.18.0"),
    "node-fetch": ("3.0.0", "Upgrade to node-fetch>=3.0.0"),
    "jsonwebtoken": ("9.0.0", "Upgrade to jsonwebtoken>=9.0.0 (CVE-2022-23529)"),
}


def parse_version(version_str):
    """Convert '9.0.0' to [9, 0, 0] for comparison."""
    parts = []
    for seg in re.split(r'[^0-9]+', version_str):
        if seg:
            try:
                parts.append(int(seg))
            except ValueError:
                break
    return parts or [0]


def is_vulnerable(installed, min_safe):
    """Return True if installed version is below min_safe."""
    c = parse_version(installed)
    t = parse_version(min_safe)
    for i in range(max(len(c), len(t))):
        cv = c[i] if i < len(c) else 0
        tv = t[i] if i < len(t) else 0
        if cv < tv:
            return True
        if cv > tv:
            return False
    return False


def exists_on_pypi(package_name):
    """Return True if package exists on PyPI. Returns None on network error."""
    try:
        url = f"https://pypi.org/pypi/{package_name}/json"
        req = urllib.request.Request(url, method='HEAD')
        resp = urllib.request.urlopen(req, timeout=5)
        return True
    except urllib.error.HTTPError as e:
        # 404 = package genuinely doesn't exist
        if e.code == 404:
            return False
        # Other HTTP errors (500, 403, etc.) = can't determine
        return None
    except Exception:
        # Network timeout, DNS failure, etc. = can't determine
        return None


def parse_requirements_txt(req_path):
    """Return list of (package_name, version_or_None, line_number)."""
    packages = []
    try:
        with open(req_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Skip pip options and -r includes
                if line.startswith('-') or line.startswith('git+'):
                    continue
                # Strip inline comments
                line = line.split('#')[0].strip()
                # Strip extras like flask[async] -> flask
                line = re.sub(r'\[.*?\]', '', line)
                match = re.match(
                    r'^([A-Za-z0-9_.-]+)\s*(?:[=<>!~]+\s*([0-9][0-9.]*))?',
                    line
                )
                if match:
                    name = match.group(1).lower()
                    version = match.group(2) if match.group(2) else None
                    packages.append((name, version, line_num))
    except Exception:
        pass
    return packages


def parse_package_json(pkg_path):
    """Return list of (package_name, version, line_number)."""
    packages = []
    try:
        with open(pkg_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        for section in ("dependencies", "devDependencies"):
            for name, ver in data.get(section, {}).items():
                clean_ver = re.sub(r'^[\^~>=<! ]+', '', ver)
                packages.append((name.lower(), clean_ver, 1))
    except Exception:
        pass
    return packages


def scan(repo_path: str) -> dict:
    try:
        details = []

        # ── CHECK requirements.txt ────────────────────────────
        req_path = os.path.join(repo_path, 'requirements.txt')
        if os.path.exists(req_path):
            packages = parse_requirements_txt(req_path)

            # Check vulnerable versions
            for name, version, line_num in packages:
                if name in PYTHON_VULNERABLE and version:
                    min_safe, fix_msg = PYTHON_VULNERABLE[name]
                    if is_vulnerable(version, min_safe):
                        details.append({
                            "file": "requirements.txt",
                            "line": line_num,
                            "type": "Vulnerable Dependency",
                            "severity": "high",
                            "reason": f"{name}=={version} is vulnerable. {fix_msg}"
                        })

            # Hallucination check — run in parallel for speed
            def check_pkg(item):
                name, version, line_num = item
                result = exists_on_pypi(name)
                if result is False:
                    # Confirmed not on PyPI
                    return {
                        "file": "requirements.txt",
                        "line": line_num,
                        "type": "Hallucinated Package",
                        "severity": "critical",
                        "reason": f"'{name}' does not exist on PyPI — likely AI-hallucinated dependency"
                    }
                # result is True (exists) or None (network error) — skip
                return None

            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
                    results = list(ex.map(check_pkg, packages))
                for r in results:
                    if r:
                        details.append(r)
            except Exception:
                pass

        # ── CHECK package.json ────────────────────────────────
        pkg_path = os.path.join(repo_path, 'package.json')
        if os.path.exists(pkg_path):
            for name, version, line_num in parse_package_json(pkg_path):
                if name in NPM_VULNERABLE and version:
                    min_safe, fix_msg = NPM_VULNERABLE[name]
                    if is_vulnerable(version, min_safe):
                        details.append({
                            "file": "package.json",
                            "line": line_num,
                            "type": "Vulnerable Dependency",
                            "severity": "high",
                            "reason": f"{name}=={version} is vulnerable. {fix_msg}"
                        })

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
