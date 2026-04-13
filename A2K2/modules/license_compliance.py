import importlib.metadata
import os
import json
import re
import subprocess
import sys

NAME = "License Compliance"

_SCANNER_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------------
# Known npm package licenses — avoids running pip-licenses against npm deps.
# All entries are well-known permissive packages (severity "low" or "medium").
# ---------------------------------------------------------------------------
KNOWN_NPM_LICENSES = {
    "express":          ("MIT",          "low"),
    "react":            ("MIT",          "low"),
    "react-dom":        ("MIT",          "low"),
    "axios":            ("MIT",          "low"),
    "lodash":           ("MIT",          "low"),
    "cors":             ("MIT",          "low"),
    "body-parser":      ("MIT",          "low"),
    "dotenv":           ("BSD-2-Clause", "low"),
    "mongoose":         ("MIT",          "low"),
    "socket.io":        ("MIT",          "low"),
    "next":             ("MIT",          "low"),
    "typescript":       ("Apache-2.0",   "low"),
    "webpack":          ("MIT",          "low"),
    "babel-core":       ("MIT",          "low"),
    "jest":             ("MIT",          "low"),
    "eslint":           ("MIT",          "low"),
    "tailwindcss":      ("MIT",          "low"),
    "prisma":           ("Apache-2.0",   "low"),
    "sequelize":        ("MIT",          "low"),
    "knex":             ("MIT",          "low"),
    "moment":           ("MIT",          "low"),
    "dayjs":            ("MIT",          "low"),
    "uuid":             ("MIT",          "low"),
    "bcrypt":           ("MIT",          "low"),
    "jsonwebtoken":     ("MIT",          "low"),
    "multer":           ("MIT",          "low"),
    "sharp":            ("Apache-2.0",   "low"),
    "redis":            ("MIT",          "low"),
    "pg":               ("MIT",          "low"),
    "mysql2":           ("MIT",          "low"),
    "nodemailer":       ("MIT",          "low"),
    "winston":          ("MIT",          "low"),
    "morgan":           ("MIT",          "low"),
    "helmet":           ("MIT",          "low"),
    "passport":         ("MIT",          "low"),
    "stripe":           ("MIT",          "low"),
    "aws-sdk":          ("Apache-2.0",   "low"),
    "cheerio":          ("MIT",          "low"),
    "puppeteer":        ("Apache-2.0",   "low"),
    "playwright":       ("Apache-2.0",   "low"),
    "@types/node":      ("MIT",          "low"),
    "@types/react":     ("MIT",          "low"),
    "vite":             ("MIT",          "low"),
    "rollup":           ("MIT",          "low"),
    "esbuild":          ("MIT",          "low"),
    "prettier":         ("MIT",          "low"),
    "husky":            ("MIT",          "low"),
    "lint-staged":      ("MIT",          "low"),
    "concurrently":     ("MIT",          "low"),
    "nodemon":          ("MIT",          "low"),
    "express-validator":("MIT",          "low"),
    "joi":              ("BSD-3-Clause", "low"),
    "yup":              ("MIT",          "low"),
    "zod":              ("MIT",          "low"),
    "date-fns":         ("MIT",          "low"),
    "ramda":            ("MIT",          "low"),
    "rxjs":             ("Apache-2.0",   "low"),
    "graphql":          ("MIT",          "low"),
    "apollo-server":    ("MIT",          "low"),
    "typeorm":          ("MIT",          "low"),
    "mikro-orm":        ("MIT",          "low"),
}

# ---------------------------------------------------------------------------
# License risk classification
# Based on FOSSA and TLDR Legal risk taxonomy
# ---------------------------------------------------------------------------
LICENSE_RISK = {
    # CRITICAL — viral licenses, force open sourcing entire codebase
    "AGPL-3.0":             ("critical", "AGPL requires releasing ALL source code of any product/service using this library, even over a network. Google bans AGPL internally."),
    "AGPL-3.0-only":        ("critical", "AGPL requires releasing ALL source code of any product/service using this library, even over a network."),
    "AGPL-3.0-or-later":    ("critical", "AGPL requires releasing ALL source code of any product/service using this library, even over a network."),
    "SSPL-1.0":             ("critical", "SSPL (MongoDB) is more aggressive than AGPL — requires open sourcing your entire service stack."),
    "BUSL-1.1":             ("critical", "Business Source License restricts production use. Not open source."),
    "Commons Clause":       ("critical", "Commons Clause restricts commercial use and selling of the software."),

    # HIGH — copyleft, force open sourcing on distribution
    "GPL-2.0":              ("high", "GPL-2.0 requires distributing source code of the entire work. Incompatible with proprietary software."),
    "GPL-2.0-only":         ("high", "GPL-2.0 requires distributing source code of the entire work."),
    "GPL-2.0-or-later":     ("high", "GPL-2.0+ requires distributing source code of the entire work."),
    "GPL-3.0":              ("high", "GPL-3.0 requires distributing source code. Adds patent termination clauses."),
    "GPL-3.0-only":         ("high", "GPL-3.0 requires distributing source code. Adds patent termination clauses."),
    "GPL-3.0-or-later":     ("high", "GPL-3.0+ requires distributing source code. Adds patent termination clauses."),
    "EUPL-1.1":             ("high", "European Union Public Licence — strong copyleft, incompatible with some other licenses."),
    "EUPL-1.2":             ("high", "European Union Public Licence — strong copyleft."),
    "OSL-3.0":              ("high", "Open Software License 3.0 — strong copyleft with network use provisions."),

    # MEDIUM — weak copyleft, manageable
    "LGPL-2.0":             ("medium", "LGPL allows proprietary use but has linking restrictions. Use dynamic linking to stay compliant."),
    "LGPL-2.0-only":        ("medium", "LGPL allows proprietary use but has linking restrictions."),
    "LGPL-2.1":             ("medium", "LGPL-2.1 allows proprietary use but requires dynamic linking or providing object files."),
    "LGPL-2.1-only":        ("medium", "LGPL-2.1 allows proprietary use but requires dynamic linking or providing object files."),
    "LGPL-2.1-or-later":    ("medium", "LGPL allows proprietary use but has linking restrictions."),
    "LGPL-3.0":             ("medium", "LGPL-3.0 allows proprietary use with dynamic linking restrictions."),
    "LGPL-3.0-only":        ("medium", "LGPL-3.0 allows proprietary use with dynamic linking restrictions."),
    "LGPL-3.0-or-later":    ("medium", "LGPL-3.0 allows proprietary use with dynamic linking restrictions."),
    "MPL-2.0":              ("medium", "Mozilla Public License — file-level copyleft. Modified MPL files must be open sourced."),
    "MPL-1.1":              ("medium", "Mozilla Public License 1.1 — file-level copyleft."),
    "EPL-1.0":              ("medium", "Eclipse Public License — weak copyleft with patent retaliation clause."),
    "EPL-2.0":              ("medium", "Eclipse Public License 2.0 — weak copyleft, compatible with GPL-2.0."),
    "CDDL-1.0":             ("medium", "Common Development and Distribution License — weak copyleft, incompatible with GPL."),
    "EUPL-2.0":             ("medium", "EUPL 2.0 — weak copyleft variant."),

    # LOW / SAFE — permissive
    "MIT":                  ("low",  "Permissive. Commercial use allowed. Requires attribution."),
    "Apache-2.0":           ("low",  "Permissive. Commercial use allowed. Includes patent grant."),
    "BSD-2-Clause":         ("low",  "Permissive. Commercial use allowed. Minimal restrictions."),
    "BSD-3-Clause":         ("low",  "Permissive. Commercial use allowed. Cannot use project name for endorsement."),
    "BSD-4-Clause":         ("low",  "Permissive with advertising clause — slightly more restrictive than BSD-3."),
    "ISC":                  ("low",  "Permissive. Functionally equivalent to MIT."),
    "Unlicense":            ("low",  "Public domain. No restrictions whatsoever."),
    "CC0-1.0":              ("low",  "Public domain dedication. No restrictions."),
    "WTFPL":                ("low",  "Do What The F*ck You Want. No restrictions."),
    "Zlib":                 ("low",  "Permissive. Requires attribution in documentation."),
    "PSF-2.0":              ("low",  "Python Software Foundation License. Permissive."),
    "Python-2.0":           ("low",  "Python 2.0 License. Permissive."),
    "MIT-0":                ("low",  "MIT without attribution requirement. Public domain equivalent."),
    "0BSD":                 ("low",  "Zero-clause BSD. Effectively public domain."),
    "Artistic-2.0":         ("low",  "Permissive. Allows modification with restrictions on distribution of modified versions."),
}

# Normalize common license string variants to our keys
LICENSE_ALIASES = {
    "mit":                      "MIT",
    "apache 2.0":               "Apache-2.0",
    "apache-2.0":               "Apache-2.0",
    "apache2":                  "Apache-2.0",
    "apache software license":  "Apache-2.0",
    "bsd":                      "BSD-3-Clause",
    "bsd license":              "BSD-3-Clause",
    "bsd 2-clause":             "BSD-2-Clause",
    "bsd 3-clause":             "BSD-3-Clause",
    "new bsd license":          "BSD-3-Clause",
    "simplified bsd":           "BSD-2-Clause",
    "isc license":              "ISC",
    "isc license (iscl)":       "ISC",
    "python software foundation license": "PSF-2.0",
    "psf":                      "PSF-2.0",
    "gnu gpl v2":               "GPL-2.0",
    "gnu gpl v3":               "GPL-3.0",
    "gnu lgpl v2":              "LGPL-2.0",
    "gnu lgpl v3":              "LGPL-3.0",
    "gnu general public license v2 (gplv2)": "GPL-2.0",
    "gnu general public license v3 (gplv3)": "GPL-3.0",
    "gnu lesser general public license v2 (lgplv2)": "LGPL-2.0",
    "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "eclipse public license 1.0": "EPL-1.0",
    "eclipse public license 2.0": "EPL-2.0",
    "agpl-3.0":                 "AGPL-3.0",
    "gnu affero general public license v3 (agplv3)": "AGPL-3.0",
    "sspl":                     "SSPL-1.0",
    "the unlicense (unlicense)": "Unlicense",
    "unlicense":                "Unlicense",
    "cc0":                      "CC0-1.0",
    "public domain":            "Unlicense",
    "zlib/libpng":              "Zlib",
    "historical permission notice and disclaimer (hpnd)": "BSD-3-Clause",
}

UNKNOWN_LICENSE_STRINGS = {
    "unknown", "n/a", "", "none", "not found",
    "license not found", "other/proprietary"
}

# Fallback license lookup for well-known packages that may not be installed locally.
KNOWN_LICENSE_MAP = {
    "elasticsearch":     "SSPL-1.0",
    "elasticsearch-dsl": "SSPL-1.0",
    "mongodb":           "SSPL-1.0",
}


# ---------------------------------------------------------------------------
# License normalization
# ---------------------------------------------------------------------------

def normalize_license(raw_license: str) -> str:
    """Normalize a raw license string to our canonical key."""
    if not raw_license:
        return "UNKNOWN"
    cleaned = raw_license.strip()
    lower = cleaned.lower()
    if lower in UNKNOWN_LICENSE_STRINGS:
        return "UNKNOWN"
    if lower in LICENSE_ALIASES:
        return LICENSE_ALIASES[lower]
    if cleaned in LICENSE_RISK:
        return cleaned
    for key in LICENSE_RISK:
        if key.lower() == lower:
            return key
    return cleaned


# ---------------------------------------------------------------------------
# pip-licenses runner
# ---------------------------------------------------------------------------

def run_pip_licenses(repo_path):
    """
    Return installed packages with their licenses using importlib.metadata.
    Zero external dependencies — works on any Python 3.8+.
    Returns list of {Name, Version, License} dicts matching the pip-licenses schema.
    """
    try:
        result = subprocess.run(
            [
                sys.executable, "-m", "piplicenses",
                "--format=json",
                "--with-system",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=repo_path
        )

        if not result.stdout or result.stdout.strip() == "":
            return None, f"pip-licenses produced no output. stderr: {result.stderr[:300]}"

        packages = json.loads(result.stdout)
        return packages, None

    except subprocess.TimeoutExpired:
        return None, "pip-licenses timed out"
    except json.JSONDecodeError as e:
        return None, f"Could not parse pip-licenses output: {str(e)}"
    except FileNotFoundError:
        return None, "pip-licenses not found — run: pip install pip-licenses"
    except Exception as e:
        return None, str(e)


# ---------------------------------------------------------------------------
# Dependency file discovery
# ---------------------------------------------------------------------------

def find_dependency_files(repo_path):
    """Find all dependency declaration files in the repo."""
    dep_files = []
    targets = {
        'requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt',
        'package.json', 'Pipfile', 'pyproject.toml', 'setup.py',
        'setup.cfg', 'go.mod', 'Gemfile', 'pom.xml', 'build.gradle'
    }
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in {
            '.git', 'node_modules', '__pycache__', '.venv', 'venv',
            'site-packages', '.antigravity', '.cursor', '.claude',
            '.ybe-check', 'graphify-out', '.terraform',
        }]
        _real = os.path.realpath(root)
        if _real == _SCANNER_ROOT or _real.startswith(_SCANNER_ROOT + os.sep):
            dirs.clear(); continue
        for fname in files:
            if fname in targets:
                dep_files.append(os.path.join(root, fname))
    return dep_files


def _ecosystem_for_file(fname: str) -> str:
    """Return the package ecosystem for a given dependency filename."""
    if fname == 'package.json':
        return 'npm'
    if fname in ('requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py', 'setup.cfg') \
            or fname.startswith('requirements'):
        return 'pip'
    return 'unknown'


# ---------------------------------------------------------------------------
# Parsers — all return list of (package_name_lower, line_number) tuples
# ---------------------------------------------------------------------------

def parse_requirements_txt_with_lines(fpath):
    """Extract package names with their line numbers from requirements.txt."""
    packages = []
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            for lineno, line in enumerate(f, start=1):
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                match = re.match(r'^([A-Za-z0-9_\-\.]+)', line)
                if match:
                    packages.append((match.group(1).lower(), lineno))
    except Exception:
        pass
    return packages


def parse_package_json(fpath):
    """
    Extract npm package names from package.json with their actual line numbers.
    Reads line-by-line to map each package name to its source line.
    Returns list of (package_name_lower, line_number) tuples.
    """
    packages = []
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        in_dep_section = False
        dep_section_keys = {'"dependencies"', '"devDependencies"', '"peerDependencies"'}

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Detect entering a dependency section
            for key in dep_section_keys:
                if stripped.startswith(key):
                    in_dep_section = True

            # Detect end of section (closing brace at indentation level 2)
            if in_dep_section and stripped == '}':
                in_dep_section = False

            # Parse individual package lines: "package-name": "version"
            if in_dep_section:
                m = re.match(r'^\s*"([^"@][^"]*?)"\s*:', stripped)
                if m:
                    pkg_name = m.group(1)
                    # Skip section keys themselves
                    if pkg_name not in ('dependencies', 'devDependencies', 'peerDependencies'):
                        packages.append((pkg_name.lower(), lineno))
    except Exception:
        pass
    return packages


# ---------------------------------------------------------------------------
# Package collection — keeps pip and npm packages separate
# ---------------------------------------------------------------------------

def get_declared_packages(repo_path):
    """
    Scan all dependency files and return two sets:
      pip_packages: {pkg_lower: (rel_path, line_number)}
      npm_packages: {pkg_lower: (rel_path, line_number)}
    Also returns dep_files list.
    """
    pip_packages = {}
    npm_packages = {}
    dep_files = find_dependency_files(repo_path)

    for fpath in dep_files:
        fname = os.path.basename(fpath)
        rel_path = os.path.relpath(fpath, repo_path)

        if fname == 'package.json':
            pkgs = parse_package_json(fpath)
            for pkg, lineno in pkgs:
                if pkg not in npm_packages:
                    npm_packages[pkg] = (rel_path, lineno)

        elif fname in ('requirements.txt', 'Pipfile') or fname.startswith('requirements'):
            pkgs = parse_requirements_txt_with_lines(fpath)
            for pkg, lineno in pkgs:
                if pkg not in pip_packages:
                    pip_packages[pkg] = (rel_path, lineno)

    return pip_packages, npm_packages, dep_files


# ---------------------------------------------------------------------------
# Remediation advice
# ---------------------------------------------------------------------------

def get_remediation(package_name, license_id):
    """Return actionable remediation advice per license type."""
    remediations = {
        "AGPL-3.0":     f"Replace '{package_name}' with a permissively licensed alternative, or release your entire codebase under AGPL.",
        "AGPL-3.0-only": f"Replace '{package_name}' — AGPL is incompatible with proprietary SaaS. Find MIT/Apache alternative.",
        "SSPL-1.0":     f"Replace '{package_name}' immediately. SSPL requires open sourcing your entire service infrastructure.",
        "BUSL-1.1":     f"'{package_name}' restricts production use under BUSL. Check the Change Date — it may convert to open source in future.",
        "GPL-2.0":      f"Replace '{package_name}' with LGPL or permissively licensed alternative, or open source your product under GPL.",
        "GPL-2.0-only": f"Replace '{package_name}' with LGPL or permissively licensed alternative.",
        "GPL-3.0":      f"Replace '{package_name}' with LGPL/MIT/Apache alternative, or GPL your entire codebase.",
        "GPL-3.0-only": f"Replace '{package_name}' with LGPL/MIT/Apache alternative.",
        "LGPL-2.1":     f"'{package_name}' is LGPL — ensure you're using dynamic linking. Do not statically embed this library.",
        "LGPL-3.0":     f"'{package_name}' is LGPL-3.0 — use dynamic linking only. Provide object files if distributing.",
        "MPL-2.0":      f"'{package_name}' is MPL — any modifications to MPL files must be open sourced. Keep unmodified and document usage.",
    }
    return remediations.get(
        license_id,
        f"Review license terms for '{package_name}' ({license_id}) with your legal team before shipping to production."
    )


# ---------------------------------------------------------------------------
# npm package checker — try license-checker when Node available, else fallback to lookup
# ---------------------------------------------------------------------------

def run_license_checker(package_json_dir: str) -> dict | None:
    """
    Run `npx license-checker --json` in the given directory (must contain package.json).
    Returns { package_name_lower: license_string } or None on failure.
    """
    try:
        result = subprocess.run(
            ["npx", "--yes", "license-checker", "--json", "--direct", "0"],
            capture_output=True,
            text=True,
            timeout=90,
            cwd=package_json_dir,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        data = json.loads(result.stdout)
        out = {}
        for key, val in data.items():
            # key is like "package@1.2.3" or "package@file:..."
            if "@" in key:
                pkg = key.split("@")[0].strip()
                lic = (val or {}).get("licenses") or (val or {}).get("license") or "UNKNOWN"
                if isinstance(lic, list):
                    lic = "; ".join(str(x) for x in lic)
                out[pkg.lower()] = str(lic).strip() if lic else "UNKNOWN"
        return out
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return None


def check_npm_packages(npm_packages: dict, details: list, seen: set, repo_path: str):
    """
    Check npm packages: try license-checker when possible, else use KNOWN_NPM_LICENSES.
    Only flag as Unverified when we truly can't determine the license.
    """
    # Try to get real licenses from the project (run from first package.json dir)
    npm_lookup: dict | None = None
    for pkg_raw, (source_file, _) in npm_packages.items():
        # Resolve directory containing this package.json
        if not repo_path:
            break
        dir_for_pkg = os.path.dirname(os.path.join(repo_path, source_file))
        if os.path.isdir(dir_for_pkg) and os.path.exists(os.path.join(dir_for_pkg, "package.json")):
            npm_lookup = run_license_checker(dir_for_pkg)
            break
    if not npm_lookup and npm_packages and repo_path:
        # Fallback: run from repo root if it has package.json
        if os.path.exists(os.path.join(repo_path, "package.json")):
            npm_lookup = run_license_checker(repo_path)

    for pkg_raw, (source_file, pkg_line) in npm_packages.items():
        pkg_lower = pkg_raw.lower()

        # If we got license-checker output, use it
        if npm_lookup and pkg_lower in npm_lookup:
            raw_license = npm_lookup[pkg_lower]
            normalized = normalize_license(raw_license)
            if normalized in LICENSE_RISK:
                severity, reason = LICENSE_RISK[normalized]
                if severity != "low":
                    dedup_key = (pkg_raw, source_file, normalized)
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        details.append({
                            "file":       source_file,
                            "line":       pkg_line,
                            "type":       f"License Risk: {normalized}",
                            "severity":   severity,
                            "confidence": "high",
                            "ecosystem":  "npm",
                            "package":    pkg_raw,
                            "license":    normalized,
                            "reason":     f"'{pkg_raw}' uses {normalized} — {reason}",
                            "remediation": get_remediation(pkg_raw, normalized),
                        })
            # low or unknown but resolved — skip unverified
            continue

        # No license-checker or package not in output — use known table or flag unverified
        if pkg_raw in KNOWN_NPM_LICENSES:
            license_id, risk_level = KNOWN_NPM_LICENSES[pkg_raw]

            # Unknown entry (deliberately marked None) — flag as unverified
            if license_id is None:
                dedup_key = (pkg_raw, source_file, "Unverified NPM")
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    details.append({
                        "file":       source_file,
                        "line":       pkg_line,
                        "type":       "Unverified NPM License",
                        "severity":   "low",
                        "confidence": "low",
                        "ecosystem":  "npm",
                        "package":    pkg_raw,
                        "license":    "UNKNOWN",
                        "reason":     (
                            f"'{pkg_raw}' is an npm package — license could not be verified "
                            "without Node environment. Manual review recommended."
                        ),
                        "remediation": f"Run `npx license-checker --summary` in the project directory to verify.",
                    })
            # Known safe (low risk) — skip silently, no finding
            # If it were medium/high/critical we'd flag it here

        else:
            # Unknown npm package — flag as unverified (NOT "Unresolvable Dependency")
            dedup_key = (pkg_raw, source_file, "Unverified NPM")
            if dedup_key not in seen:
                seen.add(dedup_key)
                details.append({
                    "file":       source_file,
                    "line":       pkg_line,
                    "type":       "Unverified NPM License",
                    "severity":   "low",
                    "confidence": "low",
                    "ecosystem":  "npm",
                    "package":    pkg_raw,
                    "license":    "UNKNOWN",
                    "reason":     (
                        f"'{pkg_raw}' is an npm package — license could not be verified "
                        "without Node environment. Manual review recommended."
                    ),
                        "remediation": f"Run `npx license-checker --summary` in the project directory to verify.",
                    })


# ---------------------------------------------------------------------------
# pip package checker (uses pip-licenses)
# ---------------------------------------------------------------------------

def check_pip_packages(pip_packages: dict, installed_lookup: dict,
                       details: list, seen: set):
    """
    Check pip packages against pip-licenses results.
    """
    for pkg_raw, (source_file, pkg_line) in pip_packages.items():
        pkg_normalized = pkg_raw.lower().replace("-", "_").replace(".", "_")

        # Find in installed packages
        installed = installed_lookup.get(pkg_normalized) or installed_lookup.get(pkg_raw.lower())

        if not installed:
            # Check KNOWN_LICENSE_MAP — catches risky packages even when not installed
            known_license = KNOWN_LICENSE_MAP.get(pkg_raw.lower())
            if known_license and known_license in LICENSE_RISK:
                severity, reason = LICENSE_RISK[known_license]
                if severity != "low":
                    dedup_key = (pkg_raw, source_file, known_license)
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        details.append({
                            "file":        source_file,
                            "line":        pkg_line,
                            "type":        f"License Risk: {known_license}",
                            "severity":    severity,
                            "confidence":  "high",
                            "ecosystem":   "pip",
                            "package":     pkg_raw,
                            "license":     known_license,
                            "reason":      f"'{pkg_raw}' uses {known_license} — {reason}",
                            "remediation": get_remediation(pkg_raw, known_license),
                        })
                continue  # License is known — don't flag as unresolvable

            # Package declared but not installed → possibly hallucinated
            dedup_key = (pkg_raw, source_file, "Not Installed")
            if dedup_key not in seen:
                seen.add(dedup_key)
                details.append({
                    "file":        source_file,
                    "line":        pkg_line,
                    "type":        "Unresolvable Dependency",
                    "severity":    "high",
                    "confidence":  "medium",
                    "ecosystem":   "pip",
                    "package":     pkg_raw,
                    "license":     "UNKNOWN",
                    "reason":      (
                        f"'{pkg_raw}' is declared but not installed — may be a hallucinated "
                        "or non-existent package (common in vibe-coded apps)"
                    ),
                    "remediation": (
                        f"Verify '{pkg_raw}' exists on PyPI: https://pypi.org/project/{pkg_raw}/ "
                        "— if not found, remove it."
                    ),
                })
            continue

        raw_license  = installed["license"]
        version      = installed["version"]
        display_name = installed["name"]
        normalized   = normalize_license(raw_license)

        # UNKNOWN license — legal blocker
        if normalized == "UNKNOWN" or normalized.lower() in UNKNOWN_LICENSE_STRINGS:
            dedup_key = (pkg_raw, source_file, "Unknown License")
            if dedup_key not in seen:
                seen.add(dedup_key)
                details.append({
                    "file":        source_file,
                    "line":        pkg_line,
                    "type":        "Unknown License",
                    "severity":    "high",
                    "confidence":  "high",
                    "ecosystem":   "pip",
                    "package":     display_name,
                    "license":     raw_license,
                    "reason":      (
                        f"'{display_name}=={version}' has no detectable license — "
                        "legally this means no permissions are granted. Cannot be used in production."
                    ),
                    "remediation": (
                        f"Check '{display_name}' on PyPI or GitHub for license information "
                        "before using in production."
                    ),
                })
            continue

        # Check against risk table — skip low severity
        if normalized in LICENSE_RISK:
            severity, reason = LICENSE_RISK[normalized]
            if severity == "low":
                continue

            dedup_key = (pkg_raw, source_file, normalized)
            if dedup_key not in seen:
                seen.add(dedup_key)
                details.append({
                    "file":        source_file,
                    "line":        pkg_line,
                    "type":        f"License Risk: {normalized}",
                    "severity":    severity,
                    "confidence":  "high",
                    "ecosystem":   "pip",
                    "package":     display_name,
                    "license":     normalized,
                    "reason":      f"'{display_name}=={version}' uses {normalized} — {reason}",
                    "remediation": get_remediation(display_name, normalized),
                    "snippet":     f"{display_name}=={version} ({normalized})",
                })


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan(repo_path: str) -> dict:
    try:
        details = []
        seen    = set()

        # Collect declared packages — pip and npm kept separate
        pip_packages, npm_packages, dep_files = get_declared_packages(repo_path)

        if not dep_files:
            return {
                "name":    NAME,
                "score":   100,
                "issues":  0,
                "details": [],
                "warning": "No dependency files found (requirements.txt, package.json, etc.)",
            }

        # --- Check npm packages via local lookup (no pip-licenses) ---
        check_npm_packages(npm_packages, details, seen, repo_path)

        # --- Check pip packages via pip-licenses ---
        if pip_packages:
            installed_packages, error = run_pip_licenses(repo_path)

            if error or not installed_packages:
                # Can't run pip-licenses — note it as a warning but continue
                # (npm results are still valid and already processed above)
                pass
            else:
                # Build lookup: package_name_lower → {version, license, name}
                installed_lookup = {}
                for pkg in installed_packages:
                    name  = pkg.get("Name", "").lower().replace("-", "_").replace(".", "_")
                    name2 = pkg.get("Name", "").lower()
                    entry = {
                        "version": pkg.get("Version", "unknown"),
                        "license": pkg.get("License", "UNKNOWN"),
                        "name":    pkg.get("Name", ""),
                    }
                    installed_lookup[name]  = entry
                    installed_lookup[name2] = entry

                check_pip_packages(pip_packages, installed_lookup, details, seen)

        # Scoring formula
        critical = len([d for d in details if d["severity"] == "critical"])
        high     = len([d for d in details if d["severity"] == "high"])
        medium   = len([d for d in details if d["severity"] == "medium"])
        score    = max(0, 100 - (critical * 15) - (high * 10) - (medium * 5))

        return {
            "name":    NAME,
            "score":   score,
            "issues":  len(details),
            "details": details,
        }

    except Exception as e:
        return {
            "name":    NAME,
            "score":   None,
            "issues":  0,
            "details": [],
            "warning": f"Could not run: {str(e)}",
        }
