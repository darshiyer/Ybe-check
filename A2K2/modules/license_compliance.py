import os
import json
import subprocess
import sys

NAME = "License Compliance"

# License risk classification
# Based on FOSSA and TLDR Legal risk taxonomy
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
# Prevents SSPL/AGPL from hiding behind "Unresolvable Dependency" just because
# the package isn't installed in the current environment.
KNOWN_LICENSE_MAP = {
    "elasticsearch":     "SSPL-1.0",
    "elasticsearch-dsl": "SSPL-1.0",
    "mongodb":           "SSPL-1.0",
}


def normalize_license(raw_license: str) -> str:
    """Normalize a raw license string to our canonical key."""
    if not raw_license:
        return "UNKNOWN"
    cleaned = raw_license.strip()
    lower = cleaned.lower()
    if lower in UNKNOWN_LICENSE_STRINGS:
        return "UNKNOWN"
    # Direct alias lookup
    if lower in LICENSE_ALIASES:
        return LICENSE_ALIASES[lower]
    # Try direct match against our risk table
    if cleaned in LICENSE_RISK:
        return cleaned
    # Try case-insensitive match
    for key in LICENSE_RISK:
        if key.lower() == lower:
            return key
    return cleaned  # Return as-is — will be treated as unknown


def run_pip_licenses(repo_path):
    """
    Run pip-licenses in the context of the repo.
    Returns list of {name, version, license} dicts.
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
            '.git', 'node_modules', '__pycache__', '.venv', 'venv'
        }]
        for fname in files:
            if fname in targets:
                dep_files.append(os.path.join(root, fname))
    return dep_files


def parse_requirements_txt(fpath):
    """Extract package names from requirements.txt."""
    packages = []
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                # Handle: package==1.0, package>=1.0, package~=1.0, package
                import re
                match = re.match(r'^([A-Za-z0-9_\-\.]+)', line)
                if match:
                    packages.append(match.group(1).lower())
    except:
        pass
    return packages


def parse_package_json(fpath):
    """Extract package names from package.json."""
    packages = []
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        for section in ['dependencies', 'devDependencies', 'peerDependencies']:
            packages.extend(data.get(section, {}).keys())
    except:
        pass
    return [p.lower() for p in packages]


def get_declared_packages(repo_path):
    """Get all packages declared in dependency files with their source file."""
    declared = {}  # package_name_lower → source_file
    dep_files = find_dependency_files(repo_path)

    for fpath in dep_files:
        fname = os.path.basename(fpath)
        rel_path = os.path.relpath(fpath, repo_path)

        if fname == 'requirements.txt' or fname.startswith('requirements'):
            pkgs = parse_requirements_txt(fpath)
        elif fname == 'package.json':
            pkgs = parse_package_json(fpath)
        else:
            continue

        for pkg in pkgs:
            if pkg not in declared:
                declared[pkg] = rel_path

    return declared, dep_files


def scan(repo_path: str) -> dict:
    try:
        details = []

        # Find dependency files first
        declared_packages, dep_files = get_declared_packages(repo_path)

        if not dep_files:
            return {
                "name":    NAME,
                "score":   100,
                "issues":  0,
                "details": [],
                "warning": "No dependency files found (requirements.txt, package.json, etc.)"
            }

        # Get installed packages with their licenses via pip-licenses
        installed_packages, error = run_pip_licenses(repo_path)

        if error or not installed_packages:
            return {
                "name":    NAME,
                "score":   None,
                "issues":  0,
                "details": [],
                "warning": f"Could not run: {error or 'pip-licenses returned empty results'}"
            }

        # Build lookup: package_name_lower → {version, license}
        installed_lookup = {}
        for pkg in installed_packages:
            name    = pkg.get("Name", "").lower().replace("-", "_").replace(".", "_")
            name2   = pkg.get("Name", "").lower()
            license_str = pkg.get("License", "UNKNOWN")
            version = pkg.get("Version", "unknown")
            entry = {"version": version, "license": license_str, "name": pkg.get("Name", "")}
            installed_lookup[name]  = entry
            installed_lookup[name2] = entry

        seen = set()

        # Check every declared package
        for pkg_raw, source_file in declared_packages.items():
            pkg_normalized = pkg_raw.lower().replace("-", "_").replace(".", "_")

            # Find in installed packages
            installed = installed_lookup.get(pkg_normalized) or installed_lookup.get(pkg_raw.lower())

            if not installed:
                # Check KNOWN_LICENSE_MAP first — catches risky packages even when not installed
                known_license = KNOWN_LICENSE_MAP.get(pkg_raw.lower())
                if known_license and known_license in LICENSE_RISK:
                    severity, reason = LICENSE_RISK[known_license]
                    if severity != "low":
                        dedup_key = (pkg_raw, source_file, known_license)
                        if dedup_key not in seen:
                            seen.add(dedup_key)
                            details.append({
                                "file":       source_file,
                                "line":       1,
                                "type":       f"License Risk: {known_license}",
                                "severity":   severity,
                                "reason":     f"'{pkg_raw}' uses {known_license} — {reason}",
                                "confidence": "high",
                                "snippet":    f"{pkg_raw} ({known_license})",
                                "package":    pkg_raw,
                                "license":    known_license,
                                "remediation": get_remediation(pkg_raw, known_license)
                            })
                    continue  # skip the Unresolvable warning — license is known

                # Package declared but not installed → possibly hallucinated
                dedup_key = (pkg_raw, source_file, "Not Installed")
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    details.append({
                        "file":       source_file,
                        "line":       1,
                        "type":       "Unresolvable Dependency",
                        "severity":   "high",
                        "reason":     f"'{pkg_raw}' is declared but not installed — may be a hallucinated or non-existent package (common in vibe-coded apps)",
                        "confidence": "medium",
                        "snippet":    pkg_raw,
                        "package":    pkg_raw,
                        "license":    "UNKNOWN",
                        "remediation": f"Verify '{pkg_raw}' exists on PyPI: https://pypi.org/project/{pkg_raw}/ — if not found, remove it."
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
                        "file":       source_file,
                        "line":       1,
                        "type":       "Unknown License",
                        "severity":   "high",
                        "reason":     f"'{display_name}=={version}' has no detectable license — legally this means no permissions are granted. Cannot be used in production.",
                        "confidence": "high",
                        "snippet":    f"{display_name}=={version}",
                        "package":    display_name,
                        "license":    raw_license,
                        "remediation": f"Check '{display_name}' on PyPI or GitHub for license information before using in production."
                    })
                continue

            # Check against our risk table
            if normalized in LICENSE_RISK:
                severity, reason = LICENSE_RISK[normalized]

                # Skip low severity — only report medium and above
                if severity == "low":
                    continue

                dedup_key = (pkg_raw, source_file, normalized)
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    details.append({
                        "file":       source_file,
                        "line":       1,
                        "type":       f"License Risk: {normalized}",
                        "severity":   severity,
                        "reason":     f"'{display_name}=={version}' uses {normalized} — {reason}",
                        "confidence": "high",
                        "snippet":    f"{display_name}=={version} ({normalized})",
                        "package":    display_name,
                        "license":    normalized,
                        "remediation": get_remediation(display_name, normalized)
                    })

        # Scoring formula — contract law, do not change
        critical = len([d for d in details if d["severity"] == "critical"])
        high     = len([d for d in details if d["severity"] == "high"])
        medium   = len([d for d in details if d["severity"] == "medium"])
        score    = max(0, 100 - (critical * 15) - (high * 10) - (medium * 5))

        return {
            "name":    NAME,
            "score":   score,
            "issues":  len(details),
            "details": details
        }

    except Exception as e:
        return {
            "name":    NAME,
            "score":   None,
            "issues":  0,
            "details": [],
            "warning": f"Could not run: {str(e)}"
        }


def get_remediation(package_name, license_id):
    """Return actionable remediation advice per license type."""
    remediations = {
        "AGPL-3.0":     f"Replace '{package_name}' with a permissively licensed alternative, or release your entire codebase under AGPL. Consider alternatives on https://pypi.org",
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
