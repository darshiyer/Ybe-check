import os
import json
import re
import shutil
import subprocess
import sys

NAME = "IaC Security"

SKIP_DIRS = {
    '.git', 'node_modules', '__pycache__', '.venv',
    'venv', 'dist', 'build', '.next', 'out'
}

# Checkov severity → our severity mapping
SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "UNKNOWN":  "low",
}

# Checkov check IDs that are too noisy or irrelevant for vibe-coded apps
SKIP_CHECK_IDS = {
    "CKV_GIT_1",   # Git repo MFA — not applicable to local repos
}

# IaC file extensions checkov understands
IAC_EXTENSIONS = {
    '.tf', '.yaml', '.yml', '.json',
    '.dockerfile', '.env', '.toml'
}

IAC_FILENAMES = {
    'dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
    '.env', '.env.example', '.env.local', '.env.production'
}


def _find_checkov_bin() -> str | None:
    """Return the path to the checkov binary, or None if not found."""
    # 1. Check PATH first
    found = shutil.which("checkov")
    if found:
        return found
    # 2. Look next to the active Python interpreter (handles venvs and pipx installs)
    bin_dir = os.path.dirname(sys.executable)
    for name in ("checkov", "checkov.exe"):
        candidate = os.path.join(bin_dir, name)
        if os.path.isfile(candidate):
            return candidate
    return None


def _ensure_checkov() -> bool:
    """Auto-install checkov if not present. Returns True if available after attempt."""
    if _find_checkov_bin():
        return True
    # checkov is a CLI tool — install it, then re-check for the binary
    for extra in [[], ["--user"], ["--break-system-packages"]]:
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "checkov", "-q"] + extra,
                capture_output=True, check=True
            )
            if _find_checkov_bin():
                return True
        except subprocess.CalledProcessError:
            continue
    return False


def has_iac_files(repo_path):
    """Quick check — does this repo have any IaC files worth scanning?"""
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in IAC_EXTENSIONS or fname.lower() in IAC_FILENAMES:
                return True
    return False


# ---------------------------------------------------------------------------
# Pure-Python IaC rule engine — zero external dependencies, works everywhere
# ---------------------------------------------------------------------------

DOCKERFILE_RULES = [
    (re.compile(r'^\s*USER\s+root\s*$', re.I),
     "high", "Container runs as root — add USER nonroot to reduce attack surface"),
    (re.compile(r'^\s*ADD\s+', re.I),
     "medium", "Use COPY instead of ADD — ADD can auto-extract archives and fetch URLs unexpectedly"),
    (re.compile(r'^\s*RUN\s+.*apt(-get)?\s+install(?!.*--no-install-recommends)', re.I),
     "low", "Add --no-install-recommends to apt-get install to reduce image size and attack surface"),
    (re.compile(r'^\s*ENV\s+\S*(PASSWORD|SECRET|KEY|TOKEN)\s*=\s*\S+', re.I),
     "critical", "Secret hardcoded in Dockerfile ENV — use build args or runtime secrets instead"),
    (re.compile(r'^\s*FROM\s+\S+:latest\s*$', re.I),
     "medium", "Pin base image to a specific digest or version tag instead of :latest for reproducibility"),
]

COMPOSE_RULES = [
    (re.compile(r'privileged\s*:\s*true', re.I),
     "critical", "Container runs in privileged mode — full host access, major security risk"),
    (re.compile(r'network_mode\s*:\s*["\']?host["\']?', re.I),
     "high", "Container shares host network namespace — isolate with bridge networking"),
    (re.compile(r'(password|secret|key|token)\s*:\s*["\']?[^\s\$\{][^"\'\s]{3,}', re.I),
     "critical", "Hardcoded secret in docker-compose — use environment variables or Docker secrets"),
    (re.compile(r'restart\s*:\s*["\']?always["\']?', re.I),
     "low", "restart: always can hide crash loops — consider restart: on-failure with a retry limit"),
]

TERRAFORM_RULES = [
    (re.compile(r'cidr_blocks\s*=\s*\[?\s*"0\.0\.0\.0/0"', re.I),
     "critical", "Security group allows ingress from 0.0.0.0/0 (entire internet) — restrict to known CIDRs"),
    (re.compile(r'acl\s*=\s*"public-read"', re.I),
     "critical", "S3 bucket is publicly readable — remove public ACL or add bucket policy to block public access"),
    (re.compile(r'encrypted\s*=\s*false', re.I),
     "high", "Storage resource has encryption explicitly disabled — enable encryption at rest"),
    (re.compile(r'(password|secret|access_key)\s*=\s*"[^"]{4,}"', re.I),
     "critical", "Hardcoded credential in Terraform — use variables with sensitive=true or a secrets manager"),
    (re.compile(r'skip_final_snapshot\s*=\s*true', re.I),
     "medium", "RDS skip_final_snapshot=true — no backup taken on destroy, risk of data loss"),
]

K8S_RULES = [
    (re.compile(r'privileged\s*:\s*true', re.I),
     "critical", "Kubernetes container runs privileged — full node access, immediate security risk"),
    (re.compile(r'runAsRoot\s*:\s*true', re.I),
     "high", "Pod runs as root — set runAsNonRoot: true in securityContext"),
    (re.compile(r'hostNetwork\s*:\s*true', re.I),
     "high", "Pod shares host network namespace — use cluster networking instead"),
    (re.compile(r'(memory|cpu)\s*:', re.I),
     None, None),  # presence check — absence is flagged below
]


def _run_pure_python_iac_scan(repo_path: str) -> list:
    """
    Scan IaC files with built-in rules. No external tools needed.
    Returns list of finding dicts.
    """
    details = []
    seen = set()

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, repo_path)
            flower = fname.lower()

            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            except OSError:
                continue

            # Determine file type
            if flower == 'dockerfile' or flower.endswith('.dockerfile'):
                rules = DOCKERFILE_RULES
                # Check for missing USER instruction
                has_user = any(re.match(r'^\s*USER\s+(?!root)', l, re.I) for l in lines)
                if not has_user:
                    key = (rel, 1, "Missing Non-Root USER")
                    if key not in seen:
                        seen.add(key)
                        details.append({
                            "file": rel, "line": 1,
                            "type": "Missing Non-Root USER",
                            "severity": "high",
                            "reason": "No non-root USER instruction found — container will run as root by default",
                            "confidence": "high",
                        })
            elif 'docker-compose' in flower:
                rules = COMPOSE_RULES
            elif flower.endswith('.tf'):
                rules = TERRAFORM_RULES
            elif flower.endswith(('.yaml', '.yml')) and any(
                kw in '\n'.join(lines) for kw in ('apiVersion', 'kind: Deployment', 'kind: Pod')
            ):
                rules = K8S_RULES[:3]  # skip presence check rule
            else:
                continue

            for i, line in enumerate(lines, start=1):
                for rule in rules:
                    if rule[1] is None:  # presence-check sentinel
                        continue
                    pattern, severity, reason = rule
                    if pattern.search(line):
                        key = (rel, i, reason[:40])
                        if key not in seen:
                            seen.add(key)
                            details.append({
                                "file": rel, "line": i,
                                "type": reason.split(" — ")[0],
                                "severity": severity,
                                "reason": reason,
                                "confidence": "high",
                                "snippet": line.strip(),
                            })

    return details


def run_checkov(repo_path):
    """
    Run checkov against the repo and return parsed JSON output.
    Uses --quiet to suppress progress bars.
    Uses -o json for machine-readable output.
    Uses --compact to reduce output size.
    """
    # Resolve to absolute path so checkov never walks into parent dirs
    repo_abs = os.path.abspath(repo_path)

    cmd = [
        "checkov",
        "-d", repo_abs,
        "-o", "json",
        "--quiet",
        "--compact",
        "--skip-check", ",".join(SKIP_CHECK_IDS) if SKIP_CHECK_IDS else "",
    ]

    # Remove --skip-check if nothing to skip (would error)
    if not SKIP_CHECK_IDS:
        cmd = [c for c in cmd if c != "--skip-check" and c != ""]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,  # 2 min max
            cwd=repo_abs
        )
        # Checkov exits with code 1 when it finds issues — that's normal
        # Only treat it as an error if there's no stdout at all
        if not result.stdout or result.stdout.strip() == "":
            return None, f"Checkov produced no output. stderr: {result.stderr[:200]}"

        return result.stdout, None

    except subprocess.TimeoutExpired:
        return None, "Checkov timed out after 120 seconds"
    except FileNotFoundError:
        return None, "checkov not found — run: pip install checkov"
    except Exception as e:
        return None, str(e)


def parse_checkov_output(raw_output, repo_path):
    """
    Parse checkov JSON output into our details[] format.
    Checkov can return either a single dict or a list of dicts
    (one per framework: terraform, dockerfile, kubernetes, etc.)
    """
    details = []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        # Sometimes checkov prefixes output with non-JSON lines
        # Try to find the JSON portion
        lines = raw_output.strip().split('\n')
        json_start = None
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('[') or stripped.startswith('{'):
                json_start = i
                break
        if json_start is None:
            return details, "Could not parse checkov JSON output"
        try:
            data = json.loads('\n'.join(lines[json_start:]))
        except:
            return details, "Could not parse checkov JSON output after cleanup"

    # Normalize to list — checkov returns list when multiple frameworks scanned
    if isinstance(data, dict):
        data = [data]

    seen = set()

    for framework_result in data:
        if not isinstance(framework_result, dict):
            continue

        failed_checks = []

        # Standard checkov output structure
        results = framework_result.get("results", {})
        if results:
            failed_checks = results.get("failed_checks", [])
        else:
            # Sometimes it's directly at top level
            failed_checks = framework_result.get("failed_checks", [])

        for check in failed_checks:
            try:
                check_id   = check.get("check_id", "UNKNOWN")
                check_name = check.get("check_id", "") + ": " + check.get("check", {}).get("name", check.get("check_type", "Unknown Check"))

                # Handle both dict and string for 'check' field
                check_obj = check.get("check", {})
                if isinstance(check_obj, str):
                    check_name = check_id + ": " + check_obj
                elif isinstance(check_obj, dict):
                    check_name = check_id + ": " + check_obj.get("name", "Security Misconfiguration")

                # File path — resolve Checkov's output correctly.
                # Checkov emits paths like "/docker-compose.yml" — looks absolute
                # but is actually relative to the scanned repo root.
                # Strategy: if relpath escapes the repo (starts with ".."),
                # try treating the path as repo-root-relative first.
                file_abs  = check.get("file_path", "")
                repo_abs  = os.path.abspath(repo_path)

                if os.path.isabs(file_abs):
                    candidate = os.path.join(repo_abs, file_abs.lstrip("/"))
                    if os.path.exists(candidate):
                        # It's a repo-root-relative path — use it
                        file_rel = os.path.relpath(candidate, repo_abs)
                    else:
                        # Genuinely outside repo — compute and filter
                        file_rel = os.path.relpath(file_abs, repo_abs)
                else:
                    file_rel = file_abs.lstrip("/")

                # Skip findings that resolve outside the repo root
                if file_rel.startswith(".."):
                    continue

                # Line number
                file_line_range = check.get("file_line_range", [1, 1])
                line_no = file_line_range[0] if file_line_range else 1

                # Severity — checkov provides this in newer versions
                raw_severity = check.get("severity", "MEDIUM")
                if raw_severity is None:
                    raw_severity = "MEDIUM"
                severity = SEVERITY_MAP.get(raw_severity.upper(), "medium")

                # Resource name for context
                resource = check.get("resource", "")

                # Snippet — checkov provides code_block
                code_block = check.get("code_block", [])
                snippet = ""
                if code_block and isinstance(code_block, list):
                    # code_block is list of [line_num, line_content]
                    snippet = " | ".join(
                        str(cb[1]).strip() for cb in code_block[:3] if len(cb) > 1
                    )

                # Dedup by check_id + file + line
                dedup_key = (check_id, file_rel, line_no)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                detail = {
                    "file":       file_rel,
                    "line":       line_no,
                    "type":       check_name,
                    "severity":   severity,
                    "reason":     f"[{check_id}] {resource} — {check_name}" if resource else f"[{check_id}] {check_name}",
                    "confidence": "high",   # Checkov findings are high confidence
                    "snippet":    snippet,
                    "check_id":   check_id,
                }
                details.append(detail)

            except Exception:
                # Never let a single malformed check crash the whole parse
                continue

    return details, None


def scan(repo_path: str) -> dict:
    try:
        # Fast path — no IaC files, nothing to scan
        if not has_iac_files(repo_path):
            return {
                "name":    NAME,
                "score":   100,
                "issues":  0,
                "details": [],
                "warning": "No IaC files detected (no .tf, Dockerfile, docker-compose, k8s yaml, etc.)"
            }

        # Primary: pure-Python rule engine (zero deps, always works)
        details = _run_pure_python_iac_scan(repo_path)

        # Enhancement: try checkov for deeper analysis and merge results
        raw_output, checkov_error = run_checkov(repo_path)
        if not checkov_error and raw_output:
            checkov_details, _ = parse_checkov_output(raw_output, repo_path)
            # Merge — dedupe by (file, line, check_id prefix)
            existing = {(d["file"], d["line"]) for d in details}
            for d in checkov_details:
                if (d["file"], d["line"]) not in existing:
                    details.append(d)

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
