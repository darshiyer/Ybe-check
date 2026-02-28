import os
import json
import subprocess
import tempfile

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


def has_iac_files(repo_path):
    """Quick check — does this repo have any IaC files worth scanning?"""
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in IAC_EXTENSIONS or fname.lower() in IAC_FILENAMES:
                return True
    return False


def run_checkov(repo_path):
    """
    Run checkov against the repo and return parsed JSON output.
    Uses --quiet to suppress progress bars.
    Uses -o json for machine-readable output.
    Uses --compact to reduce output size.
    """
    cmd = [
        "checkov",
        "-d", repo_path,
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
            cwd=repo_path
        )
        # Checkov exits with code 1 when it finds issues — that's normal
        # Only treat it as an error if there's no stdout at all
        if not result.stdout or result.stdout.strip() == "":
            return None, f"Checkov produced no output. stderr: {result.stderr[:200]}"

        return result.stdout, None

    except subprocess.TimeoutExpired:
        return None, "Checkov timed out after 120 seconds"
    except FileNotFoundError:
        return None, "Checkov not found — run: pip install checkov"
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

                # File path — make relative
                file_abs  = check.get("file_path", "")
                file_rel  = os.path.relpath(file_abs, repo_path) if os.path.isabs(file_abs) else file_abs.lstrip("/")

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

        # Run real Checkov
        raw_output, error = run_checkov(repo_path)

        if error:
            return {
                "name":    NAME,
                "score":   None,
                "issues":  0,
                "details": [],
                "warning": f"Could not run: {error}"
            }

        # Parse output
        details, parse_error = parse_checkov_output(raw_output, repo_path)

        if parse_error and not details:
            return {
                "name":    NAME,
                "score":   None,
                "issues":  0,
                "details": [],
                "warning": f"Could not run: {parse_error}"
            }

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
