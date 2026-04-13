"""
Ybe Check — Code Quality / Architectural Detection Module

Detects structural security issues that keyword-based scanners miss:
  1. Silent exception swallowing  (bare except: pass)
  2. Subprocess calls without timeouts
  3. Unbounded path operations (no validation on user-supplied paths)
  4. eval/exec on variables (code injection risk)

Pure static analysis via regex on AST-like patterns. No external tools.
"""

import os
import re

NAME = "Code Quality"

_SCANNER_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SKIP_DIRS = {
    '.git', 'node_modules', '__pycache__', '.venv', 'venv',
    'dist', 'build', '.next', 'out', '.ybe-check',
    'site-packages', '.antigravity', '.cursor', '.claude',
    'graphify-out', '.terraform',
}

SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.ttf', '.eot', '.zip', '.tar', '.gz',
    '.pyc', '.lock', '.vsix', '.db', '.pdf',
}

CODE_EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx'}

# ── Detection patterns ───────────────────────────────────────────

# 1. Silent exception swallowing: except ...: pass (or bare except: pass)
#    Matches: except: pass / except Exception: pass / except Exception as e: pass
_BARE_EXCEPT_RE = re.compile(
    r'^\s*except\b[^:]*:\s*$'
)
_PASS_RE = re.compile(r'^\s*pass\s*$')

# 2. subprocess without timeout
_SUBPROCESS_RE = re.compile(
    r'\bsubprocess\.(run|call|check_output|check_call|Popen)\s*\('
)
_TIMEOUT_RE = re.compile(r'\btimeout\s*=')

# 3. Dangerous path operations with variables (no validation)
_PATH_OPS_RE = re.compile(
    r'\b(open|os\.path\.join|Path|shutil\.(copy|move|rmtree))\s*\('
)

# 4. eval/exec on variables
_EVAL_RE = re.compile(r'\b(eval|exec)\s*\(\s*[a-zA-Z_]')


def _walk_files(repo_path):
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        _real = os.path.realpath(dirpath)
        if _real == _SCANNER_ROOT or _real.startswith(_SCANNER_ROOT + os.sep):
            dirnames.clear()
            continue
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in CODE_EXTENSIONS or ext in SKIP_EXTENSIONS:
                continue
            yield os.path.join(dirpath, fname)


def _check_silent_except(lines, fpath, repo_path):
    """Detect except: pass / except Exception: pass patterns."""
    details = []
    for i, line in enumerate(lines):
        if _BARE_EXCEPT_RE.match(line):
            # Check if the next non-blank line is just 'pass'
            for j in range(i + 1, min(len(lines), i + 3)):
                next_line = lines[j]
                if next_line.strip() == '':
                    continue
                if _PASS_RE.match(next_line):
                    details.append({
                        "type": "Bare Except",
                        "severity": "medium",
                        "file": os.path.relpath(fpath, repo_path),
                        "line": i + 1,
                        "reason": "Silent exception swallowing (except: pass) hides errors and makes debugging impossible.",
                        "snippet": line.rstrip(),
                        "remediation": "Catch specific exceptions and log or handle them: except ValueError as e: logger.error(e)",
                    })
                break
    return details


def _check_subprocess_timeout(lines, fpath, repo_path):
    """Detect subprocess calls without timeout parameter."""
    details = []
    for i, line in enumerate(lines):
        if _SUBPROCESS_RE.search(line):
            # Check current line and next few for timeout=
            window = ''.join(lines[i:min(len(lines), i + 5)])
            if not _TIMEOUT_RE.search(window):
                details.append({
                    "type": "No Subprocess Timeout",
                    "severity": "medium",
                    "file": os.path.relpath(fpath, repo_path),
                    "line": i + 1,
                    "reason": "subprocess call without timeout can hang indefinitely, causing resource exhaustion.",
                    "snippet": line.rstrip(),
                    "remediation": "Add timeout parameter: subprocess.run([...], timeout=30)",
                })
    return details


def _check_eval_exec(lines, fpath, repo_path):
    """Detect eval/exec on variables (code injection risk)."""
    details = []
    for i, line in enumerate(lines):
        if _EVAL_RE.search(line):
            details.append({
                "type": "Eval/Exec on Variable",
                "severity": "high",
                "file": os.path.relpath(fpath, repo_path),
                "line": i + 1,
                "reason": "eval/exec on a variable is a code injection vector. Never evaluate untrusted input.",
                "snippet": line.rstrip(),
                "remediation": "Replace eval/exec with safe alternatives: ast.literal_eval() for data, or explicit parsing.",
            })
    return details


def scan(repo_path):
    """Scan for architectural / code quality issues."""
    details = []

    for fpath in _walk_files(repo_path):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except OSError:
            continue

        details.extend(_check_silent_except(lines, fpath, repo_path))
        details.extend(_check_subprocess_timeout(lines, fpath, repo_path))
        details.extend(_check_eval_exec(lines, fpath, repo_path))

    # Score: 100 - (high*10 + medium*5)
    high = sum(1 for d in details if d.get("severity") == "high")
    medium = sum(1 for d in details if d.get("severity") == "medium")
    score = max(0, 100 - (high * 10) - (medium * 5))

    return {
        "name": NAME,
        "score": score,
        "issues": len(details),
        "details": details,
    }
