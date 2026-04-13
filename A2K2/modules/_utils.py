"""
Shared utilities for Ybe Check scan modules.
Eliminates code duplication across secrets, prompt_injection, pii_logging, and auth_guards.
"""

import os
from typing import List, Optional, Set

# ── SCANNER SELF-AWARENESS ───────────────────────────────────
# Absolute path of the modules/ directory — used to skip scanning
# the scanner's own source code (prevents ironic false positives).
SCANNER_MODULES_DIR: str = os.path.dirname(os.path.abspath(__file__))
SCANNER_ROOT_DIR: str = os.path.dirname(SCANNER_MODULES_DIR)  # extension root


def is_scanner_file(fpath: str) -> bool:
    """Return True if fpath is part of the scanner's own source tree."""
    try:
        real = os.path.realpath(fpath)
        return real.startswith(SCANNER_ROOT_DIR + os.sep) or real == SCANNER_ROOT_DIR
    except (OSError, ValueError):
        return False


# ── COMMON SKIP DIRECTORIES ──────────────────────────────────
SKIP_DIRS: Set[str] = {
    '.git', 'node_modules', '__pycache__', '.venv',
    'venv', 'env', 'dist', 'build', '.next', 'out',
    '.tox', '.mypy_cache', '.pytest_cache',
    '.ybe-check', '.secret-stack', '.eggs', '*.egg-info',
    'site-packages', '.antigravity', '.cursor', '.claude',
    'graphify-out', '.terraform',
}

# ── COMMON SKIP EXTENSIONS (binary/non-text files) ───────────
SKIP_EXTENSIONS: Set[str] = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp3', '.mp4', '.avi', '.mov', '.wav',
    '.zip', '.gz', '.tar', '.bz2', '.7z', '.rar',
    '.pyc', '.pyo', '.exe', '.dll', '.so', '.dylib',
    '.bin', '.lock', '.vsix', '.pdf', '.doc', '.docx',
    '.sqlite', '.db', '.sqlite3',
}

# ── MAX FILE SIZE (skip files larger than this) ──────────────
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB


def walk_files(repo_path: str, extensions: Set[str]) -> List[str]:
    """
    Walk a repository directory yielding file paths matching given extensions.
    Skips ignored directories, binary extensions, symlinks, oversized files,
    and the scanner's own source tree.

    Args:
        repo_path: Root directory to walk.
        extensions: Set of file extensions to include (e.g., {'.py', '.js'}).

    Returns:
        List of absolute file paths matching the criteria.
    """
    files = []
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        # Skip the scanner's own directory tree
        _real = os.path.realpath(dirpath)
        if _real == SCANNER_ROOT_DIR or _real.startswith(SCANNER_ROOT_DIR + os.sep):
            dirnames.clear()
            continue
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in extensions or ext in SKIP_EXTENSIONS:
                continue
            full = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(full) > MAX_FILE_SIZE or os.path.islink(full):
                    continue
            except OSError:
                continue
            files.append(full)
    return files


def read_file_lines(fpath: str) -> List[str]:
    """
    Read a file and return its lines. Returns empty list on failure.

    Args:
        fpath: Absolute path to the file.

    Returns:
        List of lines (with newlines preserved).
    """
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except Exception:
        return []


def read_file_text(fpath: str) -> Optional[str]:
    """
    Read a file and return its full text content. Returns None on failure.

    Args:
        fpath: Absolute path to the file.

    Returns:
        File content as a string, or None on error.
    """
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception:
        return None


def rel_path(fpath: str, repo_path: str) -> str:
    """
    Return the path of fpath relative to repo_path.

    Args:
        fpath: Absolute file path.
        repo_path: Root repository path.

    Returns:
        Relative path string.
    """
    return os.path.relpath(fpath, repo_path)


def compute_score(details: list) -> int:
    """
    Compute a security score (0-100) from a list of finding details.
    Uses the standard scoring formula: 100 - (critical * 15) - (high * 10) - (medium * 5).

    Args:
        details: List of finding dicts, each with a 'severity' key.

    Returns:
        Integer score clamped to [0, 100].
    """
    critical = len([d for d in details if d.get("severity") == "critical"])
    high = len([d for d in details if d.get("severity") == "high"])
    medium = len([d for d in details if d.get("severity") == "medium"])
    return max(0, 100 - (critical * 15) - (high * 10) - (medium * 5))
