"""
Test Coverage & AI Traceability Detection Module — Ybe Check

Heuristic-based detection of:
  - Automated test files and directories
  - Test framework dependencies
  - Coverage tooling indicators
  - AI-generated code markers

Does NOT execute real coverage. Pure static analysis.
"""

import os
import re
import json

NAME = "test_coverage"

SKIP_DIRS = {
    '.git', 'node_modules', '__pycache__', '.venv',
    'venv', 'dist', 'build', '.next', 'out',
    'site-packages', '.antigravity', '.cursor', '.claude',
    '.ybe-check', 'graphify-out', '.terraform',
}

# ── DETECTION CONSTANTS ──────────────────────────────────────

TEST_DIRS = {'tests', 'test', '__tests__'}

TEST_FILE_PATTERNS = [
    re.compile(r'^test_.*\.py$'),          # test_*.py
    re.compile(r'^.*_test\.py$'),          # *_test.py
    re.compile(r'^.*\.spec\.js$'),         # *.spec.js
    re.compile(r'^.*\.test\.js$'),         # *.test.js
    re.compile(r'^.*\.spec\.ts$'),         # *.spec.ts
    re.compile(r'^.*\.test\.ts$'),         # *.test.ts
]

PYTHON_TEST_FRAMEWORKS = {'pytest', 'unittest', 'pytest-cov', 'nose', 'nose2'}
NODE_TEST_FRAMEWORKS = {'jest', 'mocha', 'vitest', 'jasmine', 'ava'}

COVERAGE_FILES = {'.coverage', 'coverage.xml', '.coveragerc'}
COVERAGE_DIRS = {'htmlcov', 'coverage'}

AI_MARKERS = [
    re.compile(r'generated\s+by\s+(?:ai|gpt|copilot|chatgpt|claude|gemini|openai|codewhisperer)',
               re.IGNORECASE),
    re.compile(r'auto[- ]?generated', re.IGNORECASE),
    re.compile(r'created\s+(?:by|with|using)\s+(?:ai|gpt|copilot|chatgpt|claude|gemini)',
               re.IGNORECASE),
    re.compile(r'@generated', re.IGNORECASE),
    re.compile(r'vibe[- ]?coded', re.IGNORECASE),
]

CODE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx',
    '.java', '.go', '.rs', '.rb', '.php'
}


# ── HELPERS ──────────────────────────────────────────────────

def read_file_safe(fpath):
    """Read file contents safely. Returns empty string on failure."""
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception:
        return ""


def read_lines_safe(fpath):
    """Read file lines safely. Returns empty list on failure."""
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except Exception:
        return []


def rel(fpath, repo_path):
    """Return path relative to repo root."""
    return os.path.relpath(fpath, repo_path)


def parse_requirements_packages(req_path):
    """Extract package names from requirements.txt."""
    packages = set()
    try:
        with open(req_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                line = line.split('#')[0].strip()
                line = re.sub(r'\[.*?\]', '', line)
                match = re.match(r'^([A-Za-z0-9_.-]+)', line)
                if match:
                    packages.add(match.group(1).lower())
    except Exception:
        pass
    return packages


def parse_package_json_deps(pkg_path):
    """Extract dependency names from package.json."""
    packages = set()
    try:
        with open(pkg_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        for section in ('dependencies', 'devDependencies'):
            for name in data.get(section, {}).keys():
                packages.add(name.lower())
        # Check for test scripts
        scripts = data.get('scripts', {})
        if 'test' in scripts:
            packages.add('__has_test_script__')
    except Exception:
        pass
    return packages


# ── MAIN SCAN ────────────────────────────────────────────────

def scan(repo_path: str) -> dict:
    try:
        details = []

        # ── STEP 1: Scan for test directories and test files ──
        test_dirs_found = []
        test_files_found = []
        all_code_files = []
        coverage_files_found = []
        coverage_dirs_found = []
        ai_markers_found = []

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            # Check for test directories
            rel_root = os.path.relpath(root, repo_path)
            dir_name = os.path.basename(root)
            if dir_name in TEST_DIRS:
                test_dirs_found.append(rel_root)

            # Check for coverage directories
            if dir_name in COVERAGE_DIRS:
                coverage_dirs_found.append(rel_root)

            for fname in files:
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, repo_path)
                ext = os.path.splitext(fname)[1].lower()

                # Check for test files
                for pat in TEST_FILE_PATTERNS:
                    if pat.match(fname):
                        test_files_found.append(rel_path)
                        break

                # Check for coverage files
                if fname in COVERAGE_FILES:
                    coverage_files_found.append(rel_path)

                # Track code files for AI marker scanning
                if ext in CODE_EXTENSIONS:
                    all_code_files.append(fpath)

        # ── STEP 2: Check test frameworks in dependency files ──
        python_frameworks_found = set()
        node_frameworks_found = set()

        req_path = os.path.join(repo_path, 'requirements.txt')
        if os.path.exists(req_path):
            py_packages = parse_requirements_packages(req_path)
            python_frameworks_found = py_packages & PYTHON_TEST_FRAMEWORKS

        pkg_path = os.path.join(repo_path, 'package.json')
        if os.path.exists(pkg_path):
            node_packages = parse_package_json_deps(pkg_path)
            node_frameworks_found = node_packages & NODE_TEST_FRAMEWORKS

        has_any_framework = bool(python_frameworks_found or node_frameworks_found)

        # ── STEP 3: Check coverage tooling ────────────────────
        has_pytest_cov = 'pytest-cov' in python_frameworks_found
        has_coverage_files = bool(coverage_files_found or coverage_dirs_found)
        has_coverage = has_pytest_cov or has_coverage_files

        # Also check for coverage in setup.cfg, pyproject.toml, etc.
        for cfg_file in ['setup.cfg', 'pyproject.toml', 'tox.ini', '.coveragerc']:
            cfg_path = os.path.join(repo_path, cfg_file)
            if os.path.exists(cfg_path):
                content = read_file_safe(cfg_path)
                if 'coverage' in content.lower():
                    has_coverage = True
                    break

        # ── STEP 4: Scan for AI-generated markers ────────────
        for fpath in all_code_files:
            lines = read_lines_safe(fpath)
            # Only scan first 30 lines (markers usually at top)
            for line_no, line in enumerate(lines[:30], 1):
                for marker_pattern in AI_MARKERS:
                    if marker_pattern.search(line):
                        ai_markers_found.append({
                            "file": rel(fpath, repo_path),
                            "line": line_no,
                            "snippet": line.strip()[:100]
                        })
                        break  # One match per line is enough

        # ── STEP 5: Build details list ─────────────────────────
        has_test_files = len(test_files_found) > 0
        has_test_dirs = len(test_dirs_found) > 0

        # No test files at all
        if not has_test_files:
            details.append({
                "type": "No Test Files",
                "severity": "high",
                "file": ".",
                "line": 0,
                "reason": "No automated test files found (test_*.py, *.test.js, etc.)"
            })

        # No test directory
        if not has_test_dirs and not has_test_files:
            details.append({
                "type": "No Test Directory",
                "severity": "high",
                "file": ".",
                "line": 0,
                "reason": "No standard test directory found (tests/, test/)"
            })

        # Framework in deps but no test files
        if has_any_framework and not has_test_files:
            details.append({
                "type": "Test Framework Unused",
                "severity": "medium",
                "file": "requirements.txt" if python_frameworks_found else "package.json",
                "line": 0,
                "reason": "Test framework installed but no test files found written"
            })

        # Test files exist but no framework in dependencies
        if has_test_files and not has_any_framework:
            details.append({
                "type": "Missing Test Framework Dependency",
                "severity": "medium",
                "file": "requirements.txt",
                "line": 0,
                "reason": "Test files found but no framework (pytest, jest) in dependencies"
            })

        # No coverage tooling
        if not has_coverage:
            details.append({
                "type": "No Coverage Tooling",
                "severity": "medium" if has_test_files else "low",
                "file": ".",
                "line": 0,
                "reason": "No test coverage tooling detected (pytest-cov, .coverage, etc.)"
            })

        # AI traceability markers
        for marker in ai_markers_found:
            details.append({
                "type": "AI Generated Code Marker",
                "severity": "low",
                "file": marker["file"],
                "line": marker["line"],
                "snippet": marker["snippet"],
                "reason": "AI-generated code marker found — ensure adequate test coverage"
            })

        # ── STEP 6: Calculate score ───────────────────────────
        score = 100
        if not has_test_files and not has_test_dirs:
            score = 10
        elif not has_test_files and has_any_framework:
            score = max(0, score - 40)
        else:
            if not has_any_framework: score = max(0, score - 15)
            if not has_coverage: score = max(0, score - 20)
            if has_test_files and has_coverage and has_any_framework: score = min(score, 95)

        if ai_markers_found:
            score = max(0, score - len(ai_markers_found) * 2)

        return {
            "name": "Test & Coverage",
            "score": max(0, score),
            "issues": len(details),
            "details": details
        }

    except Exception as e:
        return {
            "name": "Test & Coverage",
            "score": None,
            "issues": 0,
            "details": [],
            "warning": f"Could not run test coverage scan: {e}"
        }
