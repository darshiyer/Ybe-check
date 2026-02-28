"""
Prompt Injection Detection Module — Ybe Check
Author: Darsh
Status: IN PROGRESS

CONTRACT:
- Input: repo_path (string, absolute path)
- Output: dict matching module contract
- Test: cd A2K2 && python -c "
    import sys,json; sys.path.insert(0,'.')
    from modules.prompt_injection import scan
    print(json.dumps(scan('../A2K2-test'),indent=2))"

MUST DETECT IN A2K2-test/:
  app.py line ~10: f-string prompt with {user_input}
  prompts.yaml: system prompts without guardrails
"""

import os
import re

NAME = "Prompt Injection"

# ── SKIP THESE DIRS ──────────────────────────────────────────
SKIP_DIRS = {
    '.git', 'node_modules', '__pycache__', '.venv',
    'venv', 'dist', 'build', '.next', 'out'
}

# ── FILE TYPES TO SCAN ───────────────────────────────────────
TARGET_EXTENSIONS = {'.py', '.js', '.ts', '.json', '.yaml', '.yml'}

# ── PATTERNS ─────────────────────────────────────────────────

# Variables that likely hold LLM prompts
PROMPT_VAR_PATTERN = re.compile(
    r'\b(system_prompt|system_message|prompt|template|instruction|context)\s*=',
    re.IGNORECASE
)

# f-string with user input (UNSAFE PROMPT TEMPLATE)
FSTRING_INJECTION_PATTERN = re.compile(
    r'f["\'].*\{(user_input|user_message|query|request|input|message|user)\}.*["\']',
    re.IGNORECASE
)

# String concatenation into prompt
CONCAT_INJECTION_PATTERN = re.compile(
    r'(prompt|template|instruction|system_prompt)\s*\+\s*\w+|'
    r'\w+\s*\+\s*(prompt|template|instruction)',
    re.IGNORECASE
)

# .format() with user data
FORMAT_INJECTION_PATTERN = re.compile(
    r'\.format\s*\(\s*(user|input|query|message|request)\s*=',
    re.IGNORECASE
)

# Jailbreak phrases inside strings
JAILBREAK_PHRASES = [
    "you can do anything",
    "ignore previous instructions",
    "ignore all previous",
    "pretend you are",
    "disregard your instructions",
    "bypass your",
    "you are now",
    "do anything now",
    "DAN",
]

# Guardrail keywords (if present near system_prompt, it's safer)
GUARDRAIL_KEYWORDS = [
    "refuse", "ignore attempts", "do not discuss",
    "never reveal", "only answer", "you must not",
    "stay on topic", "do not follow", "reject",
    "do not comply", "disregard any"
]


def walk_files(repo_path):
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in TARGET_EXTENSIONS:
                yield os.path.join(root, fname)


def read_lines(fpath):
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except Exception:
        return []


def rel(fpath, repo_path):
    return os.path.relpath(fpath, repo_path)


def get_context_window(lines, line_idx, window=10):
    start = max(0, line_idx - window)
    end = min(len(lines), line_idx + window)
    return ' '.join(lines[start:end]).lower()


def scan(repo_path: str) -> dict:
    details = []
    seen = set()
    prompt_found = False

    for fpath in walk_files(repo_path):
        lines = read_lines(fpath)
        relative = rel(fpath, repo_path)

        for i, line in enumerate(lines):
            line_num = i + 1
            stripped = line.strip()

            # Skip comments
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            # ── DETECT 1: UNSAFE PROMPT TEMPLATES ────────────────
            # YOUR CODE HERE ↓
            if FSTRING_INJECTION_PATTERN.search(stripped):
                prompt_found = True
                key = (relative, line_num, "Unsafe Prompt Template")
                if key not in seen:
                    seen.add(key)
                    details.append({
                        "file": relative,
                        "line": line_num,
                        "type": "Unsafe Prompt Template",
                        "severity": "critical",
                        "reason": "User input concatenated directly into prompt without sanitization — enables prompt injection"
                    })
            elif CONCAT_INJECTION_PATTERN.search(stripped) and PROMPT_VAR_PATTERN.search(stripped):
                prompt_found = True
                key = (relative, line_num, "Unsafe Prompt Template")
                if key not in seen:
                    seen.add(key)
                    details.append({
                        "file": relative,
                        "line": line_num,
                        "type": "Unsafe Prompt Template",
                        "severity": "critical",
                        "reason": "User input concatenated directly into prompt without sanitization — enables prompt injection"
                    })
            elif FORMAT_INJECTION_PATTERN.search(stripped):
                prompt_found = True
                key = (relative, line_num, "Unsafe Prompt Template")
                if key not in seen:
                    seen.add(key)
                    details.append({
                        "file": relative,
                        "line": line_num,
                        "type": "Unsafe Prompt Template",
                        "severity": "critical",
                        "reason": "User input concatenated directly into prompt without sanitization — enables prompt injection"
                    })

            # ── DETECT 2: MISSING GUARDRAILS ─────────────────────
            # YOUR CODE HERE ↓
            if PROMPT_VAR_PATTERN.search(stripped):
                prompt_found = True
                context = get_context_window(lines, i)
                has_guardrail = any(kw in context for kw in GUARDRAIL_KEYWORDS)
                if not has_guardrail:
                    key = (relative, line_num, "Missing Prompt Guardrails")
                    if key not in seen:
                        seen.add(key)
                        details.append({
                            "file": relative,
                            "line": line_num,
                            "type": "Missing Prompt Guardrails",
                            "severity": "high",
                            "reason": "System prompt has no refusal instructions — vulnerable to jailbreaking"
                        })

            # ── DETECT 3: JAILBREAK PHRASES ──────────────────────
            # YOUR CODE HERE ↓
            line_lower = stripped.lower()
            for phrase in JAILBREAK_PHRASES:
                if phrase.lower() in line_lower:
                    prompt_found = True
                    key = (relative, line_num, "Jailbreak Vulnerable Prompt")
                    if key not in seen:
                        seen.add(key)
                        details.append({
                            "file": relative,
                            "line": line_num,
                            "type": "Jailbreak Vulnerable Prompt",
                            "severity": "critical",
                            "reason": "Prompt contains jailbreak-enabling language — remove or sanitize this string"
                        })
                    break

    # ── YAML/JSON SCANNING ───────────────────────────────────
    # YOUR CODE HERE ↓
    for fpath in walk_files(repo_path):
        ext = os.path.splitext(fpath)[1].lower()
        if ext not in {'.yaml', '.yml', '.json'}:
            continue
        lines = read_lines(fpath)
        relative = rel(fpath, repo_path)
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            # Check for system/prompt/instruction keys followed by a value
            if re.search(r'\b(system|prompt|instruction|template)\s*[=:]\s*.{5,}', stripped, re.IGNORECASE):
                prompt_found = True
                line_lower = stripped.lower()
                for phrase in JAILBREAK_PHRASES:
                    if phrase.lower() in line_lower:
                        key = (relative, line_num, "Jailbreak Vulnerable Prompt")
                        if key not in seen:
                            seen.add(key)
                            details.append({
                                "file": relative,
                                "line": line_num,
                                "type": "Jailbreak Vulnerable Prompt",
                                "severity": "critical",
                                "reason": "Prompt contains jailbreak-enabling language — remove or sanitize this string"
                            })
                        break
                else:
                    context = get_context_window(lines, i)
                    has_guardrail = any(kw in context for kw in GUARDRAIL_KEYWORDS)
                    if not has_guardrail:
                        key = (relative, line_num, "Missing Prompt Guardrails")
                        if key not in seen:
                            seen.add(key)
                            details.append({
                                "file": relative,
                                "line": line_num,
                                "type": "Missing Prompt Guardrails",
                                "severity": "high",
                                "reason": "System prompt has no refusal instructions — vulnerable to jailbreaking"
                            })

    # ── IF NO PROMPTS FOUND AT ALL ───────────────────────────
    if not prompt_found:
        return {
            "name": NAME,
            "score": 100,
            "issues": 0,
            "details": [],
            "warning": "No LLM prompts detected in this repo"
        }

    # ── SCORING ──────────────────────────────────────────────
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
