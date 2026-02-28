import os
import re

NAME = "Prompt Injection"

SKIP_DIRS = {
    '.git', 'node_modules', '__pycache__', '.venv',
    'venv', 'dist', 'build', '.next', 'out'
}
SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.ttf', '.eot', '.zip', '.tar', '.gz',
    '.pyc', '.lock', '.vsix', '.db'
}

# --- Prompt-like variable names we care about ---
PROMPT_VAR_NAMES = {
    'system_prompt', 'system_message', 'systemprompt',
    'prompt', 'template', 'instruction', 'context',
    'SYSTEM_PROMPT', 'SYSTEM_MESSAGE'
}

# --- User-input variable names that are dangerous in prompts ---
USER_INPUT_VARS = [
    'user_input', 'user_message', 'user_query', 'user_prompt',
    'query', 'message', 'input', 'request', 'body', 'data',
    'text', 'content', 'q', 'msg', 'userInput', 'userMessage'
]

# --- Guardrail keywords — if any present near system prompt, it's (probably) safe ---
GUARDRAIL_KEYWORDS = [
    'refuse', 'ignore attempts', 'do not discuss', 'never reveal',
    'only answer', 'you must not', 'stay on topic', 'do not follow',
    'reject', 'forbidden', 'not allowed', 'must not', 'do not reveal',
    'cannot discuss', 'will not', 'should not'
]

# --- Jailbreak phrases to scan for in all string literals ---
JAILBREAK_PHRASES = [
    'you can do anything',
    'ignore previous instructions',
    'ignore all previous',
    'pretend you are',
    'disregard your instructions',
    'bypass your',
    'you are now',
    ' DAN ',
    'do anything now',
    'jailbreak',
    'ignore your training',
    'act as if you have no restrictions',
    'you have no restrictions',
]

# --- YAML/JSON keys that likely contain prompts ---
PROMPT_KEYS = {'system', 'prompt', 'instruction', 'template', 'system_prompt', 'message'}


def walk_files(repo_path, extensions):
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in extensions and ext not in SKIP_EXTENSIONS:
                yield os.path.join(root, fname)


def read_file(fpath):
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except:
        return []


def rel(fpath, repo_path):
    return os.path.relpath(fpath, repo_path)


def already_flagged(seen, fpath, line_no):
    key = (fpath, line_no)
    if key in seen:
        return True
    seen.add(key)
    return False


def check_unsafe_template(line):
    """
    Returns True if the line assigns a prompt-like variable
    to an f-string or concatenation involving user input.
    """
    # Must be an assignment to a prompt-like variable
    var_pattern = r'(' + '|'.join(re.escape(v) for v in PROMPT_VAR_NAMES) + r')'
    if not re.search(var_pattern, line):
        return False

    # Check for f-string with user input variable inside
    for uvar in USER_INPUT_VARS:
        # f"...{user_input}..." or f'...{user_input}...'
        if re.search(r'f["\'].*\{' + re.escape(uvar) + r'[\s\}]', line):
            return True
        # "..." + user_input  or  prompt + user_input
        if re.search(re.escape(uvar), line) and ('+' in line or '.format(' in line):
            return True

    # .format(user=, input=, query=, message=)
    format_keys = ['user', 'input', 'query', 'message', 'request', 'content']
    for fkey in format_keys:
        if re.search(r'\.format\s*\(.*' + re.escape(fkey) + r'\s*=', line):
            return True

    return False


def check_jailbreak(line):
    """Returns the matched phrase if a jailbreak phrase is found in the line."""
    lower = line.lower()
    for phrase in JAILBREAK_PHRASES:
        if phrase.lower() in lower:
            return phrase
    return None


def has_guardrails(lines, line_index, window=10):
    """Check ±window lines around line_index for guardrail keywords."""
    start = max(0, line_index - window)
    end = min(len(lines), line_index + window + 1)
    context = ' '.join(lines[start:end]).lower()
    for kw in GUARDRAIL_KEYWORDS:
        if kw.lower() in context:
            return True
    return False


def scan_code_file(fpath, repo_path, details, seen):
    """Scan .py / .js / .ts files."""
    lines = read_file(fpath)
    rpath = rel(fpath, repo_path)

    prompt_var_found = False

    for i, line in enumerate(lines):
        stripped = line.strip()
        line_no = i + 1

        # --- Detector A: Unsafe Prompt Templates ---
        if check_unsafe_template(stripped):
            if not already_flagged(seen, rpath, line_no):
                details.append({
                    "file": rpath,
                    "line": line_no,
                    "snippet": stripped,
                    "type": "Unsafe Prompt Template",
                    "severity": "critical",
                    "reason": "User input concatenated directly into prompt without sanitization — enables prompt injection"
                })

        # --- Track if we saw a prompt-like variable ---
        for vname in PROMPT_VAR_NAMES:
            if vname in stripped:
                prompt_var_found = True

                # --- Detector B: Missing Guardrails ---
                if not has_guardrails(lines, i):
                    flag_key = (rpath, line_no, 'guardrail')
                    if flag_key not in seen:
                        seen.add(flag_key)
                        details.append({
                            "file": rpath,
                            "line": line_no,
                            "snippet": stripped,
                            "type": "Missing Prompt Guardrails",
                            "severity": "high",
                            "reason": "System prompt has no refusal or boundary instructions — vulnerable to jailbreaking"
                        })
                break

        # --- Detector C: Jailbreak Phrases ---
        matched = check_jailbreak(stripped)
        if matched:
            if not already_flagged(seen, rpath, line_no):
                details.append({
                    "file": rpath,
                    "line": line_no,
                    "snippet": stripped,
                    "type": "Jailbreak Vulnerable Prompt",
                    "severity": "critical",
                    "reason": f"Prompt contains language that enables jailbreak attacks (matched: '{matched}')"
                })

    return prompt_var_found


def scan_yaml_file(fpath, repo_path, details, seen):
    """Scan .yaml / .yml files for prompt keys."""
    lines = read_file(fpath)
    rpath = rel(fpath, repo_path)
    prompt_found = False

    for i, line in enumerate(lines):
        stripped = line.strip()
        line_no = i + 1

        # Look for keys like: system_prompt: "..." or prompt: |
        key_match = re.match(r'^([a-zA-Z_]+)\s*:\s*(.*)', stripped)
        if not key_match:
            continue

        key = key_match.group(1).lower()
        value = key_match.group(2).strip().strip('"\'')

        if key not in PROMPT_KEYS:
            continue

        prompt_found = True

        # Detector A on value
        for uvar in USER_INPUT_VARS:
            if '{' + uvar + '}' in value or '{' + uvar + ' ' in value:
                if not already_flagged(seen, rpath, line_no):
                    details.append({
                        "file": rpath,
                        "line": line_no,
                        "snippet": stripped,
                        "type": "Unsafe Prompt Template",
                        "severity": "critical",
                        "reason": "User input interpolated into YAML prompt value without sanitization"
                    })

        # Detector B on value + surrounding lines
        if not has_guardrails(lines, i, window=10):
            flag_key = (rpath, line_no, 'guardrail')
            if flag_key not in seen:
                seen.add(flag_key)
                details.append({
                    "file": rpath,
                    "line": line_no,
                    "snippet": stripped,
                    "type": "Missing Prompt Guardrails",
                    "severity": "high",
                    "reason": "System prompt in YAML has no refusal or boundary instructions — vulnerable to jailbreaking"
                })

        # Detector C on value
        matched = check_jailbreak(value)
        if matched:
            if not already_flagged(seen, rpath, line_no):
                details.append({
                    "file": rpath,
                    "line": line_no,
                    "snippet": stripped,
                    "type": "Jailbreak Vulnerable Prompt",
                    "severity": "critical",
                    "reason": f"YAML prompt value contains jailbreak-enabling language (matched: '{matched}')"
                })

    return prompt_found


def scan_json_file(fpath, repo_path, details, seen):
    """Scan .json files for prompt keys."""
    import json as jsonlib
    rpath = rel(fpath, repo_path)
    prompt_found = False

    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            raw = f.read()
        data = jsonlib.loads(raw)
    except:
        return prompt_found

    # Flatten all string values with their approximate line numbers
    lines = raw.splitlines()

    def find_line(key, value):
        """Find the line number of a key:value pair in raw JSON."""
        search = f'"{key}"'
        for idx, l in enumerate(lines):
            if search in l:
                return idx + 1
        return 1

    def walk_json(obj, path=""):
        nonlocal prompt_found
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() in PROMPT_KEYS and isinstance(v, str):
                    prompt_found = True
                    line_no = find_line(k, v)

                    # Detector A
                    for uvar in USER_INPUT_VARS:
                        if '{' + uvar + '}' in v:
                            if not already_flagged(seen, rpath, line_no):
                                details.append({
                                    "file": rpath,
                                    "line": line_no,
                                    "snippet": v[:120],
                                    "type": "Unsafe Prompt Template",
                                    "severity": "critical",
                                    "reason": "User input interpolated into JSON prompt value without sanitization"
                                })

                    # Detector B — check value itself for guardrails
                    has_guard = any(kw.lower() in v.lower() for kw in GUARDRAIL_KEYWORDS)
                    if not has_guard:
                        flag_key = (rpath, line_no, 'guardrail')
                        if flag_key not in seen:
                            seen.add(flag_key)
                            details.append({
                                "file": rpath,
                                "line": line_no,
                                "snippet": v[:120],
                                "type": "Missing Prompt Guardrails",
                                "severity": "high",
                                "reason": "JSON prompt value has no refusal or boundary instructions — vulnerable to jailbreaking"
                            })

                    # Detector C
                    matched = check_jailbreak(v)
                    if matched:
                        if not already_flagged(seen, rpath, line_no):
                            details.append({
                                "file": rpath,
                                "line": line_no,
                                "snippet": v[:120],
                                "type": "Jailbreak Vulnerable Prompt",
                                "severity": "critical",
                                "reason": f"JSON prompt contains jailbreak-enabling language (matched: '{matched}')"
                            })
                else:
                    walk_json(v, path + '.' + k)
        elif isinstance(obj, list):
            for item in obj:
                walk_json(item, path)

    walk_json(data)
    return prompt_found


def scan(repo_path: str) -> dict:
    try:
        details = []
        seen = set()
        prompt_found_anywhere = False

        # Scan code files
        for fpath in walk_files(repo_path, {'.py', '.js', '.ts'}):
            found = scan_code_file(fpath, repo_path, details, seen)
            if found:
                prompt_found_anywhere = True

        # Scan YAML files
        for fpath in walk_files(repo_path, {'.yaml', '.yml'}):
            found = scan_yaml_file(fpath, repo_path, details, seen)
            if found:
                prompt_found_anywhere = True

        # Scan JSON files
        for fpath in walk_files(repo_path, {'.json'}):
            found = scan_json_file(fpath, repo_path, details, seen)
            if found:
                prompt_found_anywhere = True

        # Edge case: no LLM prompts detected at all
        if not prompt_found_anywhere:
            return {
                "name": NAME,
                "score": 100,
                "issues": 0,
                "details": [],
                "warning": "No LLM prompts detected in this repo"
            }

        # Scoring formula — contract law, do not change
        critical = len([d for d in details if d["severity"] == "critical"])
        high     = len([d for d in details if d["severity"] == "high"])
        medium   = len([d for d in details if d["severity"] == "medium"])
        score    = max(0, 100 - (critical * 15) - (high * 10) - (medium * 5))

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
            "warning": f"Could not run: {str(e)}"
        }
