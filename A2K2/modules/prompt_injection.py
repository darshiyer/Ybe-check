import os
import re

NAME = "Prompt Injection"

_SCANNER_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SKIP_DIRS = {
    '.git', 'node_modules', '__pycache__', '.venv',
    'venv', 'dist', 'build', '.next', 'out', 'env',
    'site-packages', '.antigravity', '.cursor', '.claude',
    '.ybe-check', '.tox', '.mypy_cache', '.pytest_cache',
    'graphify-out', '.terraform',
}
SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.ttf', '.eot', '.zip', '.tar', '.gz',
    '.pyc', '.lock', '.vsix', '.db'
}

# --- STAGE 1: Repo-level LLM detection ---
LLM_IMPORT_SIGNATURES = [
    'openai',
    'anthropic', 
    'langchain',
    'llamaindex',
    'llama_index',
    'cohere',
    'groq',
    'mistral',
    'huggingface',
    'transformers',
    'google.generativeai',
    'genai',
    'bedrock',
    'aiplatform',
    'vertexai',
]

# --- Path suppression for non-application files ---
SUPPRESSED_PATH_SEGMENTS = {
    'network', 'crypto-config', 'crypto_config', 'infrastructure',
    'k8s', 'kubernetes', 'helm', 'terraform', 'ansible',
    'migrations', 'fixtures', 'testdata', '__fixtures__'
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
    'you have no restrictions',
]

# --- Prompt-like keys in YAML/JSON that reliably indicate LLM prompts ---
PROMPT_KEYS = {'system_prompt', 'prompt', 'instruction', 'system_message'}

# Strong LLM-context keys for YAML/JSON files
LLM_CONTEXT_KEYS = {
    'model', 'temperature', 'max_tokens', 'top_p', 'stop', 'messages',
    'llm', 'openai', 'anthropic', 'gemini', 'completion', 'embedding'
}


def _is_suppressed_path(fpath, repo_path):
    """Return True if the file path contains any suppressed segments."""
    rel_path = os.path.relpath(fpath, repo_path).replace('\\', '/')
    parts = rel_path.split('/')
    for segment in SUPPRESSED_PATH_SEGMENTS:
        if segment in parts:
            return True
    return False


def detect_llm_libraries(repo_path):
    """
    Scan ALL .py, .js, .ts files for LLM library signatures.
    Returns True if any found.
    """
    extensions = {'.py', '.js', '.ts'}
    for fpath in walk_files(repo_path, extensions, skip_suppressed=False):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().lower()
                for sig in LLM_IMPORT_SIGNATURES:
                    if sig in content:
                        return True
        except:
            continue
    return False


def walk_files(repo_path, extensions, skip_suppressed=True):
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        _real = os.path.realpath(root)
        if _real == _SCANNER_ROOT or _real.startswith(_SCANNER_ROOT + os.sep):
            dirs.clear(); continue
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in extensions and ext not in SKIP_EXTENSIONS:
                fpath = os.path.join(root, fname)
                if skip_suppressed and _is_suppressed_path(fpath, repo_path):
                    continue
                yield fpath


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
    var_pattern = r'(' + '|'.join(re.escape(v) for v in PROMPT_VAR_NAMES) + r')'
    if not re.search(var_pattern, line):
        return False
    for uvar in USER_INPUT_VARS:
        if re.search(r'f["\'].*\{' + re.escape(uvar) + r'[\s\}]', line):
            return True
        if re.search(re.escape(uvar), line) and ('+' in line or '.format(' in line):
            return True
    format_keys = ['user', 'input', 'query', 'message', 'request', 'content']
    for fkey in format_keys:
        if re.search(r'\.format\s*\(.*' + re.escape(fkey) + r'\s*=', line):
            return True
    return False


def check_multiline_prompt(lines, i):
    line = lines[i].strip()
    var_pattern = r'(' + '|'.join(re.escape(v) for v in PROMPT_VAR_NAMES) + r')'
    if not re.search(var_pattern, line):
        return False
    window = lines[i:min(len(lines), i + 5)]
    combined = ' '.join(l.strip() for l in window)
    for uvar in USER_INPUT_VARS:
        if '{' + uvar + '}' in combined or '{' + uvar + ' ' in combined:
            return True
    return False


def check_jailbreak(line):
    lower = line.lower()
    for phrase in JAILBREAK_PHRASES:
        if phrase.lower() in lower:
            return phrase
    return None


def has_guardrails(lines, line_index, window=10):
    start = max(0, line_index - window)
    end = min(len(lines), line_index + window + 1)
    context = ' '.join(lines[start:end]).lower()
    for kw in GUARDRAIL_KEYWORDS:
        if kw.lower() in context:
            return True
    return False


def scan_code_file(fpath, repo_path, details, seen):
    lines = read_file(fpath)
    rpath = rel(fpath, repo_path)
    prompt_var_found = False

    for i, line in enumerate(lines):
        stripped = line.strip()
        line_no = i + 1

        if check_unsafe_template(stripped):
            if not already_flagged(seen, rpath, line_no):
                details.append({
                    "file": rpath,
                    "line": line_no,
                    "snippet": stripped,
                    "type": "Unsafe Prompt Template",
                    "severity": "critical",
                    "confidence": "high",
                    "reason": "User input concatenated directly into prompt without sanitization — enables prompt injection"
                })
        elif check_multiline_prompt(lines, i):
            if not already_flagged(seen, rpath, line_no):
                details.append({
                    "file": rpath,
                    "line": line_no,
                    "snippet": stripped,
                    "type": "Unsafe Prompt Template (Multiline)",
                    "severity": "critical",
                    "confidence": "medium",
                    "reason": "User input appears in a multi-line prompt assignment — potential prompt injection across lines"
                })

        for vname in PROMPT_VAR_NAMES:
            if vname in stripped:
                prompt_var_found = True
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
                            "confidence": "medium",
                            "reason": "System prompt has no refusal or boundary instructions — vulnerable to jailbreaking"
                        })
                break

        matched = check_jailbreak(stripped)
        if matched:
            if not already_flagged(seen, rpath, line_no):
                details.append({
                    "file": rpath,
                    "line": line_no,
                    "snippet": stripped,
                    "type": "Jailbreak Vulnerable Prompt",
                    "severity": "critical",
                    "confidence": "high",
                    "reason": f"Prompt contains language that enables jailbreak attacks (matched: '{matched}')"
                })
    return prompt_var_found


def _file_has_llm_context(lines: list) -> bool:
    content = ' '.join(lines).lower()
    return any(kw in content for kw in LLM_CONTEXT_KEYS)


def scan_yaml_file(fpath, repo_path, details, seen):
    lines = read_file(fpath)
    rpath = rel(fpath, repo_path)
    prompt_found = False
    has_llm_ctx = _file_has_llm_context(lines)

    for i, line in enumerate(lines):
        stripped = line.strip()
        line_no = i + 1
        key_match = re.match(r'^([a-zA-Z_]+)\s*:\s*(.*)', stripped)
        if not key_match:
            continue

        key = key_match.group(1).lower()
        value = key_match.group(2).strip().strip('"\'')
        if key not in PROMPT_KEYS:
            continue

        prompt_found = True
        for uvar in USER_INPUT_VARS:
            if '{' + uvar + '}' in value or '{' + uvar + ' ' in value:
                if not already_flagged(seen, rpath, line_no):
                    details.append({
                        "file": rpath,
                        "line": line_no,
                        "snippet": stripped,
                        "type": "Unsafe Prompt Template",
                        "severity": "critical",
                        "confidence": "high",
                        "reason": "User input interpolated into YAML prompt value without sanitization"
                    })

        if has_llm_ctx and not has_guardrails(lines, i, window=10):
            flag_key = (rpath, line_no, 'guardrail')
            if flag_key not in seen:
                seen.add(flag_key)
                details.append({
                    "file": rpath,
                    "line": line_no,
                    "snippet": stripped,
                    "type": "Missing Prompt Guardrails",
                    "severity": "high",
                    "confidence": "medium",
                    "reason": "System prompt in YAML has no refusal or boundary instructions — vulnerable to jailbreaking"
                })

        matched = check_jailbreak(value)
        if matched:
            if not already_flagged(seen, rpath, line_no):
                details.append({
                    "file": rpath,
                    "line": line_no,
                    "snippet": stripped,
                    "type": "Jailbreak Vulnerable Prompt",
                    "severity": "critical",
                    "confidence": "high",
                    "reason": f"YAML prompt value contains jailbreak-enabling language (matched: '{matched}')"
                })
    return prompt_found


def scan_json_file(fpath, repo_path, details, seen):
    import json as jsonlib
    rpath = rel(fpath, repo_path)
    prompt_found = False
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            raw = f.read()
        data = jsonlib.loads(raw)
    except:
        return False
    lines = raw.splitlines()

    def find_line(key, value):
        search = f'"{key}"'
        for idx, l in enumerate(lines):
            if search in l:
                return idx + 1
        return 1

    def walk_json(obj):
        nonlocal prompt_found
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() in PROMPT_KEYS and isinstance(v, str):
                    prompt_found = True
                    line_no = find_line(k, v)
                    for uvar in USER_INPUT_VARS:
                        if '{' + uvar + '}' in v:
                            if not already_flagged(seen, rpath, line_no):
                                details.append({
                                    "file": rpath, "line": line_no, "snippet": v[:120],
                                    "type": "Unsafe Prompt Template", "severity": "critical",
                                    "confidence": "high", "reason": "User input interpolated into JSON prompt value without sanitization"
                                })
                    if not any(kw.lower() in v.lower() for kw in GUARDRAIL_KEYWORDS):
                        flag_key = (rpath, line_no, 'guardrail')
                        if flag_key not in seen:
                            seen.add(flag_key)
                            details.append({
                                "file": rpath, "line": line_no, "snippet": v[:120],
                                "type": "Missing Prompt Guardrails", "severity": "high",
                                "confidence": "medium", "reason": "JSON prompt value has no refusal or boundary instructions"
                            })
                    matched = check_jailbreak(v)
                    if matched:
                        if not already_flagged(seen, rpath, line_no):
                            details.append({
                                "file": rpath, "line": line_no, "snippet": v[:120],
                                "type": "Jailbreak Vulnerable Prompt", "severity": "critical",
                                "confidence": "high", "reason": f"JSON prompt contains jailbreak-enabling language (matched: '{matched}')"
                            })
                else:
                    walk_json(v)
        elif isinstance(obj, list):
            for item in obj:
                walk_json(item)

    walk_json(data)
    return prompt_found


def scan(repo_path: str) -> dict:
    try:
        # --- STAGE 1: Repo-level detection ---
        if not detect_llm_libraries(repo_path):
            return {
                "name": NAME,
                "score": 100,
                "issues": 0,
                "details": [],
                "warning": "No LLM libraries detected in this repo — prompt injection scan skipped."
            }

        details = []
        seen = set()
        prompt_found_anywhere = False

        # Scan code files
        for fpath in walk_files(repo_path, {'.py', '.js', '.ts'}):
            if scan_code_file(fpath, repo_path, details, seen):
                prompt_found_anywhere = True

        # Scan YAML files
        for fpath in walk_files(repo_path, {'.yaml', '.yml'}):
            if scan_yaml_file(fpath, repo_path, details, seen):
                prompt_found_anywhere = True

        # Scan JSON files
        for fpath in walk_files(repo_path, {'.json'}):
            if scan_json_file(fpath, repo_path, details, seen):
                prompt_found_anywhere = True

        # Stage 2: No LLM prompts detected at all
        if not prompt_found_anywhere:
            return {
                "name": NAME,
                "score": 100,
                "issues": 0,
                "details": [],
                "warning": "No LLM prompts detected in this repo"
            }

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
