import os
import re
from typing import List, Dict, Set, Tuple

NAME = "PII & Logging"

SKIP_DIRS = {
    '.git', 'node_modules', '__pycache__', '.venv',
    'venv', 'dist', 'build', '.next', 'out'
}
SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.ttf', '.eot', '.zip', '.tar', '.gz',
    '.pyc', '.lock', '.vsix', '.db'
}

# --- PII Patterns ---
PII_PATTERNS = [
    {
        "pattern": re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
        "type": "Hardcoded Email",
        "severity": "high",
        "confidence": "high",
        "reason": "Hardcoded email address found — move to environment config"
    },
    {
        "pattern": re.compile(r'\b[6-9]\d{9}\b'),
        "type": "Hardcoded Phone Number",
        "severity": "high",
        "confidence": "medium",
        "reason": "Hardcoded Indian phone number found — remove from source code"
    },
    {
        "pattern": re.compile(r'\b\d{4}[\s-]\d{4}[\s-]\d{4}\b'),
        "type": "Hardcoded Aadhaar",
        "severity": "critical",
        "confidence": "high",
        "reason": "Hardcoded Aadhaar number — critical PII violation under DPDP Act"
    },
    {
        "pattern": re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'),
        "type": "Hardcoded PAN",
        "severity": "critical",
        "confidence": "high",
        "reason": "Hardcoded PAN number — critical PII violation under DPDP Act"
    },
    {
        "pattern": re.compile(r'\b(?:\d{4}[- ]){3}\d{4}\b'),
        "type": "Hardcoded Credit Card",
        "severity": "critical",
        "confidence": "low",
        "reason": "Possible hardcoded credit card number — critical financial PII"
    }
]

# --- Unsafe Logging ---
LOG_FUNCTIONS = [
    "logger.info", "logger.debug", "logger.warning", "logger.error", "logger.critical",
    "logging.info", "logging.debug", "logging.warning", "logging.error",
    "console.log", "console.error", "console.warn", "console.debug", "print",
]

SENSITIVE_ARGS = [
    "request", "response", "user", "password", "token", "body", "data", "payload",
    "req", "res", "credentials", "secret", "auth", "headers", "session",
    "user_data", "userdata", "form", "params"
]

# --- Config File Patterns ---
CONFIG_FILE_PATTERNS = [
    re.compile(r'connection.?profile', re.IGNORECASE),
    re.compile(r'config\.(js|ts|json|yaml|yml)$', re.IGNORECASE),
    re.compile(r'settings\.(js|ts|json|yaml|yml)$', re.IGNORECASE),
    re.compile(r'\.config\.(js|ts)$', re.IGNORECASE),
    re.compile(r'infrastructure', re.IGNORECASE),
    re.compile(r'network/', re.IGNORECASE),
    re.compile(r'crypto.?config', re.IGNORECASE),
    re.compile(r'docker.?compose', re.IGNORECASE),
    re.compile(r'k8s/', re.IGNORECASE),
    re.compile(r'kubernetes/', re.IGNORECASE),
]

def _build_log_patterns():
    patterns = []
    sensitive_group = '|'.join(re.escape(s) for s in SENSITIVE_ARGS)
    for fn in LOG_FUNCTIONS:
        escaped_fn = re.escape(fn)
        pat = re.compile(escaped_fn + r'\s*\(\s*(' + sensitive_group + r')\s*(?![.\w])')
        patterns.append((fn, pat))
    return patterns

LOG_PATTERNS = _build_log_patterns()

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

def should_skip_file(rpath):
    lower = rpath.lower()
    skip_markers = ['test', 'spec', '__mock__', '__tests__', 'fixtures']
    return any(marker in lower for marker in skip_markers)

def is_comment_line(line):
    stripped = line.strip()
    return stripped.startswith('#') or stripped.startswith('//')

def _is_config_file(rpath):
    return any(pat.search(rpath) for pat in CONFIG_FILE_PATTERNS)

def _downgrade_severity(severity):
    if severity == "critical": return "high"
    if severity == "high":     return "medium"
    if severity == "medium":   return "low"
    return severity

def scan_file(fpath, repo_path, seen) -> List[Dict]:
    file_findings = []
    lines = read_file(fpath)
    rpath = rel(fpath, repo_path)
    is_config = _is_config_file(rpath)

    for i, line in enumerate(lines):
        line_no = i + 1
        if is_comment_line(line): continue
        stripped = line.strip()
        line_matched_phone = False

        for pii in PII_PATTERNS:
            if pii["type"] == "Hardcoded Credit Card" and line_matched_phone:
                continue
            if pii["pattern"].search(stripped):
                if pii["type"] == "Hardcoded Phone Number":
                    line_matched_phone = True
                
                dedup_key = (rpath, line_no, pii["type"])
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    
                    sev = pii["severity"]
                    reason = pii["reason"]
                    if is_config:
                        sev = _downgrade_severity(sev)
                        reason += " [config file — verify this is not user PII]"
                    
                    file_findings.append({
                        "file": rpath,
                        "line": line_no,
                        "snippet": stripped,
                        "type": pii["type"],
                        "severity": sev,
                        "confidence": pii["confidence"],
                        "reason": reason
                    })

        for fn_name, pattern in LOG_PATTERNS:
            if pattern.search(stripped):
                dedup_key = (rpath, line_no, "Unsafe Logging")
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    
                    sev = "high"
                    reason = f"Full object passed to {fn_name}() — may expose PII or secrets in logs"
                    if is_config:
                        sev = _downgrade_severity(sev)
                        reason += " [config file — verify this is not user PII]"
                    
                    file_findings.append({
                        "file": rpath,
                        "line": line_no,
                        "snippet": stripped,
                        "type": "Unsafe Logging",
                        "severity": sev,
                        "confidence": "high",
                        "reason": reason
                    })
                break
    return file_findings

def scan(repo_path: str) -> dict:
    try:
        all_findings = []
        seen = set()

        for fpath in walk_files(repo_path, {'.py', '.js', '.ts'}):
            rpath = rel(fpath, repo_path)
            if should_skip_file(rpath): continue
            
            file_findings = scan_file(fpath, repo_path, seen)
            
            # Collapse repeated findings of the SAME type in the SAME file
            findings_by_type = {}
            for f in file_findings:
                ftype = f["type"]
                if ftype not in findings_by_type:
                    findings_by_type[ftype] = []
                findings_by_type[ftype].append(f)
            
            for ftype, findings in findings_by_type.items():
                if len(findings) > 5:
                    # Keep first 3
                    all_findings.extend(findings[:3])
                    # Add summary for the rest
                    last = findings[-1]
                    rem_count = len(findings) - 3
                    all_findings.append({
                        "file": rpath,
                        "line": 0,
                        "type": f"{ftype} (repeated)",
                        "severity": last["severity"],
                        "reason": f"{rem_count} additional {ftype.lower()}s found in this file — review entire file",
                        "confidence": "medium"
                    })
                else:
                    all_findings.extend(findings)

        critical = len([d for d in all_findings if d["severity"] == "critical"])
        high     = len([d for d in all_findings if d["severity"] == "high"])
        medium   = len([d for d in all_findings if d["severity"] == "medium"])
        score    = max(0, 100 - (critical * 15) - (high * 10) - (medium * 5))

        return {
            "name": NAME,
            "score": score,
            "issues": len(all_findings),
            "details": all_findings
        }
    except Exception as e:
        return {
            "name": NAME,
            "score": None,
            "issues": 0,
            "details": [],
            "warning": f"Could not run: {str(e)}"
        }
