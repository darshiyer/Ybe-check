"""
Ybe Check AI layer — LLM-powered finding enrichment.

Provider chain: Blackbox AI → Google Gemini → static fallback.
Config stored in ~/.ybe-check/config.json.
"""

import json
import logging
from pathlib import Path
from typing import Any, Optional

import httpx

logger = logging.getLogger("ybe_check.ai")
_last_ai_error: Optional[str] = None

CONFIG_DIR = Path.home() / ".ybe-check"
CONFIG_FILE = CONFIG_DIR / "config.json"

BLACKBOX_ENDPOINT = "https://api.blackbox.ai/chat/completions"
BLACKBOX_DEFAULT_MODEL = "blackboxai/openai/gpt-5.2-chat"

SYSTEM_PROMPT = (
    "You are a senior application-security engineer. "
    "Given a scan finding from a production-readiness tool, return a JSON object with exactly these keys:\n"
    '  "impact"       — 1-2 sentence description of the security/production impact.\n'
    '  "remediation"  — concrete, actionable fix instructions (code snippets when useful).\n'
    '  "cwe"          — the most relevant CWE ID (e.g. "CWE-798"), or null.\n'
    '  "references"   — list of 1-3 URLs for further reading.\n'
    "Return ONLY valid JSON, no markdown fences, no extra text."
)


def _finding_prompt(finding: dict) -> str:
    loc = finding.get("location") or {}
    evidence = finding.get("evidence") or {}
    parts = [
        f"Type: {finding.get('type', 'unknown')}",
        f"Severity: {finding.get('severity', 'medium')}",
        f"Source module: {finding.get('source', 'unknown')}",
        f"File: {loc.get('path', 'N/A')}:{loc.get('line', '?')}",
        f"Summary: {finding.get('summary', '')}",
    ]
    if evidence.get("snippet"):
        parts.append(f"Code snippet:\n```\n{evidence['snippet'][:500]}\n```")
    if finding.get("details"):
        parts.append(f"Details: {finding['details'][:300]}")
    return "\n".join(parts)


def load_config() -> dict[str, Any]:
    cfg: dict[str, Any] = {}
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text("utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return cfg


def save_config(config: dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")


def _parse_llm_json(text: str) -> Optional[dict]:
    """Extract a JSON object from LLM output, tolerating markdown fences."""
    text = text.strip()
    if text.startswith("```"):
        first_nl = text.index("\n") if "\n" in text else 3
        text = text[first_nl:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _call_blackbox(prompt: str, config: dict) -> Optional[dict]:
    api_key = config.get("blackbox_api_key")
    if not api_key:
        return None

    payload = {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "model": config.get("blackbox_model") or BLACKBOX_DEFAULT_MODEL,
        "max_tokens": 1024,
        "stream": False,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    try:
        resp = httpx.post(BLACKBOX_ENDPOINT, json=payload, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        content = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        return _parse_llm_json(content)
    except Exception as exc:
        err_detail = str(exc)
        if hasattr(exc, "response") and exc.response is not None:
            try:
                err_body = exc.response.text[:500]
                err_detail = f"{exc} | Response: {err_body}"
            except Exception:
                pass
        logger.warning("Blackbox AI call failed: %s", err_detail)
        return None


def _call_gemini(prompt: str, config: dict) -> Optional[dict]:
    api_key = config.get("google_api_key")
    if not api_key:
        return None

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(
            f"{SYSTEM_PROMPT}\n\n{prompt}",
            generation_config={"temperature": 0.2, "max_output_tokens": 1024},
        )
        return _parse_llm_json(response.text)
    except Exception as exc:
        logger.debug("Gemini call failed: %s", exc)
        return None


def _static_fallback(finding: dict) -> dict:
    severity = finding.get("severity", "medium")
    source = finding.get("source", "unknown")
    summary = finding.get("summary", "")
    return {
        "impact": f"This {severity}-severity finding from '{source}' may affect production readiness.",
        "remediation": (
            f"Address the {source} finding: {summary[:200]}. "
            f"Severity: {severity}. "
            "Review the file/location and apply the recommended fix. "
            "For production, ensure no secrets are committed and dependencies are pinned."
        ),
        "cwe": None,
        "references": [],
    }


def enrich_finding(finding: dict, config: Optional[dict] = None) -> dict:
    """
    Return an ai_analysis dict for the given finding.

    Tries Blackbox AI first, then Gemini, then a static fallback.
    """
    if config is None:
        config = load_config()

    prompt = _finding_prompt(finding)

    result = _call_blackbox(prompt, config)
    if result and "impact" in result and "remediation" in result:
        result.setdefault("cwe", None)
        result.setdefault("references", [])
        return result

    result = _call_gemini(prompt, config)
    if result and "impact" in result and "remediation" in result:
        result.setdefault("cwe", None)
        result.setdefault("references", [])
        return result

    return _static_fallback(finding)


# ---------------------------------------------------------------------------
# Chat: free-form conversation about scan results
# ---------------------------------------------------------------------------

CHAT_SYSTEM_PROMPT = (
    "You are Ybe Check AI, a senior application-security assistant. "
    "You have access to the full scan report for a repository. "
    "Answer the user's questions about findings, how to fix them, "
    "prioritisation, and general security best practices. "
    "Be concise, actionable, and reference specific findings by ID when relevant. "
    "Use markdown formatting for readability."
)


def _build_report_context(report: dict) -> str:
    """Compress the report into a context string for the LLM."""
    lines = [
        f"Score: {report.get('overall_score', '?')}/100 — {report.get('verdict', '?')}",
        f"Modules run: {', '.join(report.get('modules_run', []))}",
        f"Total findings: {len(report.get('findings', []))}",
        "",
    ]
    for f in report.get("findings", [])[:60]:
        loc = f.get("location") or {}
        loc_str = f"{loc.get('path', '?')}:{loc.get('line', '?')}"
        lines.append(
            f"[{f.get('id')}] {f.get('severity','?').upper()} | "
            f"{f.get('type','?')} | {loc_str} | {(f.get('summary') or '')[:120]}"
        )
    if len(report.get("findings", [])) > 60:
        lines.append(f"... and {len(report['findings']) - 60} more findings")
    return "\n".join(lines)


def chat(
    message: str,
    report: dict,
    history: Optional[list[dict]] = None,
    config: Optional[dict] = None,
) -> str:
    """
    Send a chat message with scan-report context to the LLM.

    Returns the assistant's reply as a string.
    """
    if config is None:
        config = load_config()

    context = _build_report_context(report)
    messages = [
        {"role": "system", "content": f"{CHAT_SYSTEM_PROMPT}\n\n--- SCAN REPORT ---\n{context}\n--- END REPORT ---"},
    ]
    if history:
        messages.extend(history)
    messages.append({"role": "user", "content": message})

    reply = _chat_blackbox(messages, config)
    if reply:
        return reply

    reply = _chat_gemini(messages, config)
    if reply:
        return reply

    base = "I'm unable to connect to the AI service. "
    global _last_ai_error
    if _last_ai_error:
        err = _last_ai_error
        _last_ai_error = None
        return base + f"Details: {err}"
    return base + "Check API keys in ~/.ybe-check/config.json."


def _chat_blackbox(messages: list[dict], config: dict) -> Optional[str]:
    api_key = config.get("blackbox_api_key")
    if not api_key:
        return None

    payload = {
        "messages": messages,
        "model": config.get("blackbox_model") or BLACKBOX_DEFAULT_MODEL,
        "max_tokens": 2048,
        "stream": False,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    try:
        resp = httpx.post(BLACKBOX_ENDPOINT, json=payload, headers=headers, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        return (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        ) or None
    except Exception as exc:
        err_detail = str(exc)
        if hasattr(exc, "response") and exc.response is not None:
            try:
                err_detail = f"{exc} | Response: {exc.response.text[:500]}"
            except Exception:
                pass
        logger.warning("Blackbox AI chat failed: %s", err_detail)
        global _last_ai_error
        _last_ai_error = err_detail
        return None


def _chat_gemini(messages: list[dict], config: dict) -> Optional[str]:
    api_key = config.get("google_api_key")
    if not api_key:
        return None

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        combined = "\n\n".join(
            f"{'User' if m['role'] == 'user' else 'System' if m['role'] == 'system' else 'Assistant'}: {m['content']}"
            for m in messages
        )
        response = model.generate_content(
            combined,
            generation_config={"temperature": 0.3, "max_output_tokens": 2048},
        )
        return response.text or None
    except Exception as exc:
        logger.debug("Gemini chat failed: %s", exc)
        return None
