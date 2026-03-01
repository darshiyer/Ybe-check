"""
Ybe Check Dashboard — local FastAPI web UI for scan results + AI chat.

Redesigned to match the website's modern bento grid layout with
aurora hero, security persona, module scores, verdict cards, and
full findings drill-down.

Start via:  ybe-check dashboard
            python -m ybe_check.dashboard
"""

import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from .ai import CONFIG_FILE, chat as ai_chat
from .ai import enrich_finding, load_config
from .core import filter_findings, run_scan

app = FastAPI(title="Ybe Check Dashboard", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REPORT_FILE = "ybe-report.json"


def _report_path() -> Path:
    return Path.cwd() / REPORT_FILE


def _load_report() -> Optional[dict]:
    p = _report_path()
    if p.exists():
        try:
            return json.loads(p.read_text("utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return None


def _save_report(report: dict) -> None:
    _report_path().write_text(json.dumps(report, indent=2), encoding="utf-8")


@app.get("/api/ai-status")
def api_ai_status():
    """Return AI config status (no secrets)."""
    config = load_config()
    return JSONResponse({
        "has_blackbox_key": bool(config.get("blackbox_api_key")),
        "has_google_key": bool(config.get("google_api_key")),
        "config_path": str(CONFIG_FILE),
    })


@app.get("/api/report")
def api_report():
    report = _load_report()
    if not report:
        return JSONResponse({"error": "No report found. Run a scan first."}, status_code=404)
    return JSONResponse(report)


@app.post("/api/scan")
def api_scan(path: str = Query(".", description="Repository path to scan")):
    try:
        resolved = str(Path(path).resolve()) if path else str(Path.cwd())
        if not Path(resolved).is_dir():
            return JSONResponse({"error": f"Not a directory: {resolved}"}, status_code=400)
        report = run_scan(resolved)
        _save_report(report)
        return JSONResponse(report)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/remediation/{finding_id}")
def api_remediation(finding_id: str):
    report = _load_report()
    if not report:
        return JSONResponse({"error": "No report found."}, status_code=404)
    findings = report.get("findings", [])
    match = next((f for f in findings if f.get("id") == finding_id), None)
    if not match:
        return JSONResponse({"error": f"Finding '{finding_id}' not found."}, status_code=404)
    ai = match.get("ai_analysis")
    if not ai:
        config = load_config()
        ai = enrich_finding(match, config)
        match["ai_analysis"] = ai
        _save_report(report)
    return JSONResponse({"finding_id": finding_id, **ai})


@app.get("/api/findings")
def api_findings(severity: Optional[str] = Query(None), category: Optional[str] = Query(None)):
    report = _load_report()
    if not report:
        return JSONResponse({"error": "No report found."}, status_code=404)
    return JSONResponse(filter_findings(report, severity=severity, category=category))


class ChatRequest(BaseModel):
    message: str
    history: Optional[list[dict]] = None


@app.post("/api/chat")
def api_chat(req: ChatRequest):
    report = _load_report()
    if not report:
        return JSONResponse({"reply": "No scan report loaded. Please run a scan first."})
    config = load_config()
    reply = ai_chat(req.message, report, history=req.history, config=config)
    return JSONResponse({"reply": reply})


# ══════════════════════════════════════════════════════════════════
# HTML — Modern bento grid dashboard (matches website design)
# ══════════════════════════════════════════════════════════════════

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Ybe Check — Security Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet"/>
<style>
/* ── DESIGN TOKENS ─────────────────────────────────────── */
:root {
  --bg: #0a0a0b;
  --card: rgba(35, 35, 40, 0.35);
  --cardLt: rgba(255, 255, 255, 0.04);
  --border: rgba(255, 255, 255, 0.1);
  --dim: #888;
  --dimLt: #aaa;
  --radius: 20px;
  --text: #E6EDF3;
  --text2: #8B949E;
  --green: #3FB950;
  --red: #F85149;
  --orange: #DB6D28;
  --blue: #58A6FF;
  --yellow: #D29922;
  --purple: #a78bfa;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { background:var(--bg); color:var(--text); font-family:'Inter',-apple-system,'Segoe UI',Roboto,sans-serif; display:flex; height:100vh; overflow:hidden; }

/* ── ANIMATIONS ────────────────────────────────────────── */
@keyframes fadeIn { from{opacity:0;transform:translateY(12px)} to{opacity:1;transform:translateY(0)} }
@keyframes fadeInUp { from{opacity:0;transform:translateY(20px)} to{opacity:1;transform:translateY(0)} }
@keyframes heroGradientShift { 0%,100%{background-position:0% 50%} 50%{background-position:100% 50%} }
@keyframes dashboardReveal { from{opacity:0;transform:translateY(20px);filter:blur(10px)} to{opacity:1;transform:translateY(0);filter:blur(0)} }
@keyframes spinLoader { to{transform:rotate(360deg)} }
@keyframes pulseDot { 0%,100%{opacity:1} 50%{opacity:0.4} }
@keyframes pulseGlow { 0%,100%{box-shadow:0 0 15px rgba(124,107,239,0.3)} 50%{box-shadow:0 0 25px rgba(124,107,239,0.5)} }
@keyframes toastIn { from{opacity:0;transform:translate(-50%,20px)} to{opacity:1;transform:translate(-50%,0)} }
@keyframes bounce { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-4px)} }

/* ── SCROLLBAR ─────────────────────────────────────────── */
::-webkit-scrollbar { width:6px; }
::-webkit-scrollbar-track { background:var(--bg); }
::-webkit-scrollbar-thumb { background:rgba(255,255,255,0.08); border-radius:3px; }
::-webkit-scrollbar-thumb:hover { background:rgba(255,255,255,0.15); }
::selection { background:rgba(88,166,255,0.3); color:var(--text); }

/* ── CARD ──────────────────────────────────────────────── */
.mcard { background:var(--card); backdrop-filter:blur(45px) saturate(180%); -webkit-backdrop-filter:blur(45px) saturate(180%); border-radius:var(--radius); padding:28px; border:1px solid var(--border); box-shadow:0 10px 40px -10px rgba(0,0,0,0.5); }
.section-label { font-size:12px; font-weight:600; color:var(--dim); text-transform:uppercase; letter-spacing:1.5px; margin-bottom:14px; }

/* ── CHAT SIDEBAR ──────────────────────────────────────── */
.chat-sidebar { width:340px; flex-shrink:0; background:rgba(20,20,24,0.95); backdrop-filter:blur(20px); border-right:1px solid var(--border); display:flex; flex-direction:column; height:100vh; z-index:20; }
.chat-header { height:60px; display:flex; align-items:center; padding:0 20px; border-bottom:1px solid var(--border); gap:12px; }
.chat-logo { width:36px; height:36px; border-radius:10px; background:linear-gradient(135deg,#58A6FF,#a78bfa); display:flex; align-items:center; justify-content:center; color:#fff; font-weight:900; font-size:14px; }
.chat-title { font-weight:700; font-size:15px; color:var(--text); }
.chat-sub { font-size:11px; color:var(--dim); margin-top:2px; }
.chat-messages { flex:1; overflow-y:auto; padding:16px; display:flex; flex-direction:column; gap:16px; }
.chat-bubble { max-width:85%; padding:12px 16px; border-radius:16px; font-size:13px; line-height:1.6; word-wrap:break-word; white-space:pre-wrap; }
.chat-ai { background:rgba(88,166,255,0.08); border:1px solid rgba(88,166,255,0.1); border-top-left-radius:4px; color:var(--text); align-self:flex-start; }
.chat-user { background:linear-gradient(135deg,#58A6FF,#79b8ff); color:#fff; border-top-right-radius:4px; align-self:flex-end; }
.chat-input-wrap { padding:16px; border-top:1px solid var(--border); }
.chat-input { width:100%; background:rgba(255,255,255,0.05); border:1px solid var(--border); border-radius:12px; padding:12px 48px 12px 16px; color:var(--text); font-size:13px; font-family:inherit; outline:none; transition:border-color 0.2s; }
.chat-input:focus { border-color:var(--blue); }
.chat-input::placeholder { color:var(--dim); }
.chat-send { position:absolute; right:24px; top:50%; transform:translateY(-50%); background:none; border:none; color:var(--blue); cursor:pointer; font-size:18px; padding:4px; }
.chat-typing { display:flex; gap:4px; padding:12px 16px; align-self:flex-start; }
.chat-typing span { width:6px; height:6px; border-radius:50%; background:var(--dim); animation:bounce 1.2s infinite; }
.chat-typing span:nth-child(2) { animation-delay:0.1s; }
.chat-typing span:nth-child(3) { animation-delay:0.2s; }

/* ── MAIN AREA ─────────────────────────────────────────── */
.main-area { flex:1; display:flex; flex-direction:column; height:100vh; overflow:hidden; }
.top-bar { height:56px; display:flex; align-items:center; justify-content:space-between; padding:0 28px; border-bottom:1px solid var(--border); flex-shrink:0; }
.status-pill { display:flex; align-items:center; gap:8px; padding:5px 14px; border-radius:100px; font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px; }
.scan-btn { display:flex; align-items:center; gap:8px; padding:9px 20px; border-radius:10px; border:none; cursor:pointer; font-size:13px; font-weight:700; font-family:inherit; transition:all 0.2s; }
.scan-btn:hover { transform:translateY(-1px); }
.scan-primary { background:linear-gradient(135deg,#58A6FF,#79b8ff); color:#fff; box-shadow:0 4px 20px rgba(88,166,255,0.25); }
.scan-secondary { background:rgba(255,255,255,0.05); color:var(--text); border:1px solid var(--border); }
.content { flex:1; overflow-y:auto; }

/* ── EMPTY STATE ───────────────────────────────────────── */
.empty-state { display:flex; flex-direction:column; align-items:center; justify-content:center; height:100%; gap:16px; animation:fadeIn 0.6s ease-out; }
.empty-icon { width:80px; height:80px; border-radius:20px; background:var(--card); border:1px solid var(--border); display:flex; align-items:center; justify-content:center; font-size:36px; }

/* ── DASHBOARD GRID ────────────────────────────────────── */
.shell { max-width:1260px; margin:0 auto; padding:28px 24px 80px; animation:dashboardReveal 0.6s ease-out; }
.row1 { display:grid; grid-template-columns:1.3fr 0.8fr 0.9fr; gap:12px; margin-bottom:12px; }
.row2 { display:grid; grid-template-columns:1.2fr 0.8fr 1fr; gap:12px; margin-bottom:12px; }
@media(max-width:1100px) { .row1,.row2 { grid-template-columns:1fr; } }

/* ── HERO CARD ─────────────────────────────────────────── */
.hero-card { padding:0!important; overflow:hidden; position:relative; min-height:270px; }
.hero-bg { position:absolute; inset:0; background:linear-gradient(135deg,#1a0533 0%,#2d1b69 25%,#1b3a5c 50%,#0d4f4f 75%,#2a1050 100%); background-size:400% 400%; animation:heroGradientShift 12s ease-in-out infinite; }
.hero-overlay { position:absolute; inset:0; background:radial-gradient(ellipse at 30% 80%,rgba(120,80,220,0.35),transparent 60%),radial-gradient(ellipse at 70% 20%,rgba(40,180,200,0.25),transparent 50%); }
.hero-inner { position:relative; z-index:1; padding:32px 36px; display:flex; flex-direction:column; justify-content:flex-end; height:100%; min-height:270px; }
.hero-meta { display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px; }
.hero-label { font-size:14px; font-weight:500; color:rgba(255,255,255,0.55); }
.hero-version { font-size:10px; font-weight:700; color:rgba(255,255,255,0.3); background:rgba(255,255,255,0.1); padding:2px 8px; border-radius:4px; }
.hero-score { font-size:96px; font-weight:900; line-height:1; color:#fff; letter-spacing:-3px; font-variant-numeric:tabular-nums; }
.hero-summary { margin-top:20px; padding:10px 20px; background:rgba(0,0,0,0.3); backdrop-filter:blur(14px); border-radius:10px; font-size:14px; color:rgba(255,255,255,0.85); line-height:1.5; max-width:380px; }
.hero-footer { margin-top:12px; display:flex; justify-content:space-between; align-items:center; font-size:11px; color:rgba(255,255,255,0.4); font-family:monospace; }

/* ── ISSUES CARD ───────────────────────────────────────── */
.issues-card { display:flex; flex-direction:column; justify-content:space-between; }
.issues-num { font-size:72px; font-weight:900; line-height:1; font-variant-numeric:tabular-nums; margin-top:16px; }
.issues-tags { margin-top:auto; display:flex; flex-wrap:wrap; gap:6px; }
.issues-tag { padding:4px 10px; border-radius:6px; font-size:11px; font-weight:600; }

/* ── PERSONA CARD ──────────────────────────────────────── */
.persona-card { display:flex!important; flex-direction:column; align-items:center; justify-content:center; text-align:center; background:#f5f5f5!important; color:#111; }
.persona-badge { display:inline-block; padding:5px 16px; border-radius:20px; background:var(--bg); color:#fff; font-size:12px; font-weight:700; }
.persona-icon { width:56px; height:56px; border-radius:50%; background:var(--bg); display:flex; align-items:center; justify-content:center; margin:16px 0 12px; font-size:28px; }
.persona-label { font-size:11px; font-weight:600; color:#888; text-transform:uppercase; letter-spacing:1px; }
.persona-title { font-size:26px; font-weight:800; color:#111; line-height:1.15; margin:6px 0 8px; }
.persona-desc { font-size:12px; color:#666; line-height:1.5; max-width:180px; }

/* ── MODULE SCORES ─────────────────────────────────────── */
.mod-row { display:flex; align-items:center; gap:12px; margin-bottom:14px; cursor:pointer; transition:opacity 0.15s; background:none; border:none; font-family:inherit; padding:0; text-align:left; width:100%; }
.mod-row:hover { opacity:0.7; }
.mod-row:last-child { margin-bottom:0; }
.mod-icon { width:32px; height:32px; border-radius:50%; display:flex; align-items:center; justify-content:center; flex-shrink:0; font-size:14px; }
.mod-body { flex:1; min-width:0; }
.mod-name { font-size:13px; font-weight:600; color:var(--text); margin-bottom:4px; }
.mod-bar { height:6px; border-radius:3px; background:var(--border); overflow:hidden; }
.mod-fill { height:100%; border-radius:3px; transition:width 0.8s ease-out; }
.mod-pct { font-size:13px; font-weight:700; color:var(--dimLt); min-width:30px; text-align:right; }

/* ── VERDICT CARD ──────────────────────────────────────── */
.verdict-card { padding:28px; display:flex; flex-direction:column; justify-content:space-between; border-radius:var(--radius); border:1px solid var(--border); }
.verdict-label { font-size:12px; font-weight:700; color:rgba(255,255,255,0.65); text-transform:uppercase; letter-spacing:1.5px; }
.verdict-value { font-size:36px; font-weight:800; color:#fff; line-height:1.15; margin:12px 0; }
.verdict-dots { display:flex; gap:6px; flex-wrap:wrap; margin-top:auto; }
.verdict-dot { width:28px; height:28px; border-radius:6px; }

/* ── SUMMARY ───────────────────────────────────────────── */
.summary-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:20px; }
.summary-cell { padding:14px 16px; border-radius:12px; background:var(--cardLt); }
.summary-val { font-size:24px; font-weight:800; font-variant-numeric:tabular-nums; }
.summary-lbl { font-size:11px; color:var(--dim); margin-top:2px; }

/* ── TOP FIXES ─────────────────────────────────────────── */
.fix-item { padding:10px 0; border-bottom:1px solid var(--border); font-size:13px; color:var(--dimLt); line-height:1.5; display:flex; gap:10px; }
.fix-item:last-child { border-bottom:none; }
.fix-num { font-weight:800; color:var(--dim); font-size:12px; }
.fix-text { color:var(--text); }
.fix-file { font-size:11px; color:var(--dimLt); font-family:monospace; margin-top:2px; }

/* ── MODULE CARDS GRID ─────────────────────────────────── */
.modules-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(380px,1fr)); gap:12px; }
.module-card { border-radius:var(--radius); padding:20px 24px; border:1px solid var(--border); background:var(--card); display:flex; align-items:center; gap:16px; cursor:pointer; font-family:inherit; transition:all 0.2s; animation:fadeIn 0.4s ease-out both; text-align:left; width:100%; }
.module-card:hover { border-color:rgba(255,255,255,0.15); background:var(--cardLt); transform:translateY(-1px); }
.mc-icon { width:42px; height:42px; border-radius:12px; display:flex; align-items:center; justify-content:center; flex-shrink:0; font-size:18px; }
.mc-body { flex:1; min-width:0; }
.mc-name { font-size:14px; font-weight:600; color:var(--text); margin-bottom:6px; display:flex; align-items:center; gap:8px; }
.mc-meta { display:flex; align-items:center; gap:10px; }
.mc-bar { flex:1; height:4px; border-radius:2px; background:var(--border); overflow:hidden; }
.mc-fill { height:100%; border-radius:2px; transition:width 0.8s ease-out; }
.mc-issues { font-size:12px; color:var(--dim); white-space:nowrap; }
.mc-score { font-size:24px; font-weight:800; font-variant-numeric:tabular-nums; min-width:34px; text-align:right; }
.status-badge { font-size:10px; font-weight:700; padding:2px 8px; border-radius:6px; letter-spacing:0.5px; text-transform:uppercase; }

/* ── FINDINGS TABLE ────────────────────────────────────── */
.findings-wrap { border-radius:var(--radius); border:1px solid var(--border); background:var(--card); overflow:hidden; margin-top:24px; }
.findings-header { padding:20px 24px; border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px; }
.findings-title { font-size:16px; font-weight:700; color:var(--text); display:flex; align-items:center; gap:10px; }
.findings-count { font-size:11px; background:var(--cardLt); color:var(--dim); padding:3px 10px; border-radius:100px; border:1px solid var(--border); }
.filter-select { background:rgba(255,255,255,0.05); border:1px solid var(--border); color:var(--text); font-size:12px; padding:6px 12px; border-radius:8px; font-family:inherit; outline:none; cursor:pointer; }
.filter-select:focus { border-color:var(--blue); }
.ftable { width:100%; border-collapse:collapse; font-size:12px; }
.ftable th { text-align:left; padding:10px 16px; color:var(--dim); font-weight:600; text-transform:uppercase; font-size:10px; letter-spacing:0.5px; border-bottom:1px solid var(--border); background:var(--cardLt); }
.ftable td { padding:10px 16px; border-bottom:1px solid rgba(255,255,255,0.02); }
.ftable tr:hover { background:rgba(88,166,255,0.03); }
.sev-pill { display:inline-flex; align-items:center; gap:4px; padding:3px 10px; border-radius:100px; font-size:10px; font-weight:700; text-transform:uppercase; }
.file-link { font-family:monospace; color:var(--blue); font-size:11px; }
.get-fix-btn { background:linear-gradient(135deg,#58A6FF,#79b8ff); color:#fff; border:none; padding:5px 14px; border-radius:8px; cursor:pointer; font-size:11px; font-weight:700; font-family:inherit; transition:all 0.15s; }
.get-fix-btn:hover { transform:scale(1.05); box-shadow:0 4px 15px rgba(88,166,255,0.3); }
.pagination { padding:12px 24px; border-top:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; font-size:12px; color:var(--dim); }
.page-btn { padding:5px 14px; border-radius:8px; background:rgba(255,255,255,0.05); border:1px solid var(--border); color:var(--text); cursor:pointer; font-size:12px; font-family:inherit; transition:all 0.15s; }
.page-btn:hover:not(:disabled) { background:rgba(255,255,255,0.1); }
.page-btn:disabled { opacity:0.3; cursor:default; }

/* ── REMEDIATION MODAL ─────────────────────────────────── */
.modal-overlay { display:none; position:fixed; inset:0; z-index:100; background:rgba(0,0,0,0.6); backdrop-filter:blur(8px); align-items:center; justify-content:center; padding:24px; }
.modal-overlay.open { display:flex; }
.modal-box { width:100%; max-width:800px; max-height:90vh; overflow:hidden; border-radius:var(--radius); background:rgba(20,20,24,0.98); border:1px solid var(--border); box-shadow:0 40px 80px rgba(0,0,0,0.5); display:flex; flex-direction:column; animation:fadeIn 0.3s ease-out; }
.modal-header { padding:24px 28px; border-bottom:1px solid var(--border); display:flex; align-items:flex-start; justify-content:space-between; }
.modal-body { flex:1; overflow-y:auto; padding:24px 28px; }
.modal-footer { padding:16px 28px; border-top:1px solid var(--border); display:flex; justify-content:flex-end; }
.modal-close { background:rgba(255,255,255,0.05); border:1px solid var(--border); color:var(--text); padding:8px 20px; border-radius:10px; cursor:pointer; font-size:13px; font-weight:600; font-family:inherit; transition:all 0.15s; }
.modal-close:hover { background:rgba(255,255,255,0.1); }
.remediation-step { display:flex; gap:14px; padding:12px 16px; border-radius:12px; background:var(--cardLt); border:1px solid var(--border); margin-bottom:8px; }
.step-num { width:24px; height:24px; border-radius:50%; background:rgba(88,166,255,0.15); color:var(--blue); font-size:11px; font-weight:800; display:flex; align-items:center; justify-content:center; flex-shrink:0; }
.step-text { font-size:13px; color:var(--text); line-height:1.6; }

/* ── FOOTER ────────────────────────────────────────────── */
.footer { text-align:center; margin-top:32px; padding-top:16px; border-top:1px solid rgba(255,255,255,0.03); color:var(--dim); font-size:10px; letter-spacing:0.5px; }

/* ── RESPONSIVE ────────────────────────────────────────── */
@media(max-width:900px) {
  .chat-sidebar { display:none; }
  .row1,.row2 { grid-template-columns:1fr; }
  .modules-grid { grid-template-columns:1fr; }
  .hero-score { font-size:64px; }
}
</style>
</head>
<body>

<!-- ═══ CHAT SIDEBAR ═══ -->
<aside class="chat-sidebar">
  <div class="chat-header">
    <div class="chat-logo">Y</div>
    <div>
      <div class="chat-title">Ybe Check</div>
      <div class="chat-sub">AI Security Assistant</div>
    </div>
  </div>
  <div class="chat-messages" id="chatMessages">
    <div class="chat-bubble chat-ai">
      Hi! I'm your Ybe Check AI assistant. Ask me about your scan findings, how to fix issues, or security best practices.
    </div>
  </div>
  <div class="chat-input-wrap" style="position:relative;">
    <input id="chatInput" class="chat-input" placeholder="Ask about vulnerabilities..." onkeydown="if(event.key==='Enter')sendChat()"/>
    <button class="chat-send" onclick="sendChat()">→</button>
  </div>
</aside>

<!-- ═══ MAIN AREA ═══ -->
<div class="main-area">
  <!-- Top Bar -->
  <div class="top-bar">
    <div style="display:flex;align-items:center;gap:14px;">
      <div id="statusPill" class="status-pill" style="background:rgba(136,136,136,0.1);border:1px solid rgba(136,136,136,0.2);color:var(--dim);">
        <span style="width:7px;height:7px;border-radius:50%;background:var(--dim);"></span>
        No Scan
      </div>
      <span id="lastScanTime" style="font-size:12px;color:var(--dim);"></span>
    </div>
    <div style="display:flex;align-items:center;gap:10px;">
      <button class="scan-btn scan-secondary" onclick="loadReport()" title="Refresh">↻ Refresh</button>
      <button id="scanBtn" class="scan-btn scan-primary" onclick="runScan()">+ New Scan</button>
    </div>
  </div>

  <!-- Content -->
  <div class="content">
    <!-- Empty State -->
    <div id="emptyState" class="empty-state">
      <div class="empty-icon">🛡️</div>
      <div style="font-size:18px;font-weight:700;color:var(--text);">No scan report found</div>
      <div style="font-size:14px;color:var(--dim);max-width:400px;text-align:center;line-height:1.6;">Run your first security audit to see the production readiness dashboard.</div>
      <button class="scan-btn scan-primary" onclick="runScan()" style="margin-top:8px;">Run First Scan</button>
    </div>

    <!-- Dashboard -->
    <div id="dashboard" style="display:none;">
      <div class="shell" id="dashboardShell"></div>
    </div>
  </div>
</div>

<!-- ═══ REMEDIATION MODAL ═══ -->
<div id="modalOverlay" class="modal-overlay" onclick="if(event.target===this)closeModal()">
  <div class="modal-box">
    <div class="modal-header">
      <div>
        <div id="modalTitle" style="font-size:18px;font-weight:700;color:var(--text);margin-bottom:6px;"></div>
        <div id="modalMeta" style="display:flex;gap:10px;align-items:center;"></div>
      </div>
      <button onclick="closeModal()" style="background:none;border:none;color:var(--dim);cursor:pointer;font-size:18px;">✕</button>
    </div>
    <div class="modal-body" id="modalBody">
      <div style="display:flex;align-items:center;justify-content:center;padding:40px;color:var(--dim);gap:12px;">
        <div style="width:20px;height:20px;border:2px solid var(--blue);border-top-color:transparent;border-radius:50%;animation:spinLoader 1s linear infinite;"></div>
        Generating AI analysis...
      </div>
    </div>
    <div class="modal-footer">
      <button class="modal-close" onclick="closeModal()">Close</button>
    </div>
  </div>
</div>

<script>
/* ═══ STATE ═══ */
let report = null;
let chatHistory = [];
let currentPage = 0;
const PAGE_SIZE = 20;
const API = window.location.origin;

/* ═══ HELPERS ═══ */
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function scoreColor(s) {
  if (s >= 80) return 'var(--green)';
  if (s >= 50) return 'var(--yellow)';
  return 'var(--red)';
}
function scoreColorRaw(s) {
  if (s >= 80) return '#3FB950';
  if (s >= 50) return '#D29922';
  return '#F85149';
}
function sevColorRaw(sev) {
  const v = (sev||'').toLowerCase();
  if (v === 'critical' || v === 'high') return '#F85149';
  if (v === 'medium') return '#DB6D28';
  if (v === 'low') return '#58A6FF';
  return '#8B949E';
}

const MOD_EMOJI = {
  'Secrets Detection':'🔑', 'Dependencies':'📦', 'Auth Guards':'🛡️',
  'Prompt Injection':'🔍', 'PII & Logging':'📋', 'AI Traceability':'🤖',
  'IaC Security':'☁️', 'License Compliance':'📜', 'Test & Coverage':'🧪',
  'API Fuzzing':'⚡', 'Container Security':'🐳', 'Load Testing':'📊',
  'Live Prompt Testing':'💬', 'SBOM':'📄', 'Web Attacks':'🕸️', 'Config & Env':'⚙️',
};
function modEmoji(name) { return MOD_EMOJI[name] || '🛡️'; }

/* ═══ LOAD & SCAN ═══ */
async function loadReport() {
  try {
    const r = await fetch(API + '/api/report');
    if (!r.ok) { showEmpty(); return; }
    report = await r.json();
    renderDashboard();
  } catch { showEmpty(); }
}

function showEmpty() {
  document.getElementById('emptyState').style.display = '';
  document.getElementById('dashboard').style.display = 'none';
}

async function runScan() {
  const btn = document.getElementById('scanBtn');
  btn.disabled = true;
  btn.textContent = '⏳ Scanning... (2-5 min)';
  try {
    const r = await fetch(API + '/api/scan', { method: 'POST' });
    const data = await r.json();
    if (!r.ok || data.error) { alert('Scan failed: ' + (data.error || r.statusText)); return; }
    report = data;
    renderDashboard();
  } catch (e) { alert('Scan failed: ' + e.message); }
  btn.disabled = false;
  btn.textContent = '+ New Scan';
}

/* ═══ RENDER DASHBOARD ═══ */
function renderDashboard() {
  try {
    document.getElementById('emptyState').style.display = 'none';
    document.getElementById('dashboard').style.display = '';

    const score = report.overall_score || 0;
    const modules = report.module_results || report.modules || [];
    const findings = report.findings || [];
    const topFixes = report.top_fixes || [];
    const version = report.version || '0.2';
    const totalIssues = findings.length;
    const sorted = [...modules].sort((a, b) => (a.score || 0) - (b.score || 0));

    // Severity counts
    const counts = { critical:0, high:0, medium:0, low:0, info:0 };
    findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
    const critHigh = counts.critical + counts.high;

    const passed = modules.filter(m => (m.score || 0) >= 80).length;
    const failed = modules.filter(m => m.score != null && m.score < 80).length;

    // Verdict
    const verdict = report.verdict || (score >= 80 ? 'PRODUCTION READY' : score >= 50 ? 'NEEDS ATTENTION' : 'NOT READY');
    const verdictGrad = score >= 80
      ? 'linear-gradient(160deg,#0d7a3e,#15a050,#1cb85c)'
      : score >= 50
        ? 'linear-gradient(160deg,#c06000,#e07020,#f09030)'
        : 'linear-gradient(160deg,#8b2020,#c03030,#e04040)';

    // Hero summary
    const heroText = score >= 80
      ? 'Your repo is production-ready. Core security controls are solid.'
      : score >= 50
        ? 'Some areas need attention before deployment. Review the flagged modules.'
        : 'Critical vulnerabilities found. Not safe to deploy.';

    // Persona
    const personaTitle = score >= 80 ? 'Security Champion' : score >= 50 ? 'Cautious Builder' : 'Risk Taker';
    const personaDesc = score >= 80
      ? 'You follow best practices and prioritize security.'
      : score >= 50
        ? "You're aware of security but have some blind spots."
        : 'Move fast and break things. Security comes second.';
    const personaEmoji = score >= 80 ? '🏆' : score >= 50 ? '🛡️' : '⚠️';

    // Scan time
    const scanTime = report.scan_time ? new Date(report.scan_time).toLocaleString() : '';

    // Status pill
    const pill = document.getElementById('statusPill');
    if (score >= 80) {
      pill.style.background = 'rgba(63,185,80,0.1)'; pill.style.borderColor = 'rgba(63,185,80,0.2)'; pill.style.color = '#3FB950';
      pill.innerHTML = '<span style="width:7px;height:7px;border-radius:50%;background:#3FB950;animation:pulseDot 1.5s infinite;"></span> Production Ready';
    } else if (score >= 50) {
      pill.style.background = 'rgba(219,109,40,0.1)'; pill.style.borderColor = 'rgba(219,109,40,0.2)'; pill.style.color = '#DB6D28';
      pill.innerHTML = '<span style="width:7px;height:7px;border-radius:50%;background:#DB6D28;animation:pulseDot 1.5s infinite;"></span> Needs Attention';
    } else {
      pill.style.background = 'rgba(248,81,73,0.1)'; pill.style.borderColor = 'rgba(248,81,73,0.2)'; pill.style.color = '#F85149';
      pill.innerHTML = '<span style="width:7px;height:7px;border-radius:50%;background:#F85149;animation:pulseDot 1.5s infinite;"></span> Not Ready';
    }
    if (scanTime) document.getElementById('lastScanTime').innerHTML = 'Last scan: <span style="color:var(--text);">' + scanTime + '</span>';

    // Build module scores HTML
    const modScoresHtml = sorted.map(m => {
      const ms = m.score || 0; const mc = scoreColorRaw(ms);
      return `<button class="mod-row" onclick="scrollToModule('${esc(m.name)}')">
        <div class="mod-icon" style="background:${mc}18;">${modEmoji(m.name)}</div>
        <div class="mod-body">
          <div class="mod-name">${esc(m.name)}</div>
          <div class="mod-bar"><div class="mod-fill" style="width:${ms}%;background:${mc};"></div></div>
        </div>
        <span class="mod-pct">${ms}%</span>
      </button>`;
    }).join('');

    // Build verdict dots
    const verdictDots = modules.map(m => {
      const ms = m.score || 0;
      const bg = ms >= 80 ? 'rgba(255,255,255,0.3)' : ms >= 50 ? 'rgba(255,255,255,0.15)' : 'rgba(0,0,0,0.3)';
      return `<div class="verdict-dot" style="background:${bg};" title="${esc(m.name)}: ${ms}"></div>`;
    }).join('');

    // Top fixes
    const fixesHtml = (Array.isArray(topFixes) ? topFixes.slice(0, 5) : []).map((fix, i) => {
      if (typeof fix === 'string') {
        return `<div class="fix-item"><span class="fix-num">${i+1}.</span><div><span class="fix-text">${esc(fix.slice(0,200))}</span></div></div>`;
      }
      return `<div class="fix-item"><span class="fix-num">${fix.priority || i+1}.</span><div><span class="fix-text">${esc(fix.action || fix)}</span><div class="fix-file">${esc(fix.file || '')}${fix.line ? ':'+fix.line : ''}</div></div></div>`;
    }).join('');

    // Module cards
    const moduleCardsHtml = sorted.map((m, i) => {
      const ms = m.score || 0; const mc = scoreColorRaw(ms);
      const status = m.status || '';
      let statusColor = '#888';
      if (status === 'no_issues' || status === 'passed') statusColor = '#3FB950';
      if (status === 'errored' || status === 'failed') statusColor = '#F85149';
      return `<button class="module-card" id="mod-${esc(m.name.replace(/\s+/g,'-'))}" onclick="scrollToFindings('${esc(m.name)}')" style="animation-delay:${i*0.03}s;">
        <div class="mc-icon" style="background:${mc}15;">${modEmoji(m.name)}</div>
        <div class="mc-body">
          <div class="mc-name">${esc(m.name)}
            <span class="status-badge" style="background:${statusColor}15;color:${statusColor};border:1px solid ${statusColor}30;">${esc(status.replace('_',' ').toUpperCase())}</span>
          </div>
          <div class="mc-meta">
            <div class="mc-bar"><div class="mc-fill" style="width:${ms}%;background:${mc};"></div></div>
            <span class="mc-issues">${m.issues || 0} issue${(m.issues||0)!==1?'s':''}</span>
          </div>
        </div>
        <div class="mc-score" style="color:${mc};">${ms}</div>
      </button>`;
    }).join('');

    // Assemble the full dashboard
    const shell = document.getElementById('dashboardShell');
    shell.innerHTML = `
      <!-- ROW 1: Hero + Issues + Persona -->
      <div class="row1">
        <div class="mcard hero-card">
          <div class="hero-bg"></div>
          <div class="hero-overlay"></div>
          <div class="hero-inner">
            <div class="hero-meta">
              <span class="hero-label">Audit Report</span>
              <span class="hero-version">v${esc(version)}</span>
            </div>
            <div class="hero-score">${score}</div>
            <div class="hero-summary">${esc(heroText)}</div>
            <div class="hero-footer">
              <span>Target: workspace</span>
              <span>${esc(scanTime)}</span>
            </div>
          </div>
        </div>
        <div class="mcard issues-card">
          <div class="section-label">TOTAL ISSUES FOUND</div>
          <div class="issues-num" style="color:${totalIssues > 0 ? 'var(--purple)' : 'var(--green)'};">${totalIssues}</div>
          ${totalIssues > 0 ? `<div class="issues-tags">
            ${critHigh > 0 ? `<span class="issues-tag" style="background:rgba(248,81,73,0.12);color:var(--red);">${critHigh} critical</span>` : ''}
            ${counts.medium > 0 ? `<span class="issues-tag" style="background:rgba(219,109,40,0.12);color:var(--orange);">${counts.medium} medium</span>` : ''}
            ${counts.low + counts.info > 0 ? `<span class="issues-tag" style="background:rgba(88,166,255,0.12);color:var(--blue);">${counts.low + counts.info} low</span>` : ''}
          </div>` : ''}
        </div>
        <div class="mcard persona-card">
          <span class="persona-badge">Security Profile</span>
          <div class="persona-icon">${personaEmoji}</div>
          <div class="persona-label">YOU ARE A</div>
          <div class="persona-title">${esc(personaTitle)}</div>
          <div class="persona-desc">${esc(personaDesc)}</div>
        </div>
      </div>

      <!-- ROW 2: Module Scores + Verdict + Summary -->
      <div class="row2">
        <div class="mcard" style="padding:24px 28px;">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
            <span style="font-size:16px;font-weight:700;color:var(--text);">Module Scores</span>
            <span style="font-size:12px;color:var(--dim);">Score /100</span>
          </div>
          ${modScoresHtml}
        </div>
        <div class="verdict-card" style="background:${verdictGrad};">
          <div class="verdict-label">VERDICT</div>
          <div class="verdict-value">${esc(verdict)}</div>
          <div>
            <div style="font-size:12px;font-weight:600;color:rgba(255,255,255,0.6);margin-bottom:8px;">Module Health</div>
            <div class="verdict-dots">${verdictDots}</div>
          </div>
        </div>
        <div class="mcard" style="padding:24px 28px;display:flex;flex-direction:column;">
          <div class="section-label">SCAN SUMMARY</div>
          <div class="summary-grid">
            <div class="summary-cell">
              <div class="summary-val" style="color:var(--text);">${passed}/${modules.length}</div>
              <div class="summary-lbl">Passed</div>
            </div>
            <div class="summary-cell">
              <div class="summary-val" style="color:${failed > 0 ? 'var(--red)' : 'var(--green)'};">${failed}</div>
              <div class="summary-lbl">Needs Work</div>
            </div>
          </div>
          ${fixesHtml ? `<div class="section-label" style="margin-top:auto;">TOP FIXES</div><div>${fixesHtml}</div>` : ''}
        </div>
      </div>

      <!-- ALL MODULES -->
      <div class="section-label" style="margin:24px 0 12px;">ALL MODULES</div>
      <div class="modules-grid">${moduleCardsHtml}</div>

      <!-- FINDINGS TABLE -->
      <div class="findings-wrap" id="findingsWrap">
        <div class="findings-header">
          <div class="findings-title">
            All Findings
            <span class="findings-count" id="findingsCount">${findings.length} total</span>
          </div>
          <div style="display:flex;gap:10px;">
            <select id="filterSev" class="filter-select" onchange="renderFindings()">
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
            <select id="filterCat" class="filter-select" onchange="renderFindings()">
              <option value="">All Categories</option>
              <option value="static">Static</option>
              <option value="dynamic">Dynamic</option>
              <option value="infra">Infra</option>
            </select>
          </div>
        </div>
        <div style="overflow-x:auto;">
          <table class="ftable">
            <thead><tr><th>ID</th><th>Severity</th><th>Type</th><th>Location</th><th style="text-align:right;">Action</th></tr></thead>
            <tbody id="findingsBody"></tbody>
          </table>
        </div>
        <div class="pagination">
          <span id="paginationInfo"></span>
          <div style="display:flex;gap:8px;">
            <button id="prevBtn" class="page-btn" onclick="changePage(-1)" disabled>← Previous</button>
            <button id="nextBtn" class="page-btn" onclick="changePage(1)">Next →</button>
          </div>
        </div>
      </div>

      <div class="footer">Ybe Check · Security audit for vibe-coded applications</div>
    `;

    currentPage = 0;
    renderFindings();
  } catch (err) { console.error('renderDashboard error', err); }
}

/* ═══ SCROLL HELPERS ═══ */
function scrollToModule(name) {
  const el = document.getElementById('mod-' + name.replace(/\s+/g, '-'));
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
}
function scrollToFindings() {
  const el = document.getElementById('findingsWrap');
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* ═══ FINDINGS TABLE ═══ */
function getFilteredFindings() {
  if (!report) return [];
  let f = report.findings || [];
  const sev = document.getElementById('filterSev').value;
  const cat = document.getElementById('filterCat').value;
  if (sev) f = f.filter(x => x.severity === sev);
  if (cat) f = f.filter(x => x.category === cat);
  return f;
}

function renderFindings() {
  const all = getFilteredFindings();
  const total = all.length;
  const start = currentPage * PAGE_SIZE;
  const page = all.slice(start, start + PAGE_SIZE);

  document.getElementById('findingsCount').textContent = total + ' total';
  document.getElementById('paginationInfo').textContent = 'Showing ' + (total > 0 ? start + 1 : 0) + '–' + Math.min(start + PAGE_SIZE, total) + ' of ' + total;
  document.getElementById('prevBtn').disabled = currentPage === 0;
  document.getElementById('nextBtn').disabled = start + PAGE_SIZE >= total;

  document.getElementById('findingsBody').innerHTML = page.map(f => {
    const sc = sevColorRaw(f.severity);
    const loc = f.location || {};
    const locStr = (loc.path || '?') + (loc.line ? ':' + loc.line : '');
    return `<tr>
      <td><span style="color:var(--dim);font-family:monospace;font-size:11px;">${esc(f.id || '-')}</span></td>
      <td><span class="sev-pill" style="background:${sc}15;color:${sc};">${esc(f.severity || 'info')}</span></td>
      <td><span style="color:var(--text);font-size:12px;">${esc((f.type || '-').substring(0, 50))}</span></td>
      <td><span class="file-link">${esc(locStr.substring(0, 60))}</span></td>
      <td style="text-align:right;"><button class="get-fix-btn" onclick="showFix('${esc(f.id || '')}')">Get Fix</button></td>
    </tr>`;
  }).join('');
}

function changePage(d) { currentPage += d; renderFindings(); }

/* ═══ REMEDIATION MODAL ═══ */
async function showFix(id) {
  if (!id) return;
  const overlay = document.getElementById('modalOverlay');
  overlay.classList.add('open');

  const finding = (report.findings || []).find(f => f.id === id);
  const sc = sevColorRaw(finding ? finding.severity : 'medium');
  const loc = finding ? (finding.location || {}) : {};
  const locStr = (loc.path || '?') + (loc.line ? ':' + loc.line : '');

  document.getElementById('modalTitle').textContent = 'Fix: ' + (finding ? finding.type : 'Finding');
  document.getElementById('modalMeta').innerHTML = `
    <span class="sev-pill" style="background:${sc}15;color:${sc};">${esc(finding ? finding.severity : '?')}</span>
    <span style="color:var(--dim);font-size:12px;">•</span>
    <span style="color:var(--dim);font-size:12px;font-family:monospace;">${esc(locStr)}</span>
  `;
  document.getElementById('modalBody').innerHTML = `
    <div style="display:flex;align-items:center;justify-content:center;padding:40px;color:var(--dim);gap:12px;">
      <div style="width:20px;height:20px;border:2px solid var(--blue);border-top-color:transparent;border-radius:50%;animation:spinLoader 1s linear infinite;"></div>
      Generating AI analysis...
    </div>`;

  try {
    const r = await fetch(API + '/api/remediation/' + encodeURIComponent(id));
    const d = await r.json();
    if (d.error) { document.getElementById('modalBody').innerHTML = '<div style="padding:24px;color:var(--dim);">' + esc(d.error) + '</div>'; return; }

    const steps = (d.remediation || '').split(/\n/).map(s => s.trim()).filter(s => s.length > 0);
    const stepsHtml = steps.map((step, i) => `
      <div class="remediation-step">
        <div class="step-num">${i + 1}</div>
        <div class="step-text">${esc(step.replace(/^\d+\.\s*/, ''))}</div>
      </div>
    `).join('');

    let refsHtml = '';
    if (d.references && d.references.length > 0) {
      refsHtml = '<div style="margin-top:16px;display:flex;gap:8px;flex-wrap:wrap;">' +
        d.references.map(u => `<a href="${esc(u)}" target="_blank" style="color:var(--blue);font-size:12px;text-decoration:none;">${esc(u)}</a>`).join(' | ') +
        '</div>';
    }

    document.getElementById('modalBody').innerHTML = `
      <div style="margin-bottom:20px;">
        <div class="section-label">Impact Analysis</div>
        <p style="font-size:14px;color:var(--text);line-height:1.7;">${esc(d.impact || 'N/A')}</p>
      </div>
      <div>
        <div class="section-label">Recommended Actions</div>
        ${stepsHtml}
      </div>
      ${d.cwe ? `<div style="margin-top:16px;"><a href="https://cwe.mitre.org/data/definitions/${esc(d.cwe.replace('CWE-',''))}.html" target="_blank" style="color:var(--blue);font-size:12px;text-decoration:none;">${esc(d.cwe)}</a></div>` : ''}
      ${refsHtml}
    `;
  } catch (e) {
    document.getElementById('modalBody').innerHTML = '<div style="padding:24px;color:var(--red);">Error: ' + esc(e.message) + '</div>';
  }
}

function closeModal() { document.getElementById('modalOverlay').classList.remove('open'); }
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

/* ═══ CHAT ═══ */
function appendChatMsg(role, text) {
  const container = document.getElementById('chatMessages');
  const cls = role === 'user' ? 'chat-user' : 'chat-ai';
  container.innerHTML += `<div class="chat-bubble ${cls}">${esc(text)}</div>`;
  container.scrollTop = container.scrollHeight;
}

function showTyping() {
  const container = document.getElementById('chatMessages');
  container.innerHTML += `<div id="typingIndicator" class="chat-typing"><span></span><span></span><span></span></div>`;
  container.scrollTop = container.scrollHeight;
}
function removeTyping() { const t = document.getElementById('typingIndicator'); if (t) t.remove(); }

async function sendChat() {
  const input = document.getElementById('chatInput');
  const msg = input.value.trim();
  if (!msg) return;
  input.value = '';

  appendChatMsg('user', msg);
  chatHistory.push({ role: 'user', content: msg });
  showTyping();

  try {
    const r = await fetch(API + '/api/chat', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ message: msg, history: chatHistory.slice(-20) }) });
    const d = await r.json();
    removeTyping();
    const reply = d.reply || 'No response.';
    appendChatMsg('ai', reply);
    chatHistory.push({ role: 'assistant', content: reply });
  } catch (e) {
    removeTyping();
    appendChatMsg('ai', 'Error: ' + e.message);
  }
}

/* ═══ INIT ═══ */
loadReport();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index():
    return DASHBOARD_HTML


def start_server(port: int = 7474) -> None:
    """Launch the dashboard with uvicorn."""
    import uvicorn
    uvicorn.run(
        "ybe_check.dashboard:app",
        host="127.0.0.1",
        port=port,
        log_level="info",
    )


if __name__ == "__main__":
    start_server()
