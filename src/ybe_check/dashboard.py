"""
Ybe Check Dashboard — local FastAPI web UI for scan results + AI chat.

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

app = FastAPI(title="Ybe Check Dashboard", version="0.3.0")

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


# ── HTML ──────────────────────────────────────────────────────────────────

DASHBOARD_HTML = """\
<!DOCTYPE html>
<html class="dark" lang="en">
<head>
<meta charset="utf-8"/>
<meta content="width=device-width, initial-scale=1.0" name="viewport"/>
<title>Ybe Check - AI Security Scanner</title>
<link href="https://fonts.googleapis.com" rel="preconnect"/>
<link crossorigin="" href="https://fonts.gstatic.com" rel="preconnect"/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"></script>
<script>
tailwind.config = {
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        primary: "#7d6bef",
        "background-dark": "#07080c",
        "surface-dark": "#141122",
        "surface-light": "#292447",
        "accent-yellow": "#FFC107",
        "accent-orange": "#fa6938",
        "accent-green": "#0bda6c",
        "accent-red": "#EF4444",
      },
      fontFamily: { display: ["Inter","sans-serif"], mono: ["'Fira Code'","monospace"] },
      borderRadius: { DEFAULT:"0.5rem", lg:"1rem", xl:"1.5rem", "2xl":"2rem", full:"9999px" },
    },
  },
}
</script>
<style>
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:#141122}
::-webkit-scrollbar-thumb{background:#292447;border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:#3b3465}
.glass-panel{background:rgba(20,17,34,0.6);backdrop-filter:blur(12px);border:1px solid rgba(124,107,239,0.1)}
.delay-75{animation-delay:75ms}
.delay-150{animation-delay:150ms}
</style>
</head>
<body class="bg-background-dark text-slate-100 font-display min-h-screen flex overflow-hidden">

<!-- Left Sidebar: AI Chat -->
<aside class="w-[340px] flex-shrink-0 bg-surface-dark border-r border-white/5 flex flex-col h-screen z-20">
  <div class="h-16 flex items-center px-6 border-b border-white/5 gap-3">
    <div class="w-8 h-8 rounded-lg bg-primary flex items-center justify-center text-white">
      <span class="material-symbols-outlined text-xl">security</span>
    </div>
    <div>
      <h1 class="font-bold text-lg leading-none tracking-tight">Ybe Check</h1>
      <p class="text-xs text-slate-400 mt-1">AI Security Assistant</p>
    </div>
  </div>
  <div class="flex-1 overflow-y-auto p-4 space-y-4" id="chatMessages">
    <div class="flex justify-center">
      <span class="text-[10px] font-medium text-slate-500 bg-white/5 px-2 py-1 rounded-full">Today</span>
    </div>
    <div class="flex gap-3">
      <div class="w-8 h-8 rounded-full bg-gradient-to-br from-primary to-purple-800 flex-shrink-0 flex items-center justify-center">
        <span class="material-symbols-outlined text-sm text-white">smart_toy</span>
      </div>
      <div class="flex flex-col gap-1 max-w-[85%]">
        <div class="bg-[#292447] p-3 rounded-2xl rounded-tl-none text-sm leading-relaxed text-slate-200">
          Hi! I'm your Ybe Check AI assistant. Ask me anything about your scan findings, how to fix issues, or security best practices.
        </div>
      </div>
    </div>
  </div>
  <div class="p-4 border-t border-white/5 bg-surface-dark">
    <div class="relative">
      <input id="chatInput" class="w-full bg-[#1e1b2e] text-sm text-white placeholder-slate-500 rounded-xl py-3 pl-4 pr-12 border-none focus:ring-2 focus:ring-primary/50 outline-none" placeholder="Ask Ybe about vulnerabilities..." type="text" onkeydown="if(event.key==='Enter')sendChat()"/>
      <button onclick="sendChat()" class="absolute right-2 top-1/2 -translate-y-1/2 w-8 h-8 flex items-center justify-center text-primary hover:bg-white/5 rounded-lg transition-colors">
        <span class="material-symbols-outlined text-[20px]">send</span>
      </button>
    </div>
  </div>
</aside>

<!-- Main Content -->
<main class="flex-1 flex flex-col h-screen overflow-hidden bg-background-dark relative">
  <!-- Top Bar -->
  <header class="h-16 flex items-center justify-between px-8 border-b border-white/5 bg-background-dark/50 backdrop-blur-sm z-10">
    <div class="flex items-center gap-4">
      <div id="statusBadge" class="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-500/10 border border-slate-500/20">
        <div class="w-2 h-2 rounded-full bg-slate-400"></div>
        <span class="text-xs font-medium text-slate-400 uppercase tracking-wider">No Scan</span>
      </div>
      <span id="lastScanTime" class="text-slate-500 text-sm"></span>
    </div>
    <div class="flex items-center gap-4">
      <button onclick="loadReport()" class="w-9 h-9 rounded-full bg-surface-light flex items-center justify-center text-slate-300 hover:text-white hover:bg-primary transition-colors">
        <span class="material-symbols-outlined text-[20px]">refresh</span>
      </button>
      <button id="scanBtn" onclick="runScan()" class="flex items-center gap-2 bg-primary hover:bg-primary/90 text-white px-4 py-2 rounded-lg text-sm font-semibold transition-all shadow-[0_0_15px_rgba(124,107,239,0.3)]">
        <span class="material-symbols-outlined text-[18px]">add</span>
        New Scan
      </button>
    </div>
  </header>

  <!-- Scrollable Content -->
  <div class="flex-1 overflow-y-auto p-8">
    <div class="max-w-6xl mx-auto flex flex-col gap-8">

      <!-- Empty State -->
      <div id="emptyState" class="flex flex-col items-center justify-center py-20 gap-4">
        <span class="material-symbols-outlined text-6xl text-slate-600">shield</span>
        <p class="text-slate-400 text-lg">No scan report found</p>
        <button onclick="runScan()" class="bg-primary hover:bg-primary/90 text-white px-6 py-2.5 rounded-lg text-sm font-semibold transition-all">Run Your First Scan</button>
      </div>

      <!-- Dashboard (hidden until report loads) -->
      <div id="dashboard" style="display:none" class="flex flex-col gap-8">

        <!-- Overview: Score + Stats -->
        <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <!-- Score Card -->
          <div class="lg:col-span-4 glass-panel rounded-xl p-6 relative overflow-hidden group">
            <div class="absolute -right-10 -top-10 w-40 h-40 bg-primary/20 rounded-full blur-3xl group-hover:bg-primary/30 transition-all"></div>
            <h2 class="text-slate-400 text-sm font-medium mb-4 flex items-center gap-2">
              <span class="material-symbols-outlined text-lg">verified_user</span>
              Production Readiness
            </h2>
            <div class="flex items-center justify-center py-4">
              <div class="relative w-40 h-40 flex items-center justify-center">
                <svg class="w-full h-full transform -rotate-90" viewBox="0 0 160 160">
                  <circle class="text-surface-light" cx="80" cy="80" fill="transparent" r="70" stroke="currentColor" stroke-width="12"></circle>
                  <circle id="scoreArc" class="text-accent-orange" cx="80" cy="80" fill="transparent" r="70" stroke="currentColor" stroke-dasharray="440" stroke-dashoffset="440" stroke-linecap="round" stroke-width="12" style="transition:stroke-dashoffset 1s ease-out,stroke .3s"></circle>
                </svg>
                <div class="absolute flex flex-col items-center">
                  <span id="scoreNum" class="text-4xl font-bold text-white tracking-tight">0</span>
                  <span id="scoreLabel" class="text-xs font-medium uppercase mt-1">—</span>
                </div>
              </div>
            </div>
            <p id="scoreSubtext" class="text-center text-xs text-slate-400 mt-2"></p>
          </div>

          <!-- Stat Cards -->
          <div class="lg:col-span-8 grid grid-cols-2 md:grid-cols-4 gap-4" id="statsGrid">
          </div>
        </div>

        <!-- Module Chips -->
        <div>
          <div class="flex items-center justify-between mb-3">
            <h3 class="text-white font-semibold text-lg">Scan Modules</h3>
          </div>
          <div class="flex gap-4 overflow-x-auto pb-4" id="modulesStrip"></div>
        </div>

        <!-- Findings Table -->
        <div class="glass-panel rounded-xl overflow-hidden flex flex-col min-h-[300px]">
          <div class="p-5 border-b border-white/5 flex items-center justify-between flex-wrap gap-3">
            <h3 class="text-white font-semibold text-lg flex items-center gap-2">
              Latest Findings
              <span id="findingsCount" class="text-xs bg-surface-light text-slate-400 px-2 py-0.5 rounded-full border border-white/5"></span>
            </h3>
            <div class="flex items-center gap-3">
              <select id="filterSev" onchange="renderFindings()" class="bg-surface-light border-none text-xs text-white rounded-lg py-1.5 px-3 focus:ring-1 focus:ring-primary">
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
              <select id="filterCat" onchange="renderFindings()" class="bg-surface-light border-none text-xs text-white rounded-lg py-1.5 px-3 focus:ring-1 focus:ring-primary">
                <option value="">All Categories</option>
                <option value="static">Static</option>
                <option value="dynamic">Dynamic</option>
                <option value="infra">Infra</option>
              </select>
            </div>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left border-collapse">
              <thead>
                <tr class="text-xs text-slate-400 border-b border-white/5 bg-surface-light/30">
                  <th class="px-6 py-4 font-medium uppercase tracking-wider">ID</th>
                  <th class="px-6 py-4 font-medium uppercase tracking-wider">Severity</th>
                  <th class="px-6 py-4 font-medium uppercase tracking-wider">Type</th>
                  <th class="px-6 py-4 font-medium uppercase tracking-wider">Source</th>
                  <th class="px-6 py-4 font-medium uppercase tracking-wider text-right">Action</th>
                </tr>
              </thead>
              <tbody id="findingsBody" class="divide-y divide-white/5"></tbody>
            </table>
          </div>
          <div class="p-4 border-t border-white/5 flex items-center justify-between text-xs text-slate-400">
            <span id="paginationInfo"></span>
            <div class="flex gap-2">
              <button id="prevBtn" onclick="changePage(-1)" class="px-3 py-1 rounded bg-surface-light hover:bg-white/10 text-white disabled:opacity-50" disabled>Previous</button>
              <button id="nextBtn" onclick="changePage(1)" class="px-3 py-1 rounded bg-surface-light hover:bg-white/10 text-white">Next</button>
            </div>
          </div>
        </div>

      </div>
    </div>
  </div>
</main>

<!-- Remediation Modal Overlay -->
<div id="modalOverlay" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4" onclick="if(event.target===this)closeModal()">
  <div class="flex flex-col w-full max-w-[800px] max-h-[90vh] overflow-hidden rounded-xl bg-[#141122] border border-slate-700 shadow-2xl shadow-primary/10">
    <!-- Modal Header -->
    <div class="flex flex-col border-b border-slate-800 bg-[#1a162e]">
      <div class="flex flex-wrap items-start justify-between gap-4 p-6 pb-4">
        <div class="flex flex-col gap-2">
          <div class="flex items-center gap-3">
            <span id="modalIcon" class="material-symbols-outlined text-red-500 text-3xl">warning</span>
            <h2 id="modalTitle" class="text-white tracking-tight text-2xl font-bold leading-tight"></h2>
          </div>
          <div class="flex items-center gap-2 pl-[44px]" id="modalMeta"></div>
        </div>
        <button onclick="closeModal()" class="text-slate-400 hover:text-white transition-colors">
          <span class="material-symbols-outlined">close</span>
        </button>
      </div>
    </div>
    <!-- Scrollable Content -->
    <div class="flex-1 overflow-y-auto" id="modalBody">
      <div class="p-8 flex items-center justify-center text-slate-400">
        <div class="flex items-center gap-3">
          <div class="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin"></div>
          Generating AI analysis...
        </div>
      </div>
    </div>
    <!-- Footer -->
    <div class="border-t border-slate-800 bg-[#1a162e] p-4 flex justify-end gap-3">
      <button onclick="closeModal()" class="inline-flex justify-center rounded-lg bg-white/5 px-4 py-2 text-sm font-semibold text-white ring-1 ring-inset ring-slate-700 hover:bg-white/10 items-center transition-all">
        Close
      </button>
    </div>
  </div>
</div>

<script>
let report = null;
let chatHistory = [];
let currentPage = 0;
const PAGE_SIZE = 15;
const API = window.location.origin;

const MOD_ICONS = {
  secrets:'key', prompt_injection:'psychology', pii_logging:'fingerprint',
  dependencies:'inventory_2', auth_guards:'admin_panel_settings',
  iac_security:'cloud', license_compliance:'gavel', ai_traceability:'smart_toy',
  test_coverage:'science', container_scan:'deployed_code', sbom:'receipt_long',
  config_env:'settings', load_testing:'speed', web_attacks:'bug_report',
  api_fuzzing:'api', prompt_live:'chat'
};

function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}

function sevColor(s){
  switch(s){case 'critical':return{c:'text-accent-red',bg:'bg-accent-red/10',border:'border-accent-red/20',dot:'bg-accent-red',left:'border-l-accent-red'};case 'high':return{c:'text-accent-orange',bg:'bg-accent-orange/10',border:'border-accent-orange/20',dot:'bg-accent-orange',left:'border-l-accent-orange'};case 'medium':return{c:'text-accent-yellow',bg:'bg-accent-yellow/10',border:'border-accent-yellow/20',dot:'bg-accent-yellow',left:'border-l-accent-yellow'};case 'low':return{c:'text-cyan-400',bg:'bg-cyan-400/10',border:'border-cyan-400/20',dot:'bg-cyan-400',left:'border-l-cyan-400'};default:return{c:'text-slate-400',bg:'bg-slate-400/10',border:'border-slate-400/20',dot:'bg-slate-400',left:'border-l-slate-600'}}
}

function scoreStyle(s){
  if(s>=80) return{color:'text-accent-green',stroke:'text-accent-green',label:'Ready'};
  if(s>=40) return{color:'text-accent-orange',stroke:'text-accent-orange',label:'Needs Work'};
  return{color:'text-accent-red',stroke:'text-accent-red',label:'Not Ready'};
}

/* ── Load Report ── */
async function loadReport(){
  try{
    const r=await fetch(API+'/api/report');
    if(!r.ok){showEmpty();return}
    report=await r.json();
    renderDashboard();
  }catch{showEmpty()}
}
function showEmpty(){
  document.getElementById('emptyState').style.display='';
  document.getElementById('dashboard').style.display='none';
}

async function runScan(){
  const btn=document.getElementById('scanBtn');
  btn.disabled=true;btn.innerHTML='<span class="material-symbols-outlined text-[18px] animate-spin">progress_activity</span> Scanning... (may take 2-5 min)';
  try{
    const r=await fetch(API+'/api/scan',{method:'POST'});
    const data=await r.json();
    if(!r.ok){alert('Scan failed: '+(data.error||r.statusText));return}
    if(data.error){alert('Scan error: '+data.error);return}
    report=data;
    renderDashboard();
  }catch(e){alert('Scan failed: '+e.message)}
  btn.disabled=false;btn.innerHTML='<span class="material-symbols-outlined text-[18px]">add</span> New Scan';
}

/* ── Render Dashboard ── */
function renderDashboard(){
  try{
  document.getElementById('emptyState').style.display='none';
  document.getElementById('dashboard').style.display='';

  const score=report.overall_score||0;
  const st=scoreStyle(score);
  const circ=2*Math.PI*70;
  const arc=document.getElementById('scoreArc');
  arc.setAttribute('stroke-dasharray',circ);
  arc.setAttribute('stroke-dashoffset',circ-(circ*score/100));
  arc.className.baseVal=st.stroke;
  document.getElementById('scoreNum').textContent=score;
  document.getElementById('scoreNum').className='text-4xl font-bold tracking-tight '+st.color;
  const lbl=document.getElementById('scoreLabel');
  lbl.textContent=report.verdict||st.label;
  lbl.className='text-xs font-medium uppercase mt-1 '+st.color;

  const findings=report.findings||[];
  const mods=(report.modules_run||[]).length;
  document.getElementById('scoreSubtext').textContent=mods+' modules scanned, '+findings.length+' findings detected';

  // Status badge
  const badge=document.getElementById('statusBadge');
  if(score>=80) badge.innerHTML='<div class="w-2 h-2 rounded-full bg-accent-green animate-pulse"></div><span class="text-xs font-medium text-accent-green uppercase tracking-wider">Production Ready</span>';
  else if(score>=40) badge.innerHTML='<div class="w-2 h-2 rounded-full bg-accent-orange animate-pulse"></div><span class="text-xs font-medium text-accent-orange uppercase tracking-wider">Needs Attention</span>';
  else badge.innerHTML='<div class="w-2 h-2 rounded-full bg-accent-red animate-pulse"></div><span class="text-xs font-medium text-accent-red uppercase tracking-wider">Not Ready</span>';
  badge.className='flex items-center gap-2 px-3 py-1.5 rounded-full '+(score>=80?'bg-green-500/10 border border-green-500/20':score>=40?'bg-orange-500/10 border border-orange-500/20':'bg-red-500/10 border border-red-500/20');

  if(report.scan_time) document.getElementById('lastScanTime').innerHTML='Last scan: <span class="text-slate-300">'+new Date(report.scan_time).toLocaleString()+'</span>';

  // Stats
  const counts={critical:0,high:0,medium:0,low:0,info:0};
  findings.forEach(f=>{if(counts[f.severity]!==undefined)counts[f.severity]++});
  document.getElementById('statsGrid').innerHTML=`
    <div class="glass-panel rounded-xl p-5 flex flex-col justify-between border-l-4 border-l-primary/50">
      <div><div class="text-slate-400 text-xs font-medium uppercase mb-1">Total Findings</div><div class="text-3xl font-bold text-white">${findings.length}</div></div>
    </div>
    <div class="glass-panel rounded-xl p-5 flex flex-col justify-between border-l-4 border-l-accent-red">
      <div><div class="text-slate-400 text-xs font-medium uppercase mb-1">Critical</div><div class="text-3xl font-bold text-white">${counts.critical}</div></div>
      ${counts.critical>0?'<div class="mt-4 flex items-center gap-1 text-xs text-accent-red bg-accent-red/10 w-fit px-2 py-1 rounded"><span class="material-symbols-outlined text-[14px]">priority_high</span><span>Action Req.</span></div>':''}
    </div>
    <div class="glass-panel rounded-xl p-5 flex flex-col justify-between border-l-4 border-l-accent-orange">
      <div><div class="text-slate-400 text-xs font-medium uppercase mb-1">High</div><div class="text-3xl font-bold text-white">${counts.high}</div></div>
    </div>
    <div class="glass-panel rounded-xl p-5 flex flex-col justify-between border-l-4 border-l-slate-600">
      <div><div class="text-slate-400 text-xs font-medium uppercase mb-1">Medium / Low</div><div class="text-3xl font-bold text-white">${counts.medium+counts.low}</div></div>
    </div>
  `;

  // Module chips
  const strip=document.getElementById('modulesStrip');
  strip.innerHTML=(report.module_results||[]).map(m=>{
    const s=m.score!=null?m.score:-1;
    const dotCls=s>=80?'bg-accent-green':s>=40?'bg-accent-orange':'bg-accent-red';
    const name=m.name||'';
    const key=name.toLowerCase().replace(/[^a-z_]/g,'_');
    const icon=MOD_ICONS[key]||'shield';
    const issues=m.issues||0;
    return `<div class="min-w-[200px] bg-surface-light border border-white/5 rounded-xl p-4 cursor-pointer hover:bg-surface-light/80 transition-all flex flex-col gap-2">
      <div class="flex justify-between items-start">
        <div class="bg-white/5 p-2 rounded-lg text-slate-300"><span class="material-symbols-outlined">${icon}</span></div>
        <span class="w-2 h-2 rounded-full ${dotCls}"></span>
      </div>
      <div>
        <p class="text-slate-200 font-medium text-sm">${esc(name)}</p>
        <p class="text-slate-500 text-xs">${issues>0?issues+' issues':'All clear'}</p>
      </div>
    </div>`;
  }).join('');

  currentPage=0;
  renderFindings();
  }catch(err){console.error('renderDashboard error',err);alert('Error rendering: '+err.message)}
}

/* ── Findings Table ── */
function getFilteredFindings(){
  if(!report) return [];
  let f=report.findings||[];
  const sev=document.getElementById('filterSev').value;
  const cat=document.getElementById('filterCat').value;
  if(sev) f=f.filter(x=>x.severity===sev);
  if(cat) f=f.filter(x=>x.category===cat);
  return f;
}

function renderFindings(){
  const all=getFilteredFindings();
  const total=all.length;
  const start=currentPage*PAGE_SIZE;
  const page=all.slice(start,start+PAGE_SIZE);

  document.getElementById('findingsCount').textContent=total+' total';
  document.getElementById('paginationInfo').textContent='Showing '+(total>0?start+1:0)+'-'+Math.min(start+PAGE_SIZE,total)+' of '+total+' findings';
  document.getElementById('prevBtn').disabled=currentPage===0;
  document.getElementById('nextBtn').disabled=start+PAGE_SIZE>=total;

  document.getElementById('findingsBody').innerHTML=page.map(f=>{
    const sv=sevColor(f.severity);
    const loc=f.location||{};
    const locStr=(loc.path||'?')+(loc.line?':'+loc.line:'');
    return `<tr class="hover:bg-white/[0.02] transition-colors">
      <td class="px-6 py-4"><span class="text-slate-500 text-sm font-mono">${esc(f.id||'-')}</span></td>
      <td class="px-6 py-4"><div class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full ${sv.bg} border ${sv.border} ${sv.c} text-xs font-semibold"><span class="w-1.5 h-1.5 rounded-full ${sv.dot}"></span>${esc(f.severity)}</div></td>
      <td class="px-6 py-4"><span class="text-slate-200 text-sm">${esc((f.type||'-').substring(0,45))}</span></td>
      <td class="px-6 py-4"><code class="text-primary text-xs font-mono bg-primary/10 px-2 py-1 rounded">${esc(locStr.substring(0,55))}</code></td>
      <td class="px-6 py-4 text-right"><button data-fid="${esc(f.id||'')}" onclick="showFix(this.dataset.fid)" class="text-xs font-medium text-white bg-primary hover:bg-primary/90 px-3 py-1.5 rounded-lg transition-colors shadow-lg shadow-primary/20">Get Fix</button></td>
    </tr>`;
  }).join('');
}

function changePage(d){currentPage+=d;renderFindings()}

/* ── Remediation Modal ── */
async function showFix(id){
  if(!id)return;
  const overlay=document.getElementById('modalOverlay');
  overlay.classList.remove('hidden');

  const finding=(report.findings||[]).find(f=>f.id===id);
  const sv=finding?sevColor(finding.severity):sevColor('medium');
  const loc=finding?(finding.location||{}):{};
  const locStr=(loc.path||'?')+(loc.line?':'+loc.line:'');

  document.getElementById('modalIcon').className='material-symbols-outlined text-3xl '+sv.c;
  document.getElementById('modalTitle').textContent='Fix: '+(finding?finding.type:'Finding');
  document.getElementById('modalMeta').innerHTML=`
    <span class="inline-flex items-center rounded-md ${sv.bg} px-2 py-1 text-xs font-medium ${sv.c} ring-1 ring-inset ${sv.border}">Severity: ${esc(finding?finding.severity:'?')}</span>
    <span class="text-slate-400 text-xs">&bull;</span>
    <span class="text-slate-400 text-xs font-mono">${esc(locStr)}</span>
  `;
  document.getElementById('modalBody').innerHTML=`
    <div class="p-8 flex items-center justify-center text-slate-400">
      <div class="flex items-center gap-3">
        <div class="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin"></div>
        Generating AI analysis...
      </div>
    </div>`;

  try{
    const r=await fetch(API+'/api/remediation/'+encodeURIComponent(id));
    const d=await r.json();
    if(d.error){document.getElementById('modalBody').innerHTML='<div class="p-6 text-slate-400">'+esc(d.error)+'</div>';return}

    let refsHtml='';
    if(d.references&&d.references.length>0){
      refsHtml=d.references.map(u=>`<a class="flex items-center gap-1 text-primary hover:text-primary/80 transition-colors hover:underline" href="${esc(u)}" target="_blank"><span class="material-symbols-outlined text-[14px]">link</span>${esc(u)}</a>`).join('<span class="text-slate-600 mx-2">|</span>');
    }

    const remSteps=(d.remediation||'').split(/\\n/).map(s=>s.trim()).filter(s=>s.length>0);
    const stepsHtml=remSteps.map((step,i)=>`
      <div class="flex gap-4 p-3 rounded-lg bg-[#1a162e] border border-slate-800">
        <div class="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/20 text-xs font-bold text-primary">${i+1}</div>
        <div class="flex flex-col gap-1">
          <p class="text-slate-200 text-sm leading-relaxed">${esc(step.replace(/^[0-9]+\\.\\s*/,''))}</p>
        </div>
      </div>
    `).join('');

    document.getElementById('modalBody').innerHTML=`
      <div class="p-6 pb-2">
        <h3 class="text-slate-200 text-sm font-semibold mb-2 flex items-center gap-2">
          <span class="material-symbols-outlined text-lg text-primary">info</span>Impact Analysis
        </h3>
        <p class="text-slate-400 text-sm font-normal leading-relaxed">${esc(d.impact||'N/A')}</p>
      </div>
      <div class="px-6 py-4">
        <h3 class="text-slate-200 text-sm font-semibold mb-3 flex items-center gap-2">
          <span class="material-symbols-outlined text-lg text-primary">format_list_numbered</span>Recommended Actions
        </h3>
        <div class="grid gap-3">${stepsHtml}</div>
      </div>
      ${d.cwe?`<div class="px-6 py-2 pb-6"><div class="flex items-center gap-4 text-xs"><a class="flex items-center gap-1 text-primary hover:text-primary/80 transition-colors hover:underline" href="https://cwe.mitre.org/data/definitions/${esc(d.cwe.replace('CWE-',''))}.html" target="_blank"><span class="material-symbols-outlined text-[14px]">link</span>${esc(d.cwe)}</a>${refsHtml?'<span class="text-slate-600">|</span>'+refsHtml:''}</div></div>`:''}
    `;
  }catch(e){
    document.getElementById('modalBody').innerHTML='<div class="p-6 text-red-400">Error: '+esc(e.message)+'</div>';
  }
}

function closeModal(){document.getElementById('modalOverlay').classList.add('hidden')}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal()});

/* ── Chat ── */
function appendChatMsg(role, text){
  const container=document.getElementById('chatMessages');
  if(role==='user'){
    container.innerHTML+=`
      <div class="flex gap-3 flex-row-reverse">
        <div class="w-8 h-8 rounded-full bg-slate-700 flex-shrink-0 flex items-center justify-center">
          <span class="material-symbols-outlined text-sm text-slate-300">person</span>
        </div>
        <div class="flex flex-col gap-1 items-end max-w-[85%]">
          <div class="bg-primary p-3 rounded-2xl rounded-tr-none text-sm leading-relaxed text-white">${esc(text)}</div>
        </div>
      </div>`;
  } else {
    container.innerHTML+=`
      <div class="flex gap-3">
        <div class="w-8 h-8 rounded-full bg-gradient-to-br from-primary to-purple-800 flex-shrink-0 flex items-center justify-center">
          <span class="material-symbols-outlined text-sm text-white">smart_toy</span>
        </div>
        <div class="flex flex-col gap-1 max-w-[85%]">
          <div class="bg-[#292447] p-3 rounded-2xl rounded-tl-none text-sm leading-relaxed text-slate-200" style="white-space:pre-wrap">${esc(text)}</div>
        </div>
      </div>`;
  }
  container.scrollTop=container.scrollHeight;
}

function showTyping(){
  const container=document.getElementById('chatMessages');
  container.innerHTML+=`
    <div id="typingIndicator" class="flex gap-3">
      <div class="w-8 h-8 rounded-full bg-gradient-to-br from-primary to-purple-800 flex-shrink-0 flex items-center justify-center opacity-50">
        <span class="material-symbols-outlined text-sm text-white">smart_toy</span>
      </div>
      <div class="bg-[#292447] px-4 py-3 rounded-2xl rounded-tl-none flex items-center gap-1 w-16">
        <div class="w-1.5 h-1.5 bg-slate-400 rounded-full animate-bounce"></div>
        <div class="w-1.5 h-1.5 bg-slate-400 rounded-full animate-bounce delay-75"></div>
        <div class="w-1.5 h-1.5 bg-slate-400 rounded-full animate-bounce delay-150"></div>
      </div>
    </div>`;
  container.scrollTop=container.scrollHeight;
}

function removeTyping(){const t=document.getElementById('typingIndicator');if(t)t.remove()}

async function sendChat(){
  const input=document.getElementById('chatInput');
  const msg=input.value.trim();
  if(!msg)return;
  input.value='';

  appendChatMsg('user',msg);
  chatHistory.push({role:'user',content:msg});
  showTyping();

  try{
    const r=await fetch(API+'/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:msg,history:chatHistory.slice(-20)})});
    const d=await r.json();
    removeTyping();
    const reply=d.reply||'No response.';
    appendChatMsg('ai',reply);
    chatHistory.push({role:'assistant',content:reply});
  }catch(e){
    removeTyping();
    appendChatMsg('ai','Error: '+e.message);
  }
}

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
