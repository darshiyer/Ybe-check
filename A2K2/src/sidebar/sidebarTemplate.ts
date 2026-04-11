/**
 * sidebarTemplate.ts
 * Generates the full HTML for the Ybe Check sidebar WebviewView.
 * All styles and scripts are inlined — webviews cannot load external resources.
 */

export interface ModuleResult {
    name: string;
    score: number | null;
    issues: number;
    status?: string;
    warning?: string;
    details?: FindingData[];
}

export interface FindingData {
    severity?: string;
    type?: string;
    file?: string;
    line?: number | string;
    reason?: string;
    snippet?: string;
    remediation?: string;
    action?: string;
    rule_id?: string;
    confidence?: string;
}

export interface SidebarData {
    state: 'idle' | 'scanning' | 'done' | 'error';
    overall_score?: number;
    verdict?: string;
    modules?: ModuleResult[];
    scanned_at?: string;
    autoScan?: boolean;
    scanningModule?: string;
    error?: string;
}

const SEV_COLOR: Record<string, string> = {
    critical: '#f85149',
    high:     '#fb8f44',
    medium:   '#d29922',
    low:      '#388bfd',
};

function scoreColor(score: number | null): string {
    if (score === null) { return '#484f58'; }
    if (score >= 80) { return '#3fb950'; }
    if (score >= 40) { return '#d29922'; }
    return '#f85149';
}

function verdictClass(verdict?: string): string {
    if (!verdict) { return ''; }
    const v = verdict.toUpperCase();
    if (v.includes('PRODUCTION')) { return 'ready'; }
    if (v.includes('ATTENTION'))  { return 'attention'; }
    return 'not-ready';
}

function worstSeverity(details: FindingData[] = []): string {
    const order = ['critical', 'high', 'medium', 'low'];
    for (const sev of order) {
        if (details.some(d => (d.severity || '').toLowerCase() === sev)) { return sev; }
    }
    return 'pass';
}

function renderFinding(f: FindingData, modName: string, idx: number): string {
    const sev     = (f.severity || 'medium').toLowerCase();
    const color   = SEV_COLOR[sev] || '#388bfd';
    const file    = f.file || 'unknown';
    const line    = f.line ?? '?';
    const desc    = f.type || 'Security issue';
    const ruleId  = f.rule_id ? `<span class="rule-id">${f.rule_id}</span>` : '';

    const shortFile = file.length > 32 ? '…' + file.slice(-30) : file;

    return `
    <div class="finding" style="border-left-color:${color}" data-mod="${modName}" data-idx="${idx}">
      <div class="finding-top">
        <span class="sev-badge" style="background:${color}22;color:${color};border-color:${color}44">${sev}</span>
        ${ruleId}
      </div>
      <div class="finding-desc">${desc}</div>
      <div class="finding-location">📄 ${shortFile}:${line}</div>
      <div class="finding-actions">
        <button class="btn-fix btn-copy" onclick="copyPrompt('${modName}', ${idx})" title="Copy AI fix prompt to clipboard">
          <svg width="11" height="11" viewBox="0 0 16 16" fill="currentColor"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 0 1 0 1.5h-1.5a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-1.5a.75.75 0 0 1 1.5 0v1.5A1.75 1.75 0 0 1 9.25 16h-7.5A1.75 1.75 0 0 1 0 14.25Z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0 1 14.25 11h-7.5A1.75 1.75 0 0 1 5 9.25Zm1.75-.25a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-7.5a.25.25 0 0 0-.25-.25Z"/></svg>
          Copy Prompt
        </button>
        <button class="btn-fix btn-copilot" onclick="openCopilot('${modName}', ${idx})" title="Open prompt in GitHub Copilot Chat">
          <svg width="11" height="11" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
          Open in Copilot
        </button>
      </div>
    </div>`;
}

function renderModule(mod: ModuleResult, open = false): string {
    const sev    = worstSeverity(mod.details);
    const color  = sev === 'pass' ? '#3fb950' : (SEV_COLOR[sev] || '#388bfd');
    const sc     = scoreColor(mod.score);
    const scoreStr = mod.score !== null && mod.score !== undefined ? `${mod.score}` : '—';
    const openClass = open ? ' open' : '';
    const passIcon  = (mod.score === 100 || mod.issues === 0) && mod.score !== null
        ? '<span class="pass-tick">✓</span>'
        : '';
    const warnText = mod.warning
        ? `<div class="mod-warning">⚠ ${mod.warning}</div>`
        : '';

    const findings = (mod.details || []).slice(0, 8);
    const extra    = (mod.issues || 0) - findings.length;

    const findingsHtml = findings.length
        ? findings.map((f, i) => renderFinding(f, mod.name, i)).join('')
        : '<div class="no-findings">✓ No issues found</div>';

    const extraHtml = extra > 0
        ? `<div class="extra-findings">+${extra} more findings — run full scan to see all</div>`
        : '';

    return `
  <div class="module-card${openClass}" id="mod-${mod.name.replace(/\s/g, '-')}">
    <div class="module-header" onclick="toggleModule(this)">
      <span class="sev-dot" style="background:${color}"></span>
      <span class="module-name">${mod.name}</span>
      ${passIcon}
      <span class="module-score" style="color:${sc}">${scoreStr}<span class="score-denom">/100</span></span>
      <svg class="chevron" width="8" height="8" viewBox="0 0 8 8" fill="none"><path d="M2 1l3 3-3 3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
    </div>
    <div class="module-body">
      ${warnText}
      ${findingsHtml}
      ${extraHtml}
      ${findings.length > 0 ? `
      <div class="mod-footer-actions">
        <button class="btn-mod-all" onclick="copyModulePrompt('${mod.name}')">
          <svg width="10" height="10" viewBox="0 0 16 16" fill="currentColor"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 0 1 0 1.5h-1.5a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-1.5a.75.75 0 0 1 1.5 0v1.5A1.75 1.75 0 0 1 9.25 16h-7.5A1.75 1.75 0 0 1 0 14.25Z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0 1 14.25 11h-7.5A1.75 1.75 0 0 1 5 9.25Zm1.75-.25a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-7.5a.25.25 0 0 0-.25-.25Z"/></svg>
          Copy all ${mod.name} issues
        </button>
      </div>` : ''}
    </div>
  </div>`;
}

function ringDashOffset(score: number | null): number {
    const r   = 36;
    const circ = 2 * Math.PI * r;
    const pct  = score !== null ? Math.max(0, Math.min(100, score)) / 100 : 0;
    return circ * (1 - pct);
}

export function getSidebarHtml(data: SidebarData, nonce: string): string {
    const { state, overall_score, verdict, modules = [], scanned_at, autoScan, scanningModule } = data;

    const score       = overall_score ?? null;
    const ringColor   = scoreColor(score);
    const r           = 36;
    const circ        = +(2 * Math.PI * r).toFixed(2);
    const dashOffset  = +ringDashOffset(score).toFixed(2);
    const vClass      = verdictClass(verdict);
    const verdictText = verdict || '—';

    const critCount = modules.reduce((n, m) => n + (m.details || []).filter(d => d.severity === 'critical').length, 0);
    const highCount  = modules.reduce((n, m) => n + (m.details || []).filter(d => d.severity === 'high').length, 0);
    const medCount   = modules.reduce((n, m) => n + (m.details || []).filter(d => d.severity === 'medium').length, 0);

    const lastScan = scanned_at
        ? new Date(scanned_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        : 'Never';

    // Sort modules: worst score first, nulls last
    const sortedMods = [...modules].sort((a, b) => {
        if (a.score === null && b.score === null) { return 0; }
        if (a.score === null) { return 1; }
        if (b.score === null) { return -1; }
        return a.score - b.score;
    });

    // Auto-open the worst module (first with issues)
    const firstWithIssues = sortedMods.findIndex(m => (m.issues || 0) > 0);

    const modulesHtml = state === 'done'
        ? sortedMods.map((m, i) => renderModule(m, i === firstWithIssues)).join('')
        : '';

    const scanningHtml = state === 'scanning' ? `
    <div class="scanning-banner">
      <div class="scan-spinner"></div>
      <span>Scanning${scanningModule ? ` · ${scanningModule}` : '…'}</span>
    </div>` : '';

    const emptyHtml = state === 'idle' ? `
    <div class="empty-state">
      <div class="empty-icon">🛡️</div>
      <div class="empty-title">Ready to scan</div>
      <div class="empty-sub">Click <strong>Run Scan</strong> to analyse your repo for security issues, license risks, AI artifacts, and more.</div>
    </div>` : '';

    const errorHtml = state === 'error' ? `
    <div class="error-state">
      <div class="error-icon">⚠️</div>
      <div class="error-title">Scan failed</div>
      <div class="error-sub">${data.error || 'Unknown error. Check the Output panel for details.'}</div>
    </div>` : '';

    // Serialise module data for JS access
    const moduleJson = JSON.stringify(modules);

    return /* html */`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ybe Check</title>
<style>
:root {
  --bg:        #0d1117;
  --surface:   #161b22;
  --surface2:  #1c2128;
  --border:    #30363d;
  --border2:   #21262d;
  --text:      #e6edf3;
  --muted:     #7d8590;
  --accent:    #7c3aed;
  --accent2:   #a855f7;
  --glow:      rgba(124,58,237,0.18);
  --crit:      #f85149;
  --high:      #fb8f44;
  --med:       #d29922;
  --low:       #388bfd;
  --pass:      #3fb950;
  --copilot:   #19b394;
  --r:         8px;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:-apple-system,'Segoe UI',sans-serif;font-size:12px;line-height:1.5;overflow-x:hidden}
::-webkit-scrollbar{width:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}

/* ── HEADER ── */
.header{padding:14px 14px 12px;border-bottom:1px solid var(--border);background:linear-gradient(160deg,#0f1318 0%,#0d1117 100%)}
.brand{display:flex;align-items:center;gap:9px;margin-bottom:14px}
.brand-logo{width:30px;height:30px;background:linear-gradient(135deg,var(--accent),var(--accent2));border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:15px;box-shadow:0 0 16px var(--glow);flex-shrink:0}
.brand-text{flex:1}
.brand-name{font-size:13px;font-weight:700;letter-spacing:.3px;color:var(--text)}
.brand-sub{font-size:10px;color:var(--muted);margin-top:1px}
.brand-badge{font-size:9px;color:var(--muted);background:var(--surface2);padding:2px 7px;border-radius:10px;border:1px solid var(--border);align-self:flex-start;margin-top:1px;flex-shrink:0}

/* ── SCORE RING ── */
.score-row{display:flex;align-items:center;gap:14px}
.ring-wrap{position:relative;width:88px;height:88px;flex-shrink:0}
.ring-wrap svg{transform:rotate(-90deg)}
.ring-bg{fill:none;stroke:var(--surface2);stroke-width:7}
.ring-fill{fill:none;stroke-width:7;stroke-linecap:round;stroke-dasharray:${circ};stroke-dashoffset:${dashOffset};transition:stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1),stroke .5s ease}
.ring-text{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;pointer-events:none}
.ring-num{font-size:24px;font-weight:800;line-height:1;color:${ringColor};font-variant-numeric:tabular-nums}
.ring-denom{font-size:9px;color:var(--muted);letter-spacing:.5px}
.score-meta{flex:1;min-width:0}
.verdict-chip{display:inline-flex;align-items:center;gap:5px;font-size:10px;font-weight:600;padding:3px 10px;border-radius:20px;margin-bottom:9px;letter-spacing:.3px;border:1px solid}
.verdict-chip.ready{background:rgba(63,185,80,.12);color:var(--pass);border-color:rgba(63,185,80,.3)}
.verdict-chip.attention{background:rgba(210,153,34,.12);color:var(--med);border-color:rgba(210,153,34,.3)}
.verdict-chip.not-ready{background:rgba(248,81,73,.12);color:var(--crit);border-color:rgba(248,81,73,.3)}
.verdict-chip.empty{background:var(--surface2);color:var(--muted);border-color:var(--border)}
.stats-row{display:flex;gap:10px;flex-wrap:wrap}
.stat{display:flex;align-items:center;gap:4px;font-size:10px;color:var(--muted)}
.stat-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}

/* ── ACTIONS ── */
.actions{padding:10px 14px;display:flex;gap:8px;align-items:center;border-bottom:1px solid var(--border);background:var(--bg)}
.btn-scan{flex:1;height:34px;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border:none;border-radius:var(--r);font-size:12px;font-weight:600;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:6px;transition:all .2s;letter-spacing:.3px;box-shadow:0 2px 8px var(--glow)}
.btn-scan:hover{transform:translateY(-1px);box-shadow:0 4px 16px var(--glow)}
.btn-scan:active{transform:none}
.btn-scan:disabled{background:var(--surface2);color:var(--muted);cursor:default;box-shadow:none;transform:none}
.auto-wrap{display:flex;flex-direction:column;align-items:center;gap:3px;flex-shrink:0}
.auto-label{font-size:9px;color:var(--muted);letter-spacing:.3px;text-transform:uppercase}
.toggle{position:relative;width:32px;height:17px;cursor:pointer}
.toggle input{opacity:0;width:0;height:0}
.t-slider{position:absolute;inset:0;background:var(--surface2);border:1px solid var(--border);border-radius:9px;transition:.2s}
.t-slider::before{content:'';position:absolute;width:11px;height:11px;left:2px;top:50%;transform:translateY(-50%);background:var(--muted);border-radius:50%;transition:.2s}
.toggle input:checked+.t-slider{background:rgba(124,58,237,.25);border-color:var(--accent)}
.toggle input:checked+.t-slider::before{transform:translate(15px,-50%);background:var(--accent);box-shadow:0 0 6px var(--glow)}

/* ── SCANNING BANNER ── */
.scanning-banner{display:flex;align-items:center;gap:10px;padding:10px 14px;font-size:11px;color:var(--muted);border-bottom:1px solid var(--border);background:var(--surface)}
.scan-spinner{width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}

/* ── MODULES SECTION ── */
.modules-section{padding:12px 14px}
.section-label{font-size:9px;font-weight:600;text-transform:uppercase;letter-spacing:1.2px;color:var(--muted);margin-bottom:10px;display:flex;align-items:center;gap:6px}
.section-label::after{content:'';flex:1;height:1px;background:var(--border2)}

/* ── MODULE CARD ── */
.module-card{background:var(--surface);border:1px solid var(--border2);border-radius:var(--r);margin-bottom:6px;overflow:hidden;transition:border-color .15s,box-shadow .15s}
.module-card:hover{border-color:var(--border)}
.module-card.open{border-color:var(--border);box-shadow:0 2px 12px rgba(0,0,0,.3)}
.module-header{display:flex;align-items:center;gap:8px;padding:9px 11px;cursor:pointer;user-select:none;transition:background .1s}
.module-header:hover{background:var(--surface2)}
.sev-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.module-name{flex:1;font-size:12px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pass-tick{font-size:11px;color:var(--pass);margin-right:2px}
.module-score{font-size:12px;font-weight:700;font-variant-numeric:tabular-nums;white-space:nowrap}
.score-denom{font-size:9px;color:var(--muted);font-weight:400}
.chevron{color:var(--muted);transition:transform .2s;flex-shrink:0}
.module-card.open .chevron{transform:rotate(90deg)}
.module-body{display:none;padding:0 11px 11px;border-top:1px solid var(--border2)}
.module-card.open .module-body{display:block}

/* ── FINDINGS ── */
.finding{padding:9px 10px;background:var(--surface2);border-radius:6px;margin-top:8px;border-left:2px solid}
.finding-top{display:flex;align-items:center;gap:6px;margin-bottom:4px}
.sev-badge{font-size:9px;font-weight:600;padding:1px 6px;border-radius:10px;text-transform:uppercase;letter-spacing:.5px;border:1px solid}
.rule-id{font-size:9px;font-family:'Cascadia Code','Fira Code',monospace;color:var(--muted);background:var(--surface);padding:1px 5px;border-radius:4px;border:1px solid var(--border2)}
.finding-desc{font-size:11px;color:var(--text);margin-bottom:4px;line-height:1.45;font-weight:500}
.finding-location{font-family:'Cascadia Code','Fira Code',monospace;font-size:10px;color:var(--muted);margin-bottom:7px}
.finding-actions{display:flex;gap:5px;flex-wrap:wrap}
.btn-fix{height:24px;padding:0 8px;border-radius:5px;border:1px solid var(--border);background:var(--surface);color:var(--muted);font-size:10px;font-weight:500;cursor:pointer;display:inline-flex;align-items:center;gap:4px;transition:all .15s;white-space:nowrap}
.btn-fix:hover{background:var(--surface2)}
.btn-copy:hover{border-color:var(--accent);color:var(--accent)}
.btn-copilot:hover{border-color:var(--copilot);color:var(--copilot)}
.no-findings{font-size:11px;color:var(--muted);padding:8px 0 2px;display:flex;align-items:center;gap:5px}
.extra-findings{font-size:10px;color:var(--muted);margin-top:8px;text-align:center;font-style:italic}
.mod-warning{font-size:10px;color:var(--med);padding:6px 8px;background:rgba(210,153,34,.08);border-radius:5px;margin-top:8px;border:1px solid rgba(210,153,34,.2)}
.mod-footer-actions{margin-top:10px;padding-top:8px;border-top:1px solid var(--border2);display:flex;gap:5px}
.btn-mod-all{height:24px;padding:0 8px;border-radius:5px;border:1px solid var(--border);background:transparent;color:var(--muted);font-size:10px;cursor:pointer;display:inline-flex;align-items:center;gap:4px;transition:all .15s}
.btn-mod-all:hover{border-color:var(--accent);color:var(--accent)}

/* ── EMPTY / ERROR ── */
.empty-state,.error-state{padding:28px 16px;text-align:center;color:var(--muted)}
.empty-icon,.error-icon{font-size:36px;margin-bottom:12px;opacity:.6}
.empty-title,.error-title{font-size:13px;font-weight:600;color:var(--text);margin-bottom:6px}
.empty-sub,.error-sub{font-size:11px;line-height:1.6;max-width:200px;margin:0 auto}
.empty-sub strong{color:var(--accent)}

/* ── FOOTER ── */
.footer{padding:8px 14px;border-top:1px solid var(--border2);display:flex;align-items:center;justify-content:space-between;color:var(--muted);font-size:10px;background:var(--bg)}
.footer-left{display:flex;align-items:center;gap:5px}
.footer-dot{width:5px;height:5px;border-radius:50%;background:var(--pass)}
.footer-dot.inactive{background:var(--muted)}
.btn-export{background:none;border:none;color:var(--muted);font-size:10px;cursor:pointer;padding:2px 6px;border-radius:4px;transition:all .15s}
.btn-export:hover{color:var(--text);background:var(--surface2)}

/* ── TOAST ── */
.toast{position:fixed;bottom:14px;left:50%;transform:translateX(-50%) translateY(10px);background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:6px 14px;font-size:11px;font-weight:500;opacity:0;transition:all .25s;pointer-events:none;white-space:nowrap;z-index:999;box-shadow:0 4px 16px rgba(0,0,0,.4)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.success{border-color:rgba(63,185,80,.4);color:var(--pass)}
.toast.info{border-color:rgba(124,58,237,.4);color:var(--accent2)}
</style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <div class="brand">
    <div class="brand-logo">🛡️</div>
    <div class="brand-text">
      <div class="brand-name">Ybe Check</div>
      <div class="brand-sub">AI Security Scanner</div>
    </div>
    <div class="brand-badge">v1.0</div>
  </div>

  <div class="score-row">
    <div class="ring-wrap">
      <svg width="88" height="88" viewBox="0 0 88 88">
        <circle class="ring-bg"   cx="44" cy="44" r="${r}"/>
        <circle class="ring-fill" cx="44" cy="44" r="${r}" stroke="${ringColor}"/>
      </svg>
      <div class="ring-text">
        <div class="ring-num">${score !== null ? score : '—'}</div>
        <div class="ring-denom">/100</div>
      </div>
    </div>
    <div class="score-meta">
      <div class="verdict-chip ${vClass || 'empty'}">${state === 'done' ? verdictText : (state === 'scanning' ? '⏳ Scanning…' : 'Not scanned')}</div>
      <div class="stats-row">
        ${critCount > 0 ? `<div class="stat"><span class="stat-dot" style="background:var(--crit)"></span>${critCount} critical</div>` : ''}
        ${highCount  > 0 ? `<div class="stat"><span class="stat-dot" style="background:var(--high)"></span>${highCount} high</div>`  : ''}
        ${medCount   > 0 ? `<div class="stat"><span class="stat-dot" style="background:var(--med)"></span>${medCount} medium</div>` : ''}
        ${critCount === 0 && highCount === 0 && medCount === 0 && state === 'done' ? `<div class="stat"><span class="stat-dot" style="background:var(--pass)"></span>No critical issues</div>` : ''}
        ${state !== 'done' ? `<div class="stat"><span class="stat-dot inactive"></span>No scan yet</div>` : ''}
      </div>
    </div>
  </div>
</div>

<!-- ACTIONS -->
<div class="actions">
  <button class="btn-scan" id="scanBtn" onclick="runScan()" ${state === 'scanning' ? 'disabled' : ''}>
    ${state === 'scanning'
        ? '<div class="scan-spinner" style="border-color:#444;border-top-color:#888;width:12px;height:12px"></div> Scanning…'
        : '<svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor"><path d="M8 4a4 4 0 1 1 0 8A4 4 0 0 1 8 4zm0 1.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5z"/><path d="M.5 8a7.5 7.5 0 1 1 15 0A7.5 7.5 0 0 1 .5 8zm7.5-6a6 6 0 1 0 0 12A6 6 0 0 0 8 2z"/></svg> Run Scan'}
  </button>
  <div class="auto-wrap">
    <div class="auto-label">Auto</div>
    <label class="toggle" title="Auto-scan on file save">
      <input type="checkbox" id="autoToggle" ${autoScan ? 'checked' : ''} onchange="toggleAuto(this.checked)">
      <span class="t-slider"></span>
    </label>
  </div>
</div>

${scanningHtml}

<!-- MODULES -->
<div class="modules-section">
  ${state === 'done' ? `<div class="section-label">Modules <span style="color:var(--accent);margin-left:4px">${modules.length}</span></div>` : ''}
  ${modulesHtml}
  ${emptyHtml}
  ${errorHtml}
</div>

<!-- FOOTER -->
<div class="footer">
  <div class="footer-left">
    <div class="footer-dot ${state !== 'done' ? 'inactive' : ''}"></div>
    Last scan: ${lastScan}
  </div>
  <button class="btn-export" onclick="exportReport()" title="Export full JSON report">Export ↗</button>
</div>

<!-- TOAST -->
<div class="toast" id="toast"></div>

<script nonce="${nonce}">
  const vscode = acquireVsCodeApi();
  const MODULES = ${moduleJson};

  function runScan() { vscode.postMessage({ type: 'runScan' }); }
  function toggleAuto(on) { vscode.postMessage({ type: 'toggleAutoScan', value: on }); }
  function exportReport() { vscode.postMessage({ type: 'exportReport' }); }

  function toggleModule(header) {
    header.parentElement.classList.toggle('open');
  }

  function getModuleFindings(modName) {
    const m = MODULES.find(x => x.name === modName);
    return m ? (m.details || []) : [];
  }

  function copyPrompt(modName, idx) {
    const findings = getModuleFindings(modName);
    vscode.postMessage({ type: 'copyPrompt', modName, findingIdx: idx, findings });
    showToast('✓ AI prompt copied to clipboard', 'success');
  }

  function openCopilot(modName, idx) {
    const findings = getModuleFindings(modName);
    vscode.postMessage({ type: 'openCopilot', modName, findingIdx: idx, findings });
    showToast('Opening in Copilot…', 'info');
  }

  function copyModulePrompt(modName) {
    const findings = getModuleFindings(modName);
    vscode.postMessage({ type: 'copyModulePrompt', modName, findings });
    showToast('✓ All ' + modName + ' issues copied', 'success');
  }

  function showToast(msg, type = '') {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.className = 'toast show ' + type;
    setTimeout(() => { t.className = 'toast'; }, 2500);
  }

  // Handle messages from extension host
  window.addEventListener('message', e => {
    const msg = e.data;
    if (msg.type === 'toast') { showToast(msg.text, msg.style || ''); }
  });
</script>
</body>
</html>`;
}
