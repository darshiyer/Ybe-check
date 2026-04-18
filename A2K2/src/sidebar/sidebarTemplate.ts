/**
 * sidebarTemplate.ts
 * Security inbox — verdict bar, flat to-do list, settings panel, resolved section.
 */

import { StoreData, StoredFinding } from './store';

export interface ModuleProgress {
    module: string;
    score: number | null;
    issues: number;
    status: string;
    done: boolean;
}

export interface SidebarSettings {
    scope: 'full' | 'changed' | 'path';
    pathFilter: string;
    autoScan: boolean;
}

export interface SidebarInput {
    store: StoreData | null;
    scanning: boolean;
    settings: SidebarSettings;
    counts: { open: number; fixed: number; ignored: number; total: number; new: number };
    scanProgress: ModuleProgress[];
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const SEV_W: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

function scoreColor(s: number | null): string {
    if (s === null) { return '#555'; }
    if (s >= 80) { return '#34d399'; }
    if (s >= 40) { return '#e8a959'; }
    return '#ff6166';
}

function shortPath(p: string): string {
    return p.length > 38 ? '...' + p.slice(-36) : p;
}

function timeAgo(iso: string | null): string {
    if (!iso) { return ''; }
    const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
    if (diff < 60)    { return `${diff}s ago`; }
    if (diff < 3600)  { return `${Math.floor(diff / 60)}m ago`; }
    if (diff < 86400) { return `${Math.floor(diff / 3600)}h ago`; }
    return `${Math.floor(diff / 86400)}d ago`;
}

// ── Finding grouping (by type+severity, NOT by module) ────────────────────────

interface FindingRow {
    type: string;
    severity: string;
    count: number;
    ids: string[];
    files: { path: string; line: number | string }[];
    reason: string;
    hasNew: boolean;
}

function buildRows(findings: StoredFinding[]): FindingRow[] {
    const map = new Map<string, FindingRow>();
    for (const f of findings) {
        const key = `${f.severity}::${f.type}`;
        let row = map.get(key);
        if (!row) {
            row = { type: f.type, severity: f.severity, count: 0, ids: [], files: [], reason: f.reason || '', hasNew: false };
            map.set(key, row);
        }
        row.count++;
        row.ids.push(f.id);
        if (f.isNew) { row.hasNew = true; }
        if (row.files.length < 8) { row.files.push({ path: f.file, line: f.line }); }
    }
    return Array.from(map.values())
        .sort((a, b) => (SEV_W[b.severity] || 0) - (SEV_W[a.severity] || 0));
}

// ── HTML render ──────────────────────────────────────────────────────────────

export function getSidebarHtml(input: SidebarInput, nonce: string): string {
    const { store, scanning, settings, counts, scanProgress } = input;
    const score    = store?.currentScore ?? null;
    const sc       = scoreColor(score);
    const findings = store?.findings || [];
    const lastAgo  = timeAgo(store?.lastScan ?? null);
    const hasScanned = !!store?.lastScan;

    const openFindings   = findings.filter(f => f.status === 'open');
    const fixedFindings  = findings.filter(f => f.status === 'fixed');
    const ignoredFindings = findings.filter(f => f.status === 'ignored');

    const openRows    = buildRows(openFindings);
    const fixedRows   = buildRows(fixedFindings);
    const ignoredRows = buildRows(ignoredFindings);

    // Verdict
    let verdictDot = '#555';
    let verdictLabel = '';
    let verdictSub = '';
    if (scanning) {
        verdictDot = '#e8a959';
        verdictLabel = 'Scanning…';
        verdictSub = scanProgress.length > 0
            ? `${scanProgress.length} modules done`
            : 'Starting…';
    } else if (hasScanned) {
        if (score !== null && score >= 80)      { verdictDot = '#34d399'; verdictLabel = 'Ready to ship'; }
        else if (score !== null && score >= 40) { verdictDot = '#e8a959'; verdictLabel = 'Needs work'; }
        else if (score !== null)                { verdictDot = '#ff6166'; verdictLabel = 'Not ready'; }

        const critical = openFindings.filter(f => f.severity === 'critical').length;
        const high     = openFindings.filter(f => f.severity === 'high').length;
        if (counts.open === 0) {
            verdictSub = 'All clear — nothing open';
        } else if (critical > 0) {
            verdictSub = `${critical} critical issue${critical !== 1 ? 's' : ''} blocking deploy`;
        } else if (high > 0) {
            verdictSub = `${high} high-severity issue${high !== 1 ? 's' : ''} to fix`;
        } else {
            verdictSub = `${counts.open} open issue${counts.open !== 1 ? 's' : ''}`;
        }
    }

    // Settings scope label for scan button tooltip
    const scopeLabel = settings.scope === 'changed' ? 'Scan changed files'
        : settings.scope === 'path' && settings.pathFilter ? `Scan ${settings.pathFilter}`
        : 'Run scan';

    function renderRow(row: FindingRow, idx: number): string {
        const idsAttr  = row.ids.join(',');
        const fileCount = row.count > 1 ? `<span class="r-fc">${row.count} files</span>` : '';
        const newBadge  = row.hasNew ? '<span class="r-new">new</span>' : '';
        const filesHtml = row.files.map(f =>
            `<div class="exp-file f-link" data-file="${f.path}" data-line="${f.line || 0}">${shortPath(f.path)}${f.line ? ':' + f.line : ''}</div>`
        ).join('');
        const moreFiles = row.count > row.files.length
            ? `<div class="exp-file exp-more">+ ${row.count - row.files.length} more</div>` : '';
        const reasonHtml = row.reason
            ? `<div class="exp-why">${row.reason.split('.')[0].trim()}.</div>` : '';

        return `
<div class="finding" id="fr-${idx}" data-ids="${idsAttr}">
  <div class="f-row" data-toggle="${idx}">
    <span class="sev sev-${row.severity}">${row.severity}</span>
    <span class="f-title">${row.type}</span>
    ${newBadge}
    ${fileCount}
    <button class="r-ai" data-action="fix" title="Fix with AI">Fix ✦</button>
    <svg class="f-chev" width="10" height="10" viewBox="0 0 10 10" fill="none"><path d="M3 1.5l3.5 3.5L3 8.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
  </div>
  <div class="f-exp">
    <div class="exp-files">${filesHtml}${moreFiles}</div>
    ${reasonHtml}
    <div class="exp-actions">
      <button class="btn btn-fix" data-action="fix">Fix with AI</button>
      <button class="btn btn-done" data-action="done">Done</button>
      <button class="btn btn-ign" data-action="ignore">Ignore</button>
    </div>
  </div>
</div>`;
    }

    function renderResolved(rows: FindingRow[], label: string, cls: string): string {
        if (rows.length === 0) { return ''; }
        const count = rows.reduce((n, r) => n + r.count, 0);
        const items = rows.map(row => {
            const idsAttr = row.ids.join(',');
            return `<div class="res-item">
              <span class="res-type">${row.type}</span>
              <button class="btn btn-reopen" data-action="reopen" data-ids="${idsAttr}">Reopen</button>
            </div>`;
        }).join('');
        return `
<details class="res-group">
  <summary class="res-sum ${cls}">${label} <span class="res-n">${count}</span></summary>
  <div class="res-list">${items}</div>
</details>`;
    }

    // ── Scanning progress (shown while scan runs) ──────────────────
    const progressHtml = scanning && scanProgress.length > 0 ? `
<div class="prog-list">
  ${scanProgress.map(p => `
  <div class="prog-row">
    <span class="prog-check">✓</span>
    <span class="prog-name">${p.module}</span>
    <span class="prog-n ${p.issues > 0 ? 'prog-has' : 'prog-ok'}">${p.issues > 0 ? p.issues : '—'}</span>
  </div>`).join('')}
  <div class="prog-row prog-cur">
    <span class="prog-pulse"></span>
    <span class="prog-name">Scanning…</span>
  </div>
</div>` : '';

    const findingsHtml = openRows.length > 0
        ? openRows.map((r, i) => renderRow(r, i)).join('')
        : hasScanned ? `<div class="all-clear"><div class="ac-icon">✓</div><div class="ac-text">All clear</div></div>` : '';

    const resolvedHtml = (fixedRows.length > 0 || ignoredRows.length > 0) ? `
<div class="res-section">
  ${renderResolved(fixedRows, 'Fixed', 'res-fixed')}
  ${renderResolved(ignoredRows, 'Ignored', 'res-ign')}
</div>` : '';

    const emptyHtml = !hasScanned && !scanning ? `
<div class="empty-state">
  <button class="btn-first" id="first-scan-btn">Run your first scan</button>
  <div class="empty-sub">Scans your repo for secrets, injection risks,<br>missing auth, insecure deps &amp; more.</div>
</div>` : '';

    return /* html */`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{
  --bg:#0a0a0a;--s:#141414;--s2:#1c1c1c;--b:#262626;--bh:#383838;
  --t:#ededed;--ts:#a0a0a0;--m:#555;
  --g:#34d399;--gd:rgba(52,211,153,.12);--ga:rgba(52,211,153,.25);
  --r:#ff6166;--rd:rgba(255,97,102,.1);
  --a:#e8a959;--ad:rgba(232,169,89,.1);
  --bl:#6eb0f7;--bld:rgba(110,176,247,.1);
  --rad:5px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--t);font-family:'Inter',-apple-system,sans-serif;font-size:12px;line-height:1.5;-webkit-font-smoothing:antialiased;display:flex;flex-direction:column;height:100vh;overflow:hidden}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-thumb{background:var(--b);border-radius:2px}

/* ── VERDICT BAR (sticky top) ── */
.vbar{flex-shrink:0;padding:14px 14px 10px;border-bottom:1px solid var(--b);background:var(--bg)}
.v-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px}
.brand{font-size:12px;font-weight:700;letter-spacing:-.2px;color:var(--ts)}
.brand b{color:var(--t)}
.v-acts{display:flex;gap:6px;align-items:center}
.v-scan{width:26px;height:26px;border-radius:var(--rad);border:1px solid var(--b);background:var(--t);color:var(--bg);font-size:11px;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:opacity .15s}
.v-scan:hover{opacity:.85}.v-scan:disabled{background:var(--s2);color:var(--m);cursor:default;border-color:var(--b)}
.v-gear{width:26px;height:26px;border-radius:var(--rad);border:1px solid var(--b);background:none;color:var(--m);font-size:13px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s}
.v-gear:hover{border-color:var(--bh);color:var(--t)}.v-gear.active{border-color:var(--g);color:var(--g)}

.v-status{display:flex;align-items:center;gap:8px}
.v-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0;background:${verdictDot}}
${settings.autoScan && hasScanned && !scanning ? '.v-dot{animation:vp 2.5s ease-in-out infinite}@keyframes vp{0%,100%{opacity:1}50%{opacity:.35}}' : ''}
.v-label{font-size:17px;font-weight:800;color:var(--t);letter-spacing:-.3px}
.v-score{font-size:10px;font-weight:600;padding:2px 8px;border-radius:100px;background:var(--s2);color:${sc};margin-top:1px}
.v-sub{font-size:11px;color:var(--ts);margin-top:4px;display:flex;align-items:center;gap:8px}
.v-time{color:var(--m);font-size:10px}

/* ── SETTINGS PANEL ── */
.settings{flex-shrink:0;border-bottom:1px solid var(--b);background:var(--s);padding:0;overflow:hidden;max-height:0;transition:max-height .2s ease,padding .2s}
.settings.open{max-height:200px;padding:12px 14px}
.s-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;font-size:11px}
.s-row:last-child{margin-bottom:0}
.s-label{color:var(--ts);width:52px;flex-shrink:0}
.s-ctrl{flex:1;display:flex;align-items:center;gap:8px}
.s-radio{display:flex;gap:6px}
.s-radio label{display:flex;align-items:center;gap:3px;cursor:pointer;color:var(--ts)}
.s-radio input{accent-color:var(--g);cursor:pointer}
.s-radio label:has(input:checked){color:var(--t)}
.s-input{flex:1;background:var(--bg);border:1px solid var(--b);border-radius:var(--rad);color:var(--t);font-size:11px;padding:4px 8px;outline:none}
.s-input:focus{border-color:var(--g)}
.s-input::placeholder{color:var(--m)}
.tog{position:relative;width:28px;height:15px;cursor:pointer;flex-shrink:0}
.tog input{opacity:0;width:0;height:0;position:absolute}
.tsl{position:absolute;inset:0;background:var(--s2);border:1px solid var(--b);border-radius:8px;transition:.2s}
.tsl::before{content:'';position:absolute;width:11px;height:11px;left:1px;top:50%;transform:translateY(-50%);background:var(--m);border-radius:50%;transition:.2s}
.tog input:checked+.tsl{background:var(--gd);border-color:var(--ga)}
.tog input:checked+.tsl::before{transform:translate(13px,-50%);background:var(--g)}

/* ── SCAN PROGRESS ── */
.prog-list{flex-shrink:0;padding:8px 14px;border-bottom:1px solid var(--b);background:var(--s)}
.prog-row{display:flex;align-items:center;gap:8px;font-size:11px;padding:2px 0}
.prog-check{color:var(--g);font-size:10px;width:12px}
.prog-pulse{width:6px;height:6px;border-radius:50%;background:var(--a);animation:pp .9s ease-in-out infinite;margin-left:3px}
@keyframes pp{0%,100%{opacity:1}50%{opacity:.2}}
.prog-cur{color:var(--ts)}
.prog-name{flex:1;color:var(--ts)}
.prog-n{font-size:10px;font-weight:600;min-width:20px;text-align:right}
.prog-has{color:var(--a)}.prog-ok{color:var(--m)}

/* ── MAIN SCROLLABLE ── */
.main{flex:1;overflow-y:auto;padding:0}

/* ── FINDINGS ── */
.findings-lbl{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--m);padding:10px 14px 6px}
.finding{border-bottom:1px solid var(--b)}
.f-row{display:flex;align-items:center;gap:8px;padding:9px 14px;cursor:pointer;transition:background .1s}
.f-row:hover{background:var(--s)}
.finding.open .f-row{background:var(--s)}
.sev{font-size:9px;font-weight:700;padding:2px 6px;border-radius:3px;text-transform:uppercase;letter-spacing:.3px;flex-shrink:0}
.sev-critical{background:var(--rd);color:var(--r)}
.sev-high{background:var(--ad);color:var(--a)}
.sev-medium{background:rgba(201,180,88,.1);color:#c9b458}
.sev-low{background:var(--bld);color:var(--bl)}
.f-title{flex:1;font-size:11px;font-weight:500;color:var(--t);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.r-new{font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;background:var(--gd);color:var(--g);flex-shrink:0}
.r-fc{font-size:10px;color:var(--m);flex-shrink:0}
.f-chev{color:var(--m);flex-shrink:0;transition:transform .15s}
.finding.open .f-chev{transform:rotate(90deg)}
.r-ai{height:20px;padding:0 7px;border-radius:3px;border:1px solid rgba(52,211,153,.2);background:var(--gd);color:var(--g);font-size:9px;font-weight:700;cursor:pointer;flex-shrink:0;transition:all .1s;white-space:nowrap}
.r-ai:hover{background:var(--ga);border-color:rgba(52,211,153,.4)}
.f-exp{display:none;padding:0 14px 12px;border-top:1px solid var(--b);background:var(--s)}
.finding.open .f-exp{display:block}
.exp-files{margin-top:8px;margin-bottom:6px}
.exp-file{font-family:'SF Mono','Cascadia Code',monospace;font-size:10px;color:var(--ts);padding:2px 0}
.f-link{cursor:pointer}.f-link:hover{color:var(--g);text-decoration:underline}
.exp-more{color:var(--m);font-style:italic}
.exp-why{font-size:10px;color:var(--ts);margin-bottom:10px;padding:6px 8px;background:var(--bg);border-radius:4px;line-height:1.5}
.exp-actions{display:flex;gap:5px}
.btn{height:24px;padding:0 10px;border-radius:var(--rad);border:1px solid var(--b);background:var(--s2);color:var(--ts);font-size:10px;font-weight:500;cursor:pointer;transition:all .1s}
.btn:hover{border-color:var(--bh);color:var(--t)}
.btn-fix{background:var(--gd);color:var(--g);border-color:rgba(52,211,153,.2);font-weight:600}
.btn-fix:hover{background:var(--ga);border-color:rgba(52,211,153,.4)}

/* ── ALL CLEAR ── */
.all-clear{padding:48px 14px;text-align:center}
.ac-icon{font-size:32px;color:var(--g);margin-bottom:8px}
.ac-text{font-size:13px;font-weight:600;color:var(--t)}

/* ── EMPTY STATE ── */
.empty-state{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 24px;text-align:center;gap:16px}
.btn-first{height:36px;padding:0 24px;background:var(--t);color:var(--bg);border:none;border-radius:var(--rad);font-size:12px;font-weight:700;cursor:pointer;transition:opacity .15s}
.btn-first:hover{opacity:.85}
.empty-sub{font-size:11px;color:var(--m);line-height:1.7}

/* ── RESOLVED SECTION ── */
.res-section{border-top:1px solid var(--b);flex-shrink:0}
.res-group{border-bottom:1px solid var(--b)}
.res-sum{display:flex;align-items:center;gap:8px;padding:8px 14px;cursor:pointer;font-size:11px;font-weight:600;color:var(--ts);list-style:none;user-select:none}
.res-sum::-webkit-details-marker{display:none}
.res-sum:hover{color:var(--t)}
.res-fixed{color:var(--g)}.res-ign{color:var(--m)}
.res-n{font-size:10px;font-weight:700;padding:1px 6px;border-radius:100px;background:var(--s2)}
.res-list{padding:4px 14px 8px}
.res-item{display:flex;align-items:center;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--b)}
.res-item:last-child{border-bottom:none}
.res-type{font-size:10px;color:var(--ts);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.btn-reopen{background:none;border:1px solid var(--b);color:var(--m);font-size:9px;padding:1px 7px;border-radius:3px;cursor:pointer;flex-shrink:0;margin-left:8px}
.btn-reopen:hover{border-color:var(--bh);color:var(--t)}

/* ── FOOTER ── */
.footer{flex-shrink:0;padding:7px 14px;border-top:1px solid var(--b);display:flex;justify-content:space-between;align-items:center;color:var(--m);font-size:10px}
.btn-exp{background:none;border:none;color:var(--m);font-size:10px;cursor:pointer}
.btn-exp:hover{color:var(--t)}

/* ── TOAST ── */
.toast{position:fixed;bottom:14px;left:50%;transform:translateX(-50%) translateY(8px);background:var(--s2);border:1px solid var(--b);border-radius:var(--rad);padding:5px 12px;font-size:11px;font-weight:500;opacity:0;transition:all .18s;pointer-events:none;z-index:999;white-space:nowrap}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.ok{border-color:rgba(52,211,153,.25);color:var(--g)}
</style>
</head>
<body>

<!-- VERDICT BAR -->
<div class="vbar">
  <div class="v-top">
    <div class="brand"><b>ybe</b>.check</div>
    <div class="v-acts">
      <button class="v-scan" id="scan-btn" title="${scopeLabel}" ${scanning ? 'disabled' : ''}>
        ${scanning ? '…' : '▶'}
      </button>
      <button class="v-gear ${/* active when open */''}'" id="gear-btn" title="Scan settings">⚙</button>
    </div>
  </div>
  ${hasScanned || scanning ? `
  <div class="v-status">
    <div class="v-dot"></div>
    <span class="v-label">${verdictLabel || '—'}</span>
    ${score !== null ? `<span class="v-score">${score}/100</span>` : ''}
  </div>
  <div class="v-sub">
    <span>${verdictSub}</span>
    ${lastAgo ? `<span class="v-time">${lastAgo}</span>` : ''}
  </div>` : ''}
</div>

<!-- SETTINGS PANEL -->
<div class="settings" id="settings-panel">
  <div class="s-row">
    <span class="s-label">Scope</span>
    <div class="s-ctrl s-radio">
      <label><input type="radio" name="scope" value="full" ${settings.scope === 'full' ? 'checked' : ''}> Full</label>
      <label><input type="radio" name="scope" value="changed" ${settings.scope === 'changed' ? 'checked' : ''}> Changed</label>
      <label><input type="radio" name="scope" value="path" ${settings.scope === 'path' ? 'checked' : ''}> Path</label>
    </div>
  </div>
  ${settings.scope === 'path' ? `
  <div class="s-row">
    <span class="s-label">Path</span>
    <div class="s-ctrl">
      <input class="s-input" id="path-input" placeholder="e.g. src/api" value="${settings.pathFilter}">
    </div>
  </div>` : ''}
  <div class="s-row">
    <span class="s-label">Auto-scan</span>
    <div class="s-ctrl">
      <label class="tog"><input type="checkbox" id="auto-cb" ${settings.autoScan ? 'checked' : ''}><span class="tsl"></span></label>
      <span style="font-size:10px;color:var(--m);margin-left:6px">on save</span>
    </div>
  </div>
</div>

<!-- SCAN PROGRESS -->
${progressHtml}

<!-- MAIN CONTENT -->
<div class="main">
  ${emptyHtml}

  ${hasScanned && openRows.length > 0 ? `
  <div class="findings-lbl">Open — ${openRows.length} issue${openRows.length !== 1 ? 's' : ''}</div>
  <div class="findings">${findingsHtml}</div>` : ''}

  ${hasScanned && openRows.length === 0 && !scanning ? findingsHtml : ''}

  ${resolvedHtml}
</div>

<!-- FOOTER -->
<div class="footer">
  <span style="color:var(--m)">ybe.check</span>
  <button class="btn-exp" id="exp-btn">Export JSON</button>
</div>

<div class="toast" id="toast"></div>

<script nonce="${nonce}">
(function(){
  var vscode = acquireVsCodeApi();

  function toast(msg, cls) {
    var t = document.getElementById('toast');
    if (!t) return;
    t.textContent = msg;
    t.className = 'toast show ' + (cls || '');
    setTimeout(function(){ t.className = 'toast'; }, 2500);
  }

  function getIds(el) {
    var f = el.closest('[data-ids]');
    return f ? (f.getAttribute('data-ids') || '').split(',').filter(Boolean) : [];
  }

  // Scan button
  document.getElementById('scan-btn')?.addEventListener('click', function(){
    vscode.postMessage({type:'runScan'});
  });

  // Gear toggle
  var gearBtn = document.getElementById('gear-btn');
  var settingsPanel = document.getElementById('settings-panel');
  gearBtn?.addEventListener('click', function(){
    if (!settingsPanel) return;
    var open = settingsPanel.classList.toggle('open');
    gearBtn.classList.toggle('active', open);
  });

  // Scope radios
  document.querySelectorAll('input[name="scope"]').forEach(function(radio){
    radio.addEventListener('change', function(){
      vscode.postMessage({type:'updateSettings', scope: this.value});
    });
  });

  // Path input
  var pathInput = document.getElementById('path-input');
  if (pathInput) {
    var pathTimer;
    pathInput.addEventListener('input', function(){
      clearTimeout(pathTimer);
      pathTimer = setTimeout(function(){
        vscode.postMessage({type:'updateSettings', pathFilter: pathInput.value});
      }, 500);
    });
  }

  // Auto-scan toggle
  document.getElementById('auto-cb')?.addEventListener('change', function(){
    vscode.postMessage({type:'toggleAutoScan', value: this.checked});
  });

  // Export
  document.getElementById('exp-btn')?.addEventListener('click', function(){
    vscode.postMessage({type:'exportReport'});
  });

  // First scan button
  document.getElementById('first-scan-btn')?.addEventListener('click', function(){
    vscode.postMessage({type:'runScan'});
  });

  // Event delegation
  document.addEventListener('click', function(e) {
    var el = e.target;
    while (el && el !== document.documentElement) {

      // Clickable file path
      if (el.classList && el.classList.contains('f-link') && !el.classList.contains('exp-more')) {
        vscode.postMessage({type:'openFile', file: el.getAttribute('data-file'), line: parseInt(el.getAttribute('data-line')||'0', 10)});
        return;
      }

      // Toggle finding expand
      var tog = el.getAttribute('data-toggle');
      if (tog !== null) {
        var fr = document.getElementById('fr-' + tog);
        if (fr) fr.classList.toggle('open');
        return;
      }

      // Action buttons
      var action = el.getAttribute('data-action');
      if (action) {
        var ids = el.hasAttribute('data-ids')
          ? (el.getAttribute('data-ids')||'').split(',').filter(Boolean)
          : getIds(el);

        if (action === 'fix') {
          if (ids.length > 0) vscode.postMessage({type:'fixWithAgent', findingId: ids[0]});
        } else if (action === 'done') {
          ids.forEach(function(id){ vscode.postMessage({type:'setStatus', findingId:id, status:'fixed'}); });
          toast('Marked as fixed', 'ok');
        } else if (action === 'ignore') {
          ids.forEach(function(id){ vscode.postMessage({type:'setStatus', findingId:id, status:'ignored'}); });
          toast('Ignored', 'ok');
        } else if (action === 'reopen') {
          ids.forEach(function(id){ vscode.postMessage({type:'setStatus', findingId:id, status:'open'}); });
          toast('Reopened', 'ok');
        }
        return;
      }

      el = el.parentElement;
    }
  });

  window.addEventListener('message', function(e) {
    if (e.data && e.data.type === 'toast') toast(e.data.text, e.data.style || '');
  });
})();
</script>
</body>
</html>`;
}
