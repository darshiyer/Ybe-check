/**
 * sidebarTemplate.ts
 * Security inbox — compact verdict strip, animated findings, VS Code theme vars.
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

function shortPath(p: string): string {
    return p.length > 36 ? '...' + p.slice(-34) : p;
}

function timeAgo(iso: string | null): string {
    if (!iso) { return ''; }
    const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
    if (diff < 60)    { return `${diff}s ago`; }
    if (diff < 3600)  { return `${Math.floor(diff / 60)}m ago`; }
    if (diff < 86400) { return `${Math.floor(diff / 3600)}h ago`; }
    return `${Math.floor(diff / 86400)}d ago`;
}

// ── Finding grouping (by type+severity, not by module) ────────────────────────

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
    const { store, scanning, settings, scanProgress } = input;
    const score    = store?.currentScore ?? null;
    const findings = store?.findings || [];
    const lastAgo  = timeAgo(store?.lastScan ?? null);
    const hasScanned = !!store?.lastScan;

    const openFindings    = findings.filter(f => f.status === 'open');
    const fixedFindings   = findings.filter(f => f.status === 'fixed');
    const ignoredFindings = findings.filter(f => f.status === 'ignored');

    const openRows    = buildRows(openFindings);
    const fixedRows   = buildRows(fixedFindings);
    const ignoredRows = buildRows(ignoredFindings);

    // Severity counts for open findings
    const crit = openFindings.filter(f => f.severity === 'critical').length;
    const high = openFindings.filter(f => f.severity === 'high').length;
    const med  = openFindings.filter(f => f.severity === 'medium').length;
    const low  = openFindings.filter(f => f.severity === 'low').length;

    // Verdict
    let verdictDot   = '#555';
    let verdictLabel = '';
    let verdictColor = 'var(--vscode-foreground)';

    if (scanning) {
        verdictDot = '#ff8c42'; verdictLabel = 'Scanning…'; verdictColor = '#ff8c42';
    } else if (hasScanned) {
        if (score !== null && score >= 80) {
            verdictDot = '#4ade80'; verdictLabel = 'Ready to ship'; verdictColor = '#4ade80';
        } else if (score !== null && score >= 40) {
            verdictDot = '#ff8c42'; verdictLabel = 'Needs work'; verdictColor = '#ff8c42';
        } else if (score !== null) {
            verdictDot = '#ff4d4d'; verdictLabel = 'Not ready'; verdictColor = '#ff4d4d';
        }
    }

    // Severity breakdown (row 2 of verdict strip)
    const sevParts: string[] = [];
    if (scanning) {
        const done = scanProgress.length;
        sevParts.push(`<span style="color:var(--vscode-descriptionForeground)">${done} module${done !== 1 ? 's' : ''} done</span>`);
    } else if (hasScanned) {
        if (crit > 0) { sevParts.push(`<span class="sb-c">${crit} critical</span>`); }
        if (high > 0) { sevParts.push(`<span class="sb-h">${high} high</span>`); }
        if (med > 0)  { sevParts.push(`<span class="sb-m">${med} med</span>`); }
        if (low > 0)  { sevParts.push(`<span class="sb-l">${low} low</span>`); }
        if (sevParts.length === 0) { sevParts.push(`<span class="sb-ok">No issues found</span>`); }
    }

    const scopeLabel = settings.scope === 'changed' ? 'Scan changed'
        : settings.scope === 'path' && settings.pathFilter ? `Scan ${settings.pathFilter}`
        : 'Scan';

    // ── renderRow (two-line card) ─────────────────────────────────
    function renderRow(row: FindingRow, idx: number): string {
        const idsAttr    = row.ids.join(',');
        const newBadge   = row.hasNew ? '<span class="r-new">new</span>' : '';
        const primaryFile = row.files[0];
        const extraCount  = row.count > 1 ? row.count - 1 : 0;

        const filesHtml = row.files.map(f =>
            `<div class="exp-file f-link" data-file="${f.path}" data-line="${f.line || 0}">${shortPath(f.path)}${f.line ? ':' + f.line : ''}<span class="exp-jump">↗</span></div>`
        ).join('');
        const reasonHtml = row.reason
            ? `<div class="exp-why">${row.reason.split('.')[0].trim()}.</div>` : '';

        return `
<div class="finding" id="fr-${idx}" data-ids="${idsAttr}">
  <div class="f-row" data-toggle="${idx}">
    <span class="sev sev-${row.severity}">${row.severity.toUpperCase()}</span>
    <span class="f-title">${row.type}</span>${newBadge}
    <button class="r-ai" data-action="fix" title="Fix with AI">🔧</button>
    <svg class="f-chev" width="10" height="10" viewBox="0 0 10 10" fill="none"><path d="M3 1.5l3.5 3.5L3 8.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
  </div>
  ${primaryFile ? `<div class="f-row2" data-toggle="${idx}">
    <span class="f-file f-link" data-file="${primaryFile.path}" data-line="${primaryFile.line || 0}">${shortPath(primaryFile.path)}${primaryFile.line ? ':' + primaryFile.line : ''}</span>${extraCount > 0 ? `<span class="f-more">+${extraCount} files</span>` : ''}
  </div>` : ''}
  <div class="f-exp">
    <div class="exp-files">${filesHtml}</div>
    ${reasonHtml}
    <div class="exp-actions">
      <button class="btn btn-fix" data-action="fix">Fix with AI</button>
      <button class="btn btn-done" data-action="done">Done ✓</button>
      <button class="btn btn-ign" data-action="ignore">Ignore</button>
    </div>
  </div>
</div>`;
    }

    // ── renderResolved ────────────────────────────────────────────
    function renderResolved(rows: FindingRow[], label: string, cls: string): string {
        if (rows.length === 0) { return ''; }
        const count = rows.reduce((n, r) => n + r.count, 0);
        const items = rows.map(row => {
            const idsAttr = row.ids.join(',');
            return `<div class="res-item">
              <span class="res-type">${row.type}</span>
              <button class="btn-reopen" data-action="reopen" data-ids="${idsAttr}">Reopen</button>
            </div>`;
        }).join('');
        return `
<details class="res-group">
  <summary class="res-sum ${cls}">${label} <span class="res-n">${count}</span></summary>
  <div class="res-list">${items}</div>
</details>`;
    }

    // ── Scan progress ─────────────────────────────────────────────
    const progressHtml = scanning ? `
<div class="scan-prog">
  <div class="prog-bar"><div class="prog-fill"></div></div>
  ${scanProgress.length > 0 ? `<div class="prog-modules">
    ${scanProgress.map(p => `
    <div class="prog-row">
      <span class="prog-check">✓</span>
      <span class="prog-name">${p.module}</span>
      <span class="prog-n ${p.issues > 0 ? 'has-issues' : ''}">${p.issues > 0 ? p.issues : '—'}</span>
    </div>`).join('')}
    <div class="prog-row prog-cur"><span class="prog-pulse"></span><span class="prog-name">Running…</span></div>
  </div>` : ''}
</div>` : '';

    const findingsHtml = openRows.length > 0
        ? openRows.map((r, i) => renderRow(r, i)).join('')
        : hasScanned ? `<div class="all-clear"><div class="ac-icon">✓</div><div>All clear</div></div>` : '';

    const resolvedHtml = (fixedRows.length > 0 || ignoredRows.length > 0) ? `
<div class="res-section">
  ${renderResolved(fixedRows, 'Fixed', 'res-fixed')}
  ${renderResolved(ignoredRows, 'Ignored', 'res-ign')}
</div>` : '';

    const emptyHtml = !hasScanned && !scanning ? `
<div class="empty-state">
  <div class="empty-icon">🔍</div>
  <div class="empty-title">Run your first scan</div>
  <button class="btn-first" id="first-scan-btn">Scan repo</button>
  <div class="empty-sub">Secrets, injection risks, missing auth,<br>insecure deps &amp; more.</div>
</div>` : '';

    return /* html */`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
/* ── Severity palette (not theme-dependent) ── */
:root {
  --sev-c:#ff4d4d; --sev-c-bg:rgba(255,77,77,.13);
  --sev-h:#ff8c42; --sev-h-bg:rgba(255,140,66,.13);
  --sev-m:#ffd166; --sev-m-bg:rgba(255,209,102,.10);
  --sev-l:#8a8a8a; --sev-l-bg:rgba(138,138,138,.10);
  --ok:#4ade80;    --ok-bg:rgba(74,222,128,.12); --ok-hi:rgba(74,222,128,.25);
  --rad:4px;
}

/* ── Base — VS Code theme variables ── */
*{box-sizing:border-box;margin:0;padding:0}
body{
  background:var(--vscode-sideBar-background);
  color:var(--vscode-foreground);
  font-family:var(--vscode-font-family,-apple-system,sans-serif);
  font-size:12px; line-height:1.5; -webkit-font-smoothing:antialiased;
  display:flex; flex-direction:column; height:100vh; overflow:hidden;
}
::-webkit-scrollbar{width:3px}
::-webkit-scrollbar-thumb{background:var(--vscode-scrollbarSlider-background);border-radius:2px}

/* ── VERDICT STRIP ── */
.vbar{
  flex-shrink:0; padding:10px 12px 8px;
  border-bottom:1px solid var(--vscode-panel-border);
}
.v-row1{display:flex;align-items:center;justify-content:space-between;margin-bottom:5px}
.v-left{display:flex;align-items:center;gap:7px;flex:1;min-width:0}
.v-dot{
  width:8px;height:8px;border-radius:50%;flex-shrink:0;
  background:${verdictDot};
  transition:background-color .4s ease;
}
${settings.autoScan && hasScanned && !scanning ? '.v-dot{animation:vp 2.5s ease-in-out infinite}@keyframes vp{0%,100%{opacity:1}50%{opacity:.3}}' : ''}
.v-label{
  font-size:14px;font-weight:700;letter-spacing:-.2px;
  color:${verdictColor};
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}
.v-score{
  font-size:10px;font-weight:600;padding:1px 7px;border-radius:10px;
  background:var(--vscode-badge-background,rgba(255,255,255,.08));
  color:var(--vscode-badge-foreground,${verdictColor});
  flex-shrink:0; transition:color .4s ease;
}
.v-right{display:flex;align-items:center;gap:4px;flex-shrink:0}
.v-time{font-size:10px;color:var(--vscode-descriptionForeground);padding:0 2px}
.vbtn{
  width:22px;height:22px;border:1px solid var(--vscode-panel-border);
  background:none;color:var(--vscode-foreground);border-radius:var(--rad);
  cursor:pointer;font-size:12px;display:flex;align-items:center;justify-content:center;
  opacity:.65;transition:opacity .15s;flex-shrink:0;
}
.vbtn:hover{opacity:1}.vbtn:disabled{opacity:.25;cursor:default}
.vbtn.active{color:var(--ok);border-color:rgba(74,222,128,.4);opacity:1}
.v-row2{display:flex;align-items:center;gap:5px;font-size:10px;font-weight:600}
.sb-c{color:var(--sev-c)}.sb-h{color:var(--sev-h)}.sb-m{color:var(--sev-m)}.sb-l{color:var(--sev-l)}.sb-ok{color:var(--ok)}
.v-sep{color:var(--vscode-descriptionForeground);font-weight:400}
.v-scan-lnk{
  color:var(--vscode-descriptionForeground);font-weight:400;cursor:pointer;
  margin-left:auto;background:none;border:none;font-size:10px;padding:0;
}
.v-scan-lnk:hover{color:var(--vscode-foreground)}

/* ── SETTINGS PANEL ── */
.settings{
  flex-shrink:0;border-bottom:1px solid var(--vscode-panel-border);
  background:var(--vscode-editor-background);
  padding:0;overflow:hidden;max-height:0;
  transition:max-height .2s ease,padding .2s;
}
.settings.open{max-height:220px;padding:10px 12px}
.s-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:9px;font-size:11px}
.s-row:last-child{margin-bottom:0}
.s-label{color:var(--vscode-descriptionForeground);width:56px;flex-shrink:0}
.s-ctrl{flex:1;display:flex;align-items:center;gap:6px}
.s-radio{display:flex;gap:6px}
.s-radio label{display:flex;align-items:center;gap:3px;cursor:pointer;color:var(--vscode-descriptionForeground)}
.s-radio input{accent-color:var(--ok);cursor:pointer}
.s-radio label:has(input:checked){color:var(--vscode-foreground)}
.s-input{
  flex:1;background:var(--vscode-input-background);
  border:1px solid var(--vscode-input-border,var(--vscode-panel-border));
  border-radius:var(--rad);color:var(--vscode-input-foreground);
  font-size:11px;padding:3px 7px;outline:none;
}
.s-input:focus{border-color:var(--vscode-focusBorder)}
.s-input::placeholder{color:var(--vscode-input-placeholderForeground)}
.tog{position:relative;width:28px;height:15px;cursor:pointer;flex-shrink:0}
.tog input{opacity:0;width:0;height:0;position:absolute}
.tsl{position:absolute;inset:0;background:var(--vscode-panel-border);border-radius:8px;transition:.2s}
.tsl::before{content:'';position:absolute;width:11px;height:11px;left:1px;top:50%;transform:translateY(-50%);background:var(--vscode-descriptionForeground);border-radius:50%;transition:.2s}
.tog input:checked+.tsl{background:rgba(74,222,128,.25)}
.tog input:checked+.tsl::before{transform:translate(13px,-50%);background:var(--ok)}

/* ── SCAN PROGRESS ── */
.scan-prog{
  flex-shrink:0;padding:8px 12px;
  border-bottom:1px solid var(--vscode-panel-border);
  background:var(--vscode-editor-background);
}
.prog-bar{height:2px;background:var(--vscode-panel-border);border-radius:1px;overflow:hidden;margin-bottom:8px}
.prog-fill{height:100%;background:var(--ok);border-radius:1px;animation:scanslide 1.8s ease-in-out infinite}
@keyframes scanslide{0%{width:0;margin-left:0}50%{width:55%;margin-left:20%}100%{width:0;margin-left:100%}}
.prog-modules{}
.prog-row{display:flex;align-items:center;gap:7px;font-size:11px;padding:1px 0}
.prog-check{color:var(--ok);font-size:10px;width:12px}
.prog-pulse{width:6px;height:6px;border-radius:50%;background:var(--sev-h);animation:pp .9s ease-in-out infinite;margin-left:3px}
@keyframes pp{0%,100%{opacity:1}50%{opacity:.2}}
.prog-cur{color:var(--vscode-descriptionForeground)}
.prog-name{flex:1;color:var(--vscode-descriptionForeground)}
.prog-n{font-size:10px;font-weight:600;min-width:20px;text-align:right;color:var(--vscode-descriptionForeground)}
.prog-n.has-issues{color:var(--sev-h)}

/* ── MAIN ── */
.main{flex:1;overflow-y:auto}

/* ── FINDINGS ── */
.findings-hdr{
  font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;
  color:var(--vscode-descriptionForeground);padding:8px 12px 4px;
}
.finding{
  border-bottom:1px solid var(--vscode-panel-border);
  overflow:hidden; /* needed for collapse animation */
}
.f-row{display:flex;align-items:center;gap:7px;padding:8px 12px 3px;cursor:pointer}
.f-row:hover,.f-row2:hover{background:var(--vscode-list-hoverBackground)}
.finding.open .f-row{background:var(--vscode-list-activeSelectionBackground,var(--vscode-list-hoverBackground))}
.f-row2{display:flex;align-items:center;gap:6px;padding:1px 12px 7px;cursor:pointer}

/* severity badges */
.sev{font-size:8px;font-weight:800;padding:2px 5px;border-radius:3px;text-transform:uppercase;letter-spacing:.4px;flex-shrink:0}
.sev-critical{background:var(--sev-c-bg);color:var(--sev-c)}
.sev-high    {background:var(--sev-h-bg);color:var(--sev-h)}
.sev-medium  {background:var(--sev-m-bg);color:var(--sev-m)}
.sev-low     {background:var(--sev-l-bg);color:var(--sev-l)}

.f-title{flex:1;font-size:11px;font-weight:600;color:var(--vscode-foreground);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.r-new{font-size:8px;font-weight:700;padding:1px 4px;border-radius:3px;background:var(--ok-bg);color:var(--ok);flex-shrink:0}
.r-ai{
  height:20px;padding:0 6px;
  border:1px solid rgba(74,222,128,.25);background:var(--ok-bg);color:var(--ok);
  border-radius:3px;font-size:10px;cursor:pointer;flex-shrink:0;transition:all .12s;
}
.r-ai:hover{background:var(--ok-hi);border-color:rgba(74,222,128,.5);box-shadow:0 0 8px rgba(74,222,128,.2)}
.f-chev{color:var(--vscode-descriptionForeground);flex-shrink:0;transition:transform .15s}
.finding.open .f-chev{transform:rotate(90deg)}

.f-file{
  font-family:var(--vscode-editor-font-family,monospace);font-size:10px;
  color:var(--vscode-descriptionForeground);cursor:pointer;
  flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
}
.f-file:hover{color:var(--vscode-textLink-foreground,var(--ok));text-decoration:underline}
.f-more{font-size:10px;color:var(--vscode-descriptionForeground);flex-shrink:0}

/* expanded */
.f-exp{display:none;padding:0 12px 10px;border-top:1px solid var(--vscode-panel-border);background:var(--vscode-editor-background)}
.finding.open .f-exp{display:block}
.exp-files{margin:8px 0 6px}
.exp-file{
  font-family:var(--vscode-editor-font-family,monospace);font-size:10px;
  color:var(--vscode-descriptionForeground);padding:3px 0;cursor:pointer;
  display:flex;align-items:center;justify-content:space-between;
}
.exp-file:hover{color:var(--vscode-textLink-foreground,var(--ok))}
.exp-jump{font-size:9px;opacity:.5;flex-shrink:0}
.exp-why{
  font-size:10px;color:var(--vscode-descriptionForeground);
  margin-bottom:10px;padding:5px 8px;
  background:var(--vscode-sideBar-background);
  border-radius:var(--rad);border-left:2px solid var(--vscode-panel-border);line-height:1.5;
}
.exp-actions{display:flex;gap:6px}

/* buttons */
.btn{
  height:24px;padding:0 10px;border-radius:var(--rad);
  border:1px solid var(--vscode-panel-border);
  background:var(--vscode-button-secondaryBackground,rgba(255,255,255,.05));
  color:var(--vscode-descriptionForeground);font-size:10px;font-weight:500;cursor:pointer;transition:all .1s;
}
.btn:hover{background:var(--vscode-list-hoverBackground);color:var(--vscode-foreground);border-color:var(--vscode-focusBorder)}
.btn-fix{background:var(--ok-bg);color:var(--ok);border-color:rgba(74,222,128,.2);font-weight:700}
.btn-fix:hover{background:var(--ok-hi);border-color:rgba(74,222,128,.4)}
.btn-ign{background:none;border-color:transparent;color:var(--vscode-descriptionForeground)}
.btn-reopen{
  background:none;border:none;color:var(--vscode-descriptionForeground);
  font-size:9px;cursor:pointer;padding:0;
}
.btn-reopen:hover{color:var(--vscode-foreground)}

/* ── RESOLUTION ANIMATION ── */
.finding.resolving{background:var(--ok-bg) !important;transition:background .15s}
.finding.resolving .f-title{text-decoration:line-through;opacity:.45;transition:opacity .15s,text-decoration .15s}

/* ── ALL CLEAR ── */
.all-clear{padding:40px 12px;text-align:center;color:var(--ok);font-size:13px;font-weight:600}
.ac-icon{font-size:28px;margin-bottom:8px}

/* ── EMPTY STATE ── */
.empty-state{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:28px 20px;text-align:center;gap:12px}
.empty-icon{font-size:28px;opacity:.4}
.empty-title{font-size:13px;font-weight:600;color:var(--vscode-foreground)}
.btn-first{
  height:32px;padding:0 20px;
  background:var(--vscode-button-background);color:var(--vscode-button-foreground);
  border:none;border-radius:var(--rad);font-size:12px;font-weight:600;cursor:pointer;
  transition:opacity .15s;
}
.btn-first:hover{opacity:.85}
.empty-sub{font-size:10px;color:var(--vscode-descriptionForeground);line-height:1.7}

/* ── RESOLVED ── */
.res-section{border-top:1px solid var(--vscode-panel-border);flex-shrink:0}
.res-group{border-bottom:1px solid var(--vscode-panel-border)}
.res-sum{
  display:flex;align-items:center;gap:7px;padding:7px 12px;cursor:pointer;
  font-size:11px;font-weight:600;color:var(--vscode-descriptionForeground);
  list-style:none;user-select:none;
}
.res-sum::-webkit-details-marker{display:none}
.res-sum:hover{color:var(--vscode-foreground)}
.res-fixed{color:var(--ok)}.res-ign{color:var(--vscode-descriptionForeground)}
.res-n{font-size:9px;font-weight:700;padding:1px 5px;border-radius:10px;background:var(--vscode-badge-background);color:var(--vscode-badge-foreground)}
.res-list{padding:2px 12px 8px}
.res-item{display:flex;align-items:center;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--vscode-panel-border)}
.res-item:last-child{border-bottom:none}
.res-type{font-size:10px;color:var(--vscode-descriptionForeground);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* ── FOOTER ── */
.footer{
  flex-shrink:0;padding:5px 12px;border-top:1px solid var(--vscode-panel-border);
  display:flex;justify-content:space-between;align-items:center;
  font-size:10px;color:var(--vscode-descriptionForeground);
}
.btn-exp{background:none;border:none;color:var(--vscode-descriptionForeground);font-size:10px;cursor:pointer;padding:0}
.btn-exp:hover{color:var(--vscode-foreground)}

/* ── TOAST ── */
.toast{
  position:fixed;bottom:12px;left:50%;
  transform:translateX(-50%) translateY(8px);
  background:var(--vscode-editor-background);border:1px solid var(--vscode-panel-border);
  border-radius:var(--rad);padding:4px 12px;font-size:11px;font-weight:500;
  opacity:0;transition:all .18s;pointer-events:none;z-index:999;white-space:nowrap;
}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.ok{border-color:rgba(74,222,128,.3);color:var(--ok)}
</style>
</head>
<body>

<!-- VERDICT STRIP -->
<div class="vbar">
  <div class="v-row1">
    <div class="v-left">
      <div class="v-dot"></div>
      <span class="v-label">${verdictLabel || 'ybe.check'}</span>
      ${score !== null ? `<span class="v-score" id="v-score-el" data-score="${score}">${score}/100</span>` : ''}
    </div>
    <div class="v-right">
      ${lastAgo ? `<span class="v-time">${lastAgo}</span>` : ''}
      <button class="vbtn" id="scan-btn" title="${scopeLabel}" ${scanning ? 'disabled' : ''}>⟳</button>
      <button class="vbtn" id="gear-btn" title="Settings">⚙</button>
    </div>
  </div>
  <div class="v-row2">
    ${sevParts.join(`<span class="v-sep"> · </span>`)}
    ${!scanning && hasScanned ? `<button class="v-scan-lnk" id="scan-lnk">${scopeLabel}</button>` : ''}
  </div>
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
      <span style="font-size:10px;color:var(--vscode-descriptionForeground);margin-left:6px">on save</span>
    </div>
  </div>
  <div class="s-row">
    <span class="s-label">Export</span>
    <div class="s-ctrl">
      <button class="btn" id="exp-btn-s" style="height:22px;font-size:10px">Export JSON</button>
    </div>
  </div>
</div>

<!-- SCAN PROGRESS -->
${progressHtml}

<!-- MAIN CONTENT -->
<div class="main">
  ${emptyHtml}

  ${hasScanned && openRows.length > 0 ? `
  <div class="findings-hdr">Open · ${openRows.length} issue${openRows.length !== 1 ? 's' : ''}</div>
  <div class="findings">${findingsHtml}</div>` : ''}

  ${hasScanned && openRows.length === 0 && !scanning ? findingsHtml : ''}

  ${resolvedHtml}
</div>

<!-- FOOTER -->
<div class="footer">
  <span>ybe.check</span>
  <button class="btn-exp" id="exp-btn">↓ export</button>
</div>

<div class="toast" id="toast"></div>

<script nonce="${nonce}">
(function(){
  var vscode = acquireVsCodeApi();

  // ── Score count-up on re-render ────────────────────────────────
  var state = vscode.getState() || {};
  var scoreEl = document.getElementById('v-score-el');
  if (scoreEl) {
    var newScore = parseInt(scoreEl.dataset.score || '0', 10);
    var prevScore = state.score;
    if (prevScore !== undefined && prevScore !== newScore) {
      var from = prevScore, to = newScore, dur = 500, t0 = performance.now();
      (function tick(now) {
        var t = Math.min((now - t0) / dur, 1);
        var eased = 1 - Math.pow(1 - t, 3);
        scoreEl.textContent = Math.round(from + (to - from) * eased) + '/100';
        if (t < 1) requestAnimationFrame(tick);
      })(performance.now());
    }
    vscode.setState(Object.assign({}, state, {score: newScore}));
  }

  // ── Helpers ────────────────────────────────────────────────────
  function toast(msg, cls) {
    var t = document.getElementById('toast');
    if (!t) { return; }
    t.textContent = msg;
    t.className = 'toast show ' + (cls || '');
    setTimeout(function(){ t.className = 'toast'; }, 2200);
  }

  function getIds(el) {
    var f = el.closest('[data-ids]');
    return f ? (f.getAttribute('data-ids') || '').split(',').filter(Boolean) : [];
  }

  // ── Resolution animation ───────────────────────────────────────
  // Animate THEN send setStatus so re-render doesn't kill the animation
  function resolveWithAnimation(findingEl, ids, status) {
    findingEl.classList.add('resolving');
    setTimeout(function() {
      var h = findingEl.offsetHeight;
      findingEl.style.overflow = 'hidden';
      findingEl.style.maxHeight = h + 'px';
      findingEl.offsetHeight; // force reflow
      findingEl.style.transition = 'max-height 280ms ease-out, opacity 220ms ease-out, padding 280ms ease-out, margin 220ms ease-out';
      findingEl.style.maxHeight = '0';
      findingEl.style.opacity = '0';
      findingEl.style.paddingTop = '0';
      findingEl.style.paddingBottom = '0';
      findingEl.style.marginTop = '0';
      findingEl.style.marginBottom = '0';
      setTimeout(function() {
        ids.forEach(function(id){
          vscode.postMessage({type:'setStatus', findingId:id, status:status});
        });
      }, 290);
    }, 110);
  }

  // ── Scan triggers ──────────────────────────────────────────────
  function triggerScan() { vscode.postMessage({type:'runScan'}); }
  document.getElementById('scan-btn')?.addEventListener('click', triggerScan);
  document.getElementById('scan-lnk')?.addEventListener('click', triggerScan);
  document.getElementById('first-scan-btn')?.addEventListener('click', triggerScan);

  // ── Gear toggle ────────────────────────────────────────────────
  var gearBtn = document.getElementById('gear-btn');
  var panel   = document.getElementById('settings-panel');
  gearBtn?.addEventListener('click', function(){
    if (!panel) { return; }
    var open = panel.classList.toggle('open');
    gearBtn.classList.toggle('active', open);
  });

  // ── Scope radios ───────────────────────────────────────────────
  document.querySelectorAll('input[name="scope"]').forEach(function(r){
    r.addEventListener('change', function(){
      vscode.postMessage({type:'updateSettings', scope: this.value});
    });
  });

  // ── Path input ─────────────────────────────────────────────────
  var pi = document.getElementById('path-input'), piTimer;
  if (pi) {
    pi.addEventListener('input', function(){
      clearTimeout(piTimer);
      piTimer = setTimeout(function(){ vscode.postMessage({type:'updateSettings', pathFilter: pi.value}); }, 500);
    });
  }

  // ── Auto-scan toggle ───────────────────────────────────────────
  document.getElementById('auto-cb')?.addEventListener('change', function(){
    vscode.postMessage({type:'toggleAutoScan', value: this.checked});
  });

  // ── Export ─────────────────────────────────────────────────────
  function doExport() { vscode.postMessage({type:'exportReport'}); }
  document.getElementById('exp-btn')?.addEventListener('click', doExport);
  document.getElementById('exp-btn-s')?.addEventListener('click', doExport);

  // ── Event delegation ───────────────────────────────────────────
  document.addEventListener('click', function(e) {
    var el = e.target;
    while (el && el !== document.documentElement) {

      // Clickable file path
      if (el.classList && el.classList.contains('f-link') && !el.classList.contains('exp-more')) {
        var file = el.getAttribute('data-file');
        var line = parseInt(el.getAttribute('data-line') || '0', 10);
        if (file) { vscode.postMessage({type:'openFile', file:file, line:line}); return; }
      }

      // Expand toggle
      var tog = el.getAttribute('data-toggle');
      if (tog !== null) {
        var fr = document.getElementById('fr-' + tog);
        if (fr) { fr.classList.toggle('open'); }
        return;
      }

      // Action buttons
      var action = el.getAttribute('data-action');
      if (action) {
        var ids = el.hasAttribute('data-ids')
          ? (el.getAttribute('data-ids') || '').split(',').filter(Boolean)
          : getIds(el);

        if (action === 'fix') {
          if (ids.length > 0) { vscode.postMessage({type:'fixWithAgent', findingId:ids[0]}); }
          return;
        }

        if (action === 'done' || action === 'ignore') {
          var status = action === 'done' ? 'fixed' : 'ignored';
          var findingEl = el.closest('.finding');
          if (findingEl && ids.length > 0) {
            toast(status === 'fixed' ? 'Marked fixed ✓' : 'Ignored', 'ok');
            resolveWithAnimation(findingEl, ids, status);
          } else {
            ids.forEach(function(id){ vscode.postMessage({type:'setStatus', findingId:id, status:status}); });
          }
          return;
        }

        if (action === 'reopen') {
          ids.forEach(function(id){ vscode.postMessage({type:'setStatus', findingId:id, status:'open'}); });
          toast('Reopened', 'ok');
          return;
        }

        return;
      }
      el = el.parentElement;
    }
  });

  // ── Messages from extension ────────────────────────────────────
  window.addEventListener('message', function(e) {
    if (e.data && e.data.type === 'toast') { toast(e.data.text, e.data.style || ''); }
  });
})();
</script>
</body>
</html>`;
}
