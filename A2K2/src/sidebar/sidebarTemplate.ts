/**
 * sidebarTemplate.ts
 * Security inbox — streaming progress, scope indicator, last-scanned age.
 */

import { StoreData, StoredFinding } from './store';

export interface ModuleProgress {
    module: string;
    score: number | null;
    issues: number;
    status: string;
    done: boolean;
}

export interface SidebarInput {
    store: StoreData | null;
    scanning: boolean;
    autoScan: boolean;
    counts: { open: number; fixed: number; ignored: number; total: number; new: number };
    scanProgress: ModuleProgress[];
    scanScope: string;
}

interface FindingGroup {
    type: string;
    module: string;
    severity: string;
    count: number;
    files: { path: string; line: number | string }[];
    ids: string[];
    reason: string;
    hasNew: boolean;
}

function groupFindings(findings: StoredFinding[]): FindingGroup[] {
    const map = new Map<string, FindingGroup>();
    for (const f of findings) {
        const key = `${f.module}::${f.type}::${f.severity}`;
        let g = map.get(key);
        if (!g) {
            g = { type: f.type, module: f.module, severity: f.severity, count: 0, files: [], ids: [], reason: f.reason || '', hasNew: false };
            map.set(key, g);
        }
        g.count++;
        g.ids.push(f.id);
        if (f.isNew) { g.hasNew = true; }
        if (g.files.length < 5) { g.files.push({ path: f.file, line: f.line }); }
    }
    return Array.from(map.values());
}

const SEV_W: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

function scoreColor(s: number | null): string {
    if (s === null) { return '#555'; }
    if (s >= 80) { return '#34d399'; }
    if (s >= 40) { return '#e8a959'; }
    return '#ff6166';
}

function shortPath(p: string): string {
    return p.length > 35 ? '...' + p.slice(-33) : p;
}

function timeAgo(iso: string | null): string {
    if (!iso) { return ''; }
    const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
    if (diff < 60) { return 'just now'; }
    if (diff < 3600) { return `${Math.floor(diff / 60)}m ago`; }
    if (diff < 86400) { return `${Math.floor(diff / 3600)}h ago`; }
    return `${Math.floor(diff / 86400)}d ago`;
}

export function getSidebarHtml(input: SidebarInput, nonce: string): string {
    const { store, scanning, autoScan, counts, scanProgress, scanScope } = input;
    const score = store?.currentScore ?? null;
    const sc = scoreColor(score);
    const findings = store?.findings || [];
    const lastAgo = timeAgo(store?.lastScan ?? null);

    const openGroups = groupFindings(findings.filter(f => f.status === 'open'))
        .sort((a, b) => {
            const sd = (SEV_W[b.severity] || 0) - (SEV_W[a.severity] || 0);
            return sd !== 0 ? sd : b.count - a.count;
        });

    const fixedCount   = findings.filter(f => f.status === 'fixed').length;
    const ignoredCount = findings.filter(f => f.status === 'ignored').length;

    const top  = openGroups.slice(0, 5);
    const rest = openGroups.slice(5);

    let verdictText = '';
    let verdictClass = '';
    if (store?.lastScan) {
        if (score !== null && score >= 80)      { verdictText = 'Ready to ship'; verdictClass = 'v-ok'; }
        else if (score !== null && score >= 40) { verdictText = 'Needs work';    verdictClass = 'v-warn'; }
        else if (score !== null)                { verdictText = 'Not ready';     verdictClass = 'v-bad'; }
    }

    function renderGroup(g: FindingGroup, idx: number): string {
        const idsAttr  = g.ids.join(',');
        const filesHtml = g.files.map(f =>
            `<div class="f-loc">${shortPath(f.path)}${f.line ? ':' + f.line : ''}</div>`
        ).join('');
        const moreFiles = g.count > g.files.length
            ? `<div class="f-loc f-more">+ ${g.count - g.files.length} more</div>`
            : '';

        return `
        <div class="issue" id="issue-${idx}" data-ids="${idsAttr}">
          <div class="i-head" data-toggle="${idx}">
            <div class="i-left">
              <span class="sev sev-${g.severity}">${g.severity}</span>
              ${g.hasNew ? '<span class="new-dot"></span>' : ''}
            </div>
            <div class="i-mid">
              <div class="i-type">${g.type}</div>
              <div class="i-meta">${g.count} in ${g.module}</div>
            </div>
            <svg class="chev" width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M4 2l4 4-4 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </div>
          <div class="i-body">
            <div class="f-list">${filesHtml}${moreFiles}</div>
            ${g.reason ? `<div class="i-reason">${g.reason.slice(0, 180)}</div>` : ''}
            <div class="i-actions">
              <button class="btn g-btn" data-action="fix">Fix with AI</button>
              <button class="btn" data-action="done">Done</button>
              <button class="btn" data-action="ignore">Ignore</button>
            </div>
          </div>
        </div>`;
    }

    const topHtml = top.map((g, i) => renderGroup(g, i)).join('');

    const restHtml = rest.length > 0 ? `
      <div class="more-toggle" id="more-btn" data-action="show-more">
        + ${rest.length} more issue groups
      </div>
      <div class="more-list" id="more-list">
        ${rest.map((g, i) => renderGroup(g, 100 + i)).join('')}
      </div>` : '';

    const resolvedHtml = (fixedCount > 0 || ignoredCount > 0) ? `
      <div class="resolved-bar">
        ${fixedCount   > 0 ? `<span class="r-pill r-fixed">${fixedCount} fixed</span>`     : ''}
        ${ignoredCount > 0 ? `<span class="r-pill r-ignored">${ignoredCount} ignored</span>` : ''}
      </div>` : '';

    // ── Scanning progress rows ──────────────────────────────────────
    const progressHtml = scanning && scanProgress.length > 0 ? `
    <div class="prog-list">
      ${scanProgress.map(p => `
        <div class="p-row">
          <span class="p-check">&#10003;</span>
          <span class="p-name">${p.module}</span>
          <span class="p-count ${p.issues > 0 ? 'p-has' : 'p-ok'}">${p.issues > 0 ? p.issues + ' issues' : 'clean'}</span>
        </div>`).join('')}
      <div class="p-row p-current">
        <span class="p-dot"></span>
        <span class="p-name">Scanning...</span>
      </div>
    </div>` : '';

    // ── Scope pill ──────────────────────────────────────────────────
    const scopePill = scanScope && store?.lastScan ? `
      <span class="scope-pill">${scanScope}</span>` : '';

    const emptyState = !store?.lastScan ? `
    <div class="empty">
      <div class="e-title">Security Feed</div>
      <div class="e-sub">Run a scan or right-click any file/folder.<br>Or let your AI agent call <code>ybe.scan_repo</code> via MCP.</div>
    </div>` : '';

    const allClear = store?.lastScan && openGroups.length === 0 ? `
    <div class="clear">
      <div class="clear-icon">&#10003;</div>
      <div class="e-title">All clear</div>
      <div class="e-sub">No open security issues.</div>
    </div>` : '';

    return /* html */`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
:root{--bg:#0a0a0a;--s:#141414;--s2:#1a1a1a;--b:#262626;--bh:#333;--t:#ededed;--ts:#a1a1a1;--m:#666;--g:#34d399;--gd:rgba(52,211,153,.12);--r:#ff6166;--rd:rgba(255,97,102,.1);--a:#e8a959;--ad:rgba(232,169,89,.1);--bl:#6eb0f7;--rad:6px}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--t);font-family:'Inter',-apple-system,sans-serif;font-size:12px;line-height:1.5;-webkit-font-smoothing:antialiased}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-thumb{background:var(--b);border-radius:3px}

.hdr{padding:16px;border-bottom:1px solid var(--b)}
.brand{font-size:13px;font-weight:600;letter-spacing:-.2px;margin-bottom:12px}.brand span{color:var(--g)}

.score-row{display:flex;align-items:flex-end;gap:8px}
.score-num{font-size:52px;font-weight:800;line-height:.8;letter-spacing:-3px;color:${sc};font-variant-numeric:tabular-nums}
.score-r{padding-bottom:6px}
.score-lbl{font-size:10px;color:var(--m);text-transform:uppercase;letter-spacing:.5px;margin-bottom:2px}
.verdict{font-size:12px;font-weight:600}
.v-ok{color:var(--g)}.v-warn{color:var(--a)}.v-bad{color:var(--r)}

.bar{height:2px;background:var(--s2);border-radius:1px;margin:10px 0 8px;overflow:hidden}
.bar-f{height:100%;border-radius:1px;background:${sc};width:${score!==null?Math.min(100,score):0}%;transition:width .8s ease}

.meta-row{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:4px}
.summary{font-size:11px;color:var(--ts)}
.summary b{color:var(--t);font-weight:600}
.last-scan{font-size:10px;color:var(--m)}
.scope-pill{font-size:9px;font-weight:600;padding:2px 7px;border-radius:100px;background:var(--s2);border:1px solid var(--b);color:var(--ts);text-transform:uppercase;letter-spacing:.3px}

.acts{padding:10px 16px;display:flex;gap:6px;align-items:center;border-bottom:1px solid var(--b)}
.btn-scan{flex:1;height:32px;background:var(--t);color:var(--bg);border:none;border-radius:var(--rad);font-size:12px;font-weight:600;cursor:pointer;transition:opacity .15s}
.btn-scan:hover{opacity:.85}.btn-scan:disabled{background:var(--s2);color:var(--m);opacity:1;cursor:default}
.btn-changed{height:32px;padding:0 10px;background:var(--s2);color:var(--ts);border:1px solid var(--b);border-radius:var(--rad);font-size:11px;font-weight:500;cursor:pointer;white-space:nowrap;transition:all .12s}
.btn-changed:hover{border-color:var(--bh);color:var(--t)}.btn-changed:disabled{opacity:.4;cursor:default}
.auto-w{display:flex;align-items:center;gap:5px;flex-shrink:0}
.auto-l{font-size:10px;color:var(--m);text-transform:uppercase;letter-spacing:.3px}
.tog{position:relative;width:28px;height:15px;cursor:pointer}
.tog input{opacity:0;width:0;height:0}
.tsl{position:absolute;inset:0;background:var(--s2);border:1px solid var(--b);border-radius:8px;transition:.2s}
.tsl::before{content:'';position:absolute;width:11px;height:11px;left:1px;top:50%;transform:translateY(-50%);background:var(--m);border-radius:50%;transition:.2s}
.tog input:checked+.tsl{background:var(--gd);border-color:rgba(52,211,153,.3)}
.tog input:checked+.tsl::before{transform:translate(13px,-50%);background:var(--g)}

.scanning-bar{height:2px;background:var(--s);overflow:hidden}
.scanning-p{width:30%;height:100%;background:var(--g);animation:sl 1.2s ease-in-out infinite}
@keyframes sl{0%{transform:translateX(-100%)}100%{transform:translateX(400%)}}

/* ── Streaming progress ── */
.prog-list{padding:10px 16px;border-bottom:1px solid var(--b)}
.p-row{display:flex;align-items:center;gap:8px;padding:3px 0;font-size:11px}
.p-check{color:var(--g);font-size:10px;width:12px;flex-shrink:0}
.p-dot{width:6px;height:6px;border-radius:50%;background:var(--g);animation:pulse 1s ease-in-out infinite;flex-shrink:0;margin-left:3px}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.p-current{color:var(--ts)}
.p-name{flex:1;color:var(--ts)}
.p-count{font-size:10px;font-weight:600}
.p-has{color:var(--a)}.p-ok{color:var(--m)}

.section-lbl{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:var(--m);padding:12px 16px 8px}

/* ── Issues ── */
.issues{padding:0 16px 12px}
.issue{background:var(--s);border:1px solid var(--b);border-radius:var(--rad);margin-bottom:4px;overflow:hidden;transition:border-color .15s}
.issue:hover{border-color:var(--bh)}.issue.open{border-color:var(--g)}
.i-head{display:flex;align-items:center;gap:10px;padding:10px 12px;cursor:pointer}
.i-head:hover{background:var(--s2)}
.i-left{display:flex;align-items:center;gap:6px;flex-shrink:0}
.sev{font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;text-transform:uppercase;letter-spacing:.3px}
.sev-critical{background:var(--rd);color:var(--r)}.sev-high{background:var(--ad);color:var(--a)}
.sev-medium{background:rgba(201,180,88,.1);color:#c9b458}.sev-low{background:rgba(110,176,247,.1);color:var(--bl)}
.new-dot{width:6px;height:6px;border-radius:50%;background:var(--g);flex-shrink:0}
.i-mid{flex:1;min-width:0}
.i-type{font-size:12px;font-weight:500;color:var(--t);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.i-meta{font-size:10px;color:var(--m)}
.chev{color:var(--m);transition:transform .15s;flex-shrink:0}
.issue.open .chev{transform:rotate(90deg)}
.i-body{display:none;padding:0 12px 12px;border-top:1px solid var(--b)}
.issue.open .i-body{display:block}
.f-list{margin-top:8px}
.f-loc{font-family:'SF Mono','Cascadia Code',monospace;font-size:10px;color:var(--ts);padding:2px 0}
.f-more{color:var(--m);font-style:italic}
.i-reason{font-size:10px;color:var(--ts);margin-top:8px;padding:8px;background:var(--bg);border-radius:4px;line-height:1.4}
.i-actions{display:flex;gap:4px;margin-top:10px}
.btn{height:26px;padding:0 12px;border-radius:var(--rad);border:1px solid var(--b);background:var(--s2);color:var(--ts);font-size:10px;font-weight:500;cursor:pointer;transition:all .12s}
.btn:hover{border-color:var(--bh);color:var(--t)}
.g-btn{background:var(--gd);color:var(--g);border-color:rgba(52,211,153,.2)}
.g-btn:hover{background:rgba(52,211,153,.2);border-color:rgba(52,211,153,.35)}

.more-toggle{padding:10px 0;text-align:center;font-size:11px;color:var(--m);cursor:pointer}
.more-toggle:hover{color:var(--ts)}
.more-list{display:none}.more-list.show{display:block}

.resolved-bar{padding:8px 16px;display:flex;gap:6px;border-top:1px solid var(--b)}
.r-pill{font-size:10px;padding:2px 8px;border-radius:100px;background:var(--s);border:1px solid var(--b);color:var(--m)}
.r-fixed{color:var(--g);border-color:rgba(52,211,153,.2)}

.empty,.clear{padding:40px 16px;text-align:center}
.e-title{font-size:13px;font-weight:600;color:var(--t);margin-bottom:6px}
.e-sub{font-size:11px;color:var(--ts);line-height:1.6}
.e-sub code{font-size:10px;background:var(--s2);padding:2px 6px;border-radius:4px;color:var(--g)}
.clear-icon{font-size:28px;color:var(--g);margin-bottom:8px}

.ft{padding:8px 16px;border-top:1px solid var(--b);display:flex;justify-content:space-between;color:var(--m);font-size:10px}
.btn-exp{background:none;border:none;color:var(--m);font-size:10px;cursor:pointer}.btn-exp:hover{color:var(--t)}

.toast{position:fixed;bottom:16px;left:50%;transform:translateX(-50%) translateY(10px);background:var(--s);border:1px solid var(--b);border-radius:var(--rad);padding:6px 14px;font-size:11px;font-weight:500;opacity:0;transition:all .2s;pointer-events:none;z-index:999;box-shadow:0 8px 24px rgba(0,0,0,.4)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}.toast.ok{border-color:rgba(52,211,153,.25);color:var(--g)}
</style>
</head>
<body>

<div class="hdr">
  <div class="brand">ybe<span>.</span>check</div>

  ${store?.lastScan ? `
  <div class="score-row">
    <span class="score-num">${score ?? '--'}</span>
    <div class="score-r">
      <div class="score-lbl">score</div>
      <div class="verdict ${verdictClass}">${verdictText}</div>
    </div>
  </div>
  <div class="bar"><div class="bar-f"></div></div>
  <div class="meta-row">
    ${openGroups.length > 0
      ? `<span class="summary"><b>${openGroups.length}</b> issue${openGroups.length !== 1 ? 's' : ''} to fix</span>`
      : '<span class="summary">No issues found</span>'}
    ${lastAgo ? `<span class="last-scan">· ${lastAgo}</span>` : ''}
    ${scopePill}
  </div>` : ''}
</div>

<div class="acts">
  <button class="btn-scan" id="scan-btn" ${scanning ? 'disabled' : ''}>${scanning ? 'Scanning...' : 'Run scan'}</button>
  <button class="btn-changed" id="changed-btn" ${scanning ? 'disabled' : ''}>Changed</button>
  <div class="auto-w">
    <span class="auto-l">Auto</span>
    <label class="tog"><input type="checkbox" id="auto-cb" ${autoScan ? 'checked' : ''}><span class="tsl"></span></label>
  </div>
</div>

${scanning ? '<div class="scanning-bar"><div class="scanning-p"></div></div>' : ''}
${progressHtml}

${emptyState}
${allClear}

${store?.lastScan && openGroups.length > 0 ? `
<div class="section-lbl">Fix these${top.length < openGroups.length ? ' first' : ''}</div>
<div class="issues">
  ${topHtml}
  ${restHtml}
</div>
` : ''}

${resolvedHtml}

<div class="ft">
  <span>${counts.total} findings total</span>
  <button class="btn-exp" id="exp-btn">Export</button>
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
    var issue = el.closest('.issue');
    return issue ? (issue.getAttribute('data-ids') || '').split(',') : [];
  }

  document.getElementById('scan-btn')?.addEventListener('click', function(){ vscode.postMessage({type:'runScan'}); });
  document.getElementById('changed-btn')?.addEventListener('click', function(){ vscode.postMessage({type:'runChanged'}); });
  document.getElementById('auto-cb')?.addEventListener('change', function(){ vscode.postMessage({type:'toggleAutoScan', value: this.checked}); });
  document.getElementById('exp-btn')?.addEventListener('click', function(){ vscode.postMessage({type:'exportReport'}); });

  document.body.addEventListener('click', function(e) {
    var el = e.target;
    while (el && el !== document.body) {
      var toggleAttr = el.getAttribute('data-toggle');
      if (toggleAttr !== null) {
        var issue = document.getElementById('issue-' + toggleAttr);
        if (issue) issue.classList.toggle('open');
        return;
      }
      var action = el.getAttribute('data-action');
      if (action) {
        var ids = getIds(el);
        if (action === 'fix') {
          if (ids.length > 0) vscode.postMessage({type:'fixWithAgent', findingId: ids[0]});
        } else if (action === 'done') {
          ids.forEach(function(id){ vscode.postMessage({type:'setStatus', findingId:id, status:'fixed'}); });
          toast('Marked ' + ids.length + ' as fixed', 'ok');
        } else if (action === 'ignore') {
          ids.forEach(function(id){ vscode.postMessage({type:'setStatus', findingId:id, status:'ignored'}); });
          toast('Ignored ' + ids.length, 'ok');
        } else if (action === 'show-more') {
          var list = document.getElementById('more-list');
          var btn  = document.getElementById('more-btn');
          if (list) list.classList.toggle('show');
          if (btn)  btn.style.display = (list && list.classList.contains('show')) ? 'none' : 'block';
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
