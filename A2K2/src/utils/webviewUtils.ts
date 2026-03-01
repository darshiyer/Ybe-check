import * as vscode from 'vscode';

/**
 * Displays the Ybe Check production readiness report in a WebView.
 * Wires up message passing so "Fix with Copilot" buttons trigger extension commands.
 */
export function showYbeCheckReport(
    report: any,
    context: vscode.ExtensionContext
): void {
    const panel = vscode.window.createWebviewPanel(
        'ybeCheckReport',
        'Ybe Check: Production Readiness',
        vscode.ViewColumn.One,
        { enableScripts: true, retainContextWhenHidden: true }
    );

    panel.reveal();
    panel.webview.html = generateReportHtml(report);

    // Listen for messages from the webview (Fix with Copilot, Ask Copilot, etc.)
    panel.webview.onDidReceiveMessage(async (msg) => {
        if (msg.command === 'fixWithCopilot' && msg.finding) {
            await vscode.commands.executeCommand('ybe-check.fixWithCopilot', msg.finding);
        } else if (msg.command === 'askCopilot') {
            await vscode.commands.executeCommand('ybe-check.askCopilot');
        } else if (msg.command === 'securityAudit') {
            await vscode.commands.executeCommand('ybe-check.securityAudit');
        }
    }, undefined, context.subscriptions);
}

function escapeHtml(text: any): string {
    const map: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
    const str = String(text || '');
    return str.replace(/[&<>"']/g, (c) => map[c] || c);
}

function generateReportHtml(report: any): string {
    const score = report.overall_score || 0;
    const modules = report.module_results || report.modules || [];
    const totalIssues = modules.reduce((sum: number, m: any) => sum + (m.issues || 0), 0);
    const topFixes: string[] = report.top_fixes || [];
    const allFindings: any[] = report.findings || [];

    const scoreColor = score >= 80 ? '#10b981' : score >= 40 ? '#eab308' : '#f43f5e';
    const scoreGlow = score >= 80
        ? '0 0 40px rgba(16,185,129,0.25)'
        : score >= 40 ? '0 0 40px rgba(234,179,8,0.25)' : '0 0 40px rgba(244,63,94,0.25)';
    const scoreLabel = score >= 80 ? 'PRODUCTION READY' : score >= 40 ? 'NEEDS ATTENTION' : 'NOT READY';
    const scoreIcon = score >= 80 ? '&#10003;' : score >= 40 ? '&#9888;' : '&#10007;';

    const now = new Date();
    const timestamp = now.toLocaleString();

    const typeGroups: Record<string, number> = {};
    modules.forEach((mod: any) => {
        (mod.details || []).forEach((d: any) => {
            const t = d.type || d.reason || 'Unknown';
            typeGroups[t] = (typeGroups[t] || 0) + 1;
        });
    });

    const sortedTypes = Object.entries(typeGroups)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8);

    const maxTypeCount = sortedTypes.length > 0 ? sortedTypes[0][1] : 1;

    const breakdownBars = sortedTypes.map(([type, count]) => {
        const pct = Math.round((count / maxTypeCount) * 100);
        return `
        <div class="bar-row">
            <div class="bar-label">${escapeHtml(type)}</div>
            <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
            <div class="bar-count">${count}</div>
        </div>`;
    }).join('');

    const moduleCards = modules.map((mod: any, idx: number) => {
        const detailItems = (mod.details || []).slice(0, 15);
        const moreCount = (mod.details || []).length - 15;
        const modScore = mod.score != null ? mod.score : -1;
        const modScoreColor = modScore >= 80 ? '#10b981' : modScore >= 40 ? '#eab308' : '#f43f5e';
        const statusDot = modScore >= 80 ? 'dot-green' : modScore >= 40 ? 'dot-yellow' : 'dot-red';
        const modScoreDisplay = mod.score != null ? mod.score : 'N/A';

        const sevColor = (sev: string) => {
            switch((sev||'').toLowerCase()) {
                case 'critical': return '#f43f5e';
                case 'high': return '#f97316';
                case 'medium': return '#eab308';
                case 'low': return '#06b6d4';
                default: return '#6b7280';
            }
        };

        const findingsTable = detailItems.length > 0 ? `
            <div class="findings-section" id="findings-${idx}">
                <table class="findings-table">
                    <thead><tr><th>File</th><th>Line</th><th>Type</th><th>Severity</th><th>Fix</th></tr></thead>
                    <tbody>
                        ${detailItems.map((d: any, di: number) => {
                            // Try to match this detail to a unified finding for the Fix button
                            const matchId = `finding-${idx}-${di}`;
                            const findingData = JSON.stringify({
                                id: d.id || `${mod.name}:${di}`,
                                type: d.type || d.reason || 'issue',
                                severity: d.severity || 'medium',
                                summary: d.reason || d.type || 'Security issue',
                                location: { path: d.file || 'unknown', line: d.line || null },
                                evidence: d.snippet ? { snippet: d.snippet } : null,
                            }).replace(/'/g, "\\'").replace(/"/g, '&quot;');
                            return `
                        <tr>
                            <td class="cell-file">${escapeHtml(d.file || 'unknown')}</td>
                            <td class="cell-line">${d.line || '-'}</td>
                            <td class="cell-type">${escapeHtml(d.type || d.reason || 'issue')}</td>
                            <td><span class="sev-badge" style="background:${sevColor(d.severity)}20;color:${sevColor(d.severity)}">${escapeHtml((d.severity || 'medium').toUpperCase())}</span></td>
                            <td><button class="fix-btn" onclick="fixFinding(&quot;${matchId}&quot;)" data-finding="${findingData}" id="${matchId}">Fix ⚡</button></td>
                        </tr>`;
                        }).join('')}
                    </tbody>
                </table>
                ${moreCount > 0 ? `<div class="findings-more">+ ${moreCount} more findings</div>` : ''}
            </div>
        ` : '';

        return `
        <div class="module-card" style="animation-delay:${idx * 0.06}s">
            <div class="module-top">
                <div class="module-left">
                    <span class="${statusDot}"></span>
                    <div>
                        <div class="module-name">${escapeHtml(String(mod.name || '').charAt(0).toUpperCase() + String(mod.name || '').slice(1))}</div>
                        <div class="module-issues">${mod.issues} issue${mod.issues !== 1 ? 's' : ''}</div>
                    </div>
                </div>
                <div class="module-score" style="border-color:${modScoreColor};color:${modScoreColor}">
                    ${modScoreDisplay}
                </div>
            </div>
            ${mod.warning ? `<div class="module-alert warn">${escapeHtml(String(mod.warning))}</div>` : ''}
            ${detailItems.length > 0 ? `
                <button class="toggle-btn" onclick="const s=document.getElementById('findings-${idx}');s.classList.toggle('open');this.textContent=s.classList.contains('open')?'Hide Findings ▲':'Show Findings ▼'">
                    Show Findings ▼
                </button>
            ` : `
                <div class="clean-badge">All clear</div>
            `}
            ${findingsTable}
        </div>`;
    }).join('');

    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            @keyframes fadeIn { from{opacity:0;transform:translateY(12px)} to{opacity:1;transform:translateY(0)} }
            @keyframes pulseRing { 0%,100%{box-shadow:${scoreGlow}} 50%{box-shadow:${scoreGlow},0 0 60px rgba(124,106,239,0.08)} }

            :root {
                --bg:#07080c; --surface:#111318; --surface2:#181b23;
                --border:#22252f; --text:#e8e8ed; --muted:#6b6f7b;
                --accent:#7c6aef;
            }
            *{margin:0;padding:0;box-sizing:border-box}
            body{background:var(--bg);color:var(--text);font-family:'Inter',-apple-system,'Segoe UI',Roboto,sans-serif;padding:24px;display:flex;justify-content:center}
            .container{max-width:820px;width:100%}

            /* Hero */
            .hero{text-align:center;padding:36px 28px;background:var(--surface);border:1px solid var(--border);border-radius:20px;margin-bottom:24px;animation:fadeIn .5s ease-out}
            .brand{font-size:10px;text-transform:uppercase;letter-spacing:4px;color:var(--accent);font-weight:700;margin-bottom:24px}
            .score-ring{width:150px;height:150px;border-radius:50%;border:5px solid ${scoreColor};display:flex;align-items:center;justify-content:center;margin:0 auto 18px;animation:pulseRing 3s ease-in-out infinite;background:radial-gradient(circle,rgba(0,0,0,.4) 60%,transparent)}
            .score-value{font-size:52px;font-weight:900;color:${scoreColor};line-height:1}
            .score-unit{font-size:14px;color:${scoreColor};opacity:.6}
            .verdict{display:inline-flex;align-items:center;gap:8px;font-size:13px;font-weight:700;color:${scoreColor};background:rgba(255,255,255,.03);padding:6px 18px;border-radius:50px;border:1px solid rgba(255,255,255,.05);letter-spacing:1.5px}
            .stats-row{display:flex;justify-content:center;gap:10px;margin-top:18px;flex-wrap:wrap}
            .stat-chip{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.05);padding:6px 16px;border-radius:8px;font-size:12px;color:#888}
            .stat-chip strong{color:#ccc;margin-right:3px}
            .timestamp{margin-top:14px;font-size:10px;color:#444}

            /* Sections */
            .section{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:22px;margin-bottom:20px;animation:fadeIn .5s ease-out both}
            .section-label{font-size:10px;text-transform:uppercase;letter-spacing:3px;color:var(--accent);font-weight:700;margin-bottom:14px}
            .fix-item{padding:9px 12px;margin-bottom:6px;background:rgba(124,106,239,.06);border:1px solid rgba(124,106,239,.12);border-radius:8px;font-size:12px;color:#a8b4e0;line-height:1.45}
            .bar-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
            .bar-label{width:180px;font-size:11px;color:#888;text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
            .bar-track{flex:1;height:7px;background:rgba(255,255,255,.03);border-radius:4px;overflow:hidden}
            .bar-fill{height:100%;background:linear-gradient(90deg,var(--accent),#a78bfa);border-radius:4px}
            .bar-count{width:35px;font-size:11px;color:#666;font-weight:700}

            /* Module cards */
            .module-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:18px;margin-bottom:12px;transition:border-color .2s;animation:fadeIn .4s ease-out both}
            .module-card:hover{border-color:rgba(124,106,239,.25)}
            .module-top{display:flex;justify-content:space-between;align-items:center}
            .module-left{display:flex;align-items:center;gap:12px}
            .module-name{font-size:14px;font-weight:700}
            .module-issues{font-size:11px;color:#777;margin-top:2px}
            .dot-green,.dot-yellow,.dot-red{width:8px;height:8px;border-radius:50%;flex-shrink:0}
            .dot-green{background:#10b981;box-shadow:0 0 6px rgba(16,185,129,.4)}
            .dot-yellow{background:#eab308;box-shadow:0 0 6px rgba(234,179,8,.4)}
            .dot-red{background:#f43f5e;box-shadow:0 0 6px rgba(244,63,94,.4)}
            .module-score{width:44px;height:44px;border-radius:50%;border:3px solid;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:900}
            .module-alert{margin-top:10px;padding:8px 12px;border-radius:8px;font-size:11px;line-height:1.5}
            .module-alert.warn{background:rgba(234,179,8,.06);border:1px solid rgba(234,179,8,.12);color:#eab308}
            .clean-badge{margin-top:10px;padding:8px 12px;background:rgba(16,185,129,.06);border:1px solid rgba(16,185,129,.1);border-radius:8px;color:#10b981;font-size:11px;font-weight:600}
            .toggle-btn{margin-top:10px;background:rgba(124,106,239,.08);border:1px solid rgba(124,106,239,.15);color:var(--accent);padding:7px 14px;border-radius:8px;cursor:pointer;font-size:11px;font-weight:600;width:100%;text-align:center;transition:background .15s}
            .toggle-btn:hover{background:rgba(124,106,239,.15)}
            .findings-section{max-height:0;overflow:hidden;transition:max-height .4s ease-out}
            .findings-section.open{max-height:2000px}
            .findings-table{width:100%;margin-top:12px;border-collapse:collapse;font-size:11px}
            .findings-table th{text-align:left;padding:7px 8px;color:#555;font-weight:600;text-transform:uppercase;font-size:9px;letter-spacing:.5px;border-bottom:1px solid var(--border)}
            .findings-table tr{border-bottom:1px solid rgba(255,255,255,.02)}
            .findings-table tr:hover{background:rgba(124,106,239,.03)}
            .findings-table td{padding:6px 8px}
            .cell-file{font-family:'JetBrains Mono','Fira Code',monospace;color:var(--accent);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px}
            .cell-line{color:#666;font-family:monospace;text-align:center;min-width:36px}
            .cell-type{color:#999;font-size:11px}
            .sev-badge{display:inline-block;padding:1px 7px;border-radius:4px;font-size:9px;font-weight:700;letter-spacing:.3px}
            .findings-more{text-align:center;padding:8px;color:#444;font-size:10px}

            .cta-bar{text-align:center;margin-top:10px;padding:16px;background:var(--surface);border:1px solid var(--border);border-radius:14px;animation:fadeIn .5s ease-out .3s both}
            .cta-bar p{font-size:12px;color:#666}
            .cta-bar code{background:rgba(124,106,239,.1);padding:2px 8px;border-radius:4px;font-size:11px;color:var(--accent)}

            .fix-btn{background:rgba(124,106,239,.12);border:1px solid rgba(124,106,239,.25);color:var(--accent);padding:3px 10px;border-radius:6px;cursor:pointer;font-size:10px;font-weight:700;transition:all .15s;white-space:nowrap}
            .fix-btn:hover{background:rgba(124,106,239,.25);border-color:var(--accent);transform:scale(1.05)}

            .copilot-bar{display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin-top:16px;margin-bottom:8px;animation:fadeIn .5s ease-out .2s both}
            .copilot-btn{display:inline-flex;align-items:center;gap:6px;padding:10px 20px;border-radius:10px;border:1px solid rgba(124,106,239,.2);cursor:pointer;font-size:13px;font-weight:700;transition:all .2s;letter-spacing:.3px}
            .copilot-btn:hover{transform:translateY(-1px);box-shadow:0 4px 20px rgba(124,106,239,.15)}
            .copilot-primary{background:linear-gradient(135deg,#7c6aef,#a78bfa);color:#fff;border-color:transparent}
            .copilot-primary:hover{background:linear-gradient(135deg,#6d5ce0,#9b7bf0)}
            .copilot-secondary{background:rgba(124,106,239,.08);color:var(--accent)}
            .copilot-secondary:hover{background:rgba(124,106,239,.16)}

            .footer{text-align:center;margin-top:32px;padding-top:16px;border-top:1px solid rgba(255,255,255,.03);color:#333;font-size:10px;letter-spacing:.5px}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="hero">
                <div class="brand">Ybe Check &mdash; Production Readiness Audit</div>
                <div class="score-ring">
                    <div>
                        <div class="score-value">${score}</div>
                        <div class="score-unit">/100</div>
                    </div>
                </div>
                <div class="verdict"><span>${scoreIcon}</span> ${escapeHtml(report.verdict || scoreLabel)}</div>
                <div class="stats-row">
                    <div class="stat-chip"><strong>${modules.length}</strong> modules</div>
                    <div class="stat-chip"><strong>${totalIssues}</strong> issues</div>
                    <div class="stat-chip"><strong>${score}%</strong> secure</div>
                </div>
                <div class="timestamp">${timestamp}</div>
            </div>

            ${topFixes.length > 0 ? `
            <div class="section" style="animation-delay:.1s">
                <div class="section-label">Priority Fixes</div>
                ${topFixes.map((fix: any) => `<div class="fix-item">${escapeHtml(String(fix || ''))}</div>`).join('')}
            </div>
            ` : ''}

            ${sortedTypes.length > 0 ? `
            <div class="section" style="animation-delay:.15s">
                <div class="section-label">Issues by Type</div>
                ${breakdownBars}
            </div>
            ` : ''}

            <div class="section-label" style="margin-top:8px;margin-bottom:12px;font-size:10px;text-transform:uppercase;letter-spacing:3px;color:#7c6aef;font-weight:700">Module Results</div>
            ${moduleCards}

            <div class="copilot-bar">
                <button class="copilot-btn copilot-primary" onclick="securityAudit()">⚡ Security Audit with Copilot</button>
                <button class="copilot-btn copilot-secondary" onclick="askCopilot()">💬 Ask Copilot</button>
                <button class="copilot-btn copilot-secondary" onclick="fixTopIssue()">🔧 Fix Top Issue</button>
            </div>

            <div class="cta-bar">
                <p>For detailed AI analysis and chat, run <code>ybe-check dashboard</code></p>
            </div>

            <div class="footer">Ybe Check &bull; Security audit for vibe-coded applications</div>
        </div>

        <script>
            const vscode = acquireVsCodeApi();

            // Pre-embed all findings as JSON for the fix buttons
            const allFindings = ${JSON.stringify(allFindings.slice(0, 50).map((f: any) => ({
                id: f.id, type: f.type, severity: f.severity,
                summary: (f.summary || '').slice(0, 200),
                location: f.location || {},
                evidence: f.evidence || null,
                ai_analysis: f.ai_analysis || null,
            })))};

            function fixFinding(btnId) {
                const btn = document.getElementById(btnId);
                if (!btn) return;
                try {
                    const raw = btn.getAttribute('data-finding');
                    const finding = JSON.parse(raw.replace(/&quot;/g, '"'));
                    vscode.postMessage({ command: 'fixWithCopilot', finding: finding });
                    btn.textContent = 'Sent ✓';
                    btn.style.background = 'rgba(16,185,129,.15)';
                    btn.style.color = '#10b981';
                    btn.style.borderColor = '#10b981';
                    setTimeout(() => { btn.textContent = 'Fix ⚡'; btn.style.background = ''; btn.style.color = ''; btn.style.borderColor = ''; }, 2000);
                } catch(e) {
                    console.error('Fix button error:', e);
                }
            }

            function fixTopIssue() {
                if (allFindings.length > 0) {
                    // Pick the highest severity finding
                    const sevOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
                    const sorted = [...allFindings].sort((a, b) => (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0));
                    vscode.postMessage({ command: 'fixWithCopilot', finding: sorted[0] });
                }
            }

            function askCopilot() {
                vscode.postMessage({ command: 'askCopilot' });
            }

            function securityAudit() {
                vscode.postMessage({ command: 'securityAudit' });
            }
        </script>
    </body>
    </html>
    `;
}
