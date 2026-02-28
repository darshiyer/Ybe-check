import * as vscode from 'vscode';

/**
 * Displays the Ybe Check production readiness report in a WebView.
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
}

function escapeHtml(text: string): string {
    const map: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
    return text.replace(/[&<>"']/g, (c) => map[c] || c);
}

function generateReportHtml(report: any): string {
    const score = report.overall_score || 0;
    const modules = report.modules || [];
    const totalIssues = modules.reduce((sum: number, m: any) => sum + (m.issues || 0), 0);
    const topFixes: string[] = report.top_fixes || [];

    const scoreColor = score >= 80 ? '#00e676' : score >= 40 ? '#ffd740' : '#ff5252';
    const scoreGlow = score >= 80 ? '0 0 40px rgba(0,230,118,0.3)' : score >= 40 ? '0 0 40px rgba(255,215,64,0.3)' : '0 0 40px rgba(255,82,82,0.3)';
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
            <div class="bar-label">${type}</div>
            <div class="bar-track">
                <div class="bar-fill" style="width:${pct}%"></div>
            </div>
            <div class="bar-count">${count}</div>
        </div>`;
    }).join('');

    const moduleCards = modules.map((mod: any, idx: number) => {
        const detailItems = (mod.details || []).slice(0, 15);
        const moreCount = (mod.details || []).length - 15;
        const modScoreColor = mod.score >= 80 ? '#00e676' : mod.score >= 40 ? '#ffd740' : '#ff5252';
        const statusDot = mod.score >= 80 ? 'dot-green' : mod.score >= 40 ? 'dot-yellow' : 'dot-red';
        const modIcon = mod.score >= 80 ? '&#128274;' : mod.score >= 40 ? '&#128269;' : '&#9888;';

        const findingsTable = detailItems.length > 0 ? `
            <div class="findings-section" id="findings-${idx}">
                <table class="findings-table">
                    <thead>
                        <tr>
                            <th>File</th>
                            <th>Line</th>
                            <th>Type</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${detailItems.map((d: any) => `
                        <tr>
                            <td class="cell-file">${d.file || 'unknown'}</td>
                            <td class="cell-line">${d.line || '-'}</td>
                            <td class="cell-type">${d.type || d.reason || 'secret'}</td>
                        </tr>`).join('')}
                    </tbody>
                </table>
                ${moreCount > 0 ? `<div class="findings-more">+ ${moreCount} more findings not shown</div>` : ''}
            </div>
        ` : '';

        return `
        <div class="module-card animate-in" style="animation-delay:${idx * 0.1}s">
            <div class="module-top">
                <div class="module-left">
                    <span class="module-icon">${modIcon}</span>
                    <div>
                        <div class="module-name">${mod.name.charAt(0).toUpperCase() + mod.name.slice(1)}</div>
                        <div class="module-issues">
                            <span class="${statusDot}"></span>
                            ${mod.issues} issue${mod.issues !== 1 ? 's' : ''} detected
                        </div>
                    </div>
                </div>
                <div class="module-right">
                    <div class="module-score-ring" style="border-color:${modScoreColor}; color:${modScoreColor}">
                        ${mod.score}
                    </div>
                </div>
            </div>
            ${mod.warning ? `<div class="module-alert alert-warn">${mod.warning}</div>` : ''}
            ${mod.error ? `<div class="module-alert alert-err">${mod.error}</div>` : ''}
            ${detailItems.length > 0 ? `
                <button class="toggle-btn" onclick="document.getElementById('findings-${idx}').classList.toggle('open')">
                    Show Findings &#9660;
                </button>
            ` : `
                <div class="no-findings">No secrets detected — this module is clean.</div>
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
            @keyframes fadeInUp {
                from { opacity: 0; transform: translateY(20px); }
                to { opacity: 1; transform: translateY(0); }
            }
            @keyframes pulse {
                0%, 100% { box-shadow: ${scoreGlow}; }
                50% { box-shadow: ${scoreGlow}, 0 0 60px rgba(0,122,204,0.15); }
            }
            @keyframes scoreCount {
                from { opacity: 0; transform: scale(0.5); }
                to { opacity: 1; transform: scale(1); }
            }

            * { margin: 0; padding: 0; box-sizing: border-box; }

            body {
                background: #0a0a0f;
                color: #e0e0e0;
                font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                padding: 30px 20px;
                display: flex;
                justify-content: center;
            }

            .container { max-width: 860px; width: 100%; }

            /* ---- HEADER ---- */
            .hero {
                text-align: center;
                padding: 40px 30px;
                background: linear-gradient(135deg, rgba(20,20,35,0.9), rgba(10,10,20,0.95));
                border: 1px solid rgba(255,255,255,0.06);
                border-radius: 24px;
                margin-bottom: 30px;
                position: relative;
                overflow: hidden;
                animation: fadeInUp 0.6s ease-out;
            }
            .hero::before {
                content: '';
                position: absolute;
                top: -50%; left: -50%;
                width: 200%; height: 200%;
                background: radial-gradient(circle at 50% 50%, rgba(0,122,204,0.04) 0%, transparent 70%);
                pointer-events: none;
            }

            .brand {
                font-size: 11px;
                text-transform: uppercase;
                letter-spacing: 4px;
                color: #5c7cfa;
                margin-bottom: 25px;
                font-weight: 600;
            }

            .score-ring {
                width: 160px; height: 160px;
                border-radius: 50%;
                border: 6px solid ${scoreColor};
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 20px;
                position: relative;
                animation: pulse 3s ease-in-out infinite, scoreCount 0.8s ease-out 0.3s both;
                background: radial-gradient(circle, rgba(0,0,0,0.5) 60%, transparent 100%);
            }
            .score-value {
                font-size: 56px;
                font-weight: 800;
                color: ${scoreColor};
                line-height: 1;
            }
            .score-unit {
                font-size: 16px;
                font-weight: 400;
                color: ${scoreColor};
                opacity: 0.7;
            }

            .verdict {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                font-size: 15px;
                font-weight: 700;
                color: ${scoreColor};
                background: rgba(255,255,255,0.04);
                padding: 8px 20px;
                border-radius: 50px;
                border: 1px solid rgba(255,255,255,0.06);
                letter-spacing: 1px;
            }
            .verdict-icon { font-size: 18px; }

            .stats-row {
                display: flex;
                justify-content: center;
                gap: 12px;
                margin-top: 22px;
                flex-wrap: wrap;
            }
            .stat-chip {
                background: rgba(255,255,255,0.04);
                border: 1px solid rgba(255,255,255,0.06);
                padding: 8px 18px;
                border-radius: 10px;
                font-size: 13px;
                color: #aaa;
            }
            .stat-chip strong {
                color: #ddd;
                margin-right: 4px;
            }

            .timestamp {
                margin-top: 18px;
                font-size: 11px;
                color: #555;
            }

            .fix-list {
                list-style: none;
                margin: 0;
                padding: 0;
            }
            .fix-item {
                padding: 10px 14px;
                margin-bottom: 8px;
                background: rgba(92,124,250,0.08);
                border: 1px solid rgba(92,124,250,0.15);
                border-radius: 8px;
                font-size: 13px;
                color: #b8c5f0;
                line-height: 1.4;
            }
            .fix-item:last-child { margin-bottom: 0; }

            /* ---- BREAKDOWN ---- */
            .breakdown {
                background: linear-gradient(135deg, rgba(20,20,35,0.8), rgba(10,10,20,0.9));
                border: 1px solid rgba(255,255,255,0.06);
                border-radius: 16px;
                padding: 24px;
                margin-bottom: 30px;
                animation: fadeInUp 0.6s ease-out 0.2s both;
            }
            .section-label {
                font-size: 11px;
                text-transform: uppercase;
                letter-spacing: 3px;
                color: #5c7cfa;
                font-weight: 600;
                margin-bottom: 18px;
            }
            .bar-row {
                display: flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 10px;
            }
            .bar-label {
                width: 200px;
                font-size: 12px;
                color: #aaa;
                text-align: right;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }
            .bar-track {
                flex: 1;
                height: 8px;
                background: rgba(255,255,255,0.04);
                border-radius: 4px;
                overflow: hidden;
            }
            .bar-fill {
                height: 100%;
                background: linear-gradient(90deg, #5c7cfa, #7c4dff);
                border-radius: 4px;
                transition: width 1s ease-out;
            }
            .bar-count {
                width: 40px;
                font-size: 12px;
                color: #888;
                font-weight: 600;
            }

            /* ---- MODULE CARDS ---- */
            .modules-label {
                font-size: 11px;
                text-transform: uppercase;
                letter-spacing: 3px;
                color: #5c7cfa;
                font-weight: 600;
                margin-bottom: 15px;
            }

            .animate-in {
                animation: fadeInUp 0.5s ease-out both;
            }

            .module-card {
                background: linear-gradient(135deg, rgba(20,20,35,0.8), rgba(15,15,25,0.9));
                border: 1px solid rgba(255,255,255,0.06);
                border-radius: 16px;
                padding: 22px;
                margin-bottom: 16px;
                transition: border-color 0.2s, transform 0.2s;
            }
            .module-card:hover {
                border-color: rgba(92,124,250,0.3);
                transform: translateY(-2px);
            }

            .module-top {
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .module-left {
                display: flex;
                align-items: center;
                gap: 14px;
            }
            .module-icon { font-size: 28px; }
            .module-name {
                font-size: 17px;
                font-weight: 700;
                color: #eee;
            }
            .module-issues {
                display: flex;
                align-items: center;
                gap: 6px;
                font-size: 13px;
                color: #888;
                margin-top: 3px;
            }
            .dot-green, .dot-yellow, .dot-red {
                width: 8px; height: 8px;
                border-radius: 50%;
                display: inline-block;
            }
            .dot-green { background: #00e676; box-shadow: 0 0 6px rgba(0,230,118,0.5); }
            .dot-yellow { background: #ffd740; box-shadow: 0 0 6px rgba(255,215,64,0.5); }
            .dot-red { background: #ff5252; box-shadow: 0 0 6px rgba(255,82,82,0.5); }

            .module-right { display: flex; align-items: center; }
            .module-score-ring {
                width: 52px; height: 52px;
                border-radius: 50%;
                border: 3px solid;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 18px;
                font-weight: 800;
            }

            .module-alert {
                margin-top: 12px;
                padding: 10px 14px;
                border-radius: 8px;
                font-size: 12px;
                line-height: 1.5;
            }
            .alert-warn {
                background: rgba(255,215,64,0.08);
                border: 1px solid rgba(255,215,64,0.15);
                color: #ffd740;
            }
            .alert-err {
                background: rgba(255,82,82,0.08);
                border: 1px solid rgba(255,82,82,0.15);
                color: #ff5252;
            }

            .no-findings {
                margin-top: 14px;
                padding: 12px 16px;
                background: rgba(0,230,118,0.06);
                border: 1px solid rgba(0,230,118,0.12);
                border-radius: 8px;
                color: #00e676;
                font-size: 13px;
            }

            .toggle-btn {
                margin-top: 14px;
                background: rgba(92,124,250,0.1);
                border: 1px solid rgba(92,124,250,0.2);
                color: #5c7cfa;
                padding: 8px 16px;
                border-radius: 8px;
                cursor: pointer;
                font-size: 12px;
                font-weight: 600;
                transition: background 0.2s;
                width: 100%;
                text-align: center;
            }
            .toggle-btn:hover { background: rgba(92,124,250,0.2); }

            .findings-section {
                max-height: 0;
                overflow: hidden;
                transition: max-height 0.4s ease-out;
            }
            .findings-section.open { max-height: 2000px; }

            .findings-table {
                width: 100%;
                margin-top: 14px;
                border-collapse: collapse;
                font-size: 12px;
            }
            .findings-table thead th {
                text-align: left;
                padding: 8px 10px;
                color: #666;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                font-size: 10px;
                border-bottom: 1px solid rgba(255,255,255,0.06);
            }
            .findings-table tbody tr {
                border-bottom: 1px solid rgba(255,255,255,0.03);
                transition: background 0.15s;
            }
            .findings-table tbody tr:hover { background: rgba(255,255,255,0.02); }
            .findings-table td { padding: 7px 10px; }
            .cell-file {
                font-family: 'Cascadia Code', 'Fira Code', 'SF Mono', monospace;
                color: #5c7cfa;
                max-width: 350px;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }
            .cell-line {
                color: #888;
                font-family: 'Cascadia Code', 'Fira Code', monospace;
                text-align: center;
                min-width: 40px;
            }
            .cell-type { color: #aaa; font-style: italic; }

            .findings-more {
                text-align: center;
                padding: 10px;
                color: #555;
                font-size: 11px;
            }

            /* ---- FOOTER ---- */
            .footer {
                text-align: center;
                margin-top: 40px;
                padding-top: 20px;
                border-top: 1px solid rgba(255,255,255,0.04);
                color: #444;
                font-size: 11px;
                letter-spacing: 0.5px;
            }
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
                <div class="verdict">
                    <span class="verdict-icon">${scoreIcon}</span>
                    ${report.verdict || scoreLabel}
                </div>
                <div class="stats-row">
                    <div class="stat-chip"><strong>${modules.length}</strong> module${modules.length !== 1 ? 's' : ''} scanned</div>
                    <div class="stat-chip"><strong>${totalIssues}</strong> issue${totalIssues !== 1 ? 's' : ''} found</div>
                    <div class="stat-chip"><strong>${score}%</strong> secure</div>
                </div>
                <div class="timestamp">Scanned at ${timestamp}</div>
            </div>

            ${topFixes.length > 0 ? `
            <div class="breakdown top-fixes">
                <div class="section-label">Top fixes</div>
                <ul class="fix-list">
                    ${topFixes.map((fix: string) => `<li class="fix-item">${escapeHtml(fix)}</li>`).join('')}
                </ul>
            </div>
            ` : ''}

            ${sortedTypes.length > 0 ? `
            <div class="breakdown">
                <div class="section-label">Issues by Type</div>
                ${breakdownBars}
            </div>
            ` : ''}

            <div class="modules-label">Module Results</div>
            ${moduleCards}

            <div class="footer">
                Ybe Check v0.1.0 &bull; Security audit for vibe-coded applications
            </div>
        </div>
    </body>
    </html>
    `;
}

function getScoreClass(score: number): string {
    if (score >= 80) return 'score-high';
    if (score >= 40) return 'score-med';
    return 'score-low';
}
