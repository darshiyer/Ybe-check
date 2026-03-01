import * as vscode from 'vscode';

/**
 * Displays the Ybe Check production readiness report in a WebView.
 * Aligned with the website UI: same design tokens (M, T), bento layout, hero, persona, verdict.
 * Wires up message passing so "Fix with Copilot" / "Open" / "Verify licenses" trigger extension commands.
 */
export function showYbeCheckReport(
    report: any,
    context: vscode.ExtensionContext,
    workspaceRoot?: string
): void {
    const panel = vscode.window.createWebviewPanel(
        'ybeCheckReport',
        'Ybe Check: Production Readiness',
        vscode.ViewColumn.One,
        { enableScripts: true, retainContextWhenHidden: true }
    );

    panel.reveal();
    panel.webview.html = generateReportHtml(report, workspaceRoot || '');

    panel.webview.onDidReceiveMessage(async (msg) => {
        if (msg.command === 'fixWithCopilot' && msg.finding) {
            await vscode.commands.executeCommand('ybe-check.fixWithCopilot', msg.finding);
        } else if (msg.command === 'askCopilot') {
            await vscode.commands.executeCommand('ybe-check.askCopilot');
        } else if (msg.command === 'securityAudit') {
            await vscode.commands.executeCommand('ybe-check.securityAudit');
        } else if (msg.command === 'explainFinding' && msg.finding) {
            await vscode.commands.executeCommand('ybe-check.explainFinding', msg.finding);
        } else if (msg.command === 'fixAllCritical') {
            await vscode.commands.executeCommand('ybe-check.fixAllCritical');
        } else if (msg.command === 'browseBySeverity') {
            await vscode.commands.executeCommand('ybe-check.browseBySeverity');
        } else if (msg.command === 'openDashboard') {
            await vscode.commands.executeCommand('ybe-check.openDashboard');
        } else if (msg.command === 'openFile' && msg.path) {
            await vscode.commands.executeCommand('ybe-check.openFileAtLine', msg.path, msg.line, workspaceRoot);
        } else if (msg.command === 'runTerminal' && msg.terminalCommand && workspaceRoot) {
            await vscode.commands.executeCommand('ybe-check.runTerminalCommand', msg.terminalCommand, workspaceRoot);
        }
    }, undefined, context.subscriptions);
}

function escapeHtml(text: any): string {
    const map: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
    const str = String(text || '');
    return str.replace(/[&<>"']/g, (c) => map[c] || c);
}

// Map module display name (from module_results[].name) to findings[].source for grouping
const MODULE_NAME_TO_SOURCE: Record<string, string> = {
    'Secrets Detection': 'secrets',
    'Prompt Injection': 'prompt_injection',
    'PII & Logging': 'pii',
    'Dependencies': 'deps',
    'Auth Guards': 'auth',
    'IaC Security': 'iac',
    'License Compliance': 'license',
    'AI Traceability': 'ai_trace',
    'Test & Coverage': 'test_cov',
    'Container Security': 'trivy',
    'SBOM': 'syft',
    'Config & Env': 'config_env',
    'Load Testing': 'artillery',
    'Web Attacks': 'zap',
    'API Fuzzing': 'ffuf',
    'Live Prompt Testing': 'vigil',
};

function getSourceForModule(moduleName: string): string | undefined {
    return MODULE_NAME_TO_SOURCE[moduleName] ?? moduleName.toLowerCase().replace(/\s+&\s+/g, '_').replace(/\s+/g, '_');
}

function scoreColor(s: number): string {
    if (s >= 80) return '#3FB950';
    if (s >= 50) return '#D29922';
    return '#F85149';
}

function sevColor(sev: string): string {
    const v = (sev || '').toLowerCase();
    if (v === 'high' || v === 'critical') return '#F85149';
    if (v === 'medium') return '#DB6D28';
    return '#58A6FF';
}

function generateReportHtml(report: any, workspaceRoot: string): string {
    const score = report.overall_score ?? 0;
    const modules = report.module_results || report.modules || [];
    const allFindings: any[] = report.findings || [];
    const topFixes: string[] = report.top_fixes || [];
    const totalIssues = allFindings.length;
    const version = report.version || '0.2';

    const summary = {
        critical: allFindings.filter((f: any) => (f.severity || '').toLowerCase() === 'critical').length,
        high: allFindings.filter((f: any) => (f.severity || '').toLowerCase() === 'high').length,
        medium: allFindings.filter((f: any) => (f.severity || '').toLowerCase() === 'medium').length,
        low: allFindings.filter((f: any) => (f.severity || '').toLowerCase() === 'low').length,
        info: allFindings.filter((f: any) => (f.severity || '').toLowerCase() === 'info').length,
    };
    const modulesPassed = modules.filter((m: any) => (m.score ?? 0) >= 80).length;
    const modulesFailed = modules.filter((m: any) => m.score != null && m.score < 80).length;
    const modulesErrored = modules.filter((m: any) => m.score == null).length;

    const verdictGradient = score >= 80
        ? 'linear-gradient(160deg, #0d7a3e, #15a050, #1cb85c)'
        : score >= 50
            ? 'linear-gradient(160deg, #c06000, #e07020, #f09030)'
            : 'linear-gradient(160deg, #8b2020, #c03030, #e04040)';

    const heroSummaryText = score >= 80
        ? 'Your repo is production-ready. Core security controls are solid.'
        : score >= 50
            ? 'Some areas need attention before deployment. Review the flagged modules.'
            : 'Critical vulnerabilities found. Not safe to deploy.';

    const personaTitle = score >= 80 ? 'Security Champion' : score >= 50 ? 'Cautious Builder' : 'Risk Taker';
    const personaDesc = score >= 80
        ? 'You follow best practices and prioritize security.'
        : score >= 50
            ? "You're aware of security but have some blind spots."
            : 'Move fast and break things. Security comes second.';

    const sortedModules = [...modules].sort((a: any, b: any) => (a.score ?? 0) - (b.score ?? 0));
    const scanTime = report.scan_time ? new Date(report.scan_time).toLocaleString() : new Date().toLocaleString();

    const moduleScoresHtml = sortedModules.map((mod: any) => {
        const ms = mod.score ?? 0;
        const mc = scoreColor(ms);
        return `
        <div class="module-score-row">
            <div class="module-score-icon" style="background:${mc}18;">
                <span class="module-score-dot" style="background:${mc};"></span>
            </div>
            <div class="module-score-body">
                <div class="module-score-name">${escapeHtml(mod.name || '')}</div>
                <div class="module-score-bar"><div class="module-score-fill" style="width:${ms}%;background:${mc};"></div></div>
            </div>
            <span class="module-score-pct">${ms}%</span>
        </div>`;
    }).join('');

    const verdictCardHtml = `
    <div class="verdict-card" style="background:${verdictGradient};">
        <div class="verdict-label">VERDICT</div>
        <div class="verdict-value">${escapeHtml(report.verdict || (score >= 80 ? 'PRODUCTION READY' : score >= 50 ? 'NEEDS ATTENTION' : 'NOT READY'))}</div>
        <div class="verdict-modules">
            <div class="verdict-modules-label">Module Health</div>
            <div class="verdict-modules-dots">
                ${modules.map((m: any) => {
                    const ms = m.score ?? 0;
                    const bg = ms >= 80 ? 'rgba(255,255,255,0.3)' : ms >= 50 ? 'rgba(255,255,255,0.15)' : 'rgba(0,0,0,0.3)';
                    return `<div class="verdict-dot" style="background:${bg};" title="${escapeHtml(m.name)}: ${ms}"></div>`;
                }).join('')}
            </div>
        </div>
    </div>`;

    const topFixesHtml = topFixes.length > 0
        ? `
        <div class="section-label">TOP FIXES</div>
        <div class="top-fixes-list">
            ${topFixes.slice(0, 5).map((fix: string, i: number) => `
                <div class="top-fix-item">
                    <span class="top-fix-num">${i + 1}.</span>
                    <span class="top-fix-text">${escapeHtml((fix || '').slice(0, 200))}</span>
                </div>`).join('')}
        </div>`
        : '';

    const moduleCardsHtml = sortedModules.map((mod: any, idx: number) => {
        const ms = mod.score ?? 0;
        const mc = scoreColor(ms);
        const source = getSourceForModule(mod.name);
        const modFindings = source ? allFindings.filter((f: any) => f.source === source) : [];
        const findingRows = modFindings.slice(0, 15).map((f: any, di: number) => {
            const loc = f.location || {};
            const filePath = (loc.path || 'unknown').toString();
            const lineNum = loc.line != null ? loc.line : undefined;
            const findingData = JSON.stringify({
                id: f.id,
                type: f.type || 'issue',
                severity: f.severity || 'medium',
                summary: (f.summary || '').slice(0, 200),
                location: loc,
                evidence: f.evidence || null,
                ai_analysis: f.ai_analysis || null,
            }).replace(/"/g, '&quot;');
            const matchId = `fix-${idx}-${di}`;
            const isUnverifiedNpm = (f.type || '').toLowerCase().includes('unverified') && (f.type || '').toLowerCase().includes('npm');
            const openBtn = workspaceRoot && filePath !== 'unknown'
                ? `<button class="open-btn" data-path="${escapeHtml(filePath)}" data-line="${lineNum ?? ''}" title="Open file">Open</button>`
                : '';
            const verifyBtn = isUnverifiedNpm && workspaceRoot
                ? `<button class="verify-btn" title="Run license check in terminal">Verify</button>`
                : '';
            return `
            <tr>
                <td class="cell-file">${escapeHtml(filePath)}</td>
                <td class="cell-line">${lineNum ?? '-'}</td>
                <td class="cell-type">${escapeHtml((f.type || 'issue').toString().slice(0, 40))}</td>
                <td><span class="sev-badge" style="background:${sevColor(f.severity)}20;color:${sevColor(f.severity)}">${escapeHtml((f.severity || 'medium').toUpperCase())}</span></td>
                <td class="cell-actions">
                    ${openBtn}
                    ${verifyBtn}
                    <button class="fix-btn" data-finding="${findingData}" id="${matchId}">Fix ⚡</button>
                </td>
            </tr>`;
        }).join('');
        const moreCount = modFindings.length - 15;
        const hasFindings = findingRows.length > 0;
        return `
        <div class="module-card" data-idx="${idx}">
            <div class="module-card-inner">
                <div class="module-card-icon" style="background:${mc}15;">
                    <span class="module-card-dot" style="background:${mc};"></span>
                </div>
                <div class="module-card-body">
                    <div class="module-card-name">${escapeHtml(mod.name || '')}</div>
                    <div class="module-card-meta">
                        <div class="module-card-bar"><div class="module-card-fill" style="width:${ms}%;background:${mc};"></div></div>
                        <span class="module-card-issues">${mod.issues ?? 0} issue${(mod.issues ?? 0) !== 1 ? 's' : ''}</span>
                    </div>
                </div>
                <div class="module-card-score" style="color:${mc};">${ms}</div>
            </div>
            ${hasFindings ? `
            <button class="toggle-btn" data-toggle="${idx}">Show Findings ▼</button>
            <div class="findings-section" id="findings-${idx}">
                <table class="findings-table">
                    <thead><tr><th>File</th><th>Line</th><th>Type</th><th>Severity</th><th>Actions</th></tr></thead>
                    <tbody>${findingRows}</tbody>
                </table>
                ${moreCount > 0 ? `<div class="findings-more">+ ${moreCount} more</div>` : ''}
            </div>` : '<div class="clean-badge">All clear</div>'}
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
            @keyframes heroGradientShift { 0%,100%{background-position:0% 50%} 50%{background-position:100% 50%} }

            :root {
                --bg: #0a0a0b;
                --card: rgba(35, 35, 40, 0.35);
                --cardLt: rgba(255, 255, 255, 0.04);
                --border: rgba(255, 255, 255, 0.1);
                --dim: #888;
                --dimLt: #aaa;
                --radius: 20px;
                --text: #E6EDF3;
                --green: #3FB950;
                --red: #F85149;
                --orange: #DB6D28;
                --blue: #58A6FF;
                --yellow: #D29922;
            }
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { background: var(--bg); color: var(--text); font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, sans-serif; padding: 0 24px 24px; }
            .shell { max-width: 1260px; margin: 0 auto; }
            .nav { display: flex; align-items: center; justify-content: space-between; padding: 14px 0; border-bottom: 1px solid var(--border); margin-bottom: 24px; }
            .nav-title { font-weight: 700; font-size: 15px; color: var(--text); }
            .nav-link { font-size: 12px; color: var(--dim); text-decoration: none; }

            .mcard { background: var(--card); backdrop-filter: blur(45px); -webkit-backdrop-filter: blur(45px); border-radius: var(--radius); padding: 28px; border: 1px solid var(--border); box-shadow: 0 10px 40px -10px rgba(0,0,0,0.5); }
            .section-label { font-size: 12px; font-weight: 600; color: var(--dim); text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 14px; }

            .row1 { display: grid; grid-template-columns: 1.3fr 0.8fr 0.9fr; gap: 12px; margin-bottom: 12px; }
            .row2 { display: grid; grid-template-columns: 1.2fr 0.8fr 1fr; gap: 12px; margin-bottom: 12px; }
            @media (max-width: 900px) { .row1, .row2 { grid-template-columns: 1fr; } }

            .hero-card { padding: 0; overflow: hidden; position: relative; min-height: 270px; }
            .hero-card::before { content: ''; position: absolute; inset: 0; background: linear-gradient(135deg, #1a0533 0%, #2d1b69 25%, #1b3a5c 50%, #0d4f4f 75%, #2a1050 100%); background-size: 400% 400%; animation: heroGradientShift 12s ease-in-out infinite; }
            .hero-card::after { content: ''; position: absolute; inset: 0; background: radial-gradient(ellipse at 30% 80%, rgba(120,80,220,0.35), transparent 60%), radial-gradient(ellipse at 70% 20%, rgba(40,180,200,0.25), transparent 50%); }
            .hero-inner { position: relative; z-index: 1; padding: 32px 36px; display: flex; flex-direction: column; justify-content: flex-end; height: 100%; min-height: 270px; }
            .hero-meta { display: flex; justify-content: space-between; alignItems: flex-start; margin-bottom: 8px; }
            .hero-label { font-size: 14px; font-weight: 500; color: rgba(255,255,255,0.55); }
            .hero-version { font-size: 10px; font-weight: 700; color: rgba(255,255,255,0.3); background: rgba(255,255,255,0.1); padding: 2px 8px; border-radius: 4px; }
            .hero-score { font-size: 96px; font-weight: 900; line-height: 1; color: #fff; letter-spacing: -3px; font-variant-numeric: tabular-nums; }
            .hero-summary { margin-top: 20px; padding: 10px 20px; background: rgba(0,0,0,0.3); backdrop-filter: blur(14px); border-radius: 10px; font-size: 14px; color: rgba(255,255,255,0.85); line-height: 1.5; max-width: 380px; }
            .hero-footer { margin-top: 12px; display: flex; justify-content: space-between; align-items: center; font-size: 11px; color: rgba(255,255,255,0.4); font-family: monospace; }

            .issues-card { display: flex; flex-direction: column; justify-content: space-between; }
            .issues-num { font-size: 72px; font-weight: 900; line-height: 1; font-variant-numeric: tabular-nums; margin-top: 16px; }
            .issues-tags { margin-top: auto; display: flex; flex-wrap: wrap; gap: 6px; }
            .issues-tag { padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 600; }

            .persona-card { display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; background: #f5f5f5 !important; }
            .persona-badge { display: inline-block; padding: 5px 16px; border-radius: 20px; background: var(--bg); color: #fff; font-size: 12px; font-weight: 700; }
            .persona-icon { width: 56px; height: 56px; border-radius: 50%; background: var(--bg); display: flex; align-items: center; justify-content: center; margin: 16px 0 12px; }
            .persona-label { font-size: 11px; font-weight: 600; color: #888; text-transform: uppercase; letter-spacing: 1px; }
            .persona-title { font-size: 26px; font-weight: 800; color: #111; line-height: 1.15; margin: 6px 0 8px; }
            .persona-desc { font-size: 12px; color: #666; line-height: 1.5; max-width: 180px; }

            .module-scores-card { padding: 24px 28px; }
            .module-score-row { display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }
            .module-score-row:last-child { margin-bottom: 0; }
            .module-score-icon { width: 32px; height: 32px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
            .module-score-dot { width: 10px; height: 10px; border-radius: 50%; }
            .module-score-body { flex: 1; min-width: 0; }
            .module-score-name { font-size: 13px; font-weight: 600; color: var(--text); margin-bottom: 4px; }
            .module-score-bar { height: 6px; border-radius: 3px; background: var(--border); overflow: hidden; }
            .module-score-fill { height: 100%; border-radius: 3px; transition: width 0.8s ease-out; }
            .module-score-pct { font-size: 13px; font-weight: 700; color: var(--dimLt); min-width: 30px; text-align: right; }

            .verdict-card { padding: 28px; display: flex; flex-direction: column; justify-content: space-between; border-radius: var(--radius); border: 1px solid var(--border); }
            .verdict-label { font-size: 12px; font-weight: 700; color: rgba(255,255,255,0.65); text-transform: uppercase; letter-spacing: 1.5px; }
            .verdict-value { font-size: 36px; font-weight: 800; color: #fff; line-height: 1.15; margin: 12px 0; }
            .verdict-modules { margin-top: auto; }
            .verdict-modules-label { font-size: 12px; font-weight: 600; color: rgba(255,255,255,0.6); margin-bottom: 8px; }
            .verdict-modules-dots { display: flex; gap: 6px; flex-wrap: wrap; }
            .verdict-dot { width: 28px; height: 28px; border-radius: 6px; }

            .summary-card { padding: 24px 28px; }
            .summary-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 20px; }
            .summary-cell { padding: 14px 16px; border-radius: 12px; background: var(--cardLt); }
            .summary-val { font-size: 24px; font-weight: 800; font-variant-numeric: tabular-nums; }
            .summary-lbl { font-size: 11px; color: var(--dim); margin-top: 2px; }
            .top-fixes-list { display: flex; flex-direction: column; gap: 0; }
            .top-fix-item { padding: 10px 0; border-bottom: 1px solid var(--border); font-size: 13px; color: var(--dimLt); line-height: 1.5; display: flex; gap: 10px; }
            .top-fix-item:last-child { border-bottom: none; }
            .top-fix-num { font-weight: 800; color: var(--dim); font-size: 12px; }
            .top-fix-text { color: var(--text); }

            .all-modules-label { font-size: 12px; font-weight: 600; color: var(--dim); text-transform: uppercase; letter-spacing: 1.5px; margin: 24px 0 12px; }
            .modules-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(380px, 1fr)); gap: 12px; }
            .module-card { border-radius: var(--radius); padding: 20px 24px; border: 1px solid var(--border); background: var(--card); margin-bottom: 12px; transition: all 0.2s; animation: fadeIn 0.4s ease-out both; }
            .module-card:hover { border-color: rgba(255,255,255,0.15); }
            .module-card-inner { display: flex; align-items: center; gap: 16px; width: 100%; text-align: left; }
            .module-card-icon { width: 42px; height: 42px; border-radius: 12px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
            .module-card-dot { width: 12px; height: 12px; border-radius: 50%; }
            .module-card-body { flex: 1; min-width: 0; }
            .module-card-name { font-size: 14px; font-weight: 600; color: var(--text); margin-bottom: 6px; }
            .module-card-meta { display: flex; align-items: center; gap: 10px; }
            .module-card-bar { flex: 1; height: 4px; border-radius: 2px; background: var(--border); overflow: hidden; }
            .module-card-fill { height: 100%; border-radius: 2px; transition: width 0.8s ease-out; }
            .module-card-issues { font-size: 12px; color: var(--dim); white-space: nowrap; }
            .module-card-score { font-size: 24px; font-weight: 800; font-variant-numeric: tabular-nums; min-width: 34px; text-align: right; }
            .toggle-btn { margin-top: 10px; width: 100%; padding: 7px 14px; border-radius: 8px; cursor: pointer; font-size: 11px; font-weight: 600; text-align: center; background: rgba(88,166,255,0.08); border: 1px solid rgba(88,166,255,0.2); color: var(--blue); font-family: inherit; transition: background 0.15s; }
            .toggle-btn:hover { background: rgba(88,166,255,0.15); }
            .findings-section { max-height: 0; overflow: hidden; transition: max-height 0.4s ease-out; }
            .findings-section.open { max-height: 2000px; }
            .findings-table { width: 100%; margin-top: 12px; border-collapse: collapse; font-size: 11px; }
            .findings-table th { text-align: left; padding: 7px 8px; color: var(--dim); font-weight: 600; text-transform: uppercase; font-size: 9px; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); }
            .findings-table td { padding: 6px 8px; border-bottom: 1px solid rgba(255,255,255,0.02); }
            .findings-table tr:hover { background: rgba(88,166,255,0.03); }
            .cell-file { font-family: monospace; color: var(--blue); max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 11px; }
            .cell-line { color: var(--dim); font-family: monospace; text-align: center; min-width: 36px; }
            .cell-type { color: var(--dimLt); font-size: 11px; }
            .sev-badge { display: inline-block; padding: 1px 7px; border-radius: 4px; font-size: 9px; font-weight: 700; letter-spacing: 0.3px; }
            .findings-more { text-align: center; padding: 8px; color: var(--dim); font-size: 10px; }
            .clean-badge { margin-top: 10px; padding: 8px 12px; background: rgba(63,185,80,0.06); border: 1px solid rgba(63,185,80,0.1); border-radius: 8px; color: var(--green); font-size: 11px; font-weight: 600; }
            .fix-btn { background: rgba(88,166,255,0.12); border: 1px solid rgba(88,166,255,0.25); color: var(--blue); padding: 3px 10px; border-radius: 6px; cursor: pointer; font-size: 10px; font-weight: 700; transition: all 0.15s; white-space: nowrap; font-family: inherit; }
            .fix-btn:hover { background: rgba(88,166,255,0.25); border-color: var(--blue); transform: scale(1.05); }
            .open-btn, .verify-btn { background: rgba(255,255,255,0.06); border: 1px solid var(--border); color: var(--dimLt); padding: 3px 8px; border-radius: 6px; cursor: pointer; font-size: 10px; font-weight: 600; margin-right: 4px; font-family: inherit; }
            .open-btn:hover, .verify-btn:hover { background: rgba(255,255,255,0.1); color: var(--text); }
            .verify-btn { color: var(--blue); border-color: rgba(88,166,255,0.3); }
            .cell-actions { display: flex; flex-wrap: wrap; gap: 4px; align-items: center; }

            .copilot-bar { display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; margin: 24px 0 16px; }
            .copilot-btn { display: inline-flex; align-items: center; gap: 6px; padding: 10px 20px; border-radius: 10px; cursor: pointer; font-size: 13px; font-weight: 700; transition: all 0.2s; letter-spacing: 0.3px; font-family: inherit; }
            .copilot-btn:hover { transform: translateY(-1px); box-shadow: 0 4px 20px rgba(88,166,255,0.15); }
            .copilot-primary { background: linear-gradient(135deg, #58A6FF, #79b8ff); color: #fff; border: none; }
            .copilot-secondary { background: rgba(88,166,255,0.08); color: var(--blue); border: 1px solid rgba(88,166,255,0.2); }
            .cta-bar { text-align: center; padding: 16px; background: var(--card); border: 1px solid var(--border); border-radius: 14px; margin-top: 8px; }
            .cta-bar p { font-size: 12px; color: var(--dim); }
            .cta-bar code { background: rgba(88,166,255,0.1); padding: 2px 8px; border-radius: 4px; font-size: 11px; color: var(--blue); }
            .footer { text-align: center; margin-top: 32px; padding-top: 16px; border-top: 1px solid rgba(255,255,255,0.03); color: var(--dim); font-size: 10px; letter-spacing: 0.5px; }
        </style>
    </head>
    <body>
        <div class="shell">
            <nav class="nav">
                <span class="nav-title">Ybe Check</span>
                <a href="https://github.com/AddyCuber/A2K2-PS1" target="_blank" rel="noopener" class="nav-link">GitHub ↗</a>
            </nav>

            <div class="row1">
                <div class="mcard hero-card">
                    <div class="hero-inner">
                        <div class="hero-meta">
                            <span class="hero-label">Audit Report</span>
                            <span class="hero-version">v${escapeHtml(version)}</span>
                        </div>
                        <div class="hero-score">${score}</div>
                        <div class="hero-summary">${escapeHtml(heroSummaryText)}</div>
                        <div class="hero-footer">
                            <span>Target: workspace</span>
                            <span>${escapeHtml(scanTime)}</span>
                        </div>
                    </div>
                </div>
                <div class="mcard issues-card">
                    <div class="section-label">TOTAL ISSUES FOUND</div>
                    <div class="issues-num" style="color:${totalIssues > 0 ? '#a78bfa' : 'var(--green)'};">${totalIssues}</div>
                    ${totalIssues > 0 ? `
                    <div class="issues-tags">
                        ${summary.critical + summary.high > 0 ? `<span class="issues-tag" style="background:rgba(248,81,73,0.12);color:var(--red);">${summary.critical + summary.high} critical</span>` : ''}
                        ${summary.medium > 0 ? `<span class="issues-tag" style="background:rgba(219,109,40,0.12);color:var(--orange);">${summary.medium} medium</span>` : ''}
                        ${summary.low + summary.info > 0 ? `<span class="issues-tag" style="background:rgba(88,166,255,0.12);color:var(--blue);">${summary.low + summary.info} low</span>` : ''}
                    </div>` : ''}
                </div>
                <div class="mcard persona-card">
                    <span class="persona-badge">Security Profile</span>
                    <div class="persona-icon">🛡️</div>
                    <div class="persona-label">YOU ARE A</div>
                    <div class="persona-title">${escapeHtml(personaTitle)}</div>
                    <div class="persona-desc">${escapeHtml(personaDesc)}</div>
                </div>
            </div>

            <div class="row2">
                <div class="mcard module-scores-card">
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
                        <span style="font-size:16px;font-weight:700;color:var(--text);">Module Scores</span>
                        <span style="font-size:12px;color:var(--dim);">Score /100</span>
                    </div>
                    <div>${moduleScoresHtml}</div>
                </div>
                ${verdictCardHtml}
                <div class="mcard summary-card">
                    <div class="section-label">SCAN SUMMARY</div>
                    <div class="summary-grid">
                        <div class="summary-cell">
                            <div class="summary-val" style="color:var(--text);">${modulesPassed}/${modules.length}</div>
                            <div class="summary-lbl">Passed</div>
                        </div>
                        <div class="summary-cell">
                            <div class="summary-val" style="color:${modulesFailed > 0 ? 'var(--red)' : 'var(--green)'};">${modulesFailed + modulesErrored}</div>
                            <div class="summary-lbl">Errors / Failures</div>
                        </div>
                    </div>
                    ${topFixesHtml}
                </div>
            </div>

            <div class="section-label all-modules-label">ALL MODULES</div>
            <div class="modules-grid">${moduleCardsHtml}</div>

            <div class="copilot-bar">
                <button class="copilot-btn copilot-primary" onclick="securityAudit()">⚡ Security Audit</button>
                <button class="copilot-btn copilot-secondary" onclick="fixTopIssue()">🔧 Fix Top Issue</button>
                <button class="copilot-btn copilot-secondary" onclick="fixAllCritical()">🚨 Fix All Critical</button>
                <button class="copilot-btn copilot-secondary" onclick="browseBySeverity()">📊 Browse Issues</button>
                <button class="copilot-btn copilot-secondary" onclick="askCopilot()">💬 Ask Copilot</button>
            </div>
            <div class="cta-bar">
                <p>Open the full dashboard for AI chat &amp; detailed analysis: <code>ybe-check dashboard</code> or <a href="#" onclick="openDashboard();return false;" style="color:var(--blue);text-decoration:none;font-weight:600;">Open Dashboard →</a></p>
            </div>
            <div class="footer">Ybe Check · Security audit for vibe-coded applications</div>
        </div>

        <script>
            const vscode = acquireVsCodeApi();
            const workspaceRoot = ${JSON.stringify(workspaceRoot)};
            const allFindings = ${JSON.stringify(allFindings.slice(0, 50).map((f: any) => ({
                id: f.id, type: f.type, severity: f.severity,
                summary: (f.summary || '').slice(0, 200),
                location: f.location || {},
                evidence: f.evidence || null,
                ai_analysis: f.ai_analysis || null,
            })))};

            document.querySelectorAll('.toggle-btn[data-toggle]').forEach(btn => {
                btn.addEventListener('click', function() {
                    const id = 'findings-' + this.getAttribute('data-toggle');
                    const section = document.getElementById(id);
                    if (!section) return;
                    section.classList.toggle('open');
                    this.textContent = section.classList.contains('open') ? 'Hide Findings ▲' : 'Show Findings ▼';
                });
            });

            document.querySelectorAll('.fix-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    try {
                        const raw = this.getAttribute('data-finding');
                        if (!raw) return;
                        const finding = JSON.parse(raw.replace(/&quot;/g, '"'));
                        vscode.postMessage({ command: 'fixWithCopilot', finding: finding });
                        this.textContent = 'Sent ✓';
                        this.style.background = 'rgba(63,185,80,0.15)';
                        this.style.color = 'var(--green)';
                        this.style.borderColor = 'var(--green)';
                        const t = this;
                        setTimeout(() => { t.textContent = 'Fix ⚡'; t.style.background = ''; t.style.color = ''; t.style.borderColor = ''; }, 2000);
                    } catch (e) { console.error(e); }
                });
            });

            document.querySelectorAll('.open-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    const p = this.getAttribute('data-path');
                    const line = this.getAttribute('data-line');
                    if (p) vscode.postMessage({ command: 'openFile', path: p, line: line ? parseInt(line, 10) : undefined });
                });
            });

            document.querySelectorAll('.verify-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    if (workspaceRoot) vscode.postMessage({ command: 'runTerminal', terminalCommand: 'npx license-checker --summary' });
                });
            });

            function fixTopIssue() {
                if (allFindings.length > 0) {
                    const sevOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
                    const sorted = [...allFindings].sort((a, b) => (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0));
                    vscode.postMessage({ command: 'fixWithCopilot', finding: sorted[0] });
                }
            }
            function askCopilot() { vscode.postMessage({ command: 'askCopilot' }); }
            function securityAudit() { vscode.postMessage({ command: 'securityAudit' }); }
            function fixAllCritical() { vscode.postMessage({ command: 'fixAllCritical' }); }
            function browseBySeverity() { vscode.postMessage({ command: 'browseBySeverity' }); }
            function openDashboard() { vscode.postMessage({ command: 'openDashboard' }); }
        </script>
    </body>
    </html>`;
}
