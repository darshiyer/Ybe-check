/**
 * © 2025 ArpitStack. Distributed under Apache-2.0 License.
 * See http://www.apache.org/licenses/LICENSE-2.0 for details.
 */

import { initializeStatusBar, disposeStatusBar } from './utils/statusBarUtils';
import { executeScan } from './utils/scanUtils';
import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

const MCP_SERVER_ID = 'ybe-check';
const MCP_ARGS = ['-m', 'ybe_check.mcp_server'];

function writeMcpFile(dir: string, mcpFilePath: string, pythonPath: string): boolean {
    let config: { mcpServers: Record<string, unknown> } = { mcpServers: {} };
    if (fs.existsSync(mcpFilePath)) {
        try { config = JSON.parse(fs.readFileSync(mcpFilePath, 'utf8')); }
        catch { config = { mcpServers: {} }; }
    }
    if (!config.mcpServers) { config.mcpServers = {}; }

    const existing = config.mcpServers[MCP_SERVER_ID] as { command?: string; args?: string[] } | undefined;
    if (existing && existing.command === pythonPath) { return false; }

    config.mcpServers[MCP_SERVER_ID] = { command: pythonPath, args: MCP_ARGS };

    if (!fs.existsSync(dir)) { fs.mkdirSync(dir, { recursive: true }); }
    fs.writeFileSync(mcpFilePath, JSON.stringify(config, null, 2));
    return true;
}

function ensureMcpConfig(context: vscode.ExtensionContext) {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) { return; }

    const pythonPath: string = vscode.workspace
        .getConfiguration('ybe-check')
        .get('pythonPath', 'python3');

    const root = workspaceFolders[0].uri.fsPath;
    let changed = false;

    // Write .vscode/mcp.json (VS Code native MCP support)
    const vscodeDir = path.join(root, '.vscode');
    changed = writeMcpFile(vscodeDir, path.join(vscodeDir, 'mcp.json'), pythonPath) || changed;

    // Write .cursor/mcp.json (Cursor support)
    const cursorDir = path.join(root, '.cursor');
    changed = writeMcpFile(cursorDir, path.join(cursorDir, 'mcp.json'), pythonPath) || changed;

    if (changed) {
        vscode.window.showInformationMessage(
            'Ybe Check: MCP server registered for VS Code & Cursor. Reload the window to activate it.',
            'Reload'
        ).then(action => {
            if (action === 'Reload') { vscode.commands.executeCommand('workbench.action.reloadWindow'); }
        });
    }
}

// ── Copilot Chat integration helpers ────────────────────────────────

const SEV_ORDER: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
function sevWeight(s: string): number { return SEV_ORDER[s] ?? 0; }

/**
 * Load the latest ybe-report.json from the workspace root.
 */
function loadReport(): any | null {
    const ws = vscode.workspace.workspaceFolders;
    if (!ws || ws.length === 0) { return null; }
    const reportPath = path.join(ws[0].uri.fsPath, 'ybe-report.json');
    if (!fs.existsSync(reportPath)) { return null; }
    try { return JSON.parse(fs.readFileSync(reportPath, 'utf8')); }
    catch { return null; }
}

/**
 * Build a compact security context string from the report.
 */
function buildSecurityContext(report: any): string {
    const score = report.overall_score ?? 0;
    const verdict = report.verdict ?? 'UNKNOWN';
    const findings = report.findings ?? [];
    const modules = report.module_results ?? [];

    const sevCounts: Record<string, number> = {};
    for (const f of findings) {
        const s = f.severity ?? 'medium';
        sevCounts[s] = (sevCounts[s] || 0) + 1;
    }
    const sevLine = Object.entries(sevCounts)
        .sort((a, b) => sevWeight(b[0]) - sevWeight(a[0]))
        .map(([k, v]) => `${k}: ${v}`)
        .join(', ');

    const weakModules = modules
        .filter((m: any) => (m.score ?? 100) < 50)
        .map((m: any) => m.name)
        .slice(0, 5);

    const topFindings = findings
        .sort((a: any, b: any) => sevWeight(b.severity ?? 'medium') - sevWeight(a.severity ?? 'medium'))
        .slice(0, 10)
        .map((f: any) => `  - [${(f.severity ?? 'medium').toUpperCase()}] ${f.location?.path ?? 'unknown'}:${f.location?.line ?? '?'} — ${f.type}: ${(f.summary ?? '').slice(0, 120)}`)
        .join('\n');

    const fixes = (report.top_fixes ?? []).slice(0, 5).map((f: string, i: number) => `  ${i + 1}. ${f}`).join('\n');

    return `## Ybe Check Security Context
**Score: ${score}/100 — ${verdict}**
Total findings: ${findings.length} (${sevLine})
Weakest modules: ${weakModules.join(', ') || 'none'}

### Top Findings:
${topFindings || '  (none)'}

### Priority Fixes:
${fixes || '  (none)'}`;
}

/**
 * Build a fix prompt for a specific finding.
 */
function buildFixPrompt(finding: any): string {
    const loc = finding.location ?? {};
    const sev = (finding.severity ?? 'medium').toUpperCase();
    const snippet = finding.evidence?.snippet ?? finding.evidence?.match ?? '';
    const ai = finding.ai_analysis ?? {};
    const hint = ai.remediation ?? '';

    return `Fix this ${sev} security finding in my codebase:

**Finding ID**: ${finding.id}
**Type**: ${finding.type ?? 'issue'}
**Severity**: ${sev}
**File**: ${loc.path ?? 'unknown'}
**Line**: ${loc.line ?? '?'}
**Issue**: ${finding.summary ?? 'Security issue detected'}
${snippet ? `**Evidence**: \`${String(snippet).slice(0, 200)}\`` : ''}
${hint ? `**Suggested Fix**: ${hint}` : ''}

Please:
1. Show me the exact code change needed to fix this issue.
2. Explain why the current code is vulnerable.
3. Ensure the fix doesn't break existing functionality.
4. If there are related issues in the same file, mention them.`;
}

/**
 * Open Copilot Chat with a pre-filled prompt.
 * Tries multiple VS Code chat APIs for compatibility.
 */
async function openCopilotChat(prompt: string): Promise<void> {
    try {
        // VS Code 1.99+ — workbench.action.chat.open with query
        await vscode.commands.executeCommand('workbench.action.chat.open', { query: prompt });
    } catch {
        try {
            // Fallback: open chat panel and copy prompt to clipboard
            await vscode.commands.executeCommand('workbench.action.chat.open');
            await vscode.env.clipboard.writeText(prompt);
            vscode.window.showInformationMessage(
                'Ybe Check: Prompt copied to clipboard. Paste it into the Copilot Chat input (Cmd+V).',
                'OK'
            );
        } catch {
            // Last resort: just copy to clipboard
            await vscode.env.clipboard.writeText(prompt);
            vscode.window.showInformationMessage(
                'Ybe Check: Prompt copied to clipboard. Open Copilot Chat and paste (Cmd+V).',
                'OK'
            );
        }
    }
}

/**
 * Activates the Ybe Check extension.
 * Initializes status bar, registers scan commands, Copilot commands, and ensures MCP config exists.
 */
export function activate(context: vscode.ExtensionContext) {

    ensureMcpConfig(context);

    // Initialize the status bar with the scan action button
    initializeStatusBar(context);

    // ── Scan commands ───────────────────────────────────────────────
    const fullScanCommand = vscode.commands.registerCommand('ybe-check.fullScan', async () => {
        await executeScan('full', context);
    });

    const staticScanCommand = vscode.commands.registerCommand('ybe-check.staticScan', async () => {
        await executeScan('static', context);
    });

    // ── Copilot Chat integration commands ───────────────────────────

    // Ask Copilot with full security context
    const askCopilotCommand = vscode.commands.registerCommand('ybe-check.askCopilot', async () => {
        const report = loadReport();
        if (!report) {
            vscode.window.showWarningMessage('No scan report found. Run a scan first (Ybe Check: Full Audit).');
            return;
        }

        const userPrompt = await vscode.window.showInputBox({
            prompt: 'What would you like to ask? (security context will be injected automatically)',
            placeHolder: 'e.g. "How do I secure the auth flow?" or "Review app.py for vulnerabilities"',
        });
        if (!userPrompt) { return; }

        const secCtx = buildSecurityContext(report);
        const enhanced = `${secCtx}\n\n---\n\n## My Question:\n${userPrompt}\n\n---\n**Consider the security findings above in your response. Reference finding IDs when relevant.**`;
        await openCopilotChat(enhanced);
    });

    // Fix a specific finding with Copilot — called from webview or command palette
    const fixWithCopilotCommand = vscode.commands.registerCommand('ybe-check.fixWithCopilot', async (findingArg?: any) => {
        const report = loadReport();
        if (!report) {
            vscode.window.showWarningMessage('No scan report found. Run a scan first.');
            return;
        }

        let finding = findingArg;

        // If no argument, ask user to pick a finding
        if (!finding || !finding.id) {
            const findings = (report.findings ?? [])
                .sort((a: any, b: any) => sevWeight(b.severity ?? 'medium') - sevWeight(a.severity ?? 'medium'))
                .slice(0, 30);

            if (findings.length === 0) {
                vscode.window.showInformationMessage('No findings to fix!');
                return;
            }

            interface FindingItem extends vscode.QuickPickItem { finding: any; }
            const items: FindingItem[] = findings.map((f: any) => ({
                label: `$(shield) [${(f.severity ?? 'medium').toUpperCase()}] ${f.type ?? 'issue'}`,
                description: `${f.location?.path ?? 'unknown'}:${f.location?.line ?? '?'}`,
                detail: (f.summary ?? '').slice(0, 120),
                finding: f,
            }));

            const picked = await vscode.window.showQuickPick(items, {
                placeHolder: 'Select a finding to fix with Copilot',
                matchOnDescription: true,
                matchOnDetail: true,
            });
            if (!picked) { return; }
            finding = picked.finding;
        }

        const prompt = buildFixPrompt(finding);
        await openCopilotChat(prompt);
    });

    // Security audit prompt — sends full context to Copilot
    const securityAuditCommand = vscode.commands.registerCommand('ybe-check.securityAudit', async () => {
        const report = loadReport();
        if (!report) {
            vscode.window.showWarningMessage('No scan report found. Run a scan first.');
            return;
        }

        const secCtx = buildSecurityContext(report);
        const prompt = `${secCtx}\n\n---\n\nYou are a senior security engineer. Based on the Ybe Check scan results above:\n\n1. **Critical Issues** — List all critical/high findings that must be fixed before deployment.\n2. **Quick Wins** — Easy fixes that improve the score.\n3. **Architecture Concerns** — Structural security problems.\n4. **Prioritized Action Plan** — What to fix first.\n\nReference specific finding IDs. Be specific with file names and line numbers.`;
        await openCopilotChat(prompt);
    });

    // Add all commands to subscriptions
    context.subscriptions.push(
        fullScanCommand,
        staticScanCommand,
        askCopilotCommand,
        fixWithCopilotCommand,
        securityAuditCommand,
    );
}

/**
 * Deactivates the Ybe Check extension.
 */
export function deactivate() {
    disposeStatusBar();
}
