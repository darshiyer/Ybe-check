/**
 * © 2025 ArpitStack. Distributed under Apache-2.0 License.
 * See http://www.apache.org/licenses/LICENSE-2.0 for details.
 */

import { initializeStatusBar, disposeStatusBar } from './utils/statusBarUtils';
import { executeScan } from './utils/scanUtils';
import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

const MCP_SERVER_ID = 'ybe-check';
const MCP_MODULE = 'ybe_check.mcp_server';
const MCP_ARGS = ['-m', MCP_MODULE];
const PIP_PACKAGE = 'ybe-check';

// ── Severity helpers ────────────────────────────────────────────────

const SEV_ORDER: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
function sevWeight(s: string): number { return SEV_ORDER[s] ?? 0; }
function sevIcon(s: string): string {
    const v = (s || 'medium').toLowerCase();
    if (v === 'critical') { return '🔴'; }
    if (v === 'high') { return '🟠'; }
    if (v === 'medium') { return '🟡'; }
    if (v === 'low') { return '🔵'; }
    return 'ℹ️';
}

// ── Path helpers ────────────────────────────────────────────────────

function resolveFilePath(filePath: string, workspaceRoot: string): string {
    const p = path.isAbsolute(filePath) ? filePath : path.join(workspaceRoot, filePath);
    return path.normalize(p);
}

function getPythonPath(): string {
    return vscode.workspace.getConfiguration('ybe-check').get<string>('pythonPath', 'python3');
}

// =====================================================================
// MCP AUTO-INSTALL — pip install ybe-check + write MCP configs
// =====================================================================

/** Check if the ybe_check Python module is importable. */
async function isMcpInstalled(pythonPath: string): Promise<boolean> {
    try {
        await execAsync(`"${pythonPath}" -c "import ybe_check"`, { timeout: 15_000 });
        return true;
    } catch {
        return false;
    }
}

/** Install ybe-check via pip. */
async function installMcpPackage(pythonPath: string): Promise<boolean> {
    const out = vscode.window.createOutputChannel('Ybe Check Setup');
    out.show(true);
    out.appendLine('⏳ Installing ybe-check MCP server package…');

    try {
        // Detect virtualenv
        let inVenv = false;
        try {
            const { stdout } = await execAsync(
                `"${pythonPath}" -c "import sys; print(sys.prefix != sys.base_prefix)"`,
                { timeout: 10_000 },
            );
            inVenv = stdout.trim() === 'True';
        } catch { /* assume no venv */ }

        const ws = vscode.workspace.workspaceFolders;
        const root = ws && ws.length > 0 ? ws[0].uri.fsPath : undefined;

        // Strategy 1 — local editable install if we *are* the ybe-check repo
        if (root) {
            const pyproject = path.join(root, 'pyproject.toml');
            if (fs.existsSync(pyproject)) {
                const txt = fs.readFileSync(pyproject, 'utf8');
                if (txt.includes('name = "ybe-check"') || txt.includes('name="ybe-check"')) {
                    const cmd = `"${pythonPath}" -m pip install -e "${root}" --quiet`;
                    out.appendLine(`> ${cmd}`);
                    const { stdout, stderr } = await execAsync(cmd, { timeout: 120_000, cwd: root });
                    if (stdout) { out.appendLine(stdout); }
                    if (stderr) { out.appendLine(stderr); }
                    out.appendLine('✅ ybe-check installed (editable, local source).');
                    return true;
                }
            }
        }

        // Strategy 2 — pip install from PyPI
        const userFlag = inVenv ? '' : '--user';
        const cmd = `"${pythonPath}" -m pip install ${PIP_PACKAGE} ${userFlag} --quiet`;
        out.appendLine(`> ${cmd}`);
        const { stdout, stderr } = await execAsync(cmd, { timeout: 120_000 });
        if (stdout) { out.appendLine(stdout); }
        if (stderr) { out.appendLine(stderr); }
        out.appendLine('✅ ybe-check installed from PyPI.');
        return true;
    } catch (err) {
        out.appendLine(`❌ Install failed: ${err instanceof Error ? err.message : String(err)}`);
        out.appendLine('Manually run:  pip install ybe-check');
        return false;
    }
}

/** Write a single MCP config file; returns true when content changed. */
function writeMcpFile(dir: string, mcpFilePath: string, pythonPath: string): boolean {
    let config: { mcpServers: Record<string, unknown> } = { mcpServers: {} };
    if (fs.existsSync(mcpFilePath)) {
        try { config = JSON.parse(fs.readFileSync(mcpFilePath, 'utf8')); }
        catch { config = { mcpServers: {} }; }
    }
    if (!config.mcpServers) { config.mcpServers = {}; }

    const existing = config.mcpServers[MCP_SERVER_ID] as
        { command?: string; args?: string[] } | undefined;

    if (
        existing &&
        existing.command === pythonPath &&
        JSON.stringify(existing.args) === JSON.stringify(MCP_ARGS)
    ) {
        return false; // already up-to-date
    }

    config.mcpServers[MCP_SERVER_ID] = { command: pythonPath, args: MCP_ARGS };
    if (!fs.existsSync(dir)) { fs.mkdirSync(dir, { recursive: true }); }
    fs.writeFileSync(mcpFilePath, JSON.stringify(config, null, 2));
    return true;
}

/**
 * Full MCP bootstrap:
 *  1. pip install ybe-check (if missing)
 *  2. Write .vscode/mcp.json  +  .cursor/mcp.json
 */
async function ensureMcpSetup(context: vscode.ExtensionContext): Promise<void> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) { return; }

    const pythonPath = getPythonPath();

    // Step 1 — install the Python package if it's not importable
    const installed = await isMcpInstalled(pythonPath);
    if (!installed) {
        const choice = await vscode.window.showInformationMessage(
            'Ybe Check: The MCP server package is not installed. Install it now?',
            'Install', 'Skip',
        );
        if (choice === 'Install') {
            const ok = await installMcpPackage(pythonPath);
            if (!ok) {
                vscode.window.showErrorMessage(
                    'Ybe Check: Could not install MCP package. Run `pip install ybe-check` manually.',
                );
                return;
            }
        } else {
            return;
        }
    }

    // Step 2 — write config files
    const root = workspaceFolders[0].uri.fsPath;
    let changed = false;

    const vscodeDir = path.join(root, '.vscode');
    changed = writeMcpFile(vscodeDir, path.join(vscodeDir, 'mcp.json'), pythonPath) || changed;

    const cursorDir = path.join(root, '.cursor');
    changed = writeMcpFile(cursorDir, path.join(cursorDir, 'mcp.json'), pythonPath) || changed;

    if (changed) {
        vscode.window.showInformationMessage(
            'Ybe Check: MCP server installed & registered. Reload to activate.',
            'Reload',
        ).then(a => {
            if (a === 'Reload') { vscode.commands.executeCommand('workbench.action.reloadWindow'); }
        });
    }
}

// =====================================================================
// REPORT LOADING
// =====================================================================

function loadReport(): any | null {
    const ws = vscode.workspace.workspaceFolders;
    if (!ws || ws.length === 0) { return null; }
    const rp = path.join(ws[0].uri.fsPath, 'ybe-report.json');
    if (!fs.existsSync(rp)) { return null; }
    try { return JSON.parse(fs.readFileSync(rp, 'utf8')); }
    catch { return null; }
}

function requireReport(): any | null {
    const r = loadReport();
    if (!r) {
        vscode.window.showWarningMessage(
            'No scan report found. Run a scan first.',
            'Run Full Scan',
        ).then(a => {
            if (a === 'Run Full Scan') { vscode.commands.executeCommand('ybe-check.fullScan'); }
        });
    }
    return r;
}

// =====================================================================
// HIGH-QUALITY PROMPT BUILDERS
// =====================================================================

function buildSecurityContext(report: any): string {
    const score = report.overall_score ?? 0;
    const verdict = report.verdict ?? 'UNKNOWN';
    const findings: any[] = report.findings ?? [];
    const modules: any[] = report.module_results ?? [];

    const sevCounts: Record<string, number> = {};
    for (const f of findings) {
        const s = f.severity ?? 'medium';
        sevCounts[s] = (sevCounts[s] || 0) + 1;
    }
    const sevLine = Object.entries(sevCounts)
        .sort((a, b) => sevWeight(b[0]) - sevWeight(a[0]))
        .map(([k, v]) => `${sevIcon(k)} ${k}: ${v}`)
        .join(' · ');

    const weakModules = modules
        .filter((m: any) => (m.score ?? 100) < 50)
        .map((m: any) => `${m.name} (${m.score ?? 0}/100)`)
        .slice(0, 5);

    const topFindings = findings
        .sort((a: any, b: any) => sevWeight(b.severity ?? 'medium') - sevWeight(a.severity ?? 'medium'))
        .slice(0, 12)
        .map((f: any) => {
            const sev = (f.severity ?? 'medium').toUpperCase();
            const loc = f.location ?? {};
            return `  ${sevIcon(f.severity)} **[${sev}]** \`${loc.path ?? '?'}:${loc.line ?? '?'}\` — ${f.type}: ${(f.summary ?? '').slice(0, 120)}  *(${f.id})*`;
        }).join('\n');

    const fixes = (report.top_fixes ?? []).slice(0, 5)
        .map((f: string, i: number) => `  ${i + 1}. ${f}`).join('\n');

    return `## 🛡️ Ybe Check Security Context
**Score: ${score}/100 — ${verdict}**
Total findings: ${findings.length} (${sevLine})
Weakest modules: ${weakModules.join(', ') || 'none'}

### Top Findings:
${topFindings || '  (none)'}

### Priority Fixes:
${fixes || '  (none)'}`;
}

function buildFileFindings(report: any, filePath: string): any[] {
    return (report.findings ?? [])
        .filter((f: any) => filePath && ((f.location?.path ?? '').includes(filePath)))
        .sort((a: any, b: any) => sevWeight(b.severity ?? 'medium') - sevWeight(a.severity ?? 'medium'));
}

// ── Fix prompt (single finding) ─────────────────────────────────────

function buildFixPrompt(finding: any): string {
    const loc = finding.location ?? {};
    const sev = (finding.severity ?? 'medium').toUpperCase();
    const source = finding.source ?? 'unknown';
    const snippet = finding.evidence?.snippet ?? finding.evidence?.match ?? '';
    const ai = finding.ai_analysis ?? {};
    const hint = ai.remediation ?? '';
    const cwe = ai.cwe ?? '';

    return `You are a senior application security engineer. Fix this **${sev}** security vulnerability.

---

### Finding Details
| Field | Value |
|-------|-------|
| **ID** | \`${finding.id}\` |
| **Type** | ${finding.type ?? 'issue'} |
| **Severity** | ${sevIcon(finding.severity)} ${sev} |
| **Scanner** | ${source} |
| **File** | \`${loc.path ?? 'unknown'}\` |
| **Line** | ${loc.line ?? '?'} |
${cwe ? `| **CWE** | ${cwe} |\n` : ''}${loc.endpoint ? `| **Endpoint** | \`${loc.endpoint}\` |\n` : ''}${loc.resource ? `| **Resource** | \`${loc.resource}\` |\n` : ''}
### Issue
${finding.summary ?? 'Security issue detected.'}

${finding.details ? `### Context\n${finding.details}\n` : ''}${snippet ? `### Evidence\n\`\`\`\n${String(snippet).slice(0, 500)}\n\`\`\`\n` : ''}${hint ? `### Suggested Approach\n${hint}\n` : ''}
---

### Your Task
1. **Read** \`${loc.path ?? 'unknown'}\` around line ${loc.line ?? '?'}.
2. **Show the vulnerable code** and explain why it's insecure.
3. **Provide the complete fixed code** (full function/block — not a diff).
4. **Verify** the fix doesn't break existing functionality.
5. **Check for related issues** — fix the same pattern elsewhere in the file.

Use secure coding best practices. Secrets → env vars. Injection → parameterized queries / sanitization. Auth → proper middleware.`;
}

// ── Explain prompt ──────────────────────────────────────────────────

function buildExplainPrompt(finding: any): string {
    const loc = finding.location ?? {};
    const sev = (finding.severity ?? 'medium').toUpperCase();
    const cwe = finding.ai_analysis?.cwe ?? '';

    return `You are a cybersecurity educator. Explain this vulnerability in detail.

### Finding
- **ID**: \`${finding.id}\`
- **Type**: ${finding.type ?? 'issue'}
- **Severity**: ${sevIcon(finding.severity)} ${sev}
- **File**: \`${loc.path ?? '?'}:${loc.line ?? '?'}\`
- **Summary**: ${finding.summary ?? 'Security issue'}
${cwe ? `- **CWE**: ${cwe}\n` : ''}
### Please explain:
1. **What is this vulnerability?** — Plain-English explanation.
2. **Why is it dangerous?** — Realistic attack scenario.
3. **Real-world examples** — Notable breaches caused by this type of issue.
4. **How to detect it** — Patterns developers should watch for.
5. **How to fix it** — Step-by-step remediation with code specific to this codebase.
6. **Prevention** — Linting rules, pre-commit hooks, CI checks to prevent recurrence.

Keep it practical and actionable.`;
}

// ── File review prompt ──────────────────────────────────────────────

function buildFileReviewPrompt(findings: any[], filePath: string, score: number): string {
    if (findings.length === 0) {
        return `You are a senior security code reviewer.

Review \`${filePath}\` for security vulnerabilities.

No findings from the automated scanner, but please check for:
- Hardcoded secrets, API keys, or tokens
- SQL / command / template injection
- Missing input validation and sanitization
- Insecure authentication or authorization
- PII / sensitive data being logged
- Missing error handling that could leak info
- Insecure cryptographic practices
- Race conditions or TOCTOU issues

Rate security quality (1-10) and provide specific recommendations.`;
    }

    const issuesList = findings.slice(0, 20).map((f, i) => {
        const sev = (f.severity ?? 'medium').toUpperCase();
        return `  ${i + 1}. ${sevIcon(f.severity)} **[${sev}]** Line ${f.location?.line ?? '?'}: ${f.type} — ${(f.summary ?? '').slice(0, 150)} *(${f.id})*`;
    }).join('\n');

    return `You are a senior security code reviewer. Workspace score: **${score}/100**.

Review \`${filePath}\` — scanner found **${findings.length} issue(s)**:

${issuesList}

### Your Review:
1. **Validate each finding** — true positive or false positive?
2. **Provide exact fixes** — complete corrected code blocks.
3. **Find missed issues** — vulnerabilities the scanner may have missed.
4. **Rate the file** — security quality (1-10) with justification.
5. **Suggest hardening** — architectural / defensive improvements.

Be precise — exact line numbers, corrected code blocks.`;
}

// ── Fix-all-critical prompt ─────────────────────────────────────────

function buildFixAllCriticalPrompt(report: any): string {
    const findings: any[] = report.findings ?? [];
    const critical = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    const score = report.overall_score ?? 0;

    if (critical.length === 0) {
        return 'No critical or high severity findings. The codebase looks good! 🎉';
    }

    const byFile: Record<string, any[]> = {};
    for (const f of critical.slice(0, 30)) {
        const fp = f.location?.path ?? 'unknown';
        if (!byFile[fp]) { byFile[fp] = []; }
        byFile[fp].push(f);
    }

    const fileBlocks = Object.entries(byFile).map(([fp, ff]) => {
        const items = ff.map(f =>
            `    - ${sevIcon(f.severity)} **[${(f.severity).toUpperCase()}]** Line ${f.location?.line ?? '?'}: ${f.type} — ${(f.summary ?? '').slice(0, 100)} *(${f.id})*`
        ).join('\n');
        return `  **\`${fp}\`** (${ff.length} issues):\n${items}`;
    }).join('\n\n');

    return `You are a security remediation specialist. Current score: **${score}/100**.

**${critical.length} critical/high** findings must be fixed before deployment.

### Findings by File:

${fileBlocks}

### Instructions:
For EACH file:
1. Read the file and understand context.
2. Show the **complete corrected code** for each vulnerable block.
3. One-sentence explanation per fix.
4. Verify fixes don't break functionality.

Start with the most severe first. After all fixes, estimate the new score.
**Goal: ${score}/100 → 80+/100 (PRODUCTION READY).**`;
}

// ── Enhanced user prompt ────────────────────────────────────────────

function buildEnhancedPrompt(report: any, userPrompt: string, filePath?: string): string {
    const ctx = buildSecurityContext(report);

    let fileSection = '';
    if (filePath) {
        const ff = buildFileFindings(report, filePath);
        if (ff.length > 0) {
            const items = ff.slice(0, 10).map(f =>
                `  - ${sevIcon(f.severity)} **[${(f.severity ?? 'medium').toUpperCase()}]** Line ${f.location?.line ?? '?'}: ${f.type} — ${(f.summary ?? '').slice(0, 120)} *(${f.id})*`
            ).join('\n');
            fileSection = `\n\n### ⚠️ Known Issues in \`${filePath}\`:\n${items}`;
        }
    }

    return `${ctx}${fileSection}

---

## 💬 User Request:
${userPrompt}

---

**IMPORTANT** — when responding you MUST:
1. Consider the security findings above — warn if the request touches vulnerable code.
2. Never introduce patterns that would lower the security score.
3. Reference finding IDs (e.g. \`secrets:0\`) when relevant.
4. If suggesting code changes, ensure they address or don't worsen listed issues.
5. Suggest the most secure implementation approach.`;
}

// =====================================================================
// COPILOT CHAT HELPER
// =====================================================================

async function openCopilotChat(prompt: string): Promise<void> {
    try {
        await vscode.commands.executeCommand('workbench.action.chat.open', { query: prompt });
    } catch {
        try {
            await vscode.commands.executeCommand('workbench.action.chat.open');
            await vscode.env.clipboard.writeText(prompt);
            vscode.window.showInformationMessage(
                'Ybe Check: Prompt copied to clipboard — paste into Copilot Chat (Cmd+V).',
            );
        } catch {
            await vscode.env.clipboard.writeText(prompt);
            vscode.window.showInformationMessage(
                'Ybe Check: Prompt copied to clipboard — open Copilot Chat and paste (Cmd+V).',
            );
        }
    }
}

// =====================================================================
// FINDING PICKER — reusable QuickPick for selecting a finding
// =====================================================================

interface FindingItem extends vscode.QuickPickItem { finding: any }

async function pickFinding(
    report: any,
    opts?: { severity?: string; file?: string; title?: string },
): Promise<any | null> {
    let findings: any[] = report.findings ?? [];
    if (opts?.severity) { findings = findings.filter(f => f.severity === opts.severity); }
    if (opts?.file) { findings = findings.filter(f => (f.location?.path ?? '').includes(opts.file!)); }

    findings = findings
        .sort((a, b) => sevWeight(b.severity ?? 'medium') - sevWeight(a.severity ?? 'medium'))
        .slice(0, 50);

    if (findings.length === 0) {
        vscode.window.showInformationMessage('No matching findings.');
        return null;
    }

    const items: FindingItem[] = findings.map(f => ({
        label: `${sevIcon(f.severity)} [${(f.severity ?? 'medium').toUpperCase()}] ${f.type ?? 'issue'}`,
        description: `${f.location?.path ?? '?'}:${f.location?.line ?? '?'}`,
        detail: `${f.id} — ${(f.summary ?? '').slice(0, 140)}`,
        finding: f,
    }));

    const picked = await vscode.window.showQuickPick(items, {
        placeHolder: opts?.title ?? 'Select a finding',
        matchOnDescription: true,
        matchOnDetail: true,
    });
    return picked?.finding ?? null;
}

// =====================================================================
// ACTIVATE
// =====================================================================

export function activate(context: vscode.ExtensionContext) {

    // ── Auto-install MCP package & write config files ───────────────
    ensureMcpSetup(context);

    // ── Status bar ──────────────────────────────────────────────────
    initializeStatusBar(context);

    // ── Scan commands ───────────────────────────────────────────────
    context.subscriptions.push(
        // Static-only mode for now: route Full Scan to static execution.
        vscode.commands.registerCommand('ybe-check.fullScan', () => executeScan('static', context)),
        vscode.commands.registerCommand('ybe-check.staticScan', () => executeScan('static', context)),
    );

    // =================================================================
    // COPILOT INTEGRATION COMMANDS
    // =================================================================

    // 1 ── Ask Copilot (with security context injected) ──────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('ybe-check.askCopilot', async () => {
            const report = requireReport(); if (!report) { return; }
            const editor = vscode.window.activeTextEditor;
            const curFile = editor ? vscode.workspace.asRelativePath(editor.document.uri) : undefined;

            const userPrompt = await vscode.window.showInputBox({
                prompt: 'What would you like to ask? (security context injected automatically)',
                placeHolder: 'e.g. "How do I secure the auth flow?" or "Review app.py"',
            });
            if (!userPrompt) { return; }
            await openCopilotChat(buildEnhancedPrompt(report, userPrompt, curFile));
        }),
    );

    // 2 ── Fix a specific finding ────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('ybe-check.fixWithCopilot', async (findingArg?: any) => {
            const report = requireReport(); if (!report) { return; }
            let finding = findingArg;
            if (!finding || !finding.id) {
                finding = await pickFinding(report, { title: 'Select a finding to fix with Copilot' });
            }
            if (!finding) { return; }
            await openCopilotChat(buildFixPrompt(finding));
        }),
    );

    // 3 ── Full security audit ───────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('ybe-check.securityAudit', async () => {
            const report = requireReport(); if (!report) { return; }
            const ctx = buildSecurityContext(report);
            await openCopilotChat(`${ctx}

---

You are a senior security engineer performing a **production-readiness audit**.

Provide:
1. 🔴 **Critical Issues** — all critical/high findings, grouped by file.
2. ⚡ **Quick Wins** — easy fixes (< 5 min each) that significantly improve the score.
3. 🏗️ **Architecture Concerns** — structural security problems.
4. 📋 **Compliance Gaps** — missing controls for production (HTTPS, CSP, rate limiting, CORS, etc.).
5. 📊 **Prioritized Action Plan** — ordered by max score improvement.
6. 🎯 **Estimated Score After Fixes** — prediction if all fixes are applied.

Reference finding IDs. Be specific with file names and line numbers.
**Goal: reach PRODUCTION READY (80+/100).**`);
        }),
    );

    // 4 ── Explain a finding (educational) ───────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('ybe-check.explainFinding', async (findingArg?: any) => {
            const report = requireReport(); if (!report) { return; }
            let finding = findingArg;
            if (!finding || !finding.id) {
                finding = await pickFinding(report, { title: 'Select a finding to explain' });
            }
            if (!finding) { return; }
            await openCopilotChat(buildExplainPrompt(finding));
        }),
    );

    // 5 ── Review the currently open file ────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('ybe-check.reviewFile', async () => {
            const report = requireReport(); if (!report) { return; }
            const editor = vscode.window.activeTextEditor;
            if (!editor) { vscode.window.showWarningMessage('Open a file first.'); return; }
            const fp = vscode.workspace.asRelativePath(editor.document.uri);
            const ff = buildFileFindings(report, fp);
            await openCopilotChat(buildFileReviewPrompt(ff, fp, report.overall_score ?? 0));
        }),
    );

    // 6 ── Fix ALL critical / high findings ──────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('ybe-check.fixAllCritical', async () => {
            const report = requireReport(); if (!report) { return; }
            await openCopilotChat(buildFixAllCriticalPrompt(report));
        }),
    );

    // 7 ── Fix every finding in the current file ─────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('ybe-check.fixCurrentFile', async () => {
            const report = requireReport(); if (!report) { return; }
            const editor = vscode.window.activeTextEditor;
            if (!editor) { vscode.window.showWarningMessage('Open a file first.'); return; }

            const fp = vscode.workspace.asRelativePath(editor.document.uri);
            const ff = buildFileFindings(report, fp);
            if (ff.length === 0) {
                vscode.window.showInformationMessage(`No findings in ${fp}. Looking good! 🎉`);
                return;
            }

            const items = ff.slice(0, 15).map((f, i) => {
                const sev = (f.severity ?? 'medium').toUpperCase();
                return `${i + 1}. ${sevIcon(f.severity)} **[${sev}]** Line ${f.location?.line ?? '?'}: ${f.type} — ${(f.summary ?? '').slice(0, 120)} *(${f.id})*`;
            }).join('\n');

            await openCopilotChat(`You are a security engineer. Fix ALL **${ff.length}** issues in \`${fp}\`.

### Issues:
${items}

### Instructions:
1. Read \`${fp}\`.
2. For EACH issue show the vulnerable code and the fixed version.
3. Consolidate fixes when multiple issues are in the same function.
4. Ensure fixes don't break existing functionality.
5. Check for additional issues the scanner may have missed.

Show complete corrected code blocks — not just diffs.`);
        }),
    );

    // 8 ── Secure implementation helper ──────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('ybe-check.secureImplementation', async () => {
            const report = loadReport(); // optional — works even without a report
            const userPrompt = await vscode.window.showInputBox({
                prompt: 'What feature do you want to implement securely?',
                placeHolder: 'e.g. "JWT authentication" or "file upload endpoint"',
            });
            if (!userPrompt) { return; }

            let ctx = '';
            if (report) { ctx = buildSecurityContext(report) + '\n\n---\n\n'; }

            await openCopilotChat(`${ctx}You are a senior security engineer and full-stack developer.

## Request
Implement: **${userPrompt}**

## Security Requirements
1. **Input Validation** — validate and sanitize ALL inputs; allowlists > denylists.
2. **Auth** — proper middleware; never trust client-side checks.
3. **Secrets** — environment variables only; never hardcoded.
4. **Error Handling** — don't leak stack traces; log securely.
5. **Data Protection** — bcrypt/argon2 for passwords; encrypt at rest and in transit.
6. **Injection Prevention** — parameterized queries, auto-escaping templates, subprocess arrays.
7. **Rate Limiting & CORS** — implement both.
8. **Dependencies** — pinned versions, no known CVEs.

${report ? `Current score: **${report.overall_score ?? 0}/100**. The implementation must NOT lower this.\n` : ''}
Provide:
1. Complete, production-ready code with inline security comments.
2. List of required environment variables.
3. Required dependencies.
4. Security considerations and potential attack vectors.`);
        }),
    );

    // 9 ── Browse findings by severity ───────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('ybe-check.browseBySeverity', async () => {
            const report = requireReport(); if (!report) { return; }
            const findings: any[] = report.findings ?? [];

            const sevCounts: Record<string, number> = {};
            for (const f of findings) { sevCounts[f.severity ?? 'medium'] = (sevCounts[f.severity ?? 'medium'] || 0) + 1; }

            const sevItems = Object.entries(sevCounts)
                .sort((a, b) => sevWeight(b[0]) - sevWeight(a[0]))
                .map(([sev, count]) => ({
                    label: `${sevIcon(sev)} ${sev.toUpperCase()} (${count} findings)`,
                    severity: sev,
                }));

            const picked = await vscode.window.showQuickPick(sevItems, {
                placeHolder: 'Filter by severity, then choose an action',
            });
            if (!picked) { return; }

            const action = await vscode.window.showQuickPick(
                [
                    { label: '$(tools) Fix a specific finding', value: 'fix' },
                    { label: '$(info) Explain a finding', value: 'explain' },
                    { label: '$(checklist) Fix ALL of this severity', value: 'fixAll' },
                ],
                { placeHolder: `What do you want to do with ${picked.severity.toUpperCase()} findings?` },
            );
            if (!action) { return; }

            if (action.value === 'fixAll') {
                const filtered = findings
                    .filter(f => f.severity === picked.severity)
                    .slice(0, 25);
                const items = filtered.map((f, i) => {
                    const loc = f.location ?? {};
                    return `${i + 1}. ${sevIcon(f.severity)} \`${loc.path ?? '?'}:${loc.line ?? '?'}\` — ${f.type}: ${(f.summary ?? '').slice(0, 100)} *(${f.id})*`;
                }).join('\n');

                await openCopilotChat(`You are a security remediation specialist. Fix ALL **${picked.severity.toUpperCase()}** findings.

### Findings (${filtered.length}):
${items}

For EACH:
1. Show the vulnerable code.
2. Provide the complete fix.
3. One-sentence explanation.

Group by file when possible.`);
            } else {
                const finding = await pickFinding(report, {
                    severity: picked.severity,
                    title: `Select a ${picked.severity.toUpperCase()} finding to ${action.value}`,
                });
                if (!finding) { return; }
                await openCopilotChat(
                    action.value === 'explain'
                        ? buildExplainPrompt(finding)
                        : buildFixPrompt(finding),
                );
            }
        }),
    );

    // 10 ── (Re)install MCP package manually ─────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('ybe-check.installMcp', async () => {
            const py = getPythonPath();
            const ok = await installMcpPackage(py);
            if (ok) {
                const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
                if (root) {
                    const d = path.join(root, '.vscode');
                    writeMcpFile(d, path.join(d, 'mcp.json'), py);
                }
                vscode.window.showInformationMessage('Ybe Check: MCP installed!', 'Reload')
                    .then(a => { if (a === 'Reload') { vscode.commands.executeCommand('workbench.action.reloadWindow'); } });
            }
        }),
    );

    // ── Utility commands (webview, open-file, terminal) ─────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('ybe-check.openFileAtLine',
            async (filePathArg: string, lineArg?: number, rootArg?: string) => {
                const root = rootArg || vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
                if (!root || !filePathArg) { return; }
                const uri = vscode.Uri.file(resolveFilePath(filePathArg, root));
                try {
                    const doc = await vscode.workspace.openTextDocument(uri);
                    const ed = await vscode.window.showTextDocument(doc);
                    const ln = typeof lineArg === 'number' && lineArg >= 1 ? lineArg - 1 : 0;
                    const pos = new vscode.Position(ln, 0);
                    ed.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
                    ed.selection = new vscode.Selection(pos, pos);
                } catch { vscode.window.showWarningMessage(`Could not open: ${filePathArg}`); }
            },
        ),
        vscode.commands.registerCommand('ybe-check.runTerminalCommand',
            async (cmd: string, cwd: string) => {
                const t = vscode.window.createTerminal({
                    name: 'Ybe Check',
                    cwd: cwd || vscode.workspace.workspaceFolders?.[0]?.uri.fsPath,
                });
                t.show();
                t.sendText(cmd);
            },
        ),
        vscode.commands.registerCommand('ybe-check.openDashboard', async () => {
            const wsRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
            const pyPath = getPythonPath();
            const t = vscode.window.createTerminal({
                name: 'Ybe Dashboard',
                cwd: wsRoot,
            });
            t.show();
            t.sendText(`${pyPath} -m ybe_check.dashboard`);
            vscode.window.showInformationMessage('Dashboard starting at http://127.0.0.1:7474');
            // Open in browser after a short delay
            setTimeout(() => {
                vscode.env.openExternal(vscode.Uri.parse('http://127.0.0.1:7474'));
            }, 3000);
        }),
    );
}

// =====================================================================
// DEACTIVATE
// =====================================================================

export function deactivate() {
    disposeStatusBar();
}
