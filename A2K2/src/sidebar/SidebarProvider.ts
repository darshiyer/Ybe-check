/**
 * SidebarProvider.ts
 * Implements the Ybe Check sidebar WebviewViewProvider.
 * Handles: scan execution, auto-scan on save, prompt building, Copilot integration.
 */

import * as vscode from 'vscode';
import * as path   from 'path';
import * as crypto from 'crypto';
import { exec }    from 'child_process';
import { promisify } from 'util';

import { getSidebarHtml, SidebarData, ModuleResult } from './sidebarTemplate';
import { buildAiPrompt, buildModulePrompt, Finding }  from './promptBuilder';

const execAsync = promisify(exec);

function getNonce(): string {
    return crypto.randomBytes(16).toString('hex');
}

function getPythonPath(): string {
    return vscode.workspace.getConfiguration('ybe-check').get<string>('pythonPath', 'python3');
}

function getCLIPath(context: vscode.ExtensionContext): string {
    // Try to find cli.py relative to the extension root
    return path.join(context.extensionPath, 'cli.py');
}

function getWorkspaceRoot(): string | undefined {
    return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

export class SidebarProvider implements vscode.WebviewViewProvider {

    public static readonly viewType = 'ybeCheck.sidebar';

    private _view?: vscode.WebviewView;
    private _context: vscode.ExtensionContext;
    private _data: SidebarData = { state: 'idle', autoScan: false };
    private _autoScanDisposable?: vscode.Disposable;
    private _scanning = false;

    constructor(context: vscode.ExtensionContext) {
        this._context = context;
        // Restore auto-scan preference
        this._data.autoScan = context.globalState.get('ybeAutoScan', false);
        if (this._data.autoScan) {
            this._enableAutoScan();
        }
    }

    resolveWebviewView(
        webviewView: vscode.WebviewView,
        _context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ): void {
        this._view = webviewView;

        webviewView.webview.options = {
            enableScripts: true,
        };

        this._render();

        // Handle messages from the webview HTML
        webviewView.webview.onDidReceiveMessage(msg => {
            switch (msg.type) {

                case 'runScan':
                    this.runScan();
                    break;

                case 'toggleAutoScan':
                    this._setAutoScan(msg.value);
                    break;

                case 'copyPrompt':
                    this._handleCopyPrompt(msg.modName, msg.findingIdx, msg.findings);
                    break;

                case 'openCopilot':
                    this._handleOpenCopilot(msg.modName, msg.findingIdx, msg.findings);
                    break;

                case 'copyModulePrompt':
                    this._handleCopyModulePrompt(msg.modName, msg.findings);
                    break;

                case 'exportReport':
                    this._exportReport();
                    break;
            }
        }, undefined, this._context.subscriptions);
    }

    /** Public: trigger a scan from outside (e.g. command palette). */
    public async runScan(): Promise<void> {
        if (this._scanning) { return; }

        const root = getWorkspaceRoot();
        if (!root) {
            vscode.window.showWarningMessage('Ybe Check: Open a folder first to run a scan.');
            return;
        }

        this._scanning = true;
        this._data = { ...this._data, state: 'scanning', scanningModule: 'Initialising…' };
        this._render();

        const python = getPythonPath();
        const cli    = getCLIPath(this._context);

        try {
            // Run the static scan — captures stdout as JSON
            const { stdout, stderr } = await execAsync(
                `"${python}" "${cli}" "${root}" --static --json`,
                { maxBuffer: 10 * 1024 * 1024, cwd: root }
            );

            let report: any;
            try {
                report = JSON.parse(stdout);
            } catch {
                // If stdout has prefix warnings, try to extract JSON block
                const jsonStart = stdout.indexOf('{');
                if (jsonStart !== -1) {
                    report = JSON.parse(stdout.slice(jsonStart));
                } else {
                    throw new Error(stderr || 'Unexpected output from scanner.');
                }
            }

            this._data = {
                state:         'done',
                overall_score: report.overall_score,
                verdict:       report.verdict,
                modules:       (report.modules || []) as ModuleResult[],
                scanned_at:    report.scanned_at || new Date().toISOString(),
                autoScan:      this._data.autoScan,
            };

        } catch (err: any) {
            this._data = {
                ...this._data,
                state:  'error',
                error:  err?.message || String(err),
            };
        } finally {
            this._scanning = false;
            this._render();
        }
    }

    // ── Private: render ──────────────────────────────────────────────

    private _render(): void {
        if (!this._view) { return; }
        const nonce = getNonce();
        this._view.webview.html = getSidebarHtml(this._data, nonce);
    }

    // ── Private: auto-scan ───────────────────────────────────────────

    private _setAutoScan(on: boolean): void {
        this._data.autoScan = on;
        this._context.globalState.update('ybeAutoScan', on);
        if (on) {
            this._enableAutoScan();
        } else {
            this._disableAutoScan();
        }
    }

    private _enableAutoScan(): void {
        if (this._autoScanDisposable) { return; } // already active
        this._autoScanDisposable = vscode.workspace.onDidSaveTextDocument(doc => {
            // Only trigger for source files — skip settings, JSON, markdown
            const ignored = ['.json', '.md', '.txt', '.log', '.yaml', '.yml', '.toml'];
            const ext = path.extname(doc.fileName).toLowerCase();
            if (ignored.includes(ext)) { return; }
            // Debounce: wait 1.5s after last save
            clearTimeout((this as any)._autoScanTimer);
            (this as any)._autoScanTimer = setTimeout(() => this.runScan(), 1500);
        });
        this._context.subscriptions.push(this._autoScanDisposable);
    }

    private _disableAutoScan(): void {
        this._autoScanDisposable?.dispose();
        this._autoScanDisposable = undefined;
    }

    // ── Private: prompt handlers ─────────────────────────────────────

    private _handleCopyPrompt(modName: string, findingIdx: number, findings: Finding[]): void {
        const root    = getWorkspaceRoot() || '.';
        const finding = findings[findingIdx];
        if (!finding) { return; }

        const prompt = buildAiPrompt(finding, modName, root);
        vscode.env.clipboard.writeText(prompt).then(() => {
            // Confirm in panel
            this._view?.webview.postMessage({ type: 'toast', text: '✓ AI prompt copied!', style: 'success' });
        });
    }

    private async _handleOpenCopilot(modName: string, findingIdx: number, findings: Finding[]): Promise<void> {
        const root    = getWorkspaceRoot() || '.';
        const finding = findings[findingIdx];
        if (!finding) { return; }

        const prompt = buildAiPrompt(finding, modName, root);

        // 1. Copy to clipboard so user always has it
        await vscode.env.clipboard.writeText(prompt);

        // 2. Try to open GitHub Copilot Chat with the prompt
        try {
            // The Copilot Chat API: open chat with pre-filled message
            await vscode.commands.executeCommand(
                'workbench.panel.chat.view.copilot.focus'
            );
            // Small delay to let the panel open
            await new Promise(r => setTimeout(r, 400));
            await vscode.commands.executeCommand(
                'workbench.action.chat.open',
                { query: prompt }
            );
        } catch {
            // Copilot not installed — fall back to clipboard + info
            vscode.window.showInformationMessage(
                'Prompt copied to clipboard. Paste it into your AI assistant.',
                'Open Chat'
            ).then(sel => {
                if (sel === 'Open Chat') {
                    // Try generic chat commands as fallback
                    vscode.commands.executeCommand('workbench.action.openChat')
                        .then(undefined, () => {
                            vscode.window.showInformationMessage(
                                'Prompt is in your clipboard — paste it into Copilot, Cursor, or Claude.'
                            );
                        });
                }
            });
        }
    }

    private _handleCopyModulePrompt(modName: string, findings: Finding[]): void {
        const root = getWorkspaceRoot() || '.';
        const mod  = this._data.modules?.find(m => m.name === modName);
        const prompt = buildModulePrompt(modName, findings, mod?.score ?? null, root);
        vscode.env.clipboard.writeText(prompt).then(() => {
            this._view?.webview.postMessage({
                type:  'toast',
                text:  `✓ All ${modName} issues copied`,
                style: 'success'
            });
        });
    }

    // ── Private: export ──────────────────────────────────────────────

    private async _exportReport(): Promise<void> {
        if (this._data.state !== 'done') {
            vscode.window.showWarningMessage('Run a scan first before exporting.');
            return;
        }
        const uri = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.file(
                path.join(getWorkspaceRoot() || '.', 'ybe-check-report.json')
            ),
            filters: { 'JSON': ['json'] },
        });
        if (!uri) { return; }
        const content = JSON.stringify(this._data, null, 2);
        await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf-8'));
        vscode.window.showInformationMessage(`Report saved to ${uri.fsPath}`);
    }
}
