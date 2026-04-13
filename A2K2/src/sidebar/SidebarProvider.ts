/**
 * SidebarProvider.ts
 * Security feed sidebar — watches .ybe-check/store.json and renders findings.
 * The agent feeds it via MCP/CLI, the sidebar displays it.
 */

import * as vscode from 'vscode';
import * as path   from 'path';
import * as crypto from 'crypto';
import { exec }    from 'child_process';
import { promisify } from 'util';

import { SecurityStore, StoreData, FindingStatus } from './store';
import { getSidebarHtml } from './sidebarTemplate';
import { buildAiPrompt, buildModulePrompt, Finding }  from './promptBuilder';

const execAsync = promisify(exec);

function getNonce(): string {
    return crypto.randomBytes(16).toString('hex');
}

function getPythonPath(): string {
    return vscode.workspace.getConfiguration('ybe-check').get<string>('pythonPath', 'python3');
}

function getCLIPath(context: vscode.ExtensionContext): string {
    return path.join(context.extensionPath, 'cli.py');
}

function getWorkspaceRoot(): string | undefined {
    return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

export class SidebarProvider implements vscode.WebviewViewProvider {

    public static readonly viewType = 'ybeCheck.sidebar';

    private _view?: vscode.WebviewView;
    private _context: vscode.ExtensionContext;
    private _store?: SecurityStore;
    private _fileWatcher?: vscode.FileSystemWatcher;
    private _autoScanDisposable?: vscode.Disposable;
    private _scanning = false;
    private _autoScan = false;

    constructor(context: vscode.ExtensionContext) {
        this._context = context;
        this._autoScan = context.globalState.get('ybeAutoScan', false);

        // Initialize store if workspace is open
        const root = getWorkspaceRoot();
        if (root) {
            this._store = new SecurityStore(root);
            this._watchStore(root);
        }

        if (this._autoScan) {
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

        webviewView.webview.onDidReceiveMessage(msg => {
            switch (msg.type) {

                case 'runScan':
                    this.runScan();
                    break;

                case 'toggleAutoScan':
                    this._setAutoScan(msg.value);
                    break;

                case 'setStatus':
                    this._handleSetStatus(msg.findingId, msg.status);
                    break;

                case 'copyPrompt':
                    this._handleCopyPrompt(msg.findingId);
                    break;

                case 'openCopilot':
                    this._handleOpenCopilot(msg.findingId);
                    break;

                case 'fixWithAgent':
                    this._handleFixWithAgent(msg.findingId);
                    break;

                case 'exportReport':
                    this._exportReport();
                    break;

                case 'setFilter':
                    // Filter is handled in the webview JS, just re-render isn't needed
                    break;
            }
        }, undefined, this._context.subscriptions);
    }

    /** Watch the store file for changes (e.g. from MCP or CLI). */
    private _watchStore(root: string): void {
        const pattern = new vscode.RelativePattern(root, '.ybe-check/store.json');
        this._fileWatcher = vscode.workspace.createFileSystemWatcher(pattern);

        const reload = () => {
            this._store?.reload();
            this._render();
        };

        this._fileWatcher.onDidChange(reload);
        this._fileWatcher.onDidCreate(reload);
        this._context.subscriptions.push(this._fileWatcher);
    }

    /** Trigger a scan from sidebar or command palette. */
    public async runScan(): Promise<void> {
        if (this._scanning) { return; }

        const root = getWorkspaceRoot();
        if (!root) {
            vscode.window.showWarningMessage('Ybe Check: Open a folder first.');
            return;
        }

        this._scanning = true;
        this._render();

        const python = getPythonPath();
        const cli    = getCLIPath(this._context);

        try {
            await execAsync(
                `"${python}" "${cli}" "${root}" --static --json`,
                { maxBuffer: 10 * 1024 * 1024, cwd: root }
            );
            // CLI writes to .ybe-check/store.json — file watcher will trigger re-render
            // But force a reload just in case
            this._store?.reload();
        } catch (err: any) {
            // Even on error, CLI may have written partial results
            this._store?.reload();
        } finally {
            this._scanning = false;
            this._render();
        }
    }

    // ── Render ──────────────────────────────────────────────────────

    private _render(): void {
        if (!this._view) { return; }
        const nonce = getNonce();
        const storeData = this._store?.data;
        this._view.webview.html = getSidebarHtml({
            store: storeData || null,
            scanning: this._scanning,
            autoScan: this._autoScan,
            counts: this._store?.getCounts() || { open: 0, fixed: 0, ignored: 0, total: 0, new: 0 },
        }, nonce);
    }

    // ── Auto-scan ───────────────────────────────────────────────────

    private _setAutoScan(on: boolean): void {
        this._autoScan = on;
        this._context.globalState.update('ybeAutoScan', on);
        if (on) { this._enableAutoScan(); }
        else { this._disableAutoScan(); }
    }

    private _enableAutoScan(): void {
        if (this._autoScanDisposable) { return; }
        this._autoScanDisposable = vscode.workspace.onDidSaveTextDocument(doc => {
            const ignored = ['.json', '.md', '.txt', '.log', '.yaml', '.yml', '.toml'];
            const ext = path.extname(doc.fileName).toLowerCase();
            if (ignored.includes(ext)) { return; }
            clearTimeout((this as any)._autoScanTimer);
            (this as any)._autoScanTimer = setTimeout(() => this.runScan(), 1500);
        });
        this._context.subscriptions.push(this._autoScanDisposable);
    }

    private _disableAutoScan(): void {
        this._autoScanDisposable?.dispose();
        this._autoScanDisposable = undefined;
    }

    // ── Finding actions ─────────────────────────────────────────────

    /**
     * Try to send the fix prompt directly to whichever AI agent is active.
     * Tries: Claude Code → Copilot Chat → generic VS Code chat → clipboard fallback.
     */
    private async _handleFixWithAgent(findingId: string): Promise<void> {
        const finding = this._store?.data.findings.find(f => f.id === findingId);
        if (!finding) { return; }
        const root = getWorkspaceRoot() || '.';

        const prompt = buildAiPrompt({
            severity: finding.severity,
            type: finding.type,
            file: finding.file,
            line: finding.line,
            reason: finding.reason,
            snippet: finding.snippet,
            remediation: finding.remediation,
            rule_id: finding.rule_id,
        }, finding.module, root);

        // Write fix request to queue file — MCP server picks it up
        const wsRoot = getWorkspaceRoot();
        if (wsRoot) {
            const fs = await import('fs');
            const queuePath = path.join(wsRoot, '.ybe-check', 'fix-queue.json');
            const queueDir = path.join(wsRoot, '.ybe-check');
            if (!fs.existsSync(queueDir)) { fs.mkdirSync(queueDir, { recursive: true }); }
            const request = {
                timestamp: new Date().toISOString(),
                findingId: finding.id,
                module: finding.module,
                type: finding.type,
                severity: finding.severity,
                file: finding.file,
                line: finding.line,
                reason: finding.reason,
                prompt: prompt,
            };
            fs.writeFileSync(queuePath, JSON.stringify(request, null, 2), 'utf-8');
        }

        // Send directly to Claude Code — it accepts initialPrompt as 2nd arg
        try {
            await vscode.commands.executeCommand('claude-vscode.editor.open', undefined, prompt);
            this._view?.webview.postMessage({ type: 'toast', text: 'Sent to Claude', style: 'ok' });
            return;
        } catch { /* Claude Code not available */ }

        // Try Copilot chat with query param
        try {
            await vscode.commands.executeCommand('workbench.action.chat.open', { query: prompt });
            this._view?.webview.postMessage({ type: 'toast', text: 'Sent to Copilot', style: 'ok' });
            return;
        } catch { /* Copilot not available */ }

        // Fallback: clipboard
        await vscode.env.clipboard.writeText(prompt);
        try { await vscode.commands.executeCommand('claude-vscode.sidebar.open'); } catch {}
        this._view?.webview.postMessage({ type: 'toast', text: 'Prompt copied — Cmd+V', style: 'ok' });
    }

    private _handleSetStatus(findingId: string, status: FindingStatus): void {
        if (!this._store) { return; }
        this._store.setFindingStatus(findingId, status);
        this._render();
        this._view?.webview.postMessage({
            type: 'toast',
            text: status === 'fixed' ? 'Marked as fixed' : status === 'ignored' ? 'Ignored' : 'Reopened',
            style: 'success'
        });
    }

    private _handleCopyPrompt(findingId: string): void {
        const finding = this._store?.data.findings.find(f => f.id === findingId);
        if (!finding) { return; }
        const root = getWorkspaceRoot() || '.';

        const prompt = buildAiPrompt({
            severity: finding.severity,
            type: finding.type,
            file: finding.file,
            line: finding.line,
            reason: finding.reason,
            snippet: finding.snippet,
            remediation: finding.remediation,
            rule_id: finding.rule_id,
        }, finding.module, root);

        vscode.env.clipboard.writeText(prompt).then(() => {
            this._view?.webview.postMessage({ type: 'toast', text: 'Prompt copied', style: 'success' });
        });
    }

    private async _handleOpenCopilot(findingId: string): Promise<void> {
        const finding = this._store?.data.findings.find(f => f.id === findingId);
        if (!finding) { return; }
        const root = getWorkspaceRoot() || '.';

        const prompt = buildAiPrompt({
            severity: finding.severity,
            type: finding.type,
            file: finding.file,
            line: finding.line,
            reason: finding.reason,
            snippet: finding.snippet,
            remediation: finding.remediation,
            rule_id: finding.rule_id,
        }, finding.module, root);

        await vscode.env.clipboard.writeText(prompt);

        try {
            await vscode.commands.executeCommand('workbench.panel.chat.view.copilot.focus');
            await new Promise(r => setTimeout(r, 400));
            await vscode.commands.executeCommand('workbench.action.chat.open', { query: prompt });
        } catch {
            vscode.window.showInformationMessage(
                'Prompt copied. Paste it into your AI assistant.',
                'Open Chat'
            ).then(sel => {
                if (sel === 'Open Chat') {
                    vscode.commands.executeCommand('workbench.action.openChat').then(undefined, () => {});
                }
            });
        }
    }

    // ── Export ───────────────────────────────────────────────────────

    private async _exportReport(): Promise<void> {
        if (!this._store?.data.lastScan) {
            vscode.window.showWarningMessage('No scan data to export.');
            return;
        }
        const uri = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.file(
                path.join(getWorkspaceRoot() || '.', 'ybe-check-report.json')
            ),
            filters: { 'JSON': ['json'] },
        });
        if (!uri) { return; }
        const content = JSON.stringify(this._store.data, null, 2);
        await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf-8'));
        vscode.window.showInformationMessage(`Report saved to ${uri.fsPath}`);
    }
}
