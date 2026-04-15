/**
 * SidebarProvider.ts
 * Security feed sidebar — streaming scan, changed-files mode, path targeting.
 */

import * as vscode from 'vscode';
import * as path   from 'path';
import * as crypto from 'crypto';
import { spawn } from 'child_process';

import { SecurityStore, StoreData, FindingStatus } from './store';
import { getSidebarHtml, ModuleProgress }          from './sidebarTemplate';
import { buildAiPrompt }                           from './promptBuilder';

function getNonce(): string {
    return crypto.randomBytes(16).toString('hex');
}

function getPythonPath(): string {
    return vscode.workspace.getConfiguration('ybe-check').get<string>('pythonPath', 'python3');
}

function getExcludePatterns(): string[] {
    return vscode.workspace.getConfiguration('ybe-check').get<string[]>('excludePatterns', []);
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
    private _scanProgress: ModuleProgress[] = [];
    private _scanScope = '';

    constructor(context: vscode.ExtensionContext) {
        this._context = context;
        this._autoScan = context.globalState.get('ybeAutoScan', false);

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
        webviewView.webview.options = { enableScripts: true };
        this._render();

        webviewView.webview.onDidReceiveMessage(msg => {
            switch (msg.type) {
                case 'runScan':        this.runScan(); break;
                case 'runChanged':     this.runChangedScan(); break;
                case 'toggleAutoScan': this._setAutoScan(msg.value); break;
                case 'setStatus':      this._handleSetStatus(msg.findingId, msg.status); break;
                case 'fixWithAgent':   this._handleFixWithAgent(msg.findingId); break;
                case 'exportReport':   this._exportReport(); break;
                case 'openFile':       this._openFileAtLine(msg.file, msg.line); break;
            }
        }, undefined, this._context.subscriptions);
    }

    private _watchStore(root: string): void {
        const pattern = new vscode.RelativePattern(root, '.ybe-check/store.json');
        this._fileWatcher = vscode.workspace.createFileSystemWatcher(pattern);
        const reload = () => { this._store?.reload(); this._render(); };
        this._fileWatcher.onDidChange(reload);
        this._fileWatcher.onDidCreate(reload);
        this._context.subscriptions.push(this._fileWatcher);
    }

    // ── Scan entry points ────────────────────────────────────────────

    /** Full repo scan. */
    public async runScan(): Promise<void> {
        await this._startScan({ scope: 'Full scan' });
    }

    /** Scan only git-changed/untracked files. */
    public async runChangedScan(): Promise<void> {
        const root = getWorkspaceRoot();
        if (!root) { vscode.window.showWarningMessage('Ybe Check: Open a folder first.'); return; }
        await this._startScan({ scope: 'Changed files', extraArgs: ['--changed'] });
    }

    /** Scan a specific file or folder (right-click). */
    public async runPathScan(fsPath: string): Promise<void> {
        const root = getWorkspaceRoot();
        if (!root) { vscode.window.showWarningMessage('Ybe Check: Open a folder first.'); return; }
        const rel = path.relative(root, fsPath);
        await this._startScan({
            scope: rel.length < 40 ? rel : '...' + rel.slice(-37),
            extraArgs: ['--paths', fsPath],
        });
    }

    // ── Core scan runner (streaming) ─────────────────────────────────

    private async _startScan(opts: { scope: string; extraArgs?: string[] }): Promise<void> {
        if (this._scanning) { return; }

        const root = getWorkspaceRoot();
        if (!root) { vscode.window.showWarningMessage('Ybe Check: Open a folder first.'); return; }

        this._scanning = true;
        this._scanProgress = [];
        this._scanScope = opts.scope;
        this._render();

        const python  = getPythonPath();
        const cli     = getCLIPath(this._context);
        const exclude = getExcludePatterns();

        const args = [cli, root, '--static', '--stream'];
        if (opts.extraArgs) { args.push(...opts.extraArgs); }
        if (exclude.length) { args.push('--exclude', ...exclude); }

        return new Promise<void>(resolve => {
            const proc = spawn(python, args, { cwd: root });
            let buf = '';

            proc.stdout.on('data', (chunk: Buffer) => {
                buf += chunk.toString();
                const lines = buf.split('\n');
                buf = lines.pop() ?? '';

                for (const line of lines) {
                    const trimmed = line.trim();
                    if (!trimmed) { continue; }
                    try {
                        const msg = JSON.parse(trimmed);
                        if (msg.event === 'module_progress') {
                            this._scanProgress.push({
                                module: msg.module,
                                score: msg.score,
                                issues: msg.issues,
                                status: msg.status,
                                done: true,
                            });
                            this._render();
                        } else if (msg.event === 'scan_complete') {
                            this._store?.reload();
                            this._scanning = false;
                            this._scanProgress = [];
                            this._render();
                        }
                    } catch { /* incomplete JSON line */ }
                }
            });

            proc.stderr.on('data', (chunk: Buffer) => {
                // Module warnings land here — not errors
                const txt = chunk.toString().trim();
                if (txt) { console.log('[ybe-check stderr]', txt); }
            });

            proc.on('close', () => {
                if (this._scanning) {
                    // Process ended without scan_complete (e.g. detect-secrets timeout)
                    this._store?.reload();
                    this._scanning = false;
                    this._scanProgress = [];
                    this._render();
                }
                resolve();
            });

            proc.on('error', (err) => {
                vscode.window.showErrorMessage(`Ybe Check: ${err.message}`);
                this._scanning = false;
                this._scanProgress = [];
                this._render();
                resolve();
            });
        });
    }

    // ── Render ───────────────────────────────────────────────────────

    private _render(): void {
        if (!this._view) { return; }
        const nonce = getNonce();
        this._view.webview.html = getSidebarHtml({
            store: this._store?.data ?? null,
            scanning: this._scanning,
            autoScan: this._autoScan,
            counts: this._store?.getCounts() ?? { open: 0, fixed: 0, ignored: 0, total: 0, new: 0 },
            scanProgress: this._scanProgress,
            scanScope: this._scanScope,
        }, nonce);
    }

    // ── Auto-scan ────────────────────────────────────────────────────

    private _setAutoScan(on: boolean): void {
        this._autoScan = on;
        this._context.globalState.update('ybeAutoScan', on);
        if (on) { this._enableAutoScan(); } else { this._disableAutoScan(); }
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

    // ── Finding actions ──────────────────────────────────────────────

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

        // Write to fix-queue for MCP pickup
        const wsRoot = getWorkspaceRoot();
        if (wsRoot) {
            const fs = await import('fs');
            const queuePath = path.join(wsRoot, '.ybe-check', 'fix-queue.json');
            const queueDir  = path.join(wsRoot, '.ybe-check');
            if (!fs.existsSync(queueDir)) { fs.mkdirSync(queueDir, { recursive: true }); }
            fs.writeFileSync(queuePath, JSON.stringify({
                timestamp: new Date().toISOString(),
                findingId: finding.id,
                module: finding.module,
                type: finding.type,
                severity: finding.severity,
                file: finding.file,
                line: finding.line,
                reason: finding.reason,
                prompt,
            }, null, 2), 'utf-8');
        }

        // Try Claude Code → Copilot → clipboard
        try {
            await vscode.commands.executeCommand('claude-vscode.editor.open', undefined, prompt);
            this._view?.webview.postMessage({ type: 'toast', text: 'Sent to Claude', style: 'ok' });
            return;
        } catch { /* not available */ }

        try {
            await vscode.commands.executeCommand('workbench.action.chat.open', { query: prompt });
            this._view?.webview.postMessage({ type: 'toast', text: 'Sent to Copilot', style: 'ok' });
            return;
        } catch { /* not available */ }

        await vscode.env.clipboard.writeText(prompt);
        try { await vscode.commands.executeCommand('claude-vscode.sidebar.open'); } catch {}
        this._view?.webview.postMessage({ type: 'toast', text: 'Prompt copied — Cmd+V', style: 'ok' });
    }

    private async _openFileAtLine(file: string, line: number): Promise<void> {
        const root = getWorkspaceRoot();
        if (!root || !file) { return; }
        const abs = path.isAbsolute(file) ? file : path.join(root, file);
        try {
            const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(abs));
            const ed  = await vscode.window.showTextDocument(doc, { preview: true });
            const ln  = typeof line === 'number' && line >= 1 ? line - 1 : 0;
            const pos = new vscode.Position(ln, 0);
            ed.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
            ed.selection = new vscode.Selection(pos, pos);
        } catch { /* file may have moved */ }
    }

    private _handleSetStatus(findingId: string, status: FindingStatus): void {
        if (!this._store) { return; }
        this._store.setFindingStatus(findingId, status);
        this._render();
        this._view?.webview.postMessage({
            type: 'toast',
            text: status === 'fixed' ? 'Marked as fixed' : 'Ignored',
            style: 'ok',
        });
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
