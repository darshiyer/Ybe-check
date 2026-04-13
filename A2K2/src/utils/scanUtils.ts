/**
 * © 2025 ArpitStack. Distributed under Apache-2.0 License.
 * See http://www.apache.org/licenses/LICENSE-2.0 for details.
 */

import * as vscode from 'vscode';
import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
import { logMessage, createSeparatorLogLine } from './loggingUtils';
import { setTargetPath } from './fileUtils';
import { updateStatusBarMessage } from './statusBarUtils';
import { showYbeCheckReport } from './webviewUtils';
import { exec } from 'child_process';
import { promisify } from 'util';

export type ScanType = 'full' | 'static';

const execAsync = promisify(exec);
let isScanning = false;

const MAX_BUFFER = 10 * 1024 * 1024; // 10 MB — detect-secrets can produce large output

function getPythonPath(): string {
    const config = vscode.workspace.getConfiguration('ybe-check');
    return config.get<string>('pythonPath', 'python3');
}

async function checkPythonAvailable(pythonPath: string): Promise<boolean> {
    try {
        await execAsync(`"${pythonPath}" --version`);
        return true;
    } catch {
        return false;
    }
}

type RuntimeMode = 'module' | 'script';

interface ScanRuntime {
    mode: RuntimeMode;
    scriptPath: string;
}

async function detectScanRuntime(pythonPath: string, context: vscode.ExtensionContext): Promise<ScanRuntime | null> {
    const scriptPath = path.join(context.extensionPath, 'cli.py');
    try {
        await execAsync(`"${pythonPath}" -c "import ybe_check.cli"`, { timeout: 15_000 });
        return { mode: 'module', scriptPath };
    } catch {
        if (fs.existsSync(scriptPath)) {
            return { mode: 'script', scriptPath };
        }
        return null;
    }
}

function parseJsonSafe(payload: string): any {
    try {
        return JSON.parse(payload);
    } catch {
        throw new Error('Ybe Check returned invalid JSON output.');
    }
}

export async function runEnvironmentHealthCheck(
    context: vscode.ExtensionContext,
    options?: { notifyOnSuccess?: boolean }
): Promise<boolean> {
    const pythonPath = getPythonPath();
    const hasPython = await checkPythonAvailable(pythonPath);
    if (!hasPython) {
        vscode.window.showWarningMessage(
            'Ybe Check: Python 3 is not available. Set ybe-check.pythonPath or install Python.'
        );
        return false;
    }

    const runtime = await detectScanRuntime(pythonPath, context);
    if (!runtime) {
        vscode.window.showWarningMessage(
            'Ybe Check: scanner runtime not found. Please reinstall the extension.'
        );
        return false;
    }

    if (options?.notifyOnSuccess) {
        const mode = runtime.mode === 'module' ? 'python package' : 'bundled script fallback';
        vscode.window.showInformationMessage(`Ybe Check ready (${mode}).`);
    }
    return true;
}

/**
 * Executes a Ybe Check scan using `python3 -m ybe_check.cli scan`.
 * @param scanType - The type of scan to run: 'full' (Static + Dynamic) or 'static' (Static only).
 * @param context - The VS Code extension context.
 */
export async function executeScan(
    scanType: ScanType,
    context: vscode.ExtensionContext
) {
    if (isScanning) {
        vscode.window.showInformationMessage('Ybe Check already in progress. Please wait...');
        return;
    }

    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        vscode.window.showWarningMessage('No workspace is open. Please open a workspace first.');
        return;
    }

    const pythonPath = getPythonPath();
    const hasPython = await checkPythonAvailable(pythonPath);
    if (!hasPython) {
        vscode.window.showErrorMessage(
            'Ybe Check requires Python 3. Please install it from https://python.org and reload VS Code.'
        );
        return;
    }

    const runtime = await detectScanRuntime(pythonPath, context);
    if (!runtime) {
        vscode.window.showErrorMessage(
            'Ybe Check runtime is unavailable. Please reinstall the extension or check your Python installation.'
        );
        return;
    }

    const targetPath = workspaceFolders[0].uri.fsPath;
    setTargetPath(targetPath);

    isScanning = true;
    logMessage(createSeparatorLogLine('Ybe Check started'), 'info');

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Ybe Check",
        cancellable: false
    }, async (progress) => {
        const scanLabel = 'Static Scan';
        progress.report({ message: `Running ${scanLabel} (this may take a moment)...` });

        // Write report to a temp file so we get clean JSON (no log noise)
        const tmpReport = path.join(os.tmpdir(), `ybe-report-${Date.now()}.json`);

        try {
            let report: any;

            if (runtime.mode === 'module') {
                const cmd = [
                    `"${pythonPath}"`, '-m', 'ybe_check.cli', 'scan',
                    `"${targetPath}"`,
                    '--output', `"${tmpReport}"`,
                    '--categories', 'static',
                ].join(' ');
                await execAsync(cmd, { maxBuffer: MAX_BUFFER });
                report = parseJsonSafe(fs.readFileSync(tmpReport, 'utf8'));
            } else {
                const cmd = [
                    `"${pythonPath}"`, `"${runtime.scriptPath}"`, `"${targetPath}"`,
                    '--json', '--static',
                ].join(' ');
                const { stdout } = await execAsync(cmd, { maxBuffer: MAX_BUFFER });
                report = parseJsonSafe(stdout);
            }

            logMessage(createSeparatorLogLine(`Ybe Check ${scanLabel} completed: Score ${report.overall_score}/100`), 'info');

            const score = report.overall_score != null ? report.overall_score : 0;
            updateStatusBarMessage(`$(shield) Ybe Check: ${score}/100`);

            showYbeCheckReport(report, context, targetPath);

        } catch (error) {
            logMessage(`Error during Ybe Check: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error');
            vscode.window.showErrorMessage(`Ybe Check failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        } finally {
            // Clean up temp file
            try { fs.unlinkSync(tmpReport); } catch { /* ignore */ }
            isScanning = false;
        }
    });
}
