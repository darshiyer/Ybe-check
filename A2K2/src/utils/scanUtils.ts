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

    const targetPath = workspaceFolders[0].uri.fsPath;
    setTargetPath(targetPath);

    isScanning = true;
    logMessage(createSeparatorLogLine('Ybe Check started'), 'info');

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Ybe Check",
        cancellable: false
    }, async (progress) => {
        const scanLabel = scanType === 'full' ? 'Full Audit' : 'Static Scan';
        progress.report({ message: `Running ${scanLabel} (this may take a moment)...` });

        // Write report to a temp file so we get clean JSON (no log noise)
        const tmpReport = path.join(os.tmpdir(), `ybe-report-${Date.now()}.json`);

        try {
            const categoryFlag = scanType === 'static' ? '--categories static' : '';
            const cmd = [
                `"${pythonPath}"`, '-m', 'ybe_check.cli', 'scan',
                `"${targetPath}"`,
                '--output', `"${tmpReport}"`,
                categoryFlag,
            ].filter(Boolean).join(' ');

            await execAsync(cmd, { maxBuffer: MAX_BUFFER });

            const reportJson = fs.readFileSync(tmpReport, 'utf8');
            const report = JSON.parse(reportJson);

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
