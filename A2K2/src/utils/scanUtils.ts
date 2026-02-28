/**
 * © 2025 ArpitStack. Distributed under Apache-2.0 License.
 * See http://www.apache.org/licenses/LICENSE-2.0 for details.
 */

import * as vscode from 'vscode';
import * as path from 'path';
import { logMessage, createSeparatorLogLine } from './loggingUtils';
import { setTargetPath } from './fileUtils';
import { exec } from 'child_process';
import { promisify } from 'util';

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
 * Executes a Ybe Check scan using the bundled cli.py.
 */
export async function executeScan(
    _unused: any,
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
        progress.report({ message: "Installing dependencies & scanning (this may take a moment)..." });

        try {
            const cliPath = path.join(context.extensionPath, 'cli.py');
            const { stdout, stderr } = await execAsync(
                `"${pythonPath}" "${cliPath}" "${targetPath}" --json`,
                { maxBuffer: MAX_BUFFER }
            );

            if (stderr && !stdout) {
                throw new Error(stderr);
            }

            const report = JSON.parse(stdout);

            logMessage(createSeparatorLogLine(`Ybe Check completed: Score ${report.overall_score}/100`), 'info');

            const { showYbeCheckReport } = require('./webviewUtils');
            await showYbeCheckReport(report, context);

        } catch (error) {
            logMessage(`Error during Ybe Check: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error');
            vscode.window.showErrorMessage(`Ybe Check failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        } finally {
            isScanning = false;
        }
    });
}
