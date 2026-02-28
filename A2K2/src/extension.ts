/**
 * © 2025 ArpitStack. Distributed under Apache-2.0 License.
 * See http://www.apache.org/licenses/LICENSE-2.0 for details.
 */

import { initializeStatusBar, disposeStatusBar } from './utils/statusBarUtils';
import { executeScan } from './utils/scanUtils';
import * as vscode from 'vscode';

/**
 * Activates the Ybe Check extension.
 * Initializes status bar and registers scan commands.
 * 
 * @param context - The extension context.
 */
export function activate(context: vscode.ExtensionContext) {

    // Initialize the status bar with the scan action button
    initializeStatusBar(context);

    // Register a command that starts the full scan (Static + Dynamic)
    const fullScanCommand = vscode.commands.registerCommand('ybe-check.fullScan', async () => {
        await executeScan(null, context);
    });

    // Register a command for Static Scan only
    const staticScanCommand = vscode.commands.registerCommand('ybe-check.staticScan', async () => {
        await executeScan(null, context);
    });

    // Add commands to subscriptions
    context.subscriptions.push(fullScanCommand, staticScanCommand);
}

/**
 * Deactivates the Ybe Check extension.
 */
export function deactivate() {
    disposeStatusBar();
}
