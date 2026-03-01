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

function ensureMcpConfig(context: vscode.ExtensionContext) {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) { return; }

    const pythonPath: string = vscode.workspace
        .getConfiguration('ybe-check')
        .get('pythonPath', 'python3');

    const cursorDir = path.join(workspaceFolders[0].uri.fsPath, '.cursor');
    const mcpFile = path.join(cursorDir, 'mcp.json');

    let config: { mcpServers: Record<string, unknown> } = { mcpServers: {} };
    if (fs.existsSync(mcpFile)) {
        try { config = JSON.parse(fs.readFileSync(mcpFile, 'utf8')); }
        catch { config = { mcpServers: {} }; }
    }
    if (!config.mcpServers) { config.mcpServers = {}; }

    // Skip if already registered with the same settings
    const existing = config.mcpServers[MCP_SERVER_ID] as { command?: string; args?: string[] } | undefined;
    if (existing && existing.command === pythonPath) { return; }

    config.mcpServers[MCP_SERVER_ID] = { command: pythonPath, args: MCP_ARGS };

    if (!fs.existsSync(cursorDir)) { fs.mkdirSync(cursorDir, { recursive: true }); }
    fs.writeFileSync(mcpFile, JSON.stringify(config, null, 2));

    vscode.window.showInformationMessage(
        'Ybe Check: MCP server registered in .cursor/mcp.json. Reload the window to activate it.',
        'Reload'
    ).then(action => {
        if (action === 'Reload') { vscode.commands.executeCommand('workbench.action.reloadWindow'); }
    });
}

/**
 * Activates the Ybe Check extension.
 * Initializes status bar, registers scan commands, and ensures MCP config exists.
 *
 * @param context - The extension context.
 */
export function activate(context: vscode.ExtensionContext) {

    ensureMcpConfig(context);

    // Initialize the status bar with the scan action button
    initializeStatusBar(context);

    // Register a command that starts the full scan (Static + Dynamic)
    const fullScanCommand = vscode.commands.registerCommand('ybe-check.fullScan', async () => {
        await executeScan('full', context);
    });

    // Register a command for Static Scan only
    const staticScanCommand = vscode.commands.registerCommand('ybe-check.staticScan', async () => {
        await executeScan('static', context);
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
