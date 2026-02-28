/**
 * © 2025 ArpitStack. Distributed under Apache-2.0 License.
 * See http://www.apache.org/licenses/LICENSE-2.0 for details.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as fse from 'fs-extra';
import * as crypto from 'crypto';
import { workspace } from 'vscode';
import { MAX_LOG_CACHE } from '../constants/default';
import { logMessage } from './loggingUtils';

const recentLogHashes: Set<string> = new Set();

let targetPath: string | undefined;

/**
 * Gets the current target path (for the folder or workspace being scanned).
 * @returns The current target path.
 */
export function getTargetPath(): string | undefined {
    return targetPath;
}

/**
 * Sets the target path (for the folder or workspace being scanned).
 * @param newPath - The target path to set.
 */
export function setTargetPath(newPath: string | undefined): void {
    targetPath = newPath;
}

/**
 * Retrieves the full path of a file in the workspace's `.ybe-check` directory, creating the directory if necessary.
 * Uses `getRootFolderPath` to calculate the root folder.
 * 
 * @param fileName - The name of the file (without extension).
 * @param extension - The file extension (e.g., 'txt', 'json').
 * @returns The full path of the file, or an empty string if the workspace is not found.
 */
export function getFilePath(
    fileName: string,
    extension: string,
): string {

    // Get the root folder based on the targetPath
    const rootFolder = getRootFolderPath();  // Retrieve the root folder using getRootFolderPath

    if (!rootFolder) {
        return ''; // Return an empty string if the root folder is not found
    }

    const dir = path.join(rootFolder, '.ybe-check'); // Ensure .ybe-check is created in the root folder
    const filePath = path.join(dir, `${fileName}.${extension}`);

    // Create directory if it doesn't exist
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    return filePath;
}

/**
 * Retrieves the root folder path based on the current context (selected folder or entire workspace).
 * If scanning a specific folder, the root folder containing that folder is returned.
 * If scanning the entire workspace, the root folder of the first workspace folder is used.
 * 
 * @returns The root folder path, or undefined if no workspace is open.
 */
export function getRootFolderPath(): string | undefined {
    const workspaceFolders = workspace.workspaceFolders;

    if (!workspaceFolders || workspaceFolders.length === 0) {
        return undefined; // No workspace is open
    }

    // If targetPath is provided, find the root folder that contains it
    const target = getTargetPath(); // This gets the target path set elsewhere in the code
    if (target) {
        const rootFolder = workspaceFolders.find(folder => target.startsWith(folder.uri.fsPath));
        return rootFolder ? rootFolder.uri.fsPath : undefined;
    }

    // If no target path, return the first folder of the workspace
    return workspaceFolders[0].uri.fsPath;
}

/**
 * Generates a SHA-256 hash for the provided message.
 * 
 * @param message - The input string to hash.
 * @returns The resulting SHA-256 hash as a hexadecimal string.
 */
export function createHash(message: string): string {
    return crypto.createHash('sha256').update(message).digest('hex');
}

/**
 * Checks if the given message is a duplicate by comparing its hash against previously processed messages.
 * 
 * @param message - The message to check for duplication.
 * @returns `true` if the message is a duplicate, otherwise `false`.
 */
export function isDuplicate(message: string): boolean {
    const messageHash = createHash(message);

    // Check if the message hash is already in the recent log cache
    if (recentLogHashes.has(messageHash)) return true;

    recentLogHashes.add(messageHash);

    // Remove the oldest hash if the cache exceeds the maximum allowed size
    if (recentLogHashes.size > MAX_LOG_CACHE) {
        const iterator = recentLogHashes.values();
        const value = iterator.next().value;

        if (value !== undefined) {
            recentLogHashes.delete(value);  // Delete the oldest entry if defined
        }
    }

    return false;
}

/**
 * Ensures exclusive access to a log file by using a lock file. The callback is executed once the lock is acquired.
 * Uses atomic file creation with 'wx' flag for proper mutual exclusion.
 * Includes timeout and stale lock detection to prevent deadlocks.
 * 
 * @param logFilePath - The path to the log file.
 * @param callback - The function to execute while holding the lock.
 */
export function withFileLock(logFilePath: string, callback: () => void): void {
    const lockFilePath = `${logFilePath}.lock`;
    const maxRetries = 50;       // Maximum number of retry attempts
    const retryDelayMs = 100;    // Delay between retries (ms) — avoids busy-wait
    const staleLockMs = 30000;   // Consider lock stale after 30 seconds

    let lockAcquired = false;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            // Atomic lock acquisition: 'wx' flag fails if file already exists
            fs.writeFileSync(lockFilePath, String(Date.now()), { flag: 'wx' });
            lockAcquired = true;
            break;
        } catch (error: any) {
            if (error.code === 'EEXIST') {
                // Lock file exists — check if it's stale
                try {
                    const lockContent = fs.readFileSync(lockFilePath, 'utf-8');
                    const lockTime = parseInt(lockContent, 10);
                    if (!isNaN(lockTime) && (Date.now() - lockTime) > staleLockMs) {
                        // Stale lock detected — remove and retry
                        try {
                            fs.unlinkSync(lockFilePath);
                        } catch {
                            // Another process may have already removed it
                        }
                        continue;
                    }
                } catch {
                    // Can't read lock file — it may have been removed; retry
                    continue;
                }

                // Lock is held by another process — wait before retrying
                // Use a synchronous sleep to avoid busy-wait CPU consumption
                const waitUntil = Date.now() + retryDelayMs;
                while (Date.now() < waitUntil) {
                    // Minimal busy-wait with bounded duration
                }
            } else {
                // Unexpected error (permissions, disk full, etc.)
                console.error('[Ybe Check] Error acquiring lock file:', error);
                break;
            }
        }
    }

    if (!lockAcquired) {
        // Fallback: execute callback without lock rather than silently failing
        console.error('[Ybe Check] Could not acquire file lock after retries, proceeding without lock');
    }

    try {
        callback();  // Execute the callback (with or without lock)
    } catch (error) {
        console.error('[Ybe Check] Error executing callback in withFileLock:', error);
    } finally {
        if (lockAcquired) {
            try {
                fs.unlinkSync(lockFilePath);  // Remove the lock file after callback execution
            } catch (error) {
                console.error('[Ybe Check] Error removing lock file:', error);
            }
        }
    }
}
