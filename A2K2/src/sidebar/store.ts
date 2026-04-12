/**
 * store.ts
 * Persistent security store — reads/writes .ybe-check/store.json in the workspace.
 * Findings survive across sessions. The agent feeds it, the sidebar reads it.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

// ── Types ──────────────────────────────────────────────────────────────

export type FindingStatus = 'open' | 'fixed' | 'ignored';

export interface StoredFinding {
    id: string;
    module: string;
    severity: string;
    type: string;
    file: string;
    line: number | string;
    reason: string;
    snippet: string;
    remediation: string;
    rule_id: string;
    status: FindingStatus;
    firstSeen: string;      // ISO date
    lastSeen: string;       // ISO date
    isNew: boolean;         // appeared in the latest scan
    scanCount: number;      // how many scans have seen this
}

export interface ScanRecord {
    timestamp: string;
    score: number | null;
    verdict: string;
    modulesRun: number;
    findingsFound: number;
    findingsFixed: number;
}

export interface StoreData {
    version: 1;
    lastScan: string | null;
    currentScore: number | null;
    currentVerdict: string;
    findings: StoredFinding[];
    history: ScanRecord[];
}

// ── Helpers ────────────────────────────────────────────────────────────

function makeId(module: string, type: string, file: string, line: number | string): string {
    const raw = `${module}::${type}::${file}::${line}`;
    return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 12);
}

function emptyStore(): StoreData {
    return {
        version: 1,
        lastScan: null,
        currentScore: null,
        currentVerdict: '',
        findings: [],
        history: [],
    };
}

// ── Store class ────────────────────────────────────────────────────────

export class SecurityStore {
    private _storePath: string;
    private _data: StoreData;

    constructor(workspaceRoot: string) {
        const dir = path.join(workspaceRoot, '.ybe-check');
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        this._storePath = path.join(dir, 'store.json');
        this._data = this._load();
    }

    get data(): StoreData { return this._data; }
    get storePath(): string { return this._storePath; }

    /** Load store from disk. Returns empty store if missing/corrupt. */
    private _load(): StoreData {
        try {
            const raw = fs.readFileSync(this._storePath, 'utf-8');
            const parsed = JSON.parse(raw);
            if (parsed.version === 1) { return parsed; }
        } catch { /* ignore */ }
        return emptyStore();
    }

    /** Reload from disk (e.g. when file watcher triggers). */
    reload(): void {
        this._data = this._load();
    }

    /** Write current state to disk. */
    save(): void {
        fs.writeFileSync(this._storePath, JSON.stringify(this._data, null, 2), 'utf-8');
    }

    /**
     * Ingest raw scan results from the CLI.
     * Merges new findings, marks disappeared ones, updates timestamps.
     */
    ingestScanResults(report: {
        overall_score?: number;
        verdict?: string;
        modules?: Array<{
            name: string;
            score: number | null;
            issues: number;
            details?: Array<{
                severity?: string;
                type?: string;
                file?: string;
                line?: number | string;
                reason?: string;
                snippet?: string;
                remediation?: string;
                action?: string;
                rule_id?: string;
            }>;
        }>;
    }): void {
        const now = new Date().toISOString();
        const modules = report.modules || [];

        // Build set of IDs from this scan
        const currentIds = new Set<string>();
        const incomingFindings: StoredFinding[] = [];

        for (const mod of modules) {
            for (const d of (mod.details || [])) {
                const id = makeId(mod.name, d.type || '', d.file || '', d.line ?? 0);
                currentIds.add(id);
                incomingFindings.push({
                    id,
                    module: mod.name,
                    severity: (d.severity || 'medium').toLowerCase(),
                    type: d.type || 'Security issue',
                    file: d.file || '',
                    line: d.line ?? 0,
                    reason: d.reason || '',
                    snippet: d.snippet || '',
                    remediation: d.remediation || d.action || '',
                    rule_id: d.rule_id || '',
                    status: 'open',
                    firstSeen: now,
                    lastSeen: now,
                    isNew: true,
                    scanCount: 1,
                });
            }
        }

        // Merge with existing findings
        const merged: StoredFinding[] = [];
        const existingById = new Map(this._data.findings.map(f => [f.id, f]));

        for (const incoming of incomingFindings) {
            const existing = existingById.get(incoming.id);
            if (existing) {
                // Finding still present — update
                existing.lastSeen = now;
                existing.isNew = false;
                existing.scanCount += 1;
                // Don't overwrite status if user marked it fixed/ignored
                if (existing.status === 'fixed') {
                    // It came back — reopen it
                    existing.status = 'open';
                    existing.isNew = true;
                }
                merged.push(existing);
                existingById.delete(incoming.id);
            } else {
                // New finding
                merged.push(incoming);
            }
        }

        // Remaining existing findings that weren't in this scan
        for (const old of existingById.values()) {
            old.isNew = false;
            // Keep them — they're historical. Don't auto-mark as fixed
            // because the scan might have only run a subset of modules.
            merged.push(old);
        }

        // Count fixes for the history record
        const fixedCount = this._data.findings.filter(f => f.status === 'fixed').length;

        // Update store
        this._data.lastScan = now;
        this._data.currentScore = report.overall_score ?? null;
        this._data.currentVerdict = report.verdict || '';
        this._data.findings = merged;

        // Add history record (keep last 50)
        this._data.history.push({
            timestamp: now,
            score: report.overall_score ?? null,
            verdict: report.verdict || '',
            modulesRun: modules.length,
            findingsFound: incomingFindings.length,
            findingsFixed: fixedCount,
        });
        if (this._data.history.length > 50) {
            this._data.history = this._data.history.slice(-50);
        }

        this.save();
    }

    /** Update the status of a finding. */
    setFindingStatus(findingId: string, status: FindingStatus): boolean {
        const finding = this._data.findings.find(f => f.id === findingId);
        if (!finding) { return false; }
        finding.status = status;
        this.save();
        return true;
    }

    /** Get counts by status. */
    getCounts(): { open: number; fixed: number; ignored: number; total: number; new: number } {
        const findings = this._data.findings;
        return {
            open: findings.filter(f => f.status === 'open').length,
            fixed: findings.filter(f => f.status === 'fixed').length,
            ignored: findings.filter(f => f.status === 'ignored').length,
            total: findings.length,
            new: findings.filter(f => f.isNew).length,
        };
    }
}
