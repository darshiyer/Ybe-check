/**
 * promptBuilder.ts
 * Generates rich, detailed AI fix prompts from Ybe Check findings.
 * Prompts are designed to work with any AI: Copilot, Cursor, Claude, ChatGPT.
 */

export interface Finding {
    severity?: string;
    type?: string;
    file?: string;
    line?: number | string;
    reason?: string;
    description?: string;
    snippet?: string;
    remediation?: string;
    action?: string;
    rule_id?: string;
    confidence?: string;
    package?: string;
    license?: string;
}

const SEV_EMOJI: Record<string, string> = {
    critical: '🔴',
    high:     '🟠',
    medium:   '🟡',
    low:      '🔵',
};

const SEV_RISK: Record<string, string> = {
    critical: 'This is a critical severity issue that must be fixed before shipping to production. Exploiting this could result in full system compromise, data breach, or severe legal liability.',
    high:     'This is a high severity issue. It represents a significant security risk that should be fixed immediately — do not deploy without addressing this.',
    medium:   'This is a medium severity issue. It should be fixed before the next production release.',
    low:      'This is a low severity issue. Address it as part of your next security hardening pass.',
};

/** Sanitise a string field — trims, collapses whitespace, caps length. */
function clean(val: unknown, max = 500): string {
    if (val === null || val === undefined) { return ''; }
    return String(val).replace(/\s+/g, ' ').trim().slice(0, max);
}

/**
 * Build a detailed AI fix prompt for a single finding.
 * Handles null/undefined fields gracefully — never throws.
 */
export function buildAiPrompt(
    finding: Finding | null | undefined,
    moduleName: string,
    repoPath: string
): string {
    if (!finding) {
        return `🛡️ Ybe Check — ${moduleName}\nNo finding details available.`;
    }

    const sev        = clean(finding.severity || 'medium').toLowerCase();
    const sevUpper   = sev.toUpperCase();
    const emoji      = SEV_EMOJI[sev] || '⚠️';
    const file       = clean(finding.file) || 'unknown file';
    const line       = finding.line ?? '?';
    const type       = clean(finding.type) || 'Security Issue';
    const reason     = clean(finding.reason || finding.description, 800);
    const remediation = clean(finding.remediation || finding.action, 800);
    const snippet    = clean(finding.snippet, 400);
    const ruleId     = finding.rule_id ? `[${clean(finding.rule_id)}] ` : '';
    const confidence = finding.confidence ? ` · Confidence: ${clean(finding.confidence)}` : '';
    const riskNote   = SEV_RISK[sev] || 'Review and address this issue before deploying.';

    const lines: string[] = [];

    lines.push(`${emoji} SECURITY ISSUE — ${moduleName.toUpperCase()} · ${sevUpper}`);
    lines.push(`${'─'.repeat(60)}`);
    lines.push('');

    lines.push(`📍 LOCATION`);
    lines.push(`   File:  ${file}`);
    lines.push(`   Line:  ${line}`);
    lines.push(`   Rule:  ${ruleId}${type}${confidence}`);
    lines.push('');

    lines.push(`🔍 WHAT WAS FOUND`);
    if (reason) {
        reason.split('. ').filter(Boolean).forEach(s => {
            lines.push(`   ${s.trim()}${s.trim().endsWith('.') ? '' : '.'}`);
        });
    } else {
        lines.push(`   ${type} detected in ${file}.`);
    }
    lines.push('');

    if (snippet) {
        lines.push(`📄 CODE SNIPPET`);
        lines.push('   ```');
        snippet.split('\n').forEach(l => lines.push(`   ${l}`));
        lines.push('   ```');
        lines.push('');
    }

    lines.push(`⚠️  WHY THIS IS DANGEROUS`);
    lines.push(`   ${riskNote}`);
    lines.push('');

    lines.push(`✅ HOW TO FIX IT`);
    if (remediation) {
        remediation.split('. ').filter(Boolean).forEach((s, i) => {
            lines.push(`   ${i + 1}. ${s.trim()}${s.trim().endsWith('.') ? '' : '.'}`);
        });
    } else {
        lines.push(`   1. Locate the issue at ${file}:${line}.`);
        lines.push(`   2. Apply the appropriate security fix for ${type}.`);
        lines.push(`   3. Re-run Ybe Check to confirm the issue is resolved.`);
    }
    lines.push('');

    lines.push(`${'─'.repeat(60)}`);
    lines.push(`🛡️  Detected by Ybe Check · Module: ${moduleName}`);
    lines.push(`   Repo: ${repoPath}`);
    lines.push('');
    lines.push('Please analyze this specific security issue and provide the exact code fix.');
    lines.push('Show me the before and after code. Explain why your fix resolves the vulnerability.');

    return lines.join('\n');
}

/**
 * Build a summary prompt for ALL findings in a module.
 */
export function buildModulePrompt(
    moduleName: string,
    findings: Finding[],
    score: number | null,
    repoPath: string
): string {
    const lines: string[] = [];
    const count = findings.length;

    lines.push(`🛡️ SECURITY AUDIT — ${moduleName.toUpperCase()}`);
    lines.push(`${'─'.repeat(60)}`);
    lines.push(`Score: ${score ?? 'N/A'}/100 · ${count} issue${count !== 1 ? 's' : ''} found`);
    lines.push(`Repo:  ${repoPath}`);
    lines.push('');

    findings.forEach((f, i) => {
        const sev   = (f.severity || 'medium').toUpperCase();
        const emoji = SEV_EMOJI[f.severity?.toLowerCase() || 'medium'] || '⚠️';
        lines.push(`${emoji} Issue ${i + 1}: [${sev}] ${f.type || 'Security Issue'}`);
        lines.push(`   File: ${f.file || '?'}, Line: ${f.line ?? '?'}`);
        if (f.reason) { lines.push(`   ${f.reason}`); }
        if (f.remediation) { lines.push(`   Fix: ${f.remediation}`); }
        lines.push('');
    });

    lines.push(`${'─'.repeat(60)}`);
    lines.push('Please review all the above issues and provide fixes for each one.');
    lines.push('Prioritize by severity (critical first). Show exact code changes.');

    return lines.join('\n');
}
