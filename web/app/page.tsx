"use client";

import { useState } from "react";

type Report = {
  overall_score: number;
  verdict: string;
  summary: {
    total_issues: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    modules_passed: number;
    modules_failed: number;
    modules_errored: number;
  };
  top_fixes: Array<{
    priority: number;
    severity: string;
    rule_id: string;
    module: string;
    file: string;
    line: number | null;
    action: string;
  }>;
  modules: Array<{
    name: string;
    score: number | null;
    issues: number;
    status: string;
    rule_prefix: string;
    details: Array<{
      rule_id?: string;
      file?: string;
      line?: number;
      type?: string;
      severity?: string;
      confidence?: string;
      reason?: string;
    }>;
    warning?: string;
    error?: string;
  }>;
};

export default function Home() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<Report | null>(null);

  async function handleScan() {
    const trimmed = url.trim();
    if (!trimmed) {
      setError("Enter a GitHub repo URL");
      return;
    }
    setError(null);
    setReport(null);
    setLoading(true);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: trimmed }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Scan failed");
        return;
      }
      setReport(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Network error");
    } finally {
      setLoading(false);
    }
  }

  const score = report?.overall_score ?? 0;
  const scoreColor =
    score >= 80 ? "text-emerald-500" : score >= 40 ? "text-amber-400" : "text-red-500";
  const borderColor =
    score >= 80 ? "border-emerald-500" : score >= 40 ? "border-amber-400" : "border-red-500";

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 font-sans">
      {/* Hero */}
      <header className="border-b border-zinc-800 px-6 py-16 text-center">
        <h1 className="text-4xl font-bold tracking-tight text-white sm:text-5xl">
          Ybe Check
        </h1>
        <p className="mt-4 text-xl text-zinc-400">
          Production-readiness gatekeeper for vibe-coded apps
        </p>
        <p className="mt-2 text-sm text-zinc-500 max-w-xl mx-auto">
          Scans AI-generated repos for security issues and gives a 0–100 score with a Go/No-Go verdict.
        </p>
      </header>

      {/* Scan input */}
      <section className="max-w-3xl mx-auto px-6 py-12">
        <h2 className="text-lg font-semibold text-zinc-200 mb-4">Scan a repo</h2>
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            placeholder="https://github.com/user/repo or user/repo"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleScan()}
            className="flex-1 rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-3 text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            disabled={loading}
          />
          <button
            onClick={handleScan}
            disabled={loading}
            className="rounded-lg bg-blue-600 px-6 py-3 font-medium text-white hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? "Scanning…" : "Scan"}
          </button>
        </div>
        {error && (
          <p className="mt-3 text-sm text-red-400">{error}</p>
        )}
      </section>

      {/* Report */}
      {report && (
        <section className="max-w-4xl mx-auto px-6 pb-12">
          <h2 className="text-xl font-bold text-zinc-200 mb-6">Audit Report</h2>
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              {/* Score & verdict Card */}
              <div className="md:col-span-1 rounded-xl border border-zinc-700 bg-zinc-900/50 p-6 flex flex-col items-center justify-center text-center">
                <div
                  className={`w-28 h-28 rounded-full border-4 ${borderColor} flex items-center justify-center mb-4`}
                >
                  <span className={`text-3xl font-bold ${scoreColor}`}>{score}</span>
                </div>
                <p className={`text-lg font-bold ${scoreColor} uppercase tracking-wider`}>
                  {report.verdict}
                </p>
              </div>

              {/* Summary Dashboard Card */}
              <div className="md:col-span-3 rounded-xl border border-zinc-700 bg-zinc-900/50 p-6">
                <h3 className="text-sm font-medium text-zinc-400 mb-4 uppercase tracking-widest">Risk Summary</h3>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  <div className="bg-zinc-800/40 p-4 rounded-lg border border-red-900/20">
                    <p className="text-2xl font-bold text-red-500">{report.summary.critical}</p>
                    <p className="text-xs text-zinc-500 uppercase mt-1">Critical</p>
                  </div>
                  <div className="bg-zinc-800/40 p-4 rounded-lg border border-orange-900/20">
                    <p className="text-2xl font-bold text-orange-400">{report.summary.high}</p>
                    <p className="text-xs text-zinc-500 uppercase mt-1">High</p>
                  </div>
                  <div className="bg-zinc-800/40 p-4 rounded-lg border border-amber-900/20">
                    <p className="text-2xl font-bold text-amber-400">{report.summary.medium}</p>
                    <p className="text-xs text-zinc-500 uppercase mt-1">Medium</p>
                  </div>
                  <div className="bg-zinc-800/40 p-4 rounded-lg border border-emerald-900/20">
                    <p className="text-2xl font-bold text-emerald-500">{report.summary.total_issues}</p>
                    <p className="text-xs text-zinc-500 uppercase mt-1">Total Issues</p>
                  </div>
                </div>
                <div className="mt-6 flex flex-wrap gap-4 text-xs text-zinc-500">
                  <span className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                    {report.summary.modules_passed} Passed
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-amber-500"></span>
                    {report.summary.modules_failed} Issues Found
                  </span>
                  {report.summary.modules_errored > 0 && (
                    <span className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-red-500"></span>
                      {report.summary.modules_errored} Errored
                    </span>
                  )}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Top fixes - Left Column */}
              <div className="lg:col-span-1 space-y-4">
                <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-widest">Recommended Fixes</h3>
                {report.top_fixes && report.top_fixes.length > 0 ? (
                  <div className="space-y-3">
                    {report.top_fixes.map((fix) => (
                      <div key={fix.priority} className="rounded-xl border border-zinc-700 bg-zinc-900/50 p-4 relative overflow-hidden group">
                        <div className={`absolute top-0 left-0 w-1 h-full ${fix.severity === 'critical' ? 'bg-red-500' :
                            fix.severity === 'high' ? 'bg-orange-500' : 'bg-amber-500'
                          }`} />
                        <div className="flex justify-between items-start mb-2">
                          <span className="text-[10px] font-bold bg-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded uppercase">
                            {fix.rule_id}
                          </span>
                          <span className={`text-[10px] font-bold uppercase ${fix.severity === 'critical' ? 'text-red-500' :
                              fix.severity === 'high' ? 'text-orange-400' : 'text-amber-400'
                            }`}>
                            {fix.severity}
                          </span>
                        </div>
                        <p className="text-sm text-zinc-200 font-medium mb-2">{fix.action}</p>
                        <p className="text-[11px] text-zinc-500 font-mono">
                          {fix.file}{fix.line ? `:${fix.line}` : ''}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="rounded-xl border border-zinc-800 bg-zinc-900/30 p-8 text-center">
                    <p className="text-sm text-zinc-500 italic">No critical fixes required</p>
                  </div>
                )}
              </div>

              {/* Module Cards - Right Column */}
              <div className="lg:col-span-2 space-y-4">
                <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-widest">Module Breakdown</h3>
                <div className="space-y-3">
                  {report.modules?.map((mod) => {
                    const modScore = mod.score ?? 0;
                    const modColor =
                      modScore >= 80 ? "text-emerald-500" : modScore >= 40 ? "text-amber-400" : "text-red-500";
                    return (
                      <div
                        key={mod.name}
                        className="rounded-xl border border-zinc-700 bg-zinc-800/30 p-5"
                      >
                        <div className="flex justify-between items-start mb-4">
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-zinc-200 uppercase tracking-tight">
                                {mod.name}
                              </span>
                              <span className={`text-[10px] px-1.5 py-0.5 rounded border ${mod.status === 'no_issues' ? 'border-emerald-900/50 text-emerald-500 bg-emerald-500/5' :
                                  mod.status === 'errored' ? 'border-red-900/50 text-red-500 bg-red-500/5' :
                                    'border-zinc-700 text-zinc-400 bg-zinc-400/5'
                                }`}>
                                {mod.status.replace('_', ' ')}
                              </span>
                            </div>
                            <p className="text-zinc-500 text-xs mt-1">
                              {mod.issues} vulnerability identified
                            </p>
                          </div>
                          <div className="text-right">
                            <span className={`text-2xl font-bold ${modColor}`}>
                              {mod.score != null ? mod.score : "—"}
                            </span>
                            <p className="text-[10px] text-zinc-600 uppercase font-bold tracking-tighter">Score</p>
                          </div>
                        </div>

                        {(mod.warning || mod.error) && (
                          <div className="mt-2 bg-red-950/20 border border-red-900/30 rounded-lg px-3 py-2">
                            <p className="text-xs text-red-400">
                              {mod.warning || mod.error}
                            </p>
                          </div>
                        )}

                        {mod.details && mod.details.length > 0 && (
                          <div className="mt-4 overflow-x-auto rounded-lg border border-zinc-700/50">
                            <table className="w-full text-xs text-left">
                              <thead className="bg-zinc-800/50 text-zinc-500 uppercase text-[10px] font-bold">
                                <tr>
                                  <th className="px-3 py-2">ID</th>
                                  <th className="px-3 py-2">Location</th>
                                  <th className="px-3 py-2">Type</th>
                                  <th className="px-3 py-2">Severity</th>
                                </tr>
                              </thead>
                              <tbody>
                                {mod.details.slice(0, 5).map((d, i) => (
                                  <tr key={i} className="border-t border-zinc-700/50 hover:bg-zinc-700/10 transition-colors">
                                    <td className="px-3 py-2 text-zinc-500 font-mono">{d.rule_id}</td>
                                    <td className="px-3 py-2 text-zinc-300 font-mono truncate max-w-[150px]">
                                      {d.file}:{d.line}
                                    </td>
                                    <td className="px-3 py-2 text-zinc-400 capitalize">{d.type}</td>
                                    <td className="px-3 py-2">
                                      <span className={`${d.severity === 'critical' ? 'text-red-500' :
                                          d.severity === 'high' ? 'text-orange-400' : 'text-amber-400'
                                        } font-bold`}>
                                        {d.severity}
                                      </span>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                            {mod.details.length > 5 && (
                              <div className="bg-zinc-800/20 px-3 py-1.5 border-t border-zinc-700/50">
                                <p className="text-[10px] text-zinc-500 italic">
                                  + {mod.details.length - 5} additional findings in this module
                                </p>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* What it does */}
      <section className="max-w-4xl mx-auto px-6 py-12 border-t border-zinc-800">
        <h2 className="text-lg font-semibold text-zinc-200 mb-4 uppercase tracking-widest text-center">Security Coverage</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6 mt-8">
          <div className="bg-zinc-900/30 p-4 rounded-xl border border-zinc-800">
            <h3 className="text-zinc-200 font-bold mb-2 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-red-500"></span> Secrets
            </h3>
            <p className="text-xs text-zinc-400">Deep scan for API keys, tokens, and hardcoded credentials in source code.</p>
          </div>
          <div className="bg-zinc-900/30 p-4 rounded-xl border border-zinc-800">
            <h3 className="text-zinc-200 font-bold mb-2 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-orange-500"></span> Propmt Injection
            </h3>
            <p className="text-xs text-zinc-400">Analysis of unsafe templates, missing guardrails, and jailbreak phrases.</p>
          </div>
          <div className="bg-zinc-900/30 p-4 rounded-xl border border-zinc-800">
            <h3 className="text-zinc-200 font-bold mb-2 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-amber-500"></span> PII & Logging
            </h3>
            <p className="text-xs text-zinc-400">Detecting exposure of personal data and unsafe logging patterns.</p>
          </div>
          <div className="bg-zinc-900/30 p-4 rounded-xl border border-zinc-800">
            <h3 className="text-zinc-200 font-bold mb-2 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-blue-500"></span> Dependencies
            </h3>
            <p className="text-xs text-zinc-400">Detection of vulnerable versions and hallucinated/malicious packages.</p>
          </div>
          <div className="bg-zinc-900/30 p-4 rounded-xl border border-zinc-800">
            <h3 className="text-zinc-200 font-bold mb-2 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-purple-500"></span> Auth Guards
            </h3>
            <p className="text-xs text-zinc-400">Uncovering unprotected routes, debug modes, and wildcard CORS.</p>
          </div>
          <div className="bg-zinc-900/30 p-4 rounded-xl border border-zinc-800">
            <h3 className="text-zinc-200 font-bold mb-2 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-500"></span> IaC Security
            </h3>
            <p className="text-xs text-zinc-400">Scanning Terraform and Docker files for infrastructure misconfigurations.</p>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-zinc-800 px-6 py-8 text-center text-zinc-500 text-sm">
        <p>
          License: Apache-2.0 ·{" "}
          <a
            href="https://github.com/AddyCuber/A2K2-PS1"
            target="_blank"
            rel="noopener noreferrer"
            className="text-blue-400 hover:underline"
          >
            GitHub
          </a>
        </p>
      </footer>
    </div>
  );
}
