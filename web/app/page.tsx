"use client";

import { useState } from "react";

type Report = {
  overall_score: number;
  verdict: string;
  modules: Array<{
    name: string;
    score: number | null;
    issues: number;
    details: Array<{ file?: string; line?: number; type?: string; reason?: string }>;
    warning?: string;
    error?: string;
  }>;
  top_fixes?: string[];
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
      <section className="max-w-2xl mx-auto px-6 py-12">
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
        <section className="max-w-2xl mx-auto px-6 pb-12">
          <h2 className="text-lg font-semibold text-zinc-200 mb-4">Report</h2>
          <div className="rounded-xl border border-zinc-700 bg-zinc-900/50 p-6 space-y-6">
            {/* Score & verdict */}
            <div className="flex flex-col sm:flex-row items-center gap-6">
              <div
                className={`w-24 h-24 rounded-full border-4 ${borderColor} flex items-center justify-center flex-shrink-0`}
              >
                <span className={`text-2xl font-bold ${scoreColor}`}>{score}</span>
              </div>
              <div>
                <p className={`text-lg font-semibold ${scoreColor}`}>{report.verdict}</p>
                <p className="text-zinc-500 text-sm mt-1">
                  {report.modules?.length ?? 0} modules scanned
                </p>
                <p className="text-zinc-500 text-sm">
                  {report.modules?.map((m) => m.name).join(", ")}
                </p>
              </div>
            </div>

            {/* Top fixes */}
            {report.top_fixes && report.top_fixes.length > 0 && (
              <div>
                <h3 className="text-sm font-medium text-zinc-300 mb-2">Top fixes</h3>
                <ul className="space-y-2">
                  {report.top_fixes.map((fix, i) => (
                    <li
                      key={i}
                      className="text-sm text-zinc-400 bg-zinc-800/50 rounded-lg px-3 py-2"
                    >
                      {fix}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Module cards */}
            <div>
              <h3 className="text-sm font-medium text-zinc-300 mb-3">Modules</h3>
              <div className="space-y-3">
                {report.modules?.map((mod) => {
                  const modScore = mod.score ?? 0;
                  const modColor =
                    modScore >= 80 ? "text-emerald-500" : modScore >= 40 ? "text-amber-400" : "text-red-500";
                  return (
                    <div
                      key={mod.name}
                      className="rounded-lg border border-zinc-700 bg-zinc-800/30 p-4"
                    >
                      <div className="flex justify-between items-start">
                        <div>
                          <span className="font-medium text-zinc-200 capitalize">
                            {mod.name.replace(/_/g, " ")}
                          </span>
                          <span className="text-zinc-500 text-sm ml-2">
                            {mod.issues} issue{mod.issues !== 1 ? "s" : ""}
                          </span>
                        </div>
                        <span className={`font-semibold ${modColor}`}>
                          {mod.score != null ? mod.score : "—"}
                        </span>
                      </div>
                      {(mod.warning || mod.error) && (
                        <p className="mt-2 text-sm text-amber-400">
                          {mod.warning || mod.error}
                        </p>
                      )}
                      {mod.details && mod.details.length > 0 && (
                        <div className="mt-3 overflow-x-auto">
                          <table className="w-full text-xs">
                            <thead>
                              <tr className="text-zinc-500">
                                <th className="text-left py-1">File</th>
                                <th className="text-left py-1">Line</th>
                                <th className="text-left py-1">Type</th>
                              </tr>
                            </thead>
                            <tbody>
                              {mod.details.slice(0, 10).map((d, i) => (
                                <tr key={i} className="border-t border-zinc-700">
                                  <td className="py-1.5 text-zinc-400 font-mono truncate max-w-[120px]">
                                    {d.file ?? "—"}
                                  </td>
                                  <td className="py-1.5 text-zinc-500">{d.line ?? "—"}</td>
                                  <td className="py-1.5 text-zinc-400">
                                    {d.type ?? d.reason ?? "—"}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                          {mod.details.length > 10 && (
                            <p className="mt-2 text-zinc-500 text-xs">
                              +{mod.details.length - 10} more
                            </p>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </section>
      )}

      {/* What it does */}
      <section className="max-w-2xl mx-auto px-6 py-12 border-t border-zinc-800">
        <h2 className="text-lg font-semibold text-zinc-200 mb-4">What it does</h2>
        <ul className="space-y-2 text-zinc-400 text-sm">
          <li>• <strong className="text-zinc-300">Secrets</strong> — API keys, tokens, hardcoded credentials</li>
          <li>• <strong className="text-zinc-300">Prompt injection</strong> — unsafe templates, missing guardrails, jailbreak phrases</li>
          <li>• <strong className="text-zinc-300">PII &amp; logging</strong> — emails, phones, unsafe logger.info(request)</li>
          <li>• <strong className="text-zinc-300">Dependencies</strong> — vulnerable versions and hallucinated packages (PyPI check)</li>
          <li>• <strong className="text-zinc-300">Auth guards</strong> — unprotected sensitive routes, DEBUG=True, wildcard CORS</li>
        </ul>
      </section>

      {/* Footer */}
      <footer className="border-t border-zinc-800 px-6 py-8 text-center text-zinc-500 text-sm">
        <p>
          License: Apache-2.0 ·{" "}
          <a
            href="https://github.com/darshiyer/A2K2-PS1"
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
