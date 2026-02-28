"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import LetterGlitch from "./components/LetterGlitch";

/* ─── DESIGN TOKENS ──────────────────────────────────────── */

const T = {
  bg: "#0F1419",
  bgCard: "#161B22",
  bgHover: "#1C2128",
  bgInput: "#0D1117",
  border: "#21262D",
  borderLt: "#30363D",

  text: "#E6EDF3",
  text2: "#8B949E",
  text3: "#484F58",

  blue: "#58A6FF",
  blueDim: "#1F6FEB",
  green: "#3FB950",
  yellow: "#D29922",
  red: "#F85149",
  orange: "#DB6D28",
};

/* ─── TYPES (mirrors backend JSON) ───────────────────────── */

type Issue = {
  file?: string;
  line?: number;
  type?: string;
  reason?: string;
  severity?: string;
  snippet?: string;
};

type Module = {
  name: string;
  score: number | null;
  issues: number;
  details: Issue[];
  warning?: string;
  error?: string;
};

type Report = {
  overall_score: number;
  verdict: string;
  modules: Module[];
  top_fixes?: string[];
};

/* ─── HELPERS ────────────────────────────────────────────── */

function scoreColor(s: number) {
  if (s >= 80) return T.green;
  if (s >= 50) return T.yellow;
  return T.red;
}

function sevColor(s?: string) {
  const v = (s || "").toLowerCase();
  if (v === "high" || v === "critical") return T.red;
  if (v === "medium") return T.orange;
  return T.blue;
}

function useCountUp(target: number, ms = 1200) {
  const [v, setV] = useState(0);
  const ran = useRef(false);
  useEffect(() => {
    if (ran.current) return;
    ran.current = true;
    const t0 = performance.now();
    const tick = (now: number) => {
      const p = Math.min((now - t0) / ms, 1);
      setV(Math.round((1 - (1 - p) ** 3) * target));
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [target, ms]);
  return v;
}

/* ─── SVG ICONS ──────────────────────────────────────────── */

function ModuleIcon({ name, size = 20, color = "#8B949E" }: { name: string; size?: number; color?: string }) {
  const s = { width: size, height: size, fill: "none", stroke: color, strokeWidth: 1.5, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  switch (name) {
    case "Secrets Detection":
      return <svg viewBox="0 0 24 24" {...s}><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0110 0v4" /></svg>;
    case "Dependencies":
      return <svg viewBox="0 0 24 24" {...s}><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z" /><polyline points="3.27 6.96 12 12.01 20.73 6.96" /><line x1="12" y1="22.08" x2="12" y2="12" /></svg>;
    case "Auth Guards":
      return <svg viewBox="0 0 24 24" {...s}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>;
    case "Prompt Injection":
      return <svg viewBox="0 0 24 24" {...s}><circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" /><line x1="8" y1="11" x2="14" y2="11" /></svg>;
    case "PII & Logging":
      return <svg viewBox="0 0 24 24" {...s}><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /></svg>;
    case "AI Traceability":
      return <svg viewBox="0 0 24 24" {...s}><rect x="4" y="4" width="16" height="16" rx="2" /><circle cx="9" cy="9" r="1.5" fill={color} stroke="none" /><circle cx="15" cy="9" r="1.5" fill={color} stroke="none" /><path d="M8 14s1.5 2 4 2 4-2 4-2" /></svg>;
    case "IaC Security":
      return <svg viewBox="0 0 24 24" {...s}><rect x="2" y="6" width="20" height="12" rx="2" /><line x1="6" y1="10" x2="6" y2="14" /><line x1="10" y1="10" x2="10" y2="14" /><line x1="14" y1="10" x2="14" y2="14" /><line x1="18" y1="10" x2="18" y2="14" /></svg>;
    case "License Compliance":
      return <svg viewBox="0 0 24 24" {...s}><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" /><polyline points="14 2 14 8 20 8" /><path d="M9 15l2 2 4-4" /></svg>;
    case "Test & Coverage":
      return <svg viewBox="0 0 24 24" {...s}><path d="M10 2v7.31" /><path d="M14 9.3V1.99" /><path d="M8.5 2h7" /><path d="M14 9.3a6.5 6.5 0 11-4 0" /></svg>;
    default:
      return <svg viewBox="0 0 24 24" {...s}><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="16" /><line x1="8" y1="12" x2="16" y2="12" /></svg>;
  }
}

const PHASES = [
  "Cloning repository", "Secrets detection", "Prompt injection scan",
  "PII & logging check", "Dependency audit", "Auth guard analysis",
  "IaC security audit", "License compliance", "AI traceability",
  "Test & coverage analysis",
];

/* ═══════════════════════════════════════════════════════════════
   MODERN BENTO TOKENS
   ═══════════════════════════════════════════════════════════════ */

const M = {
  bg: "#0a0a0b",
  card: "#141417",
  cardLt: "#1a1a1f",
  border: "#222228",
  dim: "#555",
  dimLt: "#888",
  radius: 20,
};

const mCard = (extra?: React.CSSProperties): React.CSSProperties => ({
  background: M.card,
  borderRadius: M.radius,
  padding: "28px",
  ...extra,
});

/* ═══════════════════════════════════════════════════════════════
   MAIN – state machine with matrix → dashboard dissolve
   ═══════════════════════════════════════════════════════════════ */

export default function Home() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [activeModule, setActiveModule] = useState<string | null>(null);
  const [phase, setPhase] = useState(0);
  const [transitioning, setTransitioning] = useState(false);

  useEffect(() => {
    if (!loading) { setPhase(0); return; }
    const iv = setInterval(() => setPhase(p => Math.min(p + 1, PHASES.length - 1)), 2800);
    return () => clearInterval(iv);
  }, [loading]);

  const scan = useCallback(async () => {
    const u = url.trim();
    if (!u) { setError("Enter a GitHub repo URL"); return; }
    setError(null); setReport(null); setActiveModule(null); setLoading(true);
    try {
      const r = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: u }) });
      const d = await r.json();
      if (!r.ok) { setError(d.error || "Scan failed"); return; }
      setTransitioning(true);
      setTimeout(() => { setReport(d); setTransitioning(false); }, 1000);
    } catch (e) { setError(e instanceof Error ? e.message : "Network error"); }
    finally { setLoading(false); }
  }, [url]);

  const reset = () => { setReport(null); setActiveModule(null); };

  /* Matrix → dashboard dissolve */
  if (transitioning) {
    return (
      <div style={{ position: "relative", minHeight: "100vh", overflow: "hidden", background: M.bg }}>
        <div style={{ position: "absolute", inset: 0, zIndex: 0, animation: "fadeIn 0.3s ease-out" }}>
          <LetterGlitch glitchColors={["#2b4539", "#61dca3", "#61b3dc"]} glitchSpeed={50} centerVignette outerVignette={false} smooth />
        </div>
        <div style={{ position: "absolute", inset: 0, zIndex: 10, background: M.bg, animation: "fadeIn 1s ease-in-out forwards" }} />
        <div style={{ position: "absolute", inset: 0, zIndex: 20, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <div style={{ textAlign: "center", animation: "fadeIn 0.5s ease-out 0.3s both" }}>
            <div style={{ fontSize: 18, fontWeight: 700, color: T.text }}>Building your report...</div>
          </div>
        </div>
      </div>
    );
  }

  if (loading) return <ScanningView url={url} phase={phase} />;

  if (report && activeModule) {
    const mod = report.modules.find(m => m.name === activeModule);
    if (mod) return <ModuleDetailView mod={mod} onBack={() => setActiveModule(null)} onHome={reset} />;
  }

  if (report) return <DashboardView report={report} onModuleClick={setActiveModule} onHome={reset} />;

  return <LandingView url={url} setUrl={setUrl} scan={scan} error={error} />;
}

/* ═══════════════════════════════════════════════════════════════
   LANDING
   ═══════════════════════════════════════════════════════════════ */

function LandingView({ url, setUrl, scan, error }: { url: string; setUrl: (v: string) => void; scan: () => void; error: string | null }) {
  return (
    <div style={{ position: "relative", minHeight: "100vh", overflow: "hidden" }}>
      <div style={{ position: "absolute", inset: 0, zIndex: 0 }}>
        <LetterGlitch glitchColors={["#2b4539", "#61dca3", "#61b3dc"]} glitchSpeed={50} centerVignette outerVignette={false} smooth />
      </div>
      <nav style={{ position: "relative", zIndex: 10, display: "flex", justifyContent: "center", padding: "16px 24px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 32, padding: "10px 28px", borderRadius: 50, background: "rgba(15,20,25,0.75)", backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)", border: "1px solid rgba(255,255,255,0.08)" }}>
          <span style={{ fontWeight: 700, fontSize: 16, color: "#fff" }}>Ybe Check</span>
          <a href="https://github.com/darshiyer/A2K2-PS1" target="_blank" rel="noopener noreferrer" style={{ fontSize: 14, color: T.text2, textDecoration: "none" }}>Docs</a>
        </div>
      </nav>
      <div style={{ position: "relative", zIndex: 10, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", minHeight: "calc(100vh - 72px)", padding: "0 24px", textAlign: "center" }}>
        <h1 style={{ fontSize: "clamp(36px, 6vw, 64px)", fontWeight: 800, lineHeight: 1.15, maxWidth: 700, letterSpacing: "-0.02em", marginBottom: 20, background: "linear-gradient(90deg, #9BA7B4 0%, #E6EDF3 20%, #FFFFFF 40%, #feb3ff 50%, #FFFFFF 60%, #E6EDF3 80%, #9BA7B4 100%)", backgroundSize: "300% 100%", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text", animation: "metallicShine 4s ease-in-out infinite", filter: "drop-shadow(0 2px 40px rgba(0,0,0,0.5))" }}>
          Production-readiness audit for vibe-coded apps
        </h1>
        <p style={{ fontSize: 16, color: "rgba(255,255,255,0.55)", maxWidth: 460, lineHeight: 1.6, marginBottom: 36 }}>
          Scan any GitHub repo for security vulnerabilities. Get a 0–100 production readiness score.
        </p>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", justifyContent: "center", maxWidth: 540, width: "100%" }}>
          <input type="text" placeholder="https://github.com/user/repo" value={url} onChange={e => setUrl(e.target.value)} onKeyDown={e => e.key === "Enter" && scan()}
            style={{ flex: 1, minWidth: 240, padding: "14px 20px", borderRadius: 50, background: "rgba(15,20,25,0.7)", border: "1px solid rgba(255,255,255,0.1)", color: "#fff", fontSize: 15, outline: "none", fontFamily: "inherit", backdropFilter: "blur(10px)" }}
            onFocus={e => { e.currentTarget.style.borderColor = "rgba(88,166,255,0.5)"; e.currentTarget.style.boxShadow = "0 0 0 3px rgba(88,166,255,0.15)"; }}
            onBlur={e => { e.currentTarget.style.borderColor = "rgba(255,255,255,0.1)"; e.currentTarget.style.boxShadow = "none"; }}
          />
          <button onClick={scan} style={{ padding: "14px 32px", borderRadius: 50, border: "none", cursor: "pointer", background: "#fff", color: "#000", fontSize: 15, fontWeight: 600, fontFamily: "inherit", transition: "transform 0.15s" }}
            onMouseEnter={e => { e.currentTarget.style.transform = "scale(1.03)"; }}
            onMouseLeave={e => { e.currentTarget.style.transform = "scale(1)"; }}
          >Get Started</button>
          <button onClick={() => window.open("https://github.com/darshiyer/A2K2-PS1", "_blank")} style={{ padding: "14px 32px", borderRadius: 50, cursor: "pointer", background: "rgba(15,20,25,0.6)", border: "1px solid rgba(255,255,255,0.15)", color: "rgba(255,255,255,0.8)", fontSize: 15, fontWeight: 500, fontFamily: "inherit", backdropFilter: "blur(10px)" }}>Learn More</button>
        </div>
        {error && <p style={{ marginTop: 12, fontSize: 14, color: T.red }}>{error}</p>}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   SCANNING
   ═══════════════════════════════════════════════════════════════ */

function ScanningView({ url, phase }: { url: string; phase: number }) {
  return (
    <Shell>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "calc(100vh - 60px)", padding: 24 }}>
        <div style={{ textAlign: "center", maxWidth: 420, animation: "fadeIn 0.5s ease-out" }}>
          <div style={{ width: 56, height: 56, borderRadius: "50%", border: `3px solid ${M.border}`, borderTopColor: T.blue, animation: "spinLoader 1.2s linear infinite", margin: "0 auto 28px" }} />
          <h2 style={{ fontSize: 20, fontWeight: 600, color: T.text, marginBottom: 6 }}>Scanning repository…</h2>
          <p style={{ fontSize: 13, color: M.dim, fontFamily: "monospace", marginBottom: 32 }}>{url.replace(/https?:\/\/github\.com\//, "")}</p>
          <div style={{ textAlign: "left", display: "flex", flexDirection: "column", gap: 10 }}>
            {PHASES.map((p, i) => (
              <div key={p} style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 13 }}>
                <div style={{ width: 20, height: 20, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, fontWeight: 700, flexShrink: 0, ...(i < phase ? { background: `${T.green}20`, color: T.green } : i === phase ? { background: T.blue, animation: "pulseDot 1.5s ease-in-out infinite" } : { border: `1.5px solid ${M.border}` }) }}>
                  {i < phase ? "✓" : ""}
                </div>
                <span style={{ color: i <= phase ? T.text : M.dim }}>{p}</span>
              </div>
            ))}
          </div>
          <p style={{ marginTop: 32, fontSize: 11, color: M.dim }}>Usually takes 15–30s</p>
        </div>
      </div>
    </Shell>
  );
}

/* ═══════════════════════════════════════════════════════════════
   VIEW: DASHBOARD — modern bento grid
   ═══════════════════════════════════════════════════════════════ */

function DashboardView({ report, onModuleClick, onHome }: { report: Report; onModuleClick: (name: string) => void; onHome: () => void }) {
  const score = report.overall_score ?? 0;
  const animated = useCountUp(score);
  const color = scoreColor(score);
  const totalIssues = report.modules.reduce((a, m) => a + (m.issues || 0), 0);
  const highCount = report.modules.reduce((a, m) => a + m.details.filter(d => ["high", "critical"].includes((d.severity || "").toLowerCase())).length, 0);
  const animIssues = useCountUp(totalIssues, 1000);
  const animModules = useCountUp(report.modules.length, 800);
  const passCount = report.modules.filter(m => (m.score ?? 0) >= 80).length;
  const sorted = [...report.modules].sort((a, b) => (a.score ?? 0) - (b.score ?? 0));

  return (
    <Shell>
      <div style={{ maxWidth: 1260, margin: "0 auto", padding: "28px 24px 80px", animation: "dashboardReveal 0.6s ease-out" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
          <button onClick={onHome} style={{ ...linkBtn, fontSize: 14 }}>← New Scan</button>
        </div>

        {/* ── ROW 1: Hero + Stat + Persona ────────────────── */}
        <div style={{ display: "grid", gridTemplateColumns: "1.3fr 0.8fr 0.9fr", gap: 12, marginBottom: 12 }}>

          {/* HERO — gradient aurora */}
          <div style={{ ...mCard({ padding: "0", overflow: "hidden", position: "relative", minHeight: 270 }) }}>
            <div style={{
              position: "absolute", inset: 0,
              background: "linear-gradient(135deg, #1a0533 0%, #2d1b69 25%, #1b3a5c 50%, #0d4f4f 75%, #2a1050 100%)",
              backgroundSize: "400% 400%", animation: "heroGradientShift 12s ease-in-out infinite",
            }} />
            <div style={{
              position: "absolute", inset: 0,
              background: "radial-gradient(ellipse at 30% 80%, rgba(120,80,220,0.35), transparent 60%), radial-gradient(ellipse at 70% 20%, rgba(40,180,200,0.25), transparent 50%)",
            }} />
            <div style={{ position: "relative", zIndex: 1, padding: "32px 36px", display: "flex", flexDirection: "column", justifyContent: "flex-end", height: "100%" }}>
              <div style={{ fontSize: 14, fontWeight: 500, color: "rgba(255,255,255,0.55)", marginBottom: 8 }}>Audit Report</div>
              <div style={{ fontSize: 96, fontWeight: 900, lineHeight: 1, color: "#fff", letterSpacing: "-3px", fontVariantNumeric: "tabular-nums" }}>{animated}</div>
              <div style={{
                marginTop: 20, padding: "10px 20px",
                background: "rgba(0,0,0,0.3)", backdropFilter: "blur(14px)", borderRadius: 10,
                fontSize: 14, color: "rgba(255,255,255,0.85)", lineHeight: 1.5, maxWidth: 380,
              }}>
                {score >= 80 ? "Your repo is production-ready. Core security controls are solid." : score >= 50 ? "Some areas need attention before deployment. Review the flagged modules." : "Critical vulnerabilities found. Not safe to deploy."}
              </div>
            </div>
          </div>

          {/* TOTAL ISSUES */}
          <div style={mCard({ display: "flex", flexDirection: "column", justifyContent: "space-between" })}>
            <div style={{ fontSize: 12, fontWeight: 600, color: M.dim, textTransform: "uppercase", letterSpacing: 1.5 }}>TOTAL ISSUES FOUND</div>
            <div style={{ fontSize: 72, fontWeight: 900, lineHeight: 1, color: totalIssues > 0 ? "#a78bfa" : T.green, fontVariantNumeric: "tabular-nums", marginTop: 16 }}>{animIssues}</div>
            {highCount > 0 && (
              <div style={{ marginTop: "auto", paddingTop: 16 }}>
                <span style={{ display: "inline-block", padding: "5px 14px", borderRadius: 8, background: "rgba(248,81,73,0.12)", color: T.red, fontSize: 13, fontWeight: 600 }}>{highCount} critical</span>
              </div>
            )}
          </div>

          {/* SECURITY PERSONA — light card */}
          <div style={mCard({ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", textAlign: "center", background: "#f5f5f5" })}>
            <span style={{ display: "inline-block", padding: "5px 16px", borderRadius: 20, background: M.bg, color: "#fff", fontSize: 12, fontWeight: 700 }}>Security Profile</span>
            <div style={{ width: 56, height: 56, borderRadius: 50, background: M.bg, display: "flex", alignItems: "center", justifyContent: "center", margin: "16px 0 12px" }}>
              <ModuleIcon name="Auth Guards" size={28} color="#fff" />
            </div>
            <div style={{ fontSize: 11, fontWeight: 600, color: "#888", textTransform: "uppercase", letterSpacing: 1 }}>YOU ARE A</div>
            <div style={{ fontSize: 26, fontWeight: 800, color: "#111", lineHeight: 1.15, margin: "6px 0 8px" }}>
              {score >= 80 ? "Security Champion" : score >= 50 ? "Cautious Builder" : "Risk Taker"}
            </div>
            <div style={{ fontSize: 12, color: "#666", lineHeight: 1.5, maxWidth: 180 }}>
              {score >= 80 ? "You follow best practices and prioritize security." : score >= 50 ? "You're aware of security but have some blind spots." : "Move fast and break things. Security comes second."}
            </div>
          </div>
        </div>

        {/* ── ROW 2: Module Scores + Verdict + Summary ──── */}
        <div style={{ display: "grid", gridTemplateColumns: "1.2fr 0.8fr 1fr", gap: 12, marginBottom: 12 }}>

          {/* MODULE SCORES — progress bars */}
          <div style={mCard({ padding: "24px 28px" })}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
              <span style={{ fontSize: 16, fontWeight: 700, color: T.text }}>Module Scores</span>
              <span style={{ fontSize: 12, color: M.dim }}>Score /100</span>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              {sorted.map((mod) => {
                const ms = mod.score ?? 0;
                const mc = scoreColor(ms);
                return (
                  <button key={mod.name} onClick={() => onModuleClick(mod.name)} style={{ display: "flex", alignItems: "center", gap: 12, background: "none", border: "none", cursor: "pointer", fontFamily: "inherit", padding: 0, textAlign: "left", transition: "opacity 0.15s" }}
                    onMouseEnter={e => { e.currentTarget.style.opacity = "0.7"; }}
                    onMouseLeave={e => { e.currentTarget.style.opacity = "1"; }}
                  >
                    <div style={{ width: 32, height: 32, borderRadius: 50, background: `${mc}18`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                      <ModuleIcon name={mod.name} size={16} color={mc} />
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: T.text, marginBottom: 4 }}>{mod.name}</div>
                      <div style={{ height: 6, borderRadius: 3, background: M.border, overflow: "hidden" }}>
                        <div style={{ height: "100%", borderRadius: 3, background: mc, width: `${ms}%`, transition: "width 0.8s ease-out" }} />
                      </div>
                    </div>
                    <span style={{ fontSize: 13, fontWeight: 700, color: M.dimLt, minWidth: 30, textAlign: "right" }}>{ms}%</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* VERDICT — accent gradient card */}
          <div style={{
            ...mCard({ padding: "28px", display: "flex", flexDirection: "column", justifyContent: "space-between" }),
            background: score >= 80 ? "linear-gradient(160deg, #0d7a3e, #15a050, #1cb85c)" : score >= 50 ? "linear-gradient(160deg, #c06000, #e07020, #f09030)" : "linear-gradient(160deg, #8b2020, #c03030, #e04040)",
          }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: "rgba(255,255,255,0.65)", textTransform: "uppercase", letterSpacing: 1.5 }}>VERDICT</div>
            <div style={{ fontSize: 36, fontWeight: 800, color: "#fff", lineHeight: 1.15, margin: "12px 0" }}>{report.verdict}</div>
            <div style={{ marginTop: "auto" }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: "rgba(255,255,255,0.6)", marginBottom: 8 }}>Module Health</div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {report.modules.map((mod) => {
                  const ms = mod.score ?? 0;
                  const bg = ms >= 80 ? "rgba(255,255,255,0.3)" : ms >= 50 ? "rgba(255,255,255,0.15)" : "rgba(0,0,0,0.3)";
                  return <div key={mod.name} style={{ width: 28, height: 28, borderRadius: 6, background: bg }} title={`${mod.name}: ${ms}`} />;
                })}
              </div>
            </div>
          </div>

          {/* SCAN SUMMARY + FIXES */}
          <div style={mCard({ padding: "24px 28px", display: "flex", flexDirection: "column" })}>
            <div style={{ fontSize: 12, fontWeight: 600, color: M.dim, textTransform: "uppercase", letterSpacing: 1.5, marginBottom: 14 }}>SCAN SUMMARY</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 20 }}>
              <div style={{ padding: "14px 16px", borderRadius: 12, background: M.cardLt }}>
                <div style={{ fontSize: 28, fontWeight: 800, color: T.text, fontVariantNumeric: "tabular-nums" }}>{animModules}</div>
                <div style={{ fontSize: 11, color: M.dim, marginTop: 2 }}>Modules</div>
              </div>
              <div style={{ padding: "14px 16px", borderRadius: 12, background: M.cardLt }}>
                <div style={{ fontSize: 28, fontWeight: 800, color: T.green, fontVariantNumeric: "tabular-nums" }}>{passCount}</div>
                <div style={{ fontSize: 11, color: M.dim, marginTop: 2 }}>Passing</div>
              </div>
            </div>
            {report.top_fixes && report.top_fixes.length > 0 && (
              <>
                <div style={{ fontSize: 12, fontWeight: 600, color: M.dim, textTransform: "uppercase", letterSpacing: 1.5, marginBottom: 10 }}>TOP FIXES</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
                  {report.top_fixes.slice(0, 3).map((fix, i) => (
                    <div key={i} style={{ padding: "10px 0", borderBottom: i < 2 ? `1px solid ${M.border}` : "none", fontSize: 13, color: T.text2, lineHeight: 1.5, display: "flex", gap: 10 }}>
                      <span style={{ fontWeight: 800, color: M.dim, fontSize: 12 }}>{i + 1}.</span>
                      <span>{fix}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>

        {/* ── ALL MODULES ─────────────────────────────────── */}
        <div style={{ fontSize: 12, fontWeight: 600, color: M.dim, textTransform: "uppercase", letterSpacing: 1.5, margin: "24px 0 12px" }}>ALL MODULES</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(380px, 1fr))", gap: 12 }}>
          {sorted.map((mod, i) => {
            const ms = mod.score ?? 0;
            const mc = scoreColor(ms);
            const isCritical = ms < 40;
            return (
              <button key={mod.name} onClick={() => onModuleClick(mod.name)} style={{
                ...mCard({ padding: "20px 24px", cursor: "pointer", textAlign: "left" }),
                display: "flex", alignItems: "center", gap: 16, width: "100%",
                fontFamily: "inherit", transition: "all 0.2s ease",
                animation: `fadeInUp 0.3s ease-out ${i * 0.03}s both`,
                boxShadow: isCritical ? "0 0 24px rgba(248,81,73,0.08)" : "none",
              }}
                onMouseEnter={e => { e.currentTarget.style.background = M.cardLt; e.currentTarget.style.transform = "translateY(-1px)"; }}
                onMouseLeave={e => { e.currentTarget.style.background = M.card; e.currentTarget.style.transform = "translateY(0)"; }}
              >
                <div style={{ width: 42, height: 42, borderRadius: 12, background: `${mc}15`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                  <ModuleIcon name={mod.name} size={20} color={mc} />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 14, fontWeight: 600, color: T.text, marginBottom: 6 }}>{mod.name}</div>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <div style={{ flex: 1, height: 4, borderRadius: 2, background: M.border, overflow: "hidden" }}>
                      <div style={{ height: "100%", borderRadius: 2, background: mc, width: `${ms}%`, transition: "width 0.8s ease-out" }} />
                    </div>
                    <span style={{ fontSize: 12, color: M.dim, whiteSpace: "nowrap" }}>{mod.issues} issue{mod.issues !== 1 ? "s" : ""}</span>
                  </div>
                </div>
                <div style={{ fontSize: 24, fontWeight: 800, color: mc, fontVariantNumeric: "tabular-nums", minWidth: 34, textAlign: "right" }}>{ms}</div>
              </button>
            );
          })}
        </div>
      </div>
    </Shell>
  );
}


/* ═══════════════════════════════════════════════════════════════
   MODULE DETAIL
   ═══════════════════════════════════════════════════════════════ */

function ModuleDetailView({ mod, onBack }: { mod: Module; onBack: () => void; onHome: () => void }) {
  const s = mod.score ?? 0;
  const color = scoreColor(s);

  const highIssues = mod.details.filter(d => ["high", "critical"].includes((d.severity || "").toLowerCase()));
  const medIssues = mod.details.filter(d => (d.severity || "").toLowerCase() === "medium");
  const lowIssues = mod.details.filter(d => !["high", "critical", "medium"].includes((d.severity || "").toLowerCase()));

  return (
    <Shell>
      <div style={{ maxWidth: 1260, margin: "0 auto", padding: "28px 24px 80px", animation: "dashboardReveal 0.4s ease-out" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
          <button onClick={onBack} style={{ ...linkBtn, fontSize: 14, padding: "8px 20px", background: M.card, borderRadius: 10, color: T.text, fontWeight: 600 }}
            onMouseEnter={e => { e.currentTarget.style.background = M.cardLt; }}
            onMouseLeave={e => { e.currentTarget.style.background = M.card; }}
          >← Dashboard</button>
          <span style={{ fontSize: 12, color: M.dim }}>Dashboard / {mod.name}</span>
        </div>

        {/* Header */}
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 12, marginBottom: 24 }}>
          <div style={mCard({ display: "flex", flexDirection: "column", justifyContent: "space-between" })}>
            <div style={{ fontSize: 12, fontWeight: 600, color: M.dim, textTransform: "uppercase", letterSpacing: 1.5 }}>{mod.name}</div>
            <div style={{ display: "flex", alignItems: "baseline", gap: 16, marginTop: 10 }}>
              <span style={{ fontSize: 64, fontWeight: 900, lineHeight: 1, color, fontVariantNumeric: "tabular-nums" }}>{s}</span>
              <span style={{ fontSize: 18, color: M.dim }}>/100</span>
            </div>
            <div style={{ display: "flex", gap: 10, marginTop: 16, flexWrap: "wrap" }}>
              <Chip label="Total" value={mod.issues} />
              {highIssues.length > 0 && <Chip label="Critical" value={highIssues.length} color={T.red} />}
              {medIssues.length > 0 && <Chip label="Medium" value={medIssues.length} color={T.orange} />}
              {lowIssues.length > 0 && <Chip label="Low" value={lowIssues.length} color={T.blue} />}
            </div>
          </div>
          <div style={mCard({ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", textAlign: "center" })}>
            <div style={{ width: 56, height: 56, borderRadius: 14, background: `${color}15`, display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 12 }}>
              <ModuleIcon name={mod.name} size={28} color={color} />
            </div>
            <div style={{ fontSize: 14, fontWeight: 700, color: T.text }}>{mod.name}</div>
            <div style={{ fontSize: 12, color: M.dim, marginTop: 4 }}>{s >= 80 ? "Passing" : s >= 50 ? "Review" : "Critical"}</div>
          </div>
        </div>

        {(mod.warning || mod.error) && (
          <div style={mCard({ padding: "14px 20px", marginBottom: 16, display: "flex", alignItems: "center", gap: 12, background: "rgba(210,153,34,0.08)" })}>
            <span style={{ fontWeight: 900, fontSize: 16, color: T.yellow }}>!</span>
            <span style={{ fontSize: 14, color: T.yellow, lineHeight: 1.5 }}>{mod.warning || mod.error}</span>
          </div>
        )}

        {mod.details.length === 0 ? (
          <div style={mCard({ padding: "48px", textAlign: "center" })}>
            <div style={{ fontSize: 18, fontWeight: 700, color: T.green }}>All clear</div>
            <div style={{ fontSize: 14, color: M.dim, marginTop: 6 }}>No issues found in this module.</div>
          </div>
        ) : (
          <>
            {highIssues.length > 0 && <IssueGroup label="CRITICAL / HIGH" color={T.red} issues={highIssues} />}
            {medIssues.length > 0 && <IssueGroup label="MEDIUM" color={T.orange} issues={medIssues} />}
            {lowIssues.length > 0 && <IssueGroup label="LOW / INFO" color={T.blue} issues={lowIssues} />}
          </>
        )}

        <div style={{ marginTop: 40, display: "flex", justifyContent: "center" }}>
          <button onClick={onBack} style={{ padding: "10px 32px", borderRadius: 10, background: M.card, color: T.text, fontSize: 14, fontWeight: 600, cursor: "pointer", fontFamily: "inherit", transition: "all 0.15s", border: "none" }}
            onMouseEnter={e => { e.currentTarget.style.background = M.cardLt; }}
            onMouseLeave={e => { e.currentTarget.style.background = M.card; }}
          >← Back to Dashboard</button>
        </div>
      </div>
    </Shell>
  );
}


/* ─── ISSUE GROUP ────────────────────────────────────────── */

function IssueGroup({ label, color, issues }: { label: string; color: string; issues: Issue[] }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
        <div style={{ width: 10, height: 3, borderRadius: 2, background: color }} />
        <span style={{ fontSize: 12, fontWeight: 700, color, letterSpacing: 1 }}>{label}</span>
        <span style={{ fontSize: 12, fontWeight: 700, color: M.dim }}>{issues.length}</span>
      </div>
      <div style={{ borderRadius: M.radius, overflow: "hidden" }}>
        {issues.map((issue, i) => (
          <div key={i} style={{ display: "grid", gridTemplateColumns: "minmax(140px, 260px) 1fr", gap: 20, padding: "16px 20px", background: i % 2 === 0 ? M.card : M.cardLt }}>
            <div style={{ minWidth: 0 }}>
              {issue.type && <div style={{ fontSize: 13, fontWeight: 700, color: T.text, marginBottom: 4 }}>{issue.type}</div>}
              {issue.file && <div style={{ fontSize: 12, fontFamily: "monospace", color: T.blue, wordBreak: "break-all" }}>{issue.file}{issue.line != null ? `:${issue.line}` : ""}</div>}
              {issue.severity && (
                <span style={{ display: "inline-block", marginTop: 6, fontSize: 10, fontWeight: 700, textTransform: "uppercase", padding: "3px 8px", borderRadius: 6, background: `${sevColor(issue.severity)}15`, color: sevColor(issue.severity) }}>{issue.severity}</span>
              )}
            </div>
            <div>
              {issue.reason && <p style={{ fontSize: 14, color: T.text2, lineHeight: 1.6, margin: 0 }}>{issue.reason}</p>}
              {issue.snippet && (
                <pre style={{ marginTop: 8, padding: "10px 12px", borderRadius: 8, background: M.bg, border: `1px solid ${M.border}`, fontSize: 12, color: T.text, fontFamily: "monospace", overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{issue.snippet}</pre>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}


/* ─── REUSABLE ───────────────────────────────────────────── */

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ background: M.bg, minHeight: "100vh", color: T.text }}>
      <nav style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "14px 24px", borderBottom: `1px solid ${M.border}` }}>
        <span style={{ fontWeight: 700, fontSize: 15, color: T.text }}>Ybe Check</span>
        <a href="https://github.com/darshiyer/A2K2-PS1" target="_blank" rel="noopener noreferrer" style={{ fontSize: 12, color: M.dim, textDecoration: "none" }}>GitHub ↗</a>
      </nav>
      {children}
    </div>
  );
}

function Chip({ label, value, color }: { label: string; value: number; color?: string }) {
  const c = color || T.text;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "5px 14px", borderRadius: 8, background: `${c}12`, fontSize: 13, fontWeight: 600, color: c }}>
      <span style={{ fontWeight: 800 }}>{value}</span> {label}
    </span>
  );
}

const linkBtn: React.CSSProperties = {
  background: "none", border: "none", cursor: "pointer", fontFamily: "inherit",
  fontSize: 13, color: M.dim, padding: 0, transition: "all 0.15s",
};
