# Changelog

## 1.0.0 — Production Release

### Extension
- 🎨 **New icon** — `icon.png` logo in marketplace and sidebar
- ⚡ **MCP auto-install** — extension automatically installs `ybe-check` Python package and writes `.vscode/mcp.json` + `.cursor/mcp.json` on activation
- 🤖 **13 Copilot commands** — Full Scan, Static Scan, Ask Copilot, Fix Finding, Security Audit, Explain Finding, Review File, Fix All Critical, Fix Current File, Secure Implementation, Browse by Severity, Install MCP, Open Dashboard
- 🎯 **High-quality prompt engineering** — every command builds structured markdown prompts with severity icons, CWE references, and contextual code snippets
- 🖥️ **Bento grid webview** — aurora hero card, security persona, verdict gradient, module score bars, findings table with Fix ⚡ buttons
- 🌐 **Open Dashboard** command — launches full localhost dashboard and opens browser

### MCP Server
- 🔧 **7 tools**: `ybe.scan_repo`, `ybe.list_findings`, `ybe.get_remediation`, `ybe.get_security_context`, `ybe.enhance_prompt`, `ybe.get_fix_prompt`, `ybe.get_review_prompt`
- 📝 **3 prompt templates**: `security-audit`, `fix-critical`, `review-file`
- 📡 Stdio + HTTP transports
- `server.json` updated with all tools, prompts, and schema

### Dashboard (localhost)
- 🎨 **Full redesign** to modern bento grid layout matching the website
- Aurora gradient hero with animated score
- Security persona card (Champion / Cautious Builder / Risk Taker)
- Module scores with progress bars
- Verdict gradient card with health dots
- Paginated findings table with severity pills
- AI remediation modal with step-by-step fixes
- Chat sidebar with AI assistant

### CLI
- All commands (`scan`, `report`, `setup`, `init`, `dashboard`) working
- `ybe-check init` — one-command setup: extension + MCP + scan + dashboard
- Version bumped to 1.0.0

### Python Package
- 16 scan modules across static, dynamic, and infra categories
- AI enrichment chain: Blackbox AI → Google Gemini → static fallback
- Unified findings schema with `make_finding()` and `detail_to_finding()`

## 0.1.0

- Initial release: secrets detection for vibe-coded repos
- Bundled Python CLI for zero-config scanning
- WebView report with Ybe-to-Value score
- Status bar integration for one-click audits
- Supports custom Python path via `ybe-check.pythonPath` setting
