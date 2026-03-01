# 🔌 How to Access the Ybe Check MCP in VS Code / GitHub Copilot

## ✅ Current Status

Your MCP server **IS ALREADY CONFIGURED** and ready to use!

---

## 📍 Where to See the MCP in VS Code

### 1. **MCP Config File** ✅ Already Created

Location: `.vscode/mcp.json`

```json
{
  "mcpServers": {
    "ybe-check": {
      "command": "python3",
      "args": ["-m", "ybe_check.mcp_server"]
    }
  }
}
```

This file tells VS Code / Copilot Chat where to find your MCP server.

---

### 2. **Extension Package.json** 📦

Location: `A2K2/package.json`

The extension declares the MCP server in the `contributes.mcpServers` section:

```json
"mcpServers": {
  "ybe-check": {
    "command": "${config:ybe-check.pythonPath}",
    "args": ["-m", "ybe_check.mcp_server"],
    "description": "Ybe Check – security scanner with prompt engineering..."
  }
}
```

---

### 3. **How the Extension Sets Up MCP** 🔧

Location: `A2K2/src/extension.ts` (lines 12-60)

When the extension activates, it automatically:

1. **Creates `.vscode/mcp.json`** in your workspace
2. **Creates `.cursor/mcp.json`** if you use Cursor
3. **Registers the MCP server** with the command: `python3 -m ybe_check.mcp_server`

```typescript
function ensureMcpConfig(context: vscode.ExtensionContext) {
    // ...
    // Write .vscode/mcp.json (VS Code native MCP support)
    const vscodeDir = path.join(root, '.vscode');
    writeMcpFile(vscodeDir, path.join(vscodeDir, 'mcp.json'), pythonPath);

    // Write .cursor/mcp.json (Cursor support)
    const cursorDir = path.join(root, '.cursor');
    writeMcpFile(cursorDir, path.join(cursorDir, 'mcp.json'), pythonPath);
}
```

---

## 🎯 How to ACCESS the MCP Tools

### Option 1: GitHub Copilot Chat (Recommended)

1. **Open GitHub Copilot Chat** in VS Code (click the chat icon or `Cmd+Shift+I`)

2. **Type `@workspace`** followed by your question — Copilot will automatically have access to the MCP tools

3. **The MCP tools available to Copilot:**
   - `ybe.scan_repo` — Run a security scan
   - `ybe.list_findings` — List findings by severity
   - `ybe.get_remediation` — Get fix guidance
   - `ybe.get_security_context` — Get security summary
   - `ybe.enhance_prompt` — Wrap prompts with security context
   - `ybe.get_fix_prompt` — Generate fix prompts
   - `ybe.get_review_prompt` — Generate review prompts

4. **Example prompts to try:**
   ```
   @workspace Run a security scan on this project
   @workspace Show me critical security findings
   @workspace How do I fix finding secrets:0?
   @workspace Review app.py for security issues
   ```

### Option 2: VS Code Extension Commands

The extension also provides direct Copilot integration commands:

| Command | What it does |
|---------|-------------|
| **Ybe Check: Ask Copilot** | Opens Copilot with security context injected |
| **Ybe Check: Fix Finding with Copilot** | Pick a finding and get a fix prompt |
| **Ybe Check: Security Audit with Copilot** | Full security audit via Copilot |

Access via:
- Command Palette (`Cmd+Shift+P`) → type "Ybe Check"
- Or the scan button in the status bar

### Option 3: Cursor AI (if using Cursor editor)

The extension also creates `.cursor/mcp.json` for Cursor users. Same workflow — just chat with Cursor AI and it will have access to the MCP tools.

---

## 🔍 How to VERIFY the MCP is Working

### Test 1: Check if the MCP server starts

```bash
cd /Users/adityaray/Desktop/hackx
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}' | python3 -m ybe_check.mcp_server 2>/dev/null | head -1
```

**Expected output:**
```json
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":...}}
```

### Test 2: Run the full test suite

```bash
cd /Users/adityaray/Desktop/hackx
.venv/bin/python _test_mcp.py
```

**Expected:** All 7 tools + 3 prompts pass ✅

### Test 3: Ask Copilot

Open Copilot Chat and try:
```
@workspace Get security context for this project
```

If Copilot responds with security scores and findings, the MCP is working!

---

## 🚀 Demo for Judges

### Quick Demo Flow (30 seconds)

1. **Show the MCP config file:**
   ```bash
   cat .vscode/mcp.json
   ```

2. **Run the test script:**
   ```bash
   .venv/bin/python _test_mcp.py
   ```
   → Shows all 7 tools passing ✅

3. **Open Copilot Chat in VS Code:**
   - Type: `@workspace Get security context`
   - Copilot will call the MCP and return: Score 34/100, 3139 findings, etc.

4. **Show a live tool call:**
   - Type: `@workspace List critical security findings`
   - Copilot calls `ybe.list_findings(severity="critical")` → 54 findings

5. **Fix a finding with Copilot:**
   - Run: `Ybe Check: Fix Finding with Copilot`
   - Pick `secrets:0` (GitHub token)
   - Copilot generates exact code fix

---

## 📊 Architecture Summary

```
┌─────────────────────────────────────────────────────────┐
│  GitHub Copilot Chat / Cursor AI                        │
│  (VS Code integrated AI assistant)                      │
└────────────────┬────────────────────────────────────────┘
                 │
                 │ Reads .vscode/mcp.json
                 │
                 v
┌─────────────────────────────────────────────────────────┐
│  MCP Server (ybe-check)                                 │
│  Command: python3 -m ybe_check.mcp_server               │
│  Protocol: JSON-RPC over stdio                          │
└────────────────┬────────────────────────────────────────┘
                 │
                 │ Provides 7 tools + 3 prompts
                 │
                 v
┌─────────────────────────────────────────────────────────┐
│  Ybe Check Core Engine                                  │
│  - src/ybe_check/core.py (scan orchestration)          │
│  - A2K2/modules/* (16 security modules)                │
│  - ybe-report.json (cached scan results)               │
└─────────────────────────────────────────────────────────┘
```

---

## ❓ Answers to Your Questions

### Q1: Where can I see the MCP model in VS Code?

**Answer:**
- The MCP server configuration is in `.vscode/mcp.json`
- You don't see the MCP "model" directly — it runs in the background
- Copilot Chat automatically uses it when you type `@workspace`
- You can verify it's working by asking Copilot security questions

### Q2: Can you access the MCP through the extension?

**Answer:**
- **YES!** The extension has 3 built-in commands that integrate with Copilot:
  1. `Ybe Check: Ask Copilot` — Injects security context into Copilot
  2. `Ybe Check: Fix Finding with Copilot` — Generate fix prompts
  3. `Ybe Check: Security Audit with Copilot` — Full audit via Copilot

- These commands build prompts with scan data and open Copilot Chat automatically

### Q3: Is the extension downloading the MCP?

**Answer:**
- **NO, the extension doesn't download the MCP**
- The MCP server is **already part of your Python package** (`ybe-check`)
- The extension just **configures VS Code to use it** by creating `.vscode/mcp.json`
- The MCP server code is in: `src/ybe_check/mcp_server.py` (503 lines)

---

## 🎓 For the Judges

**Key Points:**

1. **The MCP server is fully functional** — all 7 tools + 3 prompts pass tests
2. **It's integrated into VS Code** — via `.vscode/mcp.json` and the extension
3. **Copilot can access it** — just use `@workspace` in Copilot Chat
4. **It's production-ready** — 3,139 findings detected, score 34/100 on this repo
5. **It follows the MCP spec** — proper JSON-RPC protocol, matches the official schema

**Live Demo Script:**
```bash
# 1. Show the config
cat .vscode/mcp.json

# 2. Run tests
.venv/bin/python _test_mcp.py

# 3. Open VS Code Copilot Chat
# Type: @workspace Get security context for this project
# Watch Copilot call the MCP and return scan results!
```

---

## 🔗 Files to Review

| File | Purpose |
|------|---------|
| `.vscode/mcp.json` | MCP server config (auto-generated by extension) |
| `src/ybe_check/mcp_server.py` | MCP server implementation (503 lines) |
| `server.json` | MCP server manifest (follows official schema) |
| `A2K2/src/extension.ts` | Extension that sets up the MCP |
| `_test_mcp.py` | Test suite proving all tools work |

---

**You're all set! The MCP is ready to demo. 🎉**
