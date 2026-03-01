<!-- mcp-name: io.github.AddyCuber/ybe-check -->

# Ybe Check 🛡️

**Production-readiness security gatekeeper for vibe-coded apps.**

16 scan modules · AI remediation · MCP server · VS Code + Copilot · Bento dashboard

[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/AddyCuber/A2K2-PS1)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

## Quick Start

```bash
pip install .
ybe-check init          # Extension + MCP + Scan + Dashboard in one command
```

## CLI

```bash
ybe-check scan .                              # Run all 16 modules
ybe-check report --severity high              # Show high-severity findings
ybe-check dashboard                           # Launch bento grid dashboard
ybe-check setup                               # Install extension + configure MCP
```

## MCP Server (7 tools, 3 prompts)

```bash
python -m ybe_check.mcp_server                # stdio transport
```

Tools: `ybe.scan_repo` · `ybe.list_findings` · `ybe.get_remediation` · `ybe.get_security_context` · `ybe.enhance_prompt` · `ybe.get_fix_prompt` · `ybe.get_review_prompt`

Prompts: `security-audit` · `fix-critical` · `review-file`

## VS Code Extension (13 commands)

Auto-installs MCP on activation. Open Command Palette → "Ybe Check" to scan, audit, fix, and chat with Copilot.

## Dashboard

```bash
ybe-check dashboard     # http://127.0.0.1:7474
```

See [A2K2/README.md](A2K2/README.md) for full documentation.
