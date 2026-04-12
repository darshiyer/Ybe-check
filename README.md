<!-- mcp-name: io.github.AddyCuber/ybe-check -->

# Ybe Check

**Security scanner for AI-generated code. Catches what your copilot missed.**

10 static scan modules · MCP server · VS Code extension · Web dashboard

[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/AddyCuber/A2K2-PS1)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

## Quick Start

```bash
pip install .
ybe-check init          # Install extension + configure MCP + scan + dashboard
```

## What it scans

| Module | What it catches |
|--------|----------------|
| Secrets | Hardcoded API keys, tokens, passwords |
| Prompt Injection | Unsafe LLM prompt templates, jailbreak vectors |
| PII & Logging | Personal data in logs, exposed user info |
| Dependencies | Known vulnerable packages, hallucinated packages |
| Auth Guards | Unprotected routes, missing middleware, CORS issues |
| IaC Security | Terraform/Docker/K8s misconfigurations |
| License Compliance | GPL/AGPL risks, license conflicts |
| AI Traceability | LLM artifacts left in code (backticks, "Certainly!") |
| Config & Env | Exposed .env files, debug mode, weak defaults |
| Test Coverage | Missing test frameworks, untested code paths |

## CLI

```bash
ybe-check scan .                              # Run static scan
ybe-check scan . --dynamic                    # Include dynamic modules (needs external tools)
ybe-check report --severity high              # Filter findings
ybe-check dashboard                           # Web dashboard at :7474
```

## MCP Server

Your AI assistant (Claude, Copilot, Cursor) can call Ybe Check directly:

```bash
python -m ybe_check.mcp_server                # stdio transport
```

**7 tools:** `ybe.scan_repo` · `ybe.list_findings` · `ybe.get_remediation` · `ybe.get_security_context` · `ybe.enhance_prompt` · `ybe.get_fix_prompt` · `ybe.get_review_prompt`

**3 prompts:** `security-audit` · `fix-critical` · `review-file`

## VS Code Extension

Install the `.vsix` from releases or let `ybe-check init` handle it. Opens a sidebar panel with scan results, per-module scores, and one-click AI fix prompts.

## Advanced: Dynamic modules

These require external tools and a live target:

| Module | Requires |
|--------|----------|
| Load Testing | `artillery` (npm) |
| Web Attacks | OWASP ZAP + Docker |
| API Fuzzing | `ffuf` |
| Live Prompt Testing | `vigil-llm` + API keys |

Run with `ybe-check scan . --dynamic` after installing the required tools.

## License

Apache 2.0 — see [LICENSE](LICENSE).
