# AI Usage Disclosure

This project uses AI-assisted development tools. This file documents how and where
AI was used, in accordance with responsible AI development practices.

## Tools Used

| Tool | Purpose |
|------|---------|
| Claude (Anthropic) | Code generation, module architecture, regex design |
| GitHub Copilot | Inline completions during development |

## Scope of AI Assistance

### Generated with AI assistance
- Initial scaffolding of static analysis modules (`modules/`)
- Regex patterns for PII detection (`pii_logging.py`)
- Pure-Python IaC rule engine (`iac_security.py`)
- Sidebar WebviewView HTML/CSS (`src/sidebar/sidebarTemplate.ts`)
- AI fix prompt templates (`src/sidebar/promptBuilder.ts`)

### Human-reviewed and validated
- All security detection logic (patterns, thresholds, scoring)
- Module contract interface (`scan(repo_path) -> dict`)
- Weighted scoring formula (`cli.py`)
- License risk classification table (`license_compliance.py`)
- Extension activation and command registration (`extension.ts`)

### Not AI-generated
- Project architecture decisions
- Security rule selection and severity assignments
- Deployment and publishing configuration
- Test cases in `A2K2-test/`

## Review Process

Every AI-generated code block was:
1. Read and understood before being committed
2. Tested against real repositories
3. Checked for security anti-patterns (no eval, no shell injection, no hardcoded secrets)

## Notes

The Ybe Check scanner itself is designed to detect AI-generated code that lacks
proper review. This project practices what it scans for — all AI output was
reviewed before use.
