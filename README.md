## Fake Vibe App (for Vibe-Audit testing)

This repository is a deliberately vulnerable/demo project for testing Vibe-Audit behavior.

It contains examples of:
- Hardcoded API keys and secrets
- Prompt templates that are vulnerable to prompt-injection
- Hallucinated / suspicious dependencies
- PII handling and excessive logging
- Insecure routes (no auth middleware)
- Dockerfile and Terraform sample for infra scanning

Run your VS Code extension or the `vibe_audit` CLI against this folder to verify detection.
