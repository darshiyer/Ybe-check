<!-- mcp-name: io.github.AddyCuber/ybe-check -->

# Ybe Check

Production-readiness gatekeeper for vibe-coded apps. Scans repos for secrets, prompt injection, PII, dependencies, auth, IaC, SBOM, and more.

## CLI

```bash
pip install .
ybe-check scan .
ybe-check report --format table --severity high
```

## MCP Server

```bash
python -m ybe_check.mcp_server
```

See [A2K2/README.md](A2K2/README.md) for full documentation.
