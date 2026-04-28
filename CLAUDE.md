# Endpoint Auth Guard

Scans backend projects for endpoints missing authentication. Supports FastAPI, Flask, Django REST, Express.js, and Spring Boot. Two-layer architecture: fast AST/regex detection + optional LLM analysis via Anthropic API.

## Quick start

```bash
pip install -r requirements.txt
security-audit scan <directory> --format console
```

## Three enforcement points

1. **Claude Code hook** — blocks `git commit` when staged route files have unprotected HIGH/CRITICAL endpoints (fail-open on errors)
2. **GitHub Actions** — blocks PR merge, annotates findings inline (`--format github`)
3. **`/security-audit` slash command** — on-demand audit in Claude Code

## Commands

```bash
# Console report
security-audit scan . --format console

# JSON report
security-audit scan . --format json

# GitHub Actions annotations
security-audit scan . --format github --exit-code --severity-threshold HIGH

# Scan only staged files
security-audit scan . --git-diff --format console

# Skip LLM layer
security-audit scan . --no-llm --format console

# Set up Claude Code integration in a project
security-audit init
```

## Tests

```bash
python -m pytest tests/ -v
```

## Configuration

Edit `.security-audit.yaml` to customize allowlisted paths, auth patterns, severity rules, and LLM settings.
