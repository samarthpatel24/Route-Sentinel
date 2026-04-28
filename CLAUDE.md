# FastAPI Security Audit Agent

Scans FastAPI projects for endpoints missing authentication. Two-layer architecture: fast AST-based detection + optional LLM analysis via Anthropic API.

## Quick start

```bash
pip install -r requirements.txt
python -m src.cli scan <directory> --format console
```

## Three enforcement points

1. **Claude Code hook** — blocks `git commit` when staged route files have unprotected HIGH/CRITICAL endpoints (fail-open on errors)
2. **GitHub Actions** — blocks PR merge, annotates findings inline (`--format github`)
3. **`/security-audit` slash command** — on-demand audit in Claude Code

## Commands

```bash
# Console report
python -m src.cli scan . --format console

# JSON report
python -m src.cli scan . --format json

# GitHub Actions annotations
python -m src.cli scan . --format github --exit-code --severity-threshold HIGH

# Scan only staged files
python -m src.cli scan . --git-diff --format console

# Skip LLM layer
python -m src.cli scan . --no-llm --format console
```

## Tests

```bash
python -m pytest tests/ -v
```

## Configuration

Edit `.security-audit.yaml` to customize allowlisted paths, auth patterns, severity rules, and LLM settings.
