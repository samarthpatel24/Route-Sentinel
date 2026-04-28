from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from .config import load_config
from .scanner import scan_directory, scan_files
from .reporter import build_report, FORMATTERS, should_fail


def get_staged_python_files() -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True, check=True,
        )
        return [Path(f) for f in result.stdout.strip().splitlines() if f.endswith(".py")]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


HOOK_CONFIG = {
    "hooks": {
        "PreToolUse": [
            {
                "matcher": "Bash",
                "hooks": [
                    {
                        "type": "command",
                        "command": "python -m src.hook_handler",
                        "timeout": 30,
                    }
                ],
            }
        ]
    }
}

SLASH_COMMAND = """\
Scan all Python files in the current project for FastAPI route definitions and check each endpoint for proper authentication dependencies.

Steps:
1. Find all Python files that contain FastAPI route definitions (APIRouter, @router.get/post/etc, @app.get/post/etc)
2. For each endpoint, check if it has proper auth via Depends(get_current_user) or similar patterns
3. List any endpoints missing authentication with their file path, line number, HTTP method, and route path
4. Classify severity: CRITICAL for data/credential access, HIGH for state-changing operations, MEDIUM for read-only business data, LOW for metadata, INFO for health checks
5. For each unprotected endpoint, suggest the specific Depends(...) import and parameter to add
6. Summarize the overall security posture

You can run the scanner directly:
```
python -m src.cli scan . --format console
```

Or for JSON output:
```
python -m src.cli scan . --format json
```

To scan only staged git files:
```
python -m src.cli scan . --git-diff --format console
```
"""

DEFAULT_CONFIG = """\
version: 1

# Endpoints that are intentionally public (no auth required)
allowlist:
  - path: "/health"
    reason: "Load balancer health check"
  - path: "/docs"
    reason: "OpenAPI documentation"
  - path: "/openapi.json"
    reason: "OpenAPI schema"
  - path: "/redoc"
    reason: "ReDoc documentation"
  - path: "/auth/login"
    reason: "Authentication endpoint"
  - path: "/auth/register"
    reason: "Registration endpoint"
  - path: "/auth/token"
    reason: "Token endpoint"

# Patterns recognized as valid authentication
auth_patterns:
  - "get_current_user"
  - "get_current_active_user"
  - "require_roles"
  - "require_admin"
  - "verify_api_key"
  - "get_api_key"
  - "oauth2_scheme"
  - "HTTPBearer"
  - "HTTPBasic"
  - "SecurityScopes"

# Severity classification rules
severity_rules:
  critical_path_patterns:
    - "/database"
    - "/admin"
    - "/users"
    - "/credentials"
    - "/sessions"
    - "/api-keys"
  high_path_patterns:
    - "/data"
    - "/export"
    - "/import"
    - "/delete"
    - "/consent"
    - "/data-rights"

# LLM analysis settings
analysis:
  enabled: true
  model: "claude-sonnet-4-6"
  skip_if_all_protected: true
"""


def run_init(project_dir: Path) -> int:
    import json

    claude_dir = project_dir / ".claude"
    commands_dir = claude_dir / "commands"
    settings_path = claude_dir / "settings.json"
    command_path = commands_dir / "security-audit.md"
    config_path = project_dir / ".security-audit.yaml"

    commands_dir.mkdir(parents=True, exist_ok=True)

    created = []
    skipped = []

    if settings_path.exists():
        skipped.append(str(settings_path))
    else:
        settings_path.write_text(json.dumps(HOOK_CONFIG, indent=2) + "\n", encoding="utf-8")
        created.append(str(settings_path))

    if command_path.exists():
        skipped.append(str(command_path))
    else:
        command_path.write_text(SLASH_COMMAND, encoding="utf-8")
        created.append(str(command_path))

    if config_path.exists():
        skipped.append(str(config_path))
    else:
        config_path.write_text(DEFAULT_CONFIG, encoding="utf-8")
        created.append(str(config_path))

    if created:
        print("  Created:")
        for f in created:
            print(f"    {f}")
    if skipped:
        print("  Skipped (already exists):")
        for f in skipped:
            print(f"    {f}")

    print("\n  Setup complete. The security scanner will now:")
    print("    - Block commits with unprotected endpoints (via Claude Code hook)")
    print("    - Provide /security-audit slash command for on-demand scans")
    print("    - Use .security-audit.yaml for configuration")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="security-audit",
        description="FastAPI endpoint authentication scanner",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("init", help="Set up Claude Code hook, slash command, and config in current project")
    scan_parser = subparsers.add_parser("scan", help="Scan for unprotected endpoints")
    scan_parser.add_argument("target", nargs="?", default=".", help="Directory or file to scan")
    scan_parser.add_argument("--files", nargs="+", help="Specific files to scan")
    scan_parser.add_argument("--config", type=Path, help="Path to .security-audit.yaml")
    scan_parser.add_argument("--format", choices=["console", "json", "github"], default="console")
    scan_parser.add_argument("--output", type=Path, help="Write report to file")
    scan_parser.add_argument("--no-llm", action="store_true", help="Skip LLM analysis")
    scan_parser.add_argument("--git-diff", action="store_true", help="Only scan staged git files")
    scan_parser.add_argument(
        "--severity-threshold", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="HIGH", help="Fail threshold (default: HIGH)",
    )
    scan_parser.add_argument("--exit-code", action="store_true", help="Return non-zero on findings")

    args = parser.parse_args(argv)

    if args.command == "init":
        return run_init(Path.cwd())

    if args.command != "scan":
        parser.print_help()
        return 0

    config = load_config(args.config)

    if args.no_llm:
        config.analysis.enabled = False

    if args.git_diff:
        file_paths = get_staged_python_files()
        if not file_paths:
            if args.format == "console":
                print("  No staged Python files to scan.")
            return 0
        results = scan_files(file_paths, config)
    elif args.files:
        file_paths = [Path(f) for f in args.files]
        results = scan_files(file_paths, config)
    else:
        target = Path(args.target)
        if target.is_file():
            results = scan_files([target], config)
        else:
            results = scan_directory(target, config)

    if config.analysis.enabled and not args.no_llm:
        files_with_issues = [r for r in results if r.unprotected_endpoints]
        if files_with_issues:
            try:
                from .analyzer import analyze_results
                results = analyze_results(results, config)
            except Exception as e:
                print(f"  Warning: LLM analysis failed ({e}), using regex-only results", file=sys.stderr)

    report = build_report(results, config)

    formatter = FORMATTERS[args.format]
    if args.output:
        with open(args.output, "w") as f:
            formatter(report, f)
    else:
        formatter(report)

    if args.exit_code and should_fail(report, args.severity_threshold):
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
