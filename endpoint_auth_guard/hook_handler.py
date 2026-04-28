from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from .config import load_config
from .scanner import scan_files
from .reporter import build_report, format_console, should_fail


def _is_git_commit(command: str) -> bool:
    return bool(re.search(r"\bgit\s+commit\b", command))


SCAN_EXTENSIONS = {".py", ".js", ".ts", ".mjs", ".cjs", ".java", ".kt"}


def _get_staged_source_files() -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True, timeout=10,
        )
        return [
            Path(f) for f in result.stdout.strip().splitlines()
            if Path(f).suffix.lower() in SCAN_EXTENSIONS
        ]
    except (subprocess.SubprocessError, FileNotFoundError):
        return []


def _is_route_file(path: Path) -> bool:
    try:
        content = path.read_text(encoding="utf-8")
        from .parsers import detect_framework
        return detect_framework(content, path) is not None
    except (OSError, UnicodeDecodeError):
        return False


def main() -> None:
    try:
        hook_input = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        print("{}")
        return

    tool_input = hook_input.get("tool_input", {})
    command = tool_input.get("command", "")

    if not _is_git_commit(command):
        print("{}")
        return

    staged_files = _get_staged_source_files()
    route_files = [f for f in staged_files if f.exists() and _is_route_file(f)]

    if not route_files:
        print("{}")
        return

    try:
        config = load_config()
        config.analysis.enabled = False

        results = scan_files(route_files, config)
        report = build_report(results, config)

        if not should_fail(report, "HIGH"):
            print("{}")
            return

        from io import StringIO
        buf = StringIO()
        format_console(report, buf)
        summary = buf.getvalue()

        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    "Security audit FAILED -- unprotected endpoints detected:\n\n"
                    + summary
                ),
            }
        }
        print(json.dumps(output))

    except Exception as e:
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": f"Security audit hook error (fail-open): {e}",
            }
        }
        print(json.dumps(output))


if __name__ == "__main__":
    main()
