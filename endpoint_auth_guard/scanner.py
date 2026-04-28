from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .config import AuditConfig

SCAN_EXTENSIONS = {".py", ".js", ".ts", ".mjs", ".cjs", ".java", ".kt"}

SKIP_DIRS = {"__pycache__", "node_modules", ".venv", "venv", "dist", "build", ".git", ".next", "target"}


@dataclass
class EndpointInfo:
    file_path: str
    line_number: int
    method: str
    path: str
    function_name: str
    has_auth: bool
    auth_type: str | None = None
    is_allowlisted: bool = False


@dataclass
class ScanResult:
    file_path: str
    is_route_file: bool
    endpoints: list[EndpointInfo] = field(default_factory=list)
    framework: str | None = None
    router_has_dependencies: bool = False
    router_variable_name: str | None = None

    @property
    def unprotected_endpoints(self) -> list[EndpointInfo]:
        return [e for e in self.endpoints if not e.has_auth and not e.is_allowlisted]

    @property
    def protected_endpoints(self) -> list[EndpointInfo]:
        return [e for e in self.endpoints if e.has_auth or e.is_allowlisted]


def scan_file(file_path: Path, config: AuditConfig) -> ScanResult:
    if file_path.suffix.lower() not in SCAN_EXTENSIONS:
        return ScanResult(file_path=str(file_path), is_route_file=False)

    try:
        source = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ScanResult(file_path=str(file_path), is_route_file=False)

    from .parsers import detect_framework
    parser = detect_framework(source, file_path)
    if parser is None:
        return ScanResult(file_path=str(file_path), is_route_file=False)

    return parser.parse(source, file_path, config)


def scan_directory(directory: Path, config: AuditConfig) -> list[ScanResult]:
    results = []
    for source_file in sorted(directory.rglob("*")):
        if not source_file.is_file():
            continue
        if source_file.suffix.lower() not in SCAN_EXTENSIONS:
            continue
        if any(part.startswith(".") for part in source_file.parts):
            continue
        if any(part in SKIP_DIRS for part in source_file.parts):
            continue
        result = scan_file(source_file, config)
        if result.is_route_file:
            results.append(result)
    return results


def scan_files(file_paths: list[Path], config: AuditConfig) -> list[ScanResult]:
    results = []
    for fp in file_paths:
        result = scan_file(fp, config)
        if result.is_route_file:
            results.append(result)
    return results
