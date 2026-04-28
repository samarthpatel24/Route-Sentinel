from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ..scanner import EndpointInfo, ScanResult
from ..config import AuditConfig


class FrameworkParser(Protocol):
    name: str
    file_extensions: tuple[str, ...]

    def can_handle(self, source: str, file_path: Path) -> bool: ...
    def parse(self, source: str, file_path: Path, config: AuditConfig) -> ScanResult: ...


_PARSERS: list[FrameworkParser] = []


def register_parser(parser: FrameworkParser) -> FrameworkParser:
    _PARSERS.append(parser)
    return parser


def get_parsers() -> list[FrameworkParser]:
    return list(_PARSERS)


def detect_framework(source: str, file_path: Path) -> FrameworkParser | None:
    for parser in _PARSERS:
        ext = file_path.suffix.lower()
        if ext not in parser.file_extensions:
            continue
        if parser.can_handle(source, file_path):
            return parser
    return None


from . import fastapi_parser, flask_parser, django_parser, express_parser, spring_parser
