from __future__ import annotations

import re
from pathlib import Path

from ..config import AuditConfig
from ..scanner import EndpointInfo, ScanResult
from . import register_parser

ROUTE_PATTERN = re.compile(
    r"""(?:app|router)\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*['"]([^'"]+)['"]""",
    re.MULTILINE,
)

ROUTE_METHOD_PATTERN = re.compile(
    r"""(?:app|router)\s*\.\s*(?:route|all)\s*\(\s*['"]([^'"]+)['"]""",
    re.MULTILINE,
)

USE_PATTERN = re.compile(
    r"""(?:app|router)\s*\.\s*use\s*\(""",
    re.MULTILINE,
)

EXPRESS_AUTH_MIDDLEWARE = {
    "passport.authenticate",
    "requireAuth",
    "requireLogin",
    "isAuthenticated",
    "isLoggedIn",
    "verifyToken",
    "authenticateToken",
    "authMiddleware",
    "ensureAuthenticated",
    "protect",
    "auth",
    "checkAuth",
    "validateToken",
    "jwtAuth",
    "bearerAuth",
}

HANDLER_PATTERN = re.compile(
    r"""(?:app|router)\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*['"][^'"]+['"]\s*,(.+?)\)\s*;?""",
    re.DOTALL,
)

FUNC_NAME_PATTERN = re.compile(r"(?:async\s+)?function\s+(\w+)")
ARROW_NAME_PATTERN = re.compile(r"(?:const|let|var)\s+(\w+)\s*=")


def _line_number(source: str, match_start: int) -> int:
    return source[:match_start].count("\n") + 1


def _has_auth_in_middleware_chain(middleware_str: str, auth_patterns: list[str]) -> tuple[bool, str | None]:
    all_patterns = set(auth_patterns) | EXPRESS_AUTH_MIDDLEWARE
    for pattern in all_patterns:
        if pattern in middleware_str:
            return True, pattern
    return False, None


class ExpressParser:
    name = "express"
    file_extensions = (".js", ".ts", ".mjs", ".cjs")

    def can_handle(self, source: str, file_path: Path) -> bool:
        has_express = "express" in source and ("require(" in source or "import " in source)
        has_routes = bool(ROUTE_PATTERN.search(source))
        return has_express and has_routes

    def parse(self, source: str, file_path: Path, config: AuditConfig) -> ScanResult:
        result = ScanResult(
            file_path=str(file_path),
            is_route_file=True,
            framework="express",
        )

        app_level_auth = self._check_app_level_auth(source, config.auth_patterns)

        for match in ROUTE_PATTERN.finditer(source):
            method = match.group(1).upper()
            path = match.group(2)
            line = _line_number(source, match.start())

            handler_match = HANDLER_PATTERN.search(source[match.start():])
            middleware_str = handler_match.group(2) if handler_match else ""

            has_auth, auth_type = _has_auth_in_middleware_chain(middleware_str, config.auth_patterns)

            if not has_auth and app_level_auth:
                has_auth = True
                auth_type = f"app-level: {app_level_auth}"

            func_name = self._extract_handler_name(middleware_str, method, path)

            endpoint = EndpointInfo(
                file_path=str(file_path),
                line_number=line,
                method=method,
                path=path,
                function_name=func_name,
                has_auth=has_auth,
                auth_type=auth_type,
                is_allowlisted=config.is_allowlisted(path),
            )
            result.endpoints.append(endpoint)

        return result

    def _check_app_level_auth(self, source: str, auth_patterns: list[str]) -> str | None:
        all_patterns = set(auth_patterns) | EXPRESS_AUTH_MIDDLEWARE
        for match in USE_PATTERN.finditer(source):
            line_end = source.find("\n", match.start())
            if line_end == -1:
                line_end = len(source)
            use_line = source[match.start():line_end]

            if any(p in use_line for p in (".get(", ".post(", ".put(", ".delete(")):
                continue

            for pattern in all_patterns:
                if pattern in use_line:
                    return pattern
        return None

    def _extract_handler_name(self, middleware_str: str, method: str, path: str) -> str:
        parts = [p.strip() for p in middleware_str.split(",")]
        if parts:
            last = parts[-1].strip().rstrip(")")
            if re.match(r"^\w+$", last):
                return last
        slug = re.sub(r"[/:{}]", "_", path).strip("_") or "handler"
        return f"{method.lower()}_{slug}"


register_parser(ExpressParser())
