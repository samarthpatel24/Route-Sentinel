from __future__ import annotations

import ast
import re
from pathlib import Path

from ..config import AuditConfig
from ..scanner import EndpointInfo, ScanResult
from . import register_parser

FLASK_AUTH_DECORATORS = {
    "login_required",
    "roles_required",
    "roles_accepted",
    "auth_required",
    "jwt_required",
    "token_required",
    "permission_required",
    "fresh_login_required",
}

FLASK_PATTERN = re.compile(
    r"(?:Flask|Blueprint)\s*\(", re.MULTILINE
)

ROUTE_DECORATOR = re.compile(
    r"@\w+\.route\s*\(", re.MULTILINE
)

HTTP_METHOD_DECORATORS = {"get", "post", "put", "delete", "patch", "head", "options"}


def _extract_string_value(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _get_call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _extract_methods_from_decorator(decorator: ast.Call) -> list[str]:
    for kw in decorator.keywords:
        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
            methods = []
            for elt in kw.value.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    methods.append(elt.value.upper())
            return methods if methods else ["GET"]
    return ["GET"]


def _has_auth_decorator(func_node: ast.FunctionDef | ast.AsyncFunctionDef, auth_patterns: list[str]) -> tuple[bool, str | None]:
    all_patterns = set(auth_patterns) | FLASK_AUTH_DECORATORS
    for decorator in func_node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id in all_patterns:
            return True, f"@{decorator.id}"
        if isinstance(decorator, ast.Call):
            name = _get_call_name(decorator.func)
            if name and name in all_patterns:
                return True, f"@{name}(...)"
        if isinstance(decorator, ast.Attribute) and decorator.attr in all_patterns:
            return True, f"@{decorator.attr}"
    return False, None


def _extract_route_info(decorator: ast.expr) -> tuple[str | None, list[str]]:
    if not isinstance(decorator, ast.Call):
        return None, []

    if isinstance(decorator.func, ast.Attribute):
        attr = decorator.func.attr
        if attr == "route":
            path = None
            if decorator.args:
                path = _extract_string_value(decorator.args[0])
            methods = _extract_methods_from_decorator(decorator)
            return path, methods
        if attr in HTTP_METHOD_DECORATORS:
            path = None
            if decorator.args:
                path = _extract_string_value(decorator.args[0])
            return path, [attr.upper()]

    return None, []


class FlaskParser:
    name = "flask"
    file_extensions = (".py",)

    def can_handle(self, source: str, file_path: Path) -> bool:
        has_flask = bool(FLASK_PATTERN.search(source))
        has_route = bool(ROUTE_DECORATOR.search(source))
        has_import = "from flask" in source or "import flask" in source
        return (has_flask or has_import) and has_route

    def parse(self, source: str, file_path: Path, config: AuditConfig) -> ScanResult:
        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            return ScanResult(file_path=str(file_path), is_route_file=False)

        result = ScanResult(
            file_path=str(file_path),
            is_route_file=True,
            framework="flask",
        )

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            for decorator in node.decorator_list:
                path, methods = _extract_route_info(decorator)
                if path is None and not methods:
                    continue

                has_auth, auth_type = _has_auth_decorator(node, config.auth_patterns)

                for method in methods:
                    endpoint = EndpointInfo(
                        file_path=str(file_path),
                        line_number=node.lineno,
                        method=method,
                        path=path or "/",
                        function_name=node.name,
                        has_auth=has_auth,
                        auth_type=auth_type,
                        is_allowlisted=config.is_allowlisted(path or "/"),
                    )
                    result.endpoints.append(endpoint)

        return result


register_parser(FlaskParser())
