from __future__ import annotations

import ast
import re
from pathlib import Path

from ..config import AuditConfig
from ..scanner import EndpointInfo, ScanResult
from . import register_parser

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "trace"}

ROUTER_VARIABLE_PATTERNS = re.compile(
    r"(?:router|app)\s*=\s*(?:APIRouter|FastAPI)\s*\(", re.MULTILINE
)


def _extract_string_value(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "<f-string>"
    return None


def _get_call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _get_call_name(node.func)
    return None


def _check_depends_for_auth(call_node: ast.Call, auth_patterns: list[str]) -> str | None:
    func_name = _get_call_name(call_node.func)
    if func_name != "Depends":
        return None
    if not call_node.args:
        return None

    arg = call_node.args[0]
    if isinstance(arg, ast.Name) and arg.id in auth_patterns:
        return f"Depends({arg.id})"
    if isinstance(arg, ast.Call):
        inner_name = _get_call_name(arg.func)
        if inner_name and inner_name in auth_patterns:
            return f"Depends({inner_name}(...))"
    if isinstance(arg, ast.Attribute) and arg.attr in auth_patterns:
        return f"Depends({arg.attr})"
    return None


def _check_security_dependency(call_node: ast.Call, auth_patterns: list[str]) -> str | None:
    func_name = _get_call_name(call_node.func)
    if func_name and func_name in auth_patterns:
        return f"Depends({func_name})"
    return None


def _function_has_auth(func_node: ast.FunctionDef | ast.AsyncFunctionDef, auth_patterns: list[str]) -> tuple[bool, str | None]:
    for arg in func_node.args.args + func_node.args.kwonlyargs:
        default = None
        all_args = func_node.args.args + func_node.args.kwonlyargs

        idx = None
        for i, a in enumerate(all_args):
            if a is arg:
                idx = i
                break

        if idx is not None:
            num_defaults = len(func_node.args.defaults)
            num_kw_defaults = len(func_node.args.kw_defaults)

            if idx < len(func_node.args.args):
                default_idx = idx - (len(func_node.args.args) - num_defaults)
                if 0 <= default_idx < num_defaults:
                    default = func_node.args.defaults[default_idx]
            else:
                kw_idx = idx - len(func_node.args.args)
                if 0 <= kw_idx < num_kw_defaults:
                    default = func_node.args.kw_defaults[kw_idx]

        if default and isinstance(default, ast.Call):
            auth = _check_depends_for_auth(default, auth_patterns)
            if auth:
                return True, auth
            auth = _check_security_dependency(default, auth_patterns)
            if auth:
                return True, auth

    return False, None


def _extract_decorator_route_info(decorator: ast.expr) -> tuple[str, str] | None:
    if not isinstance(decorator, ast.Call):
        return None
    if not isinstance(decorator.func, ast.Attribute):
        return None

    method = decorator.func.attr
    if method not in HTTP_METHODS:
        return None

    if decorator.args:
        path = _extract_string_value(decorator.args[0])
        if path:
            return method.upper(), path

    for kw in decorator.keywords:
        if kw.arg == "path":
            path = _extract_string_value(kw.value)
            if path:
                return method.upper(), path

    return method.upper(), "/"


def _check_router_dependencies(tree: ast.Module, auth_patterns: list[str]) -> tuple[bool, str | None, str | None]:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Call):
            continue

        call_name = _get_call_name(node.value.func)
        if call_name not in ("APIRouter", "FastAPI"):
            continue

        var_name = None
        if node.targets and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id

        for kw in node.value.keywords:
            if kw.arg != "dependencies":
                continue
            if not isinstance(kw.value, ast.List):
                continue
            for elt in kw.value.elts:
                if isinstance(elt, ast.Call):
                    auth = _check_depends_for_auth(elt, auth_patterns)
                    if auth:
                        return True, f"router-level {auth}", var_name

    return False, None, None


class FastAPIParser:
    name = "fastapi"
    file_extensions = (".py",)

    def can_handle(self, source: str, file_path: Path) -> bool:
        has_router = bool(ROUTER_VARIABLE_PATTERNS.search(source))
        has_decorator = bool(re.search(r"@\w+\.(get|post|put|delete|patch)\s*\(", source))
        return has_router or has_decorator

    def parse(self, source: str, file_path: Path, config: AuditConfig) -> ScanResult:
        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            return ScanResult(file_path=str(file_path), is_route_file=False)

        router_has_deps, router_auth_type, router_var = _check_router_dependencies(tree, config.auth_patterns)

        result = ScanResult(
            file_path=str(file_path),
            is_route_file=True,
            framework="fastapi",
            router_has_dependencies=router_has_deps,
            router_variable_name=router_var,
        )

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            for decorator in node.decorator_list:
                route_info = _extract_decorator_route_info(decorator)
                if route_info is None:
                    continue

                method, path = route_info
                has_auth, auth_type = _function_has_auth(node, config.auth_patterns)

                if not has_auth and router_has_deps:
                    has_auth = True
                    auth_type = router_auth_type

                endpoint = EndpointInfo(
                    file_path=str(file_path),
                    line_number=node.lineno,
                    method=method,
                    path=path,
                    function_name=node.name,
                    has_auth=has_auth,
                    auth_type=auth_type,
                    is_allowlisted=config.is_allowlisted(path),
                )
                result.endpoints.append(endpoint)

        return result


register_parser(FastAPIParser())
