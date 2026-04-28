from __future__ import annotations

import ast
import re
from pathlib import Path

from ..config import AuditConfig
from ..scanner import EndpointInfo, ScanResult
from . import register_parser

DJANGO_AUTH_PATTERNS = {
    "login_required",
    "permission_required",
    "user_passes_test",
    "staff_member_required",
}

DRF_AUTH_CLASSES = {
    "IsAuthenticated",
    "IsAdminUser",
    "IsAuthenticatedOrReadOnly",
    "DjangoModelPermissions",
    "DjangoObjectPermissions",
    "TokenAuthentication",
    "SessionAuthentication",
    "BasicAuthentication",
    "JWTAuthentication",
}

DRF_DECORATOR_PATTERN = re.compile(r"@api_view\s*\(", re.MULTILINE)
DRF_CLASS_PATTERN = re.compile(r"class\s+\w+\s*\(.*(?:APIView|ViewSet|ModelViewSet|GenericAPIView)", re.MULTILINE)


def _extract_string_value(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _get_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _get_name(node.func)
    return None


def _has_auth_decorator(func_node: ast.FunctionDef | ast.AsyncFunctionDef, auth_patterns: list[str]) -> tuple[bool, str | None]:
    all_patterns = set(auth_patterns) | DJANGO_AUTH_PATTERNS
    for decorator in func_node.decorator_list:
        name = _get_name(decorator)
        if name and name in all_patterns:
            return True, f"@{name}"
    return False, None


def _extract_api_view_methods(decorator: ast.expr) -> list[str]:
    if not isinstance(decorator, ast.Call):
        return []
    name = _get_name(decorator.func)
    if name != "api_view":
        return []
    if decorator.args and isinstance(decorator.args[0], (ast.List, ast.Tuple)):
        methods = []
        for elt in decorator.args[0].elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                methods.append(elt.value.upper())
        return methods
    return ["GET"]


def _class_has_permission_classes(class_node: ast.ClassDef, auth_patterns: list[str]) -> tuple[bool, str | None]:
    all_patterns = set(auth_patterns) | DRF_AUTH_CLASSES
    for node in ast.walk(class_node):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "permission_classes":
                    if isinstance(node.value, (ast.List, ast.Tuple)):
                        for elt in node.value.elts:
                            name = _get_name(elt)
                            if name and name in all_patterns:
                                return True, f"permission_classes=[{name}]"
                    return False, None
                if isinstance(target, ast.Name) and target.id == "authentication_classes":
                    return True, "authentication_classes"
    return False, None


DRF_ACTION_METHODS = {"list": "GET", "create": "POST", "retrieve": "GET", "update": "PUT", "partial_update": "PATCH", "destroy": "DELETE"}
DRF_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


class DjangoParser:
    name = "django"
    file_extensions = (".py",)

    def can_handle(self, source: str, file_path: Path) -> bool:
        has_drf = bool(DRF_DECORATOR_PATTERN.search(source)) or bool(DRF_CLASS_PATTERN.search(source))
        has_import = "rest_framework" in source or "from django" in source
        return has_drf and has_import

    def parse(self, source: str, file_path: Path, config: AuditConfig) -> ScanResult:
        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            return ScanResult(file_path=str(file_path), is_route_file=False)

        result = ScanResult(
            file_path=str(file_path),
            is_route_file=True,
            framework="django",
        )

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._parse_function_view(node, file_path, config, result)
            elif isinstance(node, ast.ClassDef):
                self._parse_class_view(node, file_path, config, result)

        return result

    def _parse_function_view(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: Path, config: AuditConfig, result: ScanResult) -> None:
        methods = []
        for decorator in func_node.decorator_list:
            methods = _extract_api_view_methods(decorator)
            if methods:
                break

        if not methods:
            return

        has_auth, auth_type = _has_auth_decorator(func_node, config.auth_patterns)
        path = f"/{func_node.name}/"

        for method in methods:
            endpoint = EndpointInfo(
                file_path=str(file_path),
                line_number=func_node.lineno,
                method=method,
                path=path,
                function_name=func_node.name,
                has_auth=has_auth,
                auth_type=auth_type,
                is_allowlisted=config.is_allowlisted(path),
            )
            result.endpoints.append(endpoint)

    def _parse_class_view(self, class_node: ast.ClassDef, file_path: Path, config: AuditConfig, result: ScanResult) -> None:
        is_drf_view = any(
            isinstance(base, ast.Name) and base.id in ("APIView", "ViewSet", "ModelViewSet", "GenericAPIView", "ListAPIView", "CreateAPIView", "RetrieveAPIView", "UpdateAPIView", "DestroyAPIView", "ListCreateAPIView", "RetrieveUpdateAPIView", "RetrieveDestroyAPIView", "RetrieveUpdateDestroyAPIView")
            or isinstance(base, ast.Attribute) and base.attr in ("APIView", "ViewSet", "ModelViewSet", "GenericAPIView")
            for base in class_node.bases
        )
        if not is_drf_view:
            return

        class_has_auth, class_auth_type = _class_has_permission_classes(class_node, config.auth_patterns)

        for item in class_node.body:
            if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            method_name = item.name
            if method_name in DRF_ACTION_METHODS:
                http_method = DRF_ACTION_METHODS[method_name]
            elif method_name in DRF_HTTP_METHODS:
                http_method = method_name.upper()
            else:
                continue

            has_auth = class_has_auth
            auth_type = class_auth_type

            func_auth, func_auth_type = _has_auth_decorator(item, config.auth_patterns)
            if func_auth:
                has_auth = True
                auth_type = func_auth_type

            path = f"/{class_node.name}/"

            endpoint = EndpointInfo(
                file_path=str(file_path),
                line_number=item.lineno,
                method=http_method,
                path=path,
                function_name=f"{class_node.name}.{method_name}",
                has_auth=has_auth,
                auth_type=auth_type,
                is_allowlisted=config.is_allowlisted(path),
            )
            result.endpoints.append(endpoint)


register_parser(DjangoParser())
