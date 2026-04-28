from __future__ import annotations

import re
from pathlib import Path

from ..config import AuditConfig
from ..scanner import EndpointInfo, ScanResult
from . import register_parser

MAPPING_PATTERN = re.compile(
    r"""@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\((?:[^)]*value\s*=\s*)?["']?([^"')]+)?""",
    re.MULTILINE,
)

REQUEST_MAPPING_METHODS = re.compile(
    r"""@RequestMapping\s*\([^)]*method\s*=\s*(?:RequestMethod\.)?(\w+)""",
    re.MULTILINE,
)

CONTROLLER_PATTERN = re.compile(
    r"""@(?:RestController|Controller)\s*\n""",
    re.MULTILINE,
)

CLASS_MAPPING_PATTERN = re.compile(
    r"""@RequestMapping\s*\(\s*["']([^"']+)["']\s*\)\s*\n\s*(?:public\s+)?class""",
    re.MULTILINE,
)

METHOD_DEF_PATTERN = re.compile(
    r"""(?:public|private|protected)\s+(?:[\w<>\[\],\s]+?)\s+(\w+)\s*\(""",
)

SPRING_AUTH_ANNOTATIONS = {
    "PreAuthorize",
    "Secured",
    "RolesAllowed",
    "WithMockUser",
}

SPRING_AUTH_PATTERN = re.compile(
    r"""@(PreAuthorize|Secured|RolesAllowed)\s*\(""",
    re.MULTILINE,
)

SECURITY_CONFIG_PATTERN = re.compile(
    r"""\.(?:authenticated|hasRole|hasAuthority|hasAnyRole|hasAnyAuthority|permitAll)\s*\(""",
    re.MULTILINE,
)

MAPPING_TO_METHOD = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
    "RequestMapping": "GET",
}


def _line_number(source: str, pos: int) -> int:
    return source[:pos].count("\n") + 1


class SpringParser:
    name = "spring"
    file_extensions = (".java", ".kt")

    def can_handle(self, source: str, file_path: Path) -> bool:
        has_controller = bool(CONTROLLER_PATTERN.search(source))
        has_mapping = bool(MAPPING_PATTERN.search(source))
        return has_controller and has_mapping

    def parse(self, source: str, file_path: Path, config: AuditConfig) -> ScanResult:
        result = ScanResult(
            file_path=str(file_path),
            is_route_file=True,
            framework="spring",
        )

        base_path = ""
        class_match = CLASS_MAPPING_PATTERN.search(source)
        if class_match:
            base_path = class_match.group(1).rstrip("/")

        class_has_auth = self._class_has_auth(source)

        for match in MAPPING_PATTERN.finditer(source):
            mapping_type = match.group(1)
            path_value = match.group(2)

            if mapping_type == "RequestMapping":
                method_match = REQUEST_MAPPING_METHODS.search(source[match.start():match.end() + 100])
                method = method_match.group(1).upper() if method_match else "GET"
            else:
                method = MAPPING_TO_METHOD.get(mapping_type, "GET")

            path = base_path
            if path_value and path_value.strip():
                clean_path = path_value.strip().strip("\"'")
                if clean_path and clean_path != ")":
                    path = f"{base_path}/{clean_path.lstrip('/')}"
            if not path:
                path = "/"

            line = _line_number(source, match.start())

            func_name = self._find_method_name(source, match.end())
            has_auth, auth_type = self._method_has_auth(source, match.start(), config.auth_patterns)

            if not has_auth and class_has_auth:
                has_auth = True
                auth_type = "class-level security"

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

    def _class_has_auth(self, source: str) -> bool:
        lines_before_class = source[:source.find("class ")] if "class " in source else ""
        return bool(SPRING_AUTH_PATTERN.search(lines_before_class))

    def _method_has_auth(self, source: str, mapping_pos: int, auth_patterns: list[str]) -> tuple[bool, str | None]:
        start = max(0, mapping_pos - 500)
        context = source[start:mapping_pos]

        all_patterns = set(auth_patterns) | SPRING_AUTH_ANNOTATIONS
        for line in reversed(context.splitlines()):
            line = line.strip()
            if not line.startswith("@"):
                if line and not line.startswith("//") and not line.startswith("*"):
                    break
                continue
            for pattern in all_patterns:
                if pattern in line:
                    return True, line
        return False, None

    def _find_method_name(self, source: str, after_pos: int) -> str:
        search_region = source[after_pos:after_pos + 500]
        match = METHOD_DEF_PATTERN.search(search_region)
        if match:
            return match.group(1)
        return "unknown"


register_parser(SpringParser())
