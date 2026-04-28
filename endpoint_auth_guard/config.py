from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_ALLOWLIST = [
    {"path": "/health", "reason": "Load balancer health check"},
    {"path": "/docs", "reason": "OpenAPI documentation"},
    {"path": "/openapi.json", "reason": "OpenAPI schema"},
    {"path": "/redoc", "reason": "ReDoc documentation"},
    {"path": "/auth/login", "reason": "Authentication endpoint"},
    {"path": "/auth/register", "reason": "Registration endpoint"},
    {"path": "/auth/token", "reason": "Token endpoint"},
]

DEFAULT_AUTH_PATTERNS = [
    "get_current_user",
    "get_current_active_user",
    "require_roles",
    "require_admin",
    "verify_api_key",
    "get_api_key",
    "oauth2_scheme",
    "HTTPBearer",
    "HTTPBasic",
    "SecurityScopes",
]

DEFAULT_CRITICAL_PATHS = [
    "/database",
    "/admin",
    "/users",
    "/credentials",
    "/sessions",
    "/api-keys",
]

DEFAULT_HIGH_PATHS = [
    "/data",
    "/export",
    "/import",
    "/delete",
    "/consent",
    "/data-rights",
]


@dataclass
class SeverityRules:
    critical_path_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_CRITICAL_PATHS))
    high_path_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_HIGH_PATHS))


@dataclass
class AnalysisConfig:
    enabled: bool = True
    model: str = "claude-sonnet-4-20250514"
    skip_if_all_protected: bool = True


@dataclass
class AuditConfig:
    allowlist: list[dict[str, str]] = field(default_factory=lambda: list(DEFAULT_ALLOWLIST))
    auth_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_AUTH_PATTERNS))
    severity_rules: SeverityRules = field(default_factory=SeverityRules)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)

    def is_allowlisted(self, endpoint_path: str) -> bool:
        for entry in self.allowlist:
            pattern = entry["path"]
            if endpoint_path == pattern or endpoint_path.startswith(pattern + "/"):
                return True
        return False


def load_config(config_path: Path | None = None) -> AuditConfig:
    if config_path is None:
        config_path = Path.cwd() / ".security-audit.yaml"

    if not config_path.exists():
        return AuditConfig()

    with open(config_path) as f:
        raw: dict[str, Any] = yaml.safe_load(f) or {}

    allowlist = raw.get("allowlist", DEFAULT_ALLOWLIST)
    auth_patterns = raw.get("auth_patterns", DEFAULT_AUTH_PATTERNS)

    severity_raw = raw.get("severity_rules", {})
    severity_rules = SeverityRules(
        critical_path_patterns=severity_raw.get("critical_path_patterns", DEFAULT_CRITICAL_PATHS),
        high_path_patterns=severity_raw.get("high_path_patterns", DEFAULT_HIGH_PATHS),
    )

    analysis_raw = raw.get("analysis", {})
    analysis = AnalysisConfig(
        enabled=analysis_raw.get("enabled", True),
        model=analysis_raw.get("model", "claude-sonnet-4-20250514"),
        skip_if_all_protected=analysis_raw.get("skip_if_all_protected", True),
    )

    return AuditConfig(
        allowlist=allowlist,
        auth_patterns=auth_patterns,
        severity_rules=severity_rules,
        analysis=analysis,
    )
