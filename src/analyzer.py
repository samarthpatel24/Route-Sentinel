from __future__ import annotations

import json
import os
from pathlib import Path

import anthropic

from .config import AuditConfig
from .scanner import ScanResult, EndpointInfo

ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "endpoints": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "function_name": {"type": "string"},
                    "path": {"type": "string"},
                    "method": {"type": "string"},
                    "has_hidden_auth": {"type": "boolean"},
                    "hidden_auth_explanation": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                    },
                    "severity_reason": {"type": "string"},
                },
                "required": [
                    "function_name",
                    "path",
                    "method",
                    "has_hidden_auth",
                    "hidden_auth_explanation",
                    "severity",
                    "severity_reason",
                ],
                "additionalProperties": False,
            },
        },
    },
    "required": ["endpoints"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = """\
You are a FastAPI security analyst. You analyze Python route files for authentication vulnerabilities.

For each UNPROTECTED endpoint listed, determine:
1. Whether there is non-obvious authentication (middleware, class-based dependency injection, \
custom decorators, or router-level dependencies applied elsewhere) that the static scanner missed.
2. The severity of the missing authentication:
   - CRITICAL: Endpoint accesses sensitive data (credentials, PII, database records, session tokens, API keys) \
or provides direct data store access.
   - HIGH: Endpoint performs state-changing operations (create, update, delete) on business data, \
or handles compliance-related operations (GDPR, consent).
   - MEDIUM: Endpoint reads business data, configuration, or operational metrics.
   - LOW: Endpoint reads non-sensitive metadata or system information.
   - INFO: Endpoint is a health check, documentation, or intentionally public.

Respond with your analysis for each unprotected endpoint. If you see auth that the scanner missed, \
set has_hidden_auth to true and explain. Otherwise set it to false.\
"""


def _build_user_message(file_path: str, file_content: str, unprotected: list[EndpointInfo]) -> str:
    endpoint_list = "\n".join(
        f"  - {ep.method} {ep.path} (function: {ep.function_name}, line {ep.line_number})"
        for ep in unprotected
    )
    return (
        f"File: {file_path}\n\n"
        f"Unprotected endpoints flagged by static scanner:\n{endpoint_list}\n\n"
        f"Full file content:\n```python\n{file_content}\n```"
    )


def analyze_file(
    file_path: str,
    file_content: str,
    unprotected: list[EndpointInfo],
    client: anthropic.Anthropic,
    model: str,
) -> dict:
    user_msg = _build_user_message(file_path, file_content, unprotected)

    response = client.messages.create(
        model=model,
        max_tokens=4096,
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        output_config={
            "format": {
                "type": "json_schema",
                "schema": ANALYSIS_SCHEMA,
            }
        },
        messages=[{"role": "user", "content": user_msg}],
    )

    text = next((b.text for b in response.content if b.type == "text"), "{}")
    return json.loads(text)


def analyze_results(results: list[ScanResult], config: AuditConfig) -> list[ScanResult]:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return results

    client = anthropic.Anthropic(api_key=api_key)
    model = config.analysis.model

    for result in results:
        unprotected = result.unprotected_endpoints
        if not unprotected:
            continue

        try:
            file_content = Path(result.file_path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        try:
            analysis = analyze_file(
                result.file_path, file_content, unprotected, client, model
            )
        except (anthropic.APIError, json.JSONDecodeError):
            continue

        analyzed_map = {
            ep["function_name"]: ep for ep in analysis.get("endpoints", [])
        }

        for ep in result.endpoints:
            info = analyzed_map.get(ep.function_name)
            if not info:
                continue
            if info.get("has_hidden_auth"):
                ep.has_auth = True
                ep.auth_type = f"LLM-detected: {info.get('hidden_auth_explanation', 'unknown')}"

    return results
