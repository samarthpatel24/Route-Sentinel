from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import TextIO
import sys

from .scanner import ScanResult, EndpointInfo
from .config import AuditConfig

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def classify_severity(endpoint: EndpointInfo, config: AuditConfig) -> str:
    if endpoint.has_auth or endpoint.is_allowlisted:
        return "INFO"

    path = endpoint.path.lower()

    for pattern in config.severity_rules.critical_path_patterns:
        if pattern.lower() in path:
            return "CRITICAL"

    if endpoint.method in ("POST", "PUT", "DELETE", "PATCH"):
        for pattern in config.severity_rules.high_path_patterns:
            if pattern.lower() in path:
                return "CRITICAL"
        return "HIGH"

    for pattern in config.severity_rules.high_path_patterns:
        if pattern.lower() in path:
            return "HIGH"

    return "MEDIUM"


def build_report(results: list[ScanResult], config: AuditConfig) -> dict:
    total_endpoints = 0
    unprotected = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    file_reports = []

    for result in results:
        endpoint_reports = []
        for ep in result.endpoints:
            severity = classify_severity(ep, config)
            if not ep.has_auth and not ep.is_allowlisted:
                unprotected += 1
                severity_counts[severity] += 1
            total_endpoints += 1

            endpoint_reports.append({
                "method": ep.method,
                "path": ep.path,
                "function": ep.function_name,
                "line": ep.line_number,
                "has_auth": ep.has_auth,
                "auth_type": ep.auth_type,
                "is_allowlisted": ep.is_allowlisted,
                "severity": severity,
            })

        file_reports.append({
            "path": result.file_path,
            "router_has_dependencies": result.router_has_dependencies,
            "total_endpoints": len(result.endpoints),
            "unprotected_count": len(result.unprotected_endpoints),
            "endpoints": endpoint_reports,
        })

    passed = severity_counts["CRITICAL"] == 0 and severity_counts["HIGH"] == 0

    return {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "files_scanned": len(results),
            "total_endpoints": total_endpoints,
            "unprotected_endpoints": unprotected,
            "critical": severity_counts["CRITICAL"],
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "low": severity_counts["LOW"],
            "info": severity_counts["INFO"],
            "pass": passed,
        },
        "files": file_reports,
    }


def format_console(report: dict, out: TextIO = sys.stdout) -> None:
    summary = report["summary"]

    out.write("\n")
    if summary["pass"]:
        out.write("  PASS — All endpoints have proper authentication\n")
    else:
        out.write("  FAIL — Unprotected endpoints detected\n")
    out.write("\n")

    out.write(f"  Files scanned:    {summary['files_scanned']}\n")
    out.write(f"  Total endpoints:  {summary['total_endpoints']}\n")
    out.write(f"  Unprotected:      {summary['unprotected_endpoints']}\n")
    out.write("\n")

    if summary["critical"]:
        out.write(f"  CRITICAL: {summary['critical']}\n")
    if summary["high"]:
        out.write(f"  HIGH:     {summary['high']}\n")
    if summary["medium"]:
        out.write(f"  MEDIUM:   {summary['medium']}\n")
    if summary["low"]:
        out.write(f"  LOW:      {summary['low']}\n")
    out.write("\n")

    for file_report in report["files"]:
        unprotected = [e for e in file_report["endpoints"] if not e["has_auth"] and not e["is_allowlisted"]]
        if not unprotected:
            continue

        out.write(f"  {file_report['path']}\n")
        out.write(f"  {'-' * 60}\n")

        for ep in sorted(unprotected, key=lambda e: SEVERITY_ORDER.get(e["severity"], 99)):
            severity = ep["severity"]
            out.write(f"    [{severity}] {ep['method']} {ep['path']}\n")
            out.write(f"           function: {ep['function']}  (line {ep['line']})\n")

        out.write("\n")


def format_json(report: dict, out: TextIO = sys.stdout) -> None:
    json.dump(report, out, indent=2)
    out.write("\n")


def format_github(report: dict, out: TextIO = sys.stdout) -> None:
    for file_report in report["files"]:
        for ep in file_report["endpoints"]:
            if ep["has_auth"] or ep["is_allowlisted"]:
                continue
            severity = ep["severity"]
            level = "error" if severity in ("CRITICAL", "HIGH") else "warning"
            out.write(
                f"::{level} file={file_report['path']},line={ep['line']}"
                f"::{severity}: {ep['method']} {ep['path']} -- endpoint '{ep['function']}' has no authentication\n"
            )


FORMATTERS = {
    "console": format_console,
    "json": format_json,
    "github": format_github,
}


def should_fail(report: dict, threshold: str = "HIGH") -> bool:
    threshold_order = SEVERITY_ORDER.get(threshold.upper(), 1)
    summary = report["summary"]
    for severity, count in [
        ("CRITICAL", summary["critical"]),
        ("HIGH", summary["high"]),
        ("MEDIUM", summary["medium"]),
        ("LOW", summary["low"]),
    ]:
        if count > 0 and SEVERITY_ORDER[severity] <= threshold_order:
            return True
    return False
