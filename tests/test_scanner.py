from pathlib import Path
from src.scanner import scan_file, scan_directory
from src.config import AuditConfig

FIXTURES = Path(__file__).parent / "fixtures"


def test_unprotected_route_detected():
    config = AuditConfig()
    result = scan_file(FIXTURES / "unprotected_route.py", config)
    assert result.is_route_file
    assert len(result.endpoints) == 4
    assert all(not ep.has_auth for ep in result.endpoints)
    assert len(result.unprotected_endpoints) == 4


def test_protected_route_passes():
    config = AuditConfig()
    result = scan_file(FIXTURES / "protected_route.py", config)
    assert result.is_route_file
    assert len(result.endpoints) == 3
    assert all(ep.has_auth for ep in result.endpoints)
    assert len(result.unprotected_endpoints) == 0


def test_router_level_auth_inherits():
    config = AuditConfig()
    result = scan_file(FIXTURES / "router_level_auth.py", config)
    assert result.is_route_file
    assert result.router_has_dependencies
    assert len(result.endpoints) == 3
    assert all(ep.has_auth for ep in result.endpoints)
    assert all("router-level" in (ep.auth_type or "") for ep in result.endpoints)


def test_health_check_allowlisted():
    config = AuditConfig()
    result = scan_file(FIXTURES / "health_check.py", config)
    assert result.is_route_file
    assert len(result.endpoints) == 2
    for ep in result.endpoints:
        assert ep.is_allowlisted, f"{ep.path} should be allowlisted"
    assert len(result.unprotected_endpoints) == 0


def test_mixed_route_partial_detection():
    config = AuditConfig()
    result = scan_file(FIXTURES / "mixed_route.py", config)
    assert result.is_route_file
    assert len(result.endpoints) == 4

    unprotected = result.unprotected_endpoints
    protected = result.protected_endpoints
    assert len(unprotected) == 2
    assert len(protected) == 2

    unprotected_names = {ep.function_name for ep in unprotected}
    assert "get_consent_status" in unprotected_names
    assert "get_consent_history" in unprotected_names

    protected_names = {ep.function_name for ep in protected}
    assert "update_consent" in protected_names
    assert "revoke_consent" in protected_names


def test_non_python_file_ignored():
    config = AuditConfig()
    result = scan_file(Path("nonexistent.py"), config)
    assert not result.is_route_file


def test_scan_directory_finds_route_files():
    config = AuditConfig()
    results = scan_directory(FIXTURES, config)
    route_files = {Path(r.file_path).name for r in results}
    assert "unprotected_route.py" in route_files
    assert "protected_route.py" in route_files
    assert "router_level_auth.py" in route_files
    assert "health_check.py" in route_files
    assert "mixed_route.py" in route_files


def test_endpoint_line_numbers():
    config = AuditConfig()
    result = scan_file(FIXTURES / "unprotected_route.py", config)
    for ep in result.endpoints:
        assert ep.line_number > 0


def test_endpoint_methods_detected():
    config = AuditConfig()
    result = scan_file(FIXTURES / "unprotected_route.py", config)
    methods = {ep.method for ep in result.endpoints}
    assert "GET" in methods
    assert "POST" in methods
    assert "DELETE" in methods


def test_custom_auth_pattern():
    config = AuditConfig(auth_patterns=["my_custom_auth"])
    result = scan_file(FIXTURES / "protected_route.py", config)
    assert all(not ep.has_auth for ep in result.endpoints)
