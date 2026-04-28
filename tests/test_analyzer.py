import json
from unittest.mock import patch, MagicMock
from pathlib import Path

from endpoint_auth_guard.analyzer import analyze_file, analyze_results, SYSTEM_PROMPT
from endpoint_auth_guard.scanner import ScanResult, EndpointInfo, scan_file
from endpoint_auth_guard.config import AuditConfig

FIXTURES = Path(__file__).parent / "fixtures"


def _mock_response(content_json: dict) -> MagicMock:
    text_block = MagicMock()
    text_block.type = "text"
    text_block.text = json.dumps(content_json)
    response = MagicMock()
    response.content = [text_block]
    return response


def test_analyze_file_returns_structured_result():
    client = MagicMock()
    client.messages.create.return_value = _mock_response({
        "endpoints": [
            {
                "function_name": "list_tables",
                "path": "/tables",
                "method": "GET",
                "has_hidden_auth": False,
                "hidden_auth_explanation": "",
                "severity": "CRITICAL",
                "severity_reason": "Direct database table listing",
            }
        ]
    })

    result = analyze_file(
        "database.py",
        "# file content",
        [EndpointInfo(
            file_path="database.py",
            line_number=10,
            method="GET",
            path="/tables",
            function_name="list_tables",
            has_auth=False,
        )],
        client,
        "claude-sonnet-4-6",
    )

    assert result["endpoints"][0]["severity"] == "CRITICAL"
    assert result["endpoints"][0]["has_hidden_auth"] is False

    call_kwargs = client.messages.create.call_args.kwargs
    assert call_kwargs["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert call_kwargs["output_config"]["format"]["type"] == "json_schema"


def test_analyze_file_detects_hidden_auth():
    client = MagicMock()
    client.messages.create.return_value = _mock_response({
        "endpoints": [
            {
                "function_name": "get_status",
                "path": "/status",
                "method": "GET",
                "has_hidden_auth": True,
                "hidden_auth_explanation": "Middleware applies auth before router",
                "severity": "INFO",
                "severity_reason": "Protected by middleware",
            }
        ]
    })

    result = analyze_file(
        "status.py", "# file",
        [EndpointInfo("status.py", 5, "GET", "/status", "get_status", False)],
        client, "claude-sonnet-4-6",
    )

    assert result["endpoints"][0]["has_hidden_auth"] is True


@patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
@patch("endpoint_auth_guard.analyzer.anthropic.Anthropic")
def test_analyze_results_updates_endpoints(mock_client_cls):
    client_instance = MagicMock()
    mock_client_cls.return_value = client_instance
    client_instance.messages.create.return_value = _mock_response({
        "endpoints": [
            {
                "function_name": "list_tables",
                "path": "/tables",
                "method": "GET",
                "has_hidden_auth": True,
                "hidden_auth_explanation": "Router middleware detected",
                "severity": "INFO",
                "severity_reason": "Has hidden auth",
            }
        ]
    })

    config = AuditConfig()
    result = scan_file(FIXTURES / "unprotected_route.py", config)
    results = analyze_results([result], config)

    updated_ep = next(
        (ep for ep in results[0].endpoints if ep.function_name == "list_tables"),
        None,
    )
    assert updated_ep is not None
    assert updated_ep.has_auth is True
    assert "LLM-detected" in (updated_ep.auth_type or "")


@patch.dict("os.environ", {}, clear=True)
def test_analyze_results_skips_without_api_key():
    config = AuditConfig()
    result = scan_file(FIXTURES / "unprotected_route.py", config)
    original_auth_states = [ep.has_auth for ep in result.endpoints]

    results = analyze_results([result], config)

    for ep, original in zip(results[0].endpoints, original_auth_states):
        assert ep.has_auth == original
