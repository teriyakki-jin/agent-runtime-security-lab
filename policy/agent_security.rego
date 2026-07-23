package agent_security

import rego.v1

default decision := {
    "allow": false,
    "action": "deny",
    "risk_score": 90,
    "reasons": ["Default-deny policy: the requested tool or arguments are not approved."],
}

decision := {
    "allow": true,
    "action": "allow",
    "risk_score": 10,
    "reasons": ["Document path is inside the approved public workspace."],
} if {
    input.tool == "read_document"
    path := object.get(input.arguments, "path", "")
    startswith(path, "public/")
    not contains(path, "..")
    not startswith(path, "/")
}

decision := {
    "allow": false,
    "action": "deny",
    "risk_score": 100,
    "reasons": ["Path traversal or absolute-path access was blocked."],
} if {
    input.tool == "read_document"
    path := object.get(input.arguments, "path", "")
    not safe_document_path(path)
}

decision := {
    "allow": true,
    "action": "allow",
    "risk_score": 20,
    "reasons": ["Destination is the isolated documentation mock service."],
} if {
    input.tool == "mock_http_request"
    url := object.get(input.arguments, "url", "")
    startswith(url, "https://docs.example.local/")
}

decision := {
    "allow": false,
    "action": "review",
    "risk_score": 80,
    "reasons": ["External HTTP destination requires explicit human approval."],
} if {
    input.tool == "mock_http_request"
    url := object.get(input.arguments, "url", "")
    not startswith(url, "https://docs.example.local/")
}

decision := {
    "allow": false,
    "action": "deny",
    "risk_score": 95,
    "reasons": ["Shell execution is disabled at the agent gateway."],
} if {
    input.tool == "run_command"
}

safe_document_path(path) if {
    startswith(path, "public/")
    not contains(path, "..")
    not startswith(path, "/")
}
