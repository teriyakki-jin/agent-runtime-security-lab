package supply_chain

import rego.v1

default decision := {
    "allow": false,
    "action": "deny",
    "risk_score": 100,
    "reasons": ["MCP artifact trust requirements were not satisfied."],
}

decision := {
    "allow": true,
    "action": "allow",
    "risk_score": 10,
    "reasons": ["Signature, digest pin, SBOM attestation, and tool manifest are trusted."],
} if {
    input.signature_verified == true
    input.digest_pinned == true
    input.sbom_attestation_verified == true
    input.tool_manifest_verified == true
}

decision := {
    "allow": false,
    "action": "deny",
    "risk_score": 100,
    "reasons": ["MCP image signature verification failed."],
} if {
    input.signature_verified == false
}

decision := {
    "allow": false,
    "action": "deny",
    "risk_score": 95,
    "reasons": ["Mutable MCP image references are forbidden."],
} if {
    input.signature_verified == true
    input.digest_pinned == false
}

decision := {
    "allow": false,
    "action": "deny",
    "risk_score": 95,
    "reasons": ["The MCP tool manifest does not match the signed image."],
} if {
    input.signature_verified == true
    input.digest_pinned == true
    input.tool_manifest_verified == false
}
