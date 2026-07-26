package supply_chain

import rego.v1

test_trusted_signed_artifact_is_allowed if {
    result := decision with input as {
        "signature_verified": true,
        "digest_pinned": true,
        "sbom_attestation_verified": true,
        "tool_manifest_verified": true,
    }
    result.allow
    result.action == "allow"
}

test_unsigned_artifact_is_denied if {
    result := decision with input as {
        "signature_verified": false,
        "digest_pinned": true,
        "sbom_attestation_verified": false,
        "tool_manifest_verified": false,
    }
    not result.allow
    result.risk_score == 100
}

test_mutable_tag_is_denied if {
    result := decision with input as {
        "signature_verified": true,
        "digest_pinned": false,
        "sbom_attestation_verified": true,
        "tool_manifest_verified": true,
    }
    not result.allow
    result.risk_score == 95
}

test_tool_manifest_drift_is_denied if {
    result := decision with input as {
        "signature_verified": true,
        "digest_pinned": true,
        "sbom_attestation_verified": true,
        "tool_manifest_verified": false,
    }
    not result.allow
    result.risk_score == 95
}
