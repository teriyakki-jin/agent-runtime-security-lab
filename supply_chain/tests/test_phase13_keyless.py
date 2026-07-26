import base64
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from supply_chain.gate import VerificationError, canonical_manifest_sha256, verify_supply_chain


def attestation(predicate_type: str, predicate: dict) -> str:
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": predicate_type,
        "predicate": predicate,
    }
    encoded = base64.b64encode(json.dumps(statement).encode()).decode()
    return json.dumps([{"payload": encoded}])


class Phase13KeylessGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.digest = "sha256:" + "c" * 64
        self.image = f"ghcr.io/teriyakki-jin/agent-runtime-security-lab/mcp-server@{self.digest}"
        self.manifest = {
            "schema_version": 2,
            "server": {"name": "arsl-mcp-server", "transport": "streamable-http", "require_digest": True},
            "policy": {
                "deny_unlisted_tools": True,
                "maximum_tools": 1,
                "require_signature": True,
                "require_sbom_attestation": True,
                "require_tool_manifest_attestation": True,
                "require_runtime_inventory": True,
            },
            "tools": [{
                "name": "read_document",
                "oauth_scope": "mcp:read_document",
                "risk": "low",
                "input_schema_sha256": "d" * 64,
            }],
        }
        self.identity = "https://github.com/teriyakki-jin/agent-runtime-security-lab/.github/workflows/supply-chain.yml@refs/heads/main"
        self.issuer = "https://token.actions.githubusercontent.com"

    @patch("supply_chain.gate._run")
    def test_keyless_identity_rekor_and_signed_manifest_are_required(self, run) -> None:
        manifest_hash = canonical_manifest_sha256(self.manifest)
        run.side_effect = [
            json.dumps([{"critical": {"image": {"docker-manifest-digest": self.digest}}}]),
            attestation("https://cyclonedx.org/bom", {"bomFormat": "CycloneDX"}),
            attestation("https://agent-runtime-security.dev/attestations/mcp-tool-manifest/v1", self.manifest),
            json.dumps([{
                "Config": {"Labels": {"org.opencontainers.image.arsl.tool-manifest-sha256": manifest_hash}},
                "RepoDigests": [self.image],
            }]),
        ]
        result = verify_supply_chain(
            image=self.image,
            manifest=self.manifest,
            public_key=None,
            cosign="cosign",
            docker="docker",
            allow_insecure_registry=False,
            certificate_identity=self.identity,
            certificate_oidc_issuer=self.issuer,
        )
        self.assertTrue(result["controls"]["github_oidc_identity_verified"])
        self.assertTrue(result["controls"]["rekor_inclusion_verified"])
        self.assertTrue(result["controls"]["signed_tool_manifest_verified"])
        signature_command = run.call_args_list[0].args[0]
        self.assertIn(f"--certificate-identity={self.identity}", signature_command)
        self.assertIn(f"--certificate-oidc-issuer={self.issuer}", signature_command)
        self.assertNotIn("--insecure-ignore-tlog", signature_command)

    @patch("supply_chain.gate._run")
    def test_label_reuse_cannot_hide_signed_manifest_drift(self, run) -> None:
        altered = json.loads(json.dumps(self.manifest))
        altered["tools"].append({
            "name": "exfiltrate",
            "oauth_scope": "mcp:exfiltrate",
            "risk": "critical",
            "input_schema_sha256": "e" * 64,
        })
        run.side_effect = [
            json.dumps([{"critical": {"image": {"docker-manifest-digest": self.digest}}}]),
            attestation("https://cyclonedx.org/bom", {"bomFormat": "CycloneDX"}),
            attestation("https://agent-runtime-security.dev/attestations/mcp-tool-manifest/v1", altered),
        ]
        with self.assertRaisesRegex(VerificationError, "signed_tool_manifest_mismatch"):
            verify_supply_chain(
                image=self.image,
                manifest=self.manifest,
                public_key=None,
                cosign="cosign",
                docker="docker",
                allow_insecure_registry=False,
                certificate_identity=self.identity,
                certificate_oidc_issuer=self.issuer,
            )


if __name__ == "__main__":
    unittest.main()
