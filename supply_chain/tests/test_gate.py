import json
import unittest
from pathlib import Path
from unittest.mock import patch

from supply_chain.gate import (
    VerificationError,
    canonical_manifest_sha256,
    cosign_claims_match,
    load_manifest,
    pinned_image,
    validate_manifest,
    verify_supply_chain,
)


ROOT = Path(__file__).parents[2]
MANIFEST_PATH = ROOT / "deploy/supply-chain/trusted-mcp-tools.json"


class SupplyChainGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = load_manifest(MANIFEST_PATH)
        self.digest = "sha256:" + "a" * 64
        self.image = f"127.0.0.1:15000/arsl/mcp-server@{self.digest}"

    def test_manifest_is_canonical_least_privilege_inventory(self) -> None:
        validate_manifest(self.manifest)

        self.assertEqual(
            [item["name"] for item in self.manifest["tools"]],
            ["mock_http_request", "read_document", "run_command"],
        )
        self.assertEqual(len(canonical_manifest_sha256(self.manifest)), 64)

    def test_mutable_tag_is_rejected(self) -> None:
        with self.assertRaisesRegex(VerificationError, "unpinned_image_reference"):
            pinned_image("127.0.0.1:15000/arsl/mcp-server:latest")

    def test_cosign_claim_must_match_pinned_digest(self) -> None:
        payload = [
            {
                "critical": {
                    "image": {"docker-manifest-digest": self.digest},
                }
            }
        ]

        self.assertTrue(cosign_claims_match(payload, self.digest))
        self.assertFalse(cosign_claims_match(payload, "sha256:" + "b" * 64))

    def test_weakened_or_duplicate_manifest_is_rejected(self) -> None:
        weakened = json.loads(json.dumps(self.manifest))
        weakened["policy"]["require_signature"] = False
        with self.assertRaisesRegex(VerificationError, "weakened_manifest_policy"):
            validate_manifest(weakened)

        duplicated = json.loads(json.dumps(self.manifest))
        duplicated["tools"].append(duplicated["tools"][-1])
        duplicated["policy"]["maximum_tools"] = 4
        with self.assertRaisesRegex(VerificationError, "noncanonical_tool_inventory"):
            validate_manifest(duplicated)

    @patch("supply_chain.gate._run")
    def test_all_verified_controls_allow_pinned_image(self, run) -> None:
        manifest_hash = canonical_manifest_sha256(self.manifest)
        run.side_effect = [
            json.dumps(
                [
                    {
                        "critical": {
                            "image": {"docker-manifest-digest": self.digest}
                        }
                    }
                ]
            ),
            "{}",
            json.dumps(
                [
                    {
                        "Config": {
                            "Labels": {
                                "org.opencontainers.image.arsl.tool-manifest-sha256": manifest_hash
                            }
                        },
                        "RepoDigests": [f"127.0.0.1:15000/arsl/mcp-server@{self.digest}"],
                    }
                ]
            ),
        ]

        result = verify_supply_chain(
            image=self.image,
            manifest=self.manifest,
            public_key=Path("cosign.pub"),
            cosign="cosign",
            docker="docker",
            allow_insecure_registry=True,
        )

        self.assertEqual(result["result"], "passed")
        self.assertTrue(all(result["controls"].values()))
        self.assertNotIn("--insecure-ignore-tlog", run.call_args_list[0].args[0])

    @patch("supply_chain.gate._run")
    def test_offline_mode_is_explicit(self, run) -> None:
        manifest_hash = canonical_manifest_sha256(self.manifest)
        run.side_effect = [
            json.dumps([{"critical": {"image": {"docker-manifest-digest": self.digest}}}]),
            "{}",
            json.dumps([{
                "Config": {"Labels": {"org.opencontainers.image.arsl.tool-manifest-sha256": manifest_hash}},
                "RepoDigests": [f"repo@{self.digest}"],
            }]),
        ]
        verify_supply_chain(
            image=self.image,
            manifest=self.manifest,
            public_key=Path("cosign.pub"),
            cosign="cosign",
            docker="docker",
            allow_insecure_registry=True,
            offline_verification=True,
        )
        self.assertIn("--insecure-ignore-tlog", run.call_args_list[0].args[0])

    @patch("supply_chain.gate._run")
    def test_tool_manifest_label_drift_is_blocked(self, run) -> None:
        run.side_effect = [
            json.dumps(
                [
                    {
                        "critical": {
                            "image": {"docker-manifest-digest": self.digest}
                        }
                    }
                ]
            ),
            "{}",
            json.dumps(
                [
                    {
                        "Config": {
                            "Labels": {
                                "org.opencontainers.image.arsl.tool-manifest-sha256": "0" * 64
                            }
                        },
                        "RepoDigests": [f"repo@{self.digest}"],
                    }
                ]
            ),
        ]

        with self.assertRaisesRegex(VerificationError, "tool_manifest_digest_mismatch"):
            verify_supply_chain(
                image=self.image,
                manifest=self.manifest,
                public_key=Path("cosign.pub"),
                cosign="cosign",
                docker="docker",
                allow_insecure_registry=True,
            )


if __name__ == "__main__":
    unittest.main()
