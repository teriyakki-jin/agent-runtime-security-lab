import argparse
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from supply_chain.admission import (
    AdmissionError,
    admitted_digest_reference,
    build_hardened_runtime_command,
    compare_tool_inventory,
    tool_schema_sha256,
)
from supply_chain.launcher import main as launcher_main
from supply_chain.launcher import runtime_command, validate_admission_bundle


class Phase13AdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        }
        self.manifest = {
            "tools": [
                {
                    "name": "read_document",
                    "oauth_scope": "mcp:read_document",
                    "input_schema_sha256": tool_schema_sha256(self.schema),
                }
            ]
        }

    def test_actual_tools_list_must_match_name_and_schema(self) -> None:
        actual = [{"name": "read_document", "inputSchema": self.schema}]
        result = compare_tool_inventory(self.manifest, actual)
        self.assertTrue(result["matched"])
        self.assertEqual(result["actual_count"], 1)

        injected = actual + [{"name": "exfiltrate", "inputSchema": {"type": "object"}}]
        result = compare_tool_inventory(self.manifest, injected)
        self.assertFalse(result["matched"])
        self.assertEqual(result["unexpected_tools"], ["exfiltrate"])

    def test_schema_drift_is_rejected_even_when_tool_name_matches(self) -> None:
        drifted = [{"name": "read_document", "inputSchema": {"type": "object"}}]
        result = compare_tool_inventory(self.manifest, drifted)
        self.assertFalse(result["matched"])
        self.assertEqual(result["schema_drift"], ["read_document"])

    def test_only_gate_output_digest_can_reach_runtime(self) -> None:
        digest = "sha256:" + "a" * 64
        requested = "ghcr.io/example/arsl/mcp-server:latest"
        gate_result = {
            "result": "passed",
            "image": {"repository": "ghcr.io/example/arsl/mcp-server", "digest": digest},
        }
        admitted = admitted_digest_reference(requested, gate_result)
        self.assertEqual(admitted, f"ghcr.io/example/arsl/mcp-server@{digest}")

        command = build_hardened_runtime_command(admitted, "arsl-mcp-server")
        self.assertEqual(command[-1], admitted)
        self.assertIn("--read-only", command)
        self.assertIn("no-new-privileges", command)
        self.assertIn("--cap-drop", command)

    def test_failed_or_mismatched_gate_output_never_builds_a_command(self) -> None:
        with self.assertRaises(AdmissionError):
            admitted_digest_reference("repo:tag", {"result": "blocked"})
        with self.assertRaises(AdmissionError):
            admitted_digest_reference(
                "ghcr.io/good/repo:tag",
                {
                    "result": "passed",
                    "image": {
                        "repository": "ghcr.io/other/repo",
                        "digest": "sha256:" + "b" * 64,
                    },
                },
            )

    def test_launcher_requires_gate_inventory_and_sbom_policy(self) -> None:
        digest = "sha256:" + "a" * 64
        requested = "ghcr.io/example/arsl/mcp-server:commit"
        gate = {
            "result": "passed",
            "image": {"repository": "ghcr.io/example/arsl/mcp-server", "digest": digest},
        }
        inventory = {"result": "passed", "inventory": {"matched": True}}
        sbom = {"allow": True}
        self.assertEqual(
            validate_admission_bundle(requested, gate, inventory, sbom),
            f"ghcr.io/example/arsl/mcp-server@{digest}",
        )
        with self.assertRaises(AdmissionError):
            validate_admission_bundle(
                requested,
                gate,
                {"result": "blocked", "inventory": {"matched": False}},
                sbom,
            )
        with self.assertRaises(AdmissionError):
            validate_admission_bundle(requested, gate, inventory, {"allow": False})

    def test_launcher_dry_run_emits_only_the_admitted_digest(self) -> None:
        digest = "sha256:" + "a" * 64
        requested = "ghcr.io/example/arsl/mcp-server:commit"
        artifacts = {
            "gate.json": {
                "result": "passed",
                "image": {
                    "repository": "ghcr.io/example/arsl/mcp-server",
                    "digest": digest,
                },
            },
            "inventory.json": {"result": "passed", "inventory": {"matched": True}},
            "sbom.json": {"allow": True},
        }
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, payload in artifacts.items():
                (root / name).write_text(json.dumps(payload), encoding="utf-8")
            args = argparse.Namespace(
                requested_image=requested,
                gate_result=root / "gate.json",
                inventory_result=root / "inventory.json",
                sbom_policy_result=root / "sbom.json",
                docker="docker",
                name="admitted",
                network="none",
                foreground=False,
                dry_run=True,
            )
            output = StringIO()
            with patch("supply_chain.launcher.parse_args", return_value=args), redirect_stdout(output):
                self.assertEqual(launcher_main(), 0)
        self.assertEqual(json.loads(output.getvalue())["admitted_image"], f"ghcr.io/example/arsl/mcp-server@{digest}")

    def test_runtime_command_is_hardened_and_invalid_artifact_fails_closed(self) -> None:
        image = "ghcr.io/example/mcp@sha256:" + "f" * 64
        command = runtime_command(
            image, docker="docker", name="admitted", network="none", detach=True
        )
        self.assertIn("-d", command)
        self.assertIn("--read-only", command)
        self.assertIn("--cap-drop=ALL", command)
        self.assertEqual(command[-1], image)

        with tempfile.TemporaryDirectory() as temp:
            invalid = Path(temp) / "invalid.json"
            invalid.write_text("[]", encoding="utf-8")
            args = argparse.Namespace(
                requested_image="repo:tag",
                gate_result=invalid,
                inventory_result=invalid,
                sbom_policy_result=invalid,
                docker="docker",
                name="admitted",
                network="none",
                foreground=False,
                dry_run=True,
            )
            output = StringIO()
            with patch("supply_chain.launcher.parse_args", return_value=args), redirect_stdout(output):
                self.assertEqual(launcher_main(), 2)
        self.assertEqual(json.loads(output.getvalue())["result"], "blocked")


if __name__ == "__main__":
    unittest.main()
