import unittest

from sensor.tetragon_adapter import normalize_tetragon_event, parse_container_aliases


class TetragonAdapterTests(unittest.TestCase):
    def test_normalizes_process_exec(self) -> None:
        event = {
            "time": "2026-07-24T00:00:00Z",
            "process_exec": {
                "process": {
                    "binary": "/bin/sh",
                    "docker": "container-123",
                }
            },
        }
        result = normalize_tetragon_event(
            event, "intent-1", {"container-123": "arsl-mcp-server"}
        )
        self.assertEqual(result["event_type"], "process_exec")
        self.assertEqual(result["target"], "/bin/sh")
        self.assertEqual(result["container"], "arsl-mcp-server")

    def test_normalizes_file_kprobe(self) -> None:
        event = {
            "process_kprobe": {
                "function_name": "security_file_permission",
                "process": {"binary": "/usr/bin/python"},
                "args": [{"file_arg": {"path": "/app/documents/public/guide.txt"}}],
            }
        }
        result = normalize_tetragon_event(event, "intent-1")
        self.assertEqual(result["event_type"], "file_access")
        self.assertEqual(result["target"], "/app/documents/public/guide.txt")

    def test_ignores_unmapped_event(self) -> None:
        self.assertIsNone(normalize_tetragon_event({"process_exit": {}}, "intent-1"))

    def test_intent_id_is_optional_for_automatic_gateway_correlation(self) -> None:
        event = {
            "time": "2026-07-24T00:00:00Z",
            "process_kprobe": {
                "function_name": "security_file_permission",
                "process": {
                    "binary": "/usr/local/bin/python",
                    "docker": "8af6ee7b969e6318e5a261f85ee2a03",
                },
                "args": [{"file_arg": {"path": "/app/documents/public/guide.txt"}}],
            },
        }
        result = normalize_tetragon_event(
            event,
            None,
            {"8af6ee7b969e": "arsl-mcp-server"},
        )
        self.assertNotIn("intent_id", result)
        self.assertEqual(result["container"], "arsl-mcp-server")

    def test_rejects_short_or_malformed_container_alias(self) -> None:
        with self.assertRaisesRegex(ValueError, "12\+"):
            parse_container_aliases(["short=arsl-mcp-server"])

    def test_enriches_event_with_kubernetes_workload_identity(self) -> None:
        event = {
            "time": "2026-07-24T00:00:00Z",
            "process_exec": {
                "process": {
                    "binary": "/bin/true",
                    "pod": {
                        "namespace": "arsl-lab",
                        "name": "approved-tool",
                        "container": {"name": "tool"},
                    },
                }
            },
        }
        identity = {
            "cluster": "arsl-phase7",
            "namespace": "arsl-lab",
            "pod_name": "approved-tool",
            "pod_uid": "pod-uid-1",
            "service_account": "agent-tools",
            "container_name": "tool",
        }
        result = normalize_tetragon_event(
            event,
            "intent-1",
            pod_identities={("arsl-lab", "approved-tool", "tool"): identity},
        )
        self.assertEqual(result["workload_identity"], identity)


if __name__ == "__main__":
    unittest.main()
