import unittest

from sensor.tetragon_adapter import normalize_tetragon_event


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
        result = normalize_tetragon_event(event, "intent-1")
        self.assertEqual(result["event_type"], "process_exec")
        self.assertEqual(result["target"], "/bin/sh")

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


if __name__ == "__main__":
    unittest.main()
