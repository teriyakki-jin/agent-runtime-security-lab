import hashlib
import hmac
import json
import os
import unittest
from datetime import datetime, timedelta

from app.runtime import RuntimeMonitor, canonical_sensor_payload, verify_sensor_signature


class RuntimeMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.monitor = RuntimeMonitor(max_records=20)

    def register(self, *, executed: bool, tool: str = "read_document") -> None:
        self.monitor.register_intent(
            intent_id="intent-1",
            tool=tool,
            actor="test-agent",
            policy_action="allow" if executed else "deny",
            executed=executed,
        )

    def test_expected_public_file_read_matches_intent(self) -> None:
        self.register(executed=True)
        finding = self.monitor.ingest({
            "intent_id": "intent-1", "source": "simulator",
            "event_type": "file_access", "process": "python",
            "target": "/app/documents/public/guide.txt",
            "container": "arsl-mcp-server",
        })
        self.assertTrue(finding["matched"])
        self.assertEqual(finding["severity"], "Informational")

    def test_process_after_policy_deny_is_critical_mismatch(self) -> None:
        self.register(executed=False, tool="run_command")
        finding = self.monitor.ingest({
            "intent_id": "intent-1", "source": "tetragon",
            "event_type": "process_exec", "process": "/bin/sh",
            "target": "/bin/sh", "container": "arsl-mcp-server",
        })
        self.assertFalse(finding["matched"])
        self.assertEqual(finding["finding_type"], "policy_runtime_mismatch")
        self.assertEqual(finding["severity"], "Critical")

    def test_network_activity_is_unexpected_for_simulated_http_tool(self) -> None:
        self.register(executed=True, tool="mock_http_request")
        finding = self.monitor.ingest({
            "intent_id": "intent-1", "source": "tetragon",
            "event_type": "network_connect", "process": "python",
            "target": "203.0.113.10:443", "container": "arsl-mcp-server",
        })
        self.assertFalse(finding["matched"])
        self.assertEqual(finding["severity"], "Critical")

    def test_orphan_observation_is_high_severity(self) -> None:
        finding = self.monitor.ingest({
            "intent_id": "unknown", "source": "tetragon",
            "event_type": "process_exec", "process": "/bin/bash",
            "target": "/bin/bash", "container": "unknown",
        })
        self.assertEqual(finding["finding_type"], "orphan_runtime_activity")
        self.assertEqual(finding["severity"], "High")

    def test_invalid_sensor_timestamp_is_rejected(self) -> None:
        self.register(executed=True)
        with self.assertRaisesRegex(ValueError, "ISO-8601"):
            self.monitor.ingest({
                "intent_id": "intent-1", "source": "tetragon",
                "event_type": "file_access", "process": "python",
                "target": "/app/documents/public/guide.txt",
                "container": "arsl-mcp-server", "timestamp": "not-a-time",
            })

    def test_container_and_time_window_auto_correlate_without_intent_id(self) -> None:
        self.register(executed=True)
        intent_time = datetime.fromisoformat(
            self.monitor.intents["intent-1"]["timestamp"]
        )
        finding = self.monitor.ingest({
            "source": "tetragon", "event_type": "file_access",
            "process": "/usr/local/bin/python",
            "target": "/app/documents/public/guide.txt",
            "container": "arsl-mcp-server",
            "timestamp": (intent_time + timedelta(milliseconds=80)).isoformat(),
        })
        self.assertTrue(finding["matched"])
        self.assertEqual(finding["intent_id"], "intent-1")
        self.assertEqual(
            finding["observation"]["correlation_method"],
            "container_time_window",
        )
        self.assertLess(finding["observation"]["correlation_delta_ms"], 100)
        status = self.monitor.status()
        self.assertEqual(status["sensor_mode"], "tetragon")
        self.assertEqual(status["auto_correlated"], 1)

    def test_observation_outside_window_stays_orphan(self) -> None:
        self.register(executed=True)
        intent_time = datetime.fromisoformat(
            self.monitor.intents["intent-1"]["timestamp"]
        )
        finding = self.monitor.ingest({
            "source": "tetragon", "event_type": "file_access",
            "process": "/usr/local/bin/python",
            "target": "/app/documents/public/guide.txt",
            "container": "arsl-mcp-server",
            "timestamp": (intent_time + timedelta(seconds=30)).isoformat(),
        })
        self.assertEqual(finding["finding_type"], "orphan_runtime_activity")
        self.assertEqual(finding["observation"]["correlation_method"], "none")


class SensorSignatureTests(unittest.TestCase):
    def test_sensor_payload_signature(self) -> None:
        os.environ["RUNTIME_SENSOR_HMAC_KEY"] = "s" * 32
        payload = {"event_type": "process_exec", "intent_id": "intent-1"}
        raw = canonical_sensor_payload(payload)
        signature = hmac.new(b"s" * 32, raw, hashlib.sha256).hexdigest()
        self.assertTrue(verify_sensor_signature(raw, signature))
        self.assertFalse(verify_sensor_signature(raw + b" ", signature))

    def test_canonical_payload_is_stable(self) -> None:
        left = canonical_sensor_payload({"b": 2, "a": 1})
        right = json.dumps(
            {"a": 1, "b": 2}, sort_keys=True, separators=(",", ":")
        ).encode()
        self.assertEqual(left, right)


if __name__ == "__main__":
    unittest.main()
