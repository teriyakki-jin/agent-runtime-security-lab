import json
import unittest

from app.ocsf import to_ocsf_api_activity, to_ocsf_detection_finding


class OcsfMappingTests(unittest.TestCase):
    def test_maps_agent_tool_event_to_ocsf_18_api_activity(self) -> None:
        event = {
            "event_id": "event-1",
            "timestamp": "2026-07-24T00:00:00+00:00",
            "actor": "lab-analyst",
            "scenario_id": "data_exfiltration",
            "tool": "mock_http_request",
            "argument_keys": ["url"],
            "argument_fingerprint": "0123456789abcdef",
            "decision": {
                "allow": False,
                "action": "review",
                "risk_score": 80,
                "reasons": ["review required"],
            },
            "approval_id": "approval-1",
            "executed": False,
            "output": [],
        }

        result = to_ocsf_api_activity(event)

        self.assertEqual(result["metadata"]["version"], "1.8.0")
        self.assertEqual(result["metadata"]["profiles"], ["ai_operation"])
        self.assertEqual(result["category_uid"], 6)
        self.assertEqual(result["class_uid"], 6003)
        self.assertEqual(result["type_uid"], 600399)
        self.assertEqual(result["status"], "Pending Review")
        self.assertEqual(result["message_context"]["ai_role_id"], 4)

    def test_export_does_not_contain_raw_arguments(self) -> None:
        event = {
            "event_id": "event-2",
            "timestamp": "2026-07-24T00:00:00+00:00",
            "actor": "lab-analyst",
            "scenario_id": None,
            "tool": "read_document",
            "argument_keys": ["path"],
            "argument_fingerprint": "fedcba9876543210",
            "decision": {
                "allow": False,
                "action": "deny",
                "risk_score": 100,
                "reasons": ["blocked"],
            },
            "approval_id": None,
            "executed": False,
            "output": [],
        }

        serialized = json.dumps(to_ocsf_api_activity(event))

        self.assertNotIn("../../etc/shadow", serialized)
        self.assertNotIn('"arguments"', serialized)

    def test_runtime_mismatch_maps_to_detection_finding(self) -> None:
        finding = {
            "finding_id": "finding-1",
            "timestamp": "2026-07-24T00:00:00+00:00",
            "intent_id": "intent-1",
            "finding_type": "policy_runtime_mismatch",
            "title": "Observed process execution after a policy deny",
            "reason": "The policy denied execution but the sensor observed activity.",
            "severity_id": 5,
            "severity": "Critical",
            "matched": False,
            "tool": "run_command",
            "policy_action": "deny",
            "observation": {
                "observation_id": "observation-1",
                "source": "tetragon",
                "event_type": "process_exec",
                "process": "/bin/sh",
                "target_fingerprint": "0123456789abcdef",
                "container": "arsl-mcp-server",
            },
        }
        result = to_ocsf_detection_finding(finding)
        self.assertEqual(result["class_uid"], 2004)
        self.assertEqual(result["metadata"]["version"], "1.8.0")
        self.assertTrue(result["is_alert"])
        self.assertEqual(
            result["finding_info"]["attacks"][0]["technique"]["uid"], "T1059"
        )
        self.assertEqual(
            result["unmapped"]["security"]["owasp_agentic"][0]["uid"], "ASI05"
        )
        self.assertNotIn("/bin/sh", str(result))
