import unittest
from pathlib import Path

from detection.esql_runner import alert_id, build_alert, load_rule_pack, rows_from_esql


RULES = (
    Path(__file__).parents[2]
    / "deploy"
    / "elastic"
    / "detection-rules"
    / "agent-runtime-rules.json"
)


class DetectionRuleTests(unittest.TestCase):
    def test_rule_pack_has_stable_bounded_esql_queries(self) -> None:
        pack = load_rule_pack(RULES)

        self.assertEqual(len(pack["rules"]), 3)
        self.assertEqual(len({rule["id"] for rule in pack["rules"]}), 3)
        for rule in pack["rules"]:
            self.assertIn("METADATA _id", rule["query"])
            self.assertIn("| LIMIT 100", rule["query"])

    def test_esql_rows_are_mapped_by_column_name(self) -> None:
        result = rows_from_esql(
            {
                "columns": [{"name": "_id"}, {"name": "severity"}],
                "values": [["finding-1", "Critical"]],
            }
        )

        self.assertEqual(result, [{"_id": "finding-1", "severity": "Critical"}])

    def test_alert_id_and_document_are_deterministic(self) -> None:
        rule = load_rule_pack(RULES)["rules"][0]
        row = {
            "_id": "finding-1",
            "@timestamp": "2026-07-24T00:00:00Z",
            "metadata.uid": "finding-1",
            "severity": "Critical",
            "finding_info.types": "policy_runtime_mismatch",
            "unmapped.security.event_type": "process_exec",
            "unmapped.security.policy_action": "deny",
            "unmapped.security.intent_id": "intent-1",
        }

        first_id, first = build_alert(rule, row)
        second_id, second = build_alert(rule, row)

        self.assertEqual(first_id, second_id)
        self.assertEqual(first, second)
        self.assertEqual(first_id, alert_id(rule["id"], "finding-1"))
        self.assertEqual(first["threat"]["owasp_agentic"][0]["uid"], "ASI05")
        self.assertEqual(
            first["threat"]["mitre_attack"][0]["technique"]["uid"], "T1059"
        )
        self.assertNotIn("/bin/sh", str(first))
