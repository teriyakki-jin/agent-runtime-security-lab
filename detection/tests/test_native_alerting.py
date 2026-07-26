import unittest
from pathlib import Path

from detection.esql_runner import load_rule_pack
from detection.native_alerting import (
    CONNECTOR_ID,
    connector_payload,
    native_rule_id,
    native_rule_payload,
)


RULES = (
    Path(__file__).parents[2]
    / "deploy"
    / "elastic"
    / "detection-rules"
    / "agent-runtime-rules.json"
)


class NativeAlertingTests(unittest.TestCase):
    def test_index_connector_is_basic_and_contains_no_secrets(self) -> None:
        payload = connector_payload()

        self.assertEqual(payload["connector_type_id"], ".index")
        self.assertEqual(payload["secrets"], {})
        self.assertTrue(payload["config"]["refresh"])

    def test_rules_are_scheduled_enabled_esql_with_per_alert_action(self) -> None:
        for rule in load_rule_pack(RULES)["rules"]:
            payload = native_rule_payload(rule)
            action = payload["actions"][0]

            self.assertEqual(payload["type"], "esql")
            self.assertTrue(payload["enabled"])
            self.assertEqual(payload["interval"], "1m")
            self.assertEqual(payload["from"], "now-2m")
            self.assertEqual(action["id"], CONNECTOR_ID)
            self.assertEqual(action["action_type_id"], ".index")
            self.assertFalse(action["frequency"]["summary"])

    def test_notification_template_exports_identifiers_not_source_content(self) -> None:
        rule = load_rule_pack(RULES)["rules"][0]
        document = native_rule_payload(rule)["actions"][0]["params"]["documents"][0]

        self.assertIn("{{alert.id}}", document.values())
        self.assertNotIn("context.alerts", str(document))
        self.assertNotIn("unmapped.security", str(document))
        self.assertEqual(native_rule_id("arsl-test"), "arsl-native-test")
