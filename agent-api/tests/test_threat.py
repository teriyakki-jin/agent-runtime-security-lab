import unittest

from app.threat import classify_finding


def finding(
    event_type: str,
    *,
    matched: bool = False,
    finding_type: str = "policy_runtime_mismatch",
) -> dict:
    return {
        "matched": matched,
        "finding_type": finding_type,
        "observation": {"event_type": event_type},
    }


class ThreatMappingTests(unittest.TestCase):
    def test_denied_process_maps_to_owasp_and_mitre_execution(self) -> None:
        result = classify_finding(finding("process_exec"))

        self.assertEqual(
            [item["uid"] for item in result["owasp_agentic"]],
            ["ASI05", "ASI02"],
        )
        self.assertEqual(result["mitre_attacks"][0]["tactic"]["uid"], "TA0002")
        self.assertEqual(result["mitre_attacks"][0]["technique"]["uid"], "T1059")

    def test_network_bypass_maps_to_exfiltration(self) -> None:
        result = classify_finding(finding("network_connect"))

        self.assertEqual(result["owasp_agentic"][0]["uid"], "ASI02")
        self.assertEqual(result["mitre_attacks"][0]["technique"]["uid"], "T1041")

    def test_orphan_activity_adds_rogue_agent_mapping(self) -> None:
        result = classify_finding(
            finding("file_access", finding_type="orphan_runtime_activity")
        )

        self.assertEqual(
            [item["uid"] for item in result["owasp_agentic"]],
            ["ASI10", "ASI01"],
        )
        self.assertEqual(result["mitre_attacks"][0]["technique"]["uid"], "T1005")

    def test_expected_runtime_match_has_no_attack_mapping(self) -> None:
        result = classify_finding(finding("file_access", matched=True))

        self.assertEqual(result, {"owasp_agentic": [], "mitre_attacks": []})
