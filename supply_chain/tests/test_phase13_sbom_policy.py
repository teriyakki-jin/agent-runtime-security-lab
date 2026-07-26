import unittest

from supply_chain.sbom_policy import evaluate_sbom_policy


class Phase13SbomPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = {
            "maximum_vulnerabilities": {"critical": 0, "high": 0},
            "maximum_observed_vulnerabilities": {"critical": 10, "high": 50},
            "vulnerability_package_types": ["python"],
            "denied_licenses": ["AGPL-3.0-only", "GPL-3.0-only"],
            "license_purl_types": ["pypi"],
            "required_components": ["mcp", "pyjwt", "opentelemetry-sdk"],
        }
        self.sbom = {
            "components": [
                {"name": "mcp", "purl": "pkg:pypi/mcp@1.28.1", "licenses": [{"license": {"id": "MIT"}}]},
                {"name": "PyJWT", "purl": "pkg:pypi/pyjwt@2.13.0", "licenses": [{"license": {"id": "MIT"}}]},
                {"name": "opentelemetry-sdk", "purl": "pkg:pypi/opentelemetry-sdk@1.44.0", "licenses": [{"license": {"id": "Apache-2.0"}}]},
            ]
        }

    def test_clean_expected_sbom_is_allowed(self) -> None:
        result = evaluate_sbom_policy(self.sbom, {"matches": []}, self.policy)
        self.assertTrue(result["allow"])
        self.assertEqual(result["critical"], 0)
        self.assertEqual(result["high"], 0)

    def test_critical_or_high_vulnerability_is_denied(self) -> None:
        report = {
            "matches": [
                {"artifact": {"type": "python"}, "vulnerability": {"id": "CVE-2099-0001", "severity": "Critical"}},
                {"artifact": {"type": "python"}, "vulnerability": {"id": "CVE-2099-0002", "severity": "High"}},
            ]
        }
        result = evaluate_sbom_policy(self.sbom, report, self.policy)
        self.assertFalse(result["allow"])
        self.assertEqual(result["critical"], 1)
        self.assertEqual(result["high"], 1)

    def test_operating_system_findings_are_reported_but_outside_app_gate(self) -> None:
        report = {
            "matches": [{
                "artifact": {"type": "deb"},
                "vulnerability": {"id": "CVE-2099-0003", "severity": "Critical"},
            }]
        }
        result = evaluate_sbom_policy(self.sbom, report, self.policy)
        self.assertTrue(result["allow"])
        self.assertEqual(result["observed_critical"], 1)
        self.assertEqual(result["critical"], 0)

        self.policy["maximum_observed_vulnerabilities"]["critical"] = 0
        result = evaluate_sbom_policy(self.sbom, report, self.policy)
        self.assertFalse(result["allow"])
        self.assertIn("observed_critical_baseline_exceeded", result["reason_codes"])

    def test_denied_license_and_missing_component_are_denied(self) -> None:
        self.sbom["components"][0]["licenses"] = [
            {"license": {"id": "AGPL-3.0-only"}}
        ]
        self.sbom["components"] = self.sbom["components"][:-1]
        result = evaluate_sbom_policy(self.sbom, {"matches": []}, self.policy)
        self.assertFalse(result["allow"])
        self.assertEqual(result["denied_licenses"], ["AGPL-3.0-only"])
        self.assertEqual(result["missing_components"], ["opentelemetry-sdk"])

    def test_unknown_or_malformed_sbom_fails_closed(self) -> None:
        result = evaluate_sbom_policy({}, {}, self.policy)
        self.assertFalse(result["allow"])
        self.assertIn("invalid_sbom", result["reason_codes"])
        self.assertIn("invalid_vulnerability_report", result["reason_codes"])


if __name__ == "__main__":
    unittest.main()
