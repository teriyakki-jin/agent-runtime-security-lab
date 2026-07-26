import unittest

from sensor.kubernetes_identity import identities_from_pod_list


class KubernetesIdentityTests(unittest.TestCase):
    def test_builds_immutable_identity_from_pod_inventory(self) -> None:
        document = {
            "kind": "List",
            "items": [{
                "metadata": {
                    "namespace": "arsl-lab",
                    "name": "approved-tool",
                    "uid": "pod-uid-1",
                },
                "spec": {
                    "serviceAccountName": "agent-tools",
                    "nodeName": "arsl-phase7-control-plane",
                    "containers": [{"name": "tool"}],
                },
            }],
        }
        identities = identities_from_pod_list(document, "arsl-phase7")
        identity = identities[("arsl-lab", "approved-tool", "tool")]
        self.assertEqual(identity["pod_uid"], "pod-uid-1")
        self.assertEqual(identity["service_account"], "agent-tools")
        self.assertEqual(identity["cluster"], "arsl-phase7")

    def test_rejects_non_list_inventory(self) -> None:
        with self.assertRaisesRegex(ValueError, "List"):
            identities_from_pod_list({"kind": "Pod"}, "arsl-phase7")


if __name__ == "__main__":
    unittest.main()
