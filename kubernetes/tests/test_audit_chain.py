import json
import tempfile
import unittest
from pathlib import Path

from kubernetes.audit_chain import ATTACKER_USERNAME, correlate
from sensor.kubernetes_identity import identities_from_pod_list


def audit_event(
    audit_id: str,
    timestamp: str,
    resource: str,
    name: str,
    *,
    subresource: str = "",
    request_object: dict | None = None,
    actor: str = ATTACKER_USERNAME,
    authenticated_actor: str | None = None,
    verb: str = "create",
    response_code: int = 201,
) -> dict:
    ref = {
        "resource": resource,
        "namespace": "arsl-lab",
        "name": name,
    }
    if subresource:
        ref["subresource"] = subresource
    event = {
        "auditID": audit_id,
        "stage": "ResponseComplete",
        "stageTimestamp": timestamp,
        "verb": verb,
        "user": {"username": authenticated_actor or actor},
        "objectRef": ref,
        "requestObject": request_object or {},
        "responseStatus": {"code": response_code},
    }
    if authenticated_actor:
        event["impersonatedUser"] = {"username": actor}
    return event


def fixtures() -> tuple[list[dict], list[dict], dict]:
    audit = [
        audit_event(
            "audit-role",
            "2026-07-24T00:00:01Z",
            "rolebindings",
            "shadow-cluster-admin",
            request_object={
                "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                "subjects": [{
                    "kind": "ServiceAccount",
                    "name": "compromised-agent",
                    "namespace": "arsl-lab",
                }],
            },
        ),
        audit_event(
            "audit-pod",
            "2026-07-24T00:00:02Z",
            "pods",
            "audit-shadow",
            request_object={"spec": {"serviceAccountName": "compromised-agent"}},
        ),
        audit_event(
            "audit-exec",
            "2026-07-24T00:00:03Z",
            "pods",
            "audit-shadow",
            subresource="exec",
            verb="get",
            response_code=101,
        ),
    ]
    tetragon = [{
        "time": "2026-07-24T00:00:04Z",
        "process_exec": {
            "process": {
                "binary": "/bin/echo",
                "pod": {
                    "namespace": "arsl-lab",
                    "name": "audit-shadow",
                    "container": {"name": "tool"},
                },
            }
        },
    }]
    inventory = identities_from_pod_list(
        {
            "kind": "List",
            "items": [{
                "metadata": {
                    "namespace": "arsl-lab",
                    "name": "audit-shadow",
                    "uid": "pod-uid-audit",
                },
                "spec": {
                    "serviceAccountName": "compromised-agent",
                    "nodeName": "arsl-phase8-control-plane",
                    "containers": [{"name": "tool"}],
                },
            }],
        },
        "arsl-phase8",
    )
    return audit, tetragon, inventory


class AuditChainTests(unittest.TestCase):
    def test_correlates_rbac_pod_and_kernel_events(self) -> None:
        audit, tetragon, inventory = fixtures()

        result = correlate(
            audit_events=audit,
            tetragon_events=tetragon,
            identities=inventory,
            cluster="arsl-phase8",
        )

        self.assertEqual(result["severity"], "Critical")
        self.assertEqual(result["finding_type"], "kubernetes_privilege_escalation_chain")
        self.assertEqual(result["mitre_attack"], ["T1098.006", "T1610"])
        self.assertEqual(result["owasp_agentic"], ["ASI03"])
        self.assertEqual(result["workload_identity"]["pod_uid"], "pod-uid-audit")
        self.assertEqual(result["correlation_delta_ms"], 3000)

    def test_rejects_role_binding_for_another_subject(self) -> None:
        audit, tetragon, inventory = fixtures()
        audit[0]["requestObject"]["subjects"][0]["name"] = "another-agent"

        with self.assertRaisesRegex(ValueError, "RoleBinding"):
            correlate(
                audit_events=audit,
                tetragon_events=tetragon,
                identities=inventory,
                cluster="arsl-phase8",
            )

    def test_export_excludes_tokens_commands_and_request_bodies(self) -> None:
        audit, tetragon, inventory = fixtures()
        audit[1]["requestObject"]["spec"]["secret"] = "not-exported-token"

        result = correlate(
            audit_events=audit,
            tetragon_events=tetragon,
            identities=inventory,
            cluster="arsl-phase8",
        )
        rendered = json.dumps(result)

        self.assertNotIn("not-exported-token", rendered)
        self.assertNotIn("/bin/echo", rendered)
        self.assertTrue(result["privacy"]["service_account_token_exported"] is False)

    def test_uses_effective_impersonated_identity(self) -> None:
        audit, tetragon, inventory = fixtures()
        for event in audit:
            event["impersonatedUser"] = {"username": ATTACKER_USERNAME}
            event["user"] = {"username": "kubernetes-admin"}

        result = correlate(
            audit_events=audit,
            tetragon_events=tetragon,
            identities=inventory,
            cluster="arsl-phase8",
        )

        self.assertEqual(result["actor"], ATTACKER_USERNAME)
        self.assertEqual(
            result["chain"]["rbac_grant"]["authenticated_actor"],
            "kubernetes-admin",
        )
        self.assertEqual(
            result["chain"]["rbac_grant"]["effective_actor"],
            ATTACKER_USERNAME,
        )


if __name__ == "__main__":
    unittest.main()
