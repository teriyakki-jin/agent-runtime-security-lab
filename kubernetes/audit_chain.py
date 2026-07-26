"""Correlate Kubernetes RBAC audit events with Tetragon runtime execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "agent-api"))
sys.path.insert(0, str(ROOT))

from app.ocsf import to_ocsf_detection_finding  # noqa: E402
from sensor.kubernetes_identity import load_pod_inventory  # noqa: E402
from sensor.tetragon_adapter import normalize_tetragon_event  # noqa: E402


ATTACKER_SERVICE_ACCOUNT = "compromised-agent"
ATTACKER_USERNAME = "system:serviceaccount:arsl-lab:compromised-agent"
ATTACK_NAMESPACE = "arsl-lab"
ATTACK_POD = "audit-shadow"
ESCALATION_BINDING = "shadow-cluster-admin"


def load_json_lines(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            events.append(item)
    return events


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("Audit event is missing an ISO-8601 timestamp.")
    normalized = re.sub(r"(\.\d{6})\d+(?=Z$|[+-]\d{2}:\d{2}$)", r"\1", value)
    parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _event_time(event: dict[str, Any]) -> datetime:
    return _timestamp(event.get("stageTimestamp") or event.get("requestReceivedTimestamp"))


def _successful(event: dict[str, Any]) -> bool:
    code = (event.get("responseStatus") or {}).get("code", 0)
    return isinstance(code, int) and 100 <= code < 400


def _actor(event: dict[str, Any]) -> str:
    effective = event.get("impersonatedUser") or event.get("user") or {}
    return str(effective.get("username") or "")


def _object_ref(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("objectRef")
    return value if isinstance(value, dict) else {}


def _matches_object(
    event: dict[str, Any],
    *,
    resource: str,
    namespace: str,
    name: str,
    subresource: str = "",
) -> bool:
    ref = _object_ref(event)
    return (
        ref.get("resource") == resource
        and ref.get("namespace") == namespace
        and ref.get("name") == name
        and str(ref.get("subresource") or "") == subresource
    )


def _find_role_grant(
    events: list[dict[str, Any]], actor: str, namespace: str, service_account: str
) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for event in events:
        request = event.get("requestObject") or {}
        subjects = request.get("subjects") or []
        subject_matches = any(
            isinstance(subject, dict)
            and subject.get("kind") == "ServiceAccount"
            and subject.get("name") == service_account
            and subject.get("namespace") == namespace
            for subject in subjects
        )
        if (
            _actor(event) == actor
            and event.get("verb") == "create"
            and _successful(event)
            and _matches_object(
                event,
                resource="rolebindings",
                namespace=namespace,
                name=ESCALATION_BINDING,
            )
            and (request.get("roleRef") or {}).get("name") == "cluster-admin"
            and subject_matches
        ):
            matches.append(event)
    if not matches:
        raise ValueError("No successful self-granted cluster-admin RoleBinding audit event found.")
    return max(matches, key=_event_time)


def _find_pod_create(
    events: list[dict[str, Any]],
    actor: str,
    namespace: str,
    pod_name: str,
    after: datetime,
) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for event in events:
        request = event.get("requestObject") or {}
        if (
            _actor(event) == actor
            and event.get("verb") == "create"
            and _successful(event)
            and _matches_object(
                event, resource="pods", namespace=namespace, name=pod_name
            )
            and (request.get("spec") or {}).get("serviceAccountName")
            == ATTACKER_SERVICE_ACCOUNT
            and _event_time(event) >= after
        ):
            matches.append(event)
    if not matches:
        raise ValueError("No successful attacker-owned Pod creation audit event found.")
    return min(matches, key=_event_time)


def _find_pod_exec(
    events: list[dict[str, Any]],
    actor: str,
    namespace: str,
    pod_name: str,
    after: datetime,
) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for event in events:
        if (
            _actor(event) == actor
            and event.get("verb") in {"get", "create"}
            and _successful(event)
            and _matches_object(
                event,
                resource="pods",
                namespace=namespace,
                name=pod_name,
                subresource="exec",
            )
            and _event_time(event) >= after
        ):
            matches.append(event)
    if not matches:
        raise ValueError("No successful Pod exec audit event found for the attacker identity.")
    return min(matches, key=_event_time)


def _find_runtime_exec(
    events: list[dict[str, Any]],
    identities: dict[tuple[str, str, str], dict[str, str]],
    pod_name: str,
    after: datetime,
) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for event in events:
        payload = normalize_tetragon_event(event, None, pod_identities=identities)
        if not payload or payload.get("event_type") != "process_exec":
            continue
        identity = payload.get("workload_identity") or {}
        if (
            identity.get("pod_name") == pod_name
            and payload.get("process") == "/bin/echo"
            and _timestamp(payload.get("timestamp")) >= after
        ):
            matches.append(payload)
    if not matches:
        raise ValueError(f"No /bin/echo Tetragon event found for Pod {pod_name}.")
    return min(matches, key=lambda item: _timestamp(item.get("timestamp")))


def _audit_summary(event: dict[str, Any]) -> dict[str, Any]:
    ref = _object_ref(event)
    return {
        "audit_id": str(event.get("auditID") or ""),
        "timestamp": _event_time(event).isoformat(),
        "authenticated_actor": str((event.get("user") or {}).get("username") or ""),
        "effective_actor": _actor(event),
        "verb": str(event.get("verb") or ""),
        "resource": str(ref.get("resource") or ""),
        "subresource": str(ref.get("subresource") or ""),
        "namespace": str(ref.get("namespace") or ""),
        "name": str(ref.get("name") or ""),
        "response_code": (event.get("responseStatus") or {}).get("code"),
    }


def correlate(
    *,
    audit_events: list[dict[str, Any]],
    tetragon_events: list[dict[str, Any]],
    identities: dict[tuple[str, str, str], dict[str, str]],
    cluster: str,
    actor: str = ATTACKER_USERNAME,
    namespace: str = ATTACK_NAMESPACE,
    pod_name: str = ATTACK_POD,
) -> dict[str, Any]:
    role_grant = _find_role_grant(
        audit_events, actor, namespace, ATTACKER_SERVICE_ACCOUNT
    )
    pod_create = _find_pod_create(
        audit_events, actor, namespace, pod_name, _event_time(role_grant)
    )
    pod_exec = _find_pod_exec(
        audit_events, actor, namespace, pod_name, _event_time(pod_create)
    )
    runtime_exec = _find_runtime_exec(
        tetragon_events, identities, pod_name, _event_time(pod_exec)
    )

    ordered = [
        _event_time(role_grant),
        _event_time(pod_create),
        _event_time(pod_exec),
        _timestamp(runtime_exec.get("timestamp")),
    ]
    if ordered != sorted(ordered):
        raise ValueError("RBAC, Pod creation, exec, and runtime events are out of order.")

    identity = runtime_exec.get("workload_identity") or {}
    if identity.get("service_account") != ATTACKER_SERVICE_ACCOUNT:
        raise ValueError("Runtime Pod did not use the compromised ServiceAccount.")
    if identity.get("cluster") != cluster:
        raise ValueError("Runtime workload identity belongs to another cluster.")

    process = str(runtime_exec.get("process") or "unknown")
    finding = {
        "finding_id": str(uuid4()),
        "timestamp": ordered[-1].isoformat(),
        "intent_id": "",
        "finding_type": "kubernetes_privilege_escalation_chain",
        "title": "Kubernetes RBAC privilege escalation reached runtime execution",
        "reason": (
            "One ServiceAccount self-granted cluster-admin, created a Pod, and "
            "reached kernel-observed process execution."
        ),
        "severity_id": 5,
        "severity": "Critical",
        "matched": False,
        "tool": "kubernetes_api",
        "policy_action": "deny",
        "observation": {
            "observation_id": str(pod_exec.get("auditID") or uuid4()),
            "timestamp": ordered[-1].isoformat(),
            "intent_id": "",
            "source": "kubernetes-audit+tetragon",
            "event_type": "process_exec",
            "process": process,
            "target": process,
            "target_fingerprint": hashlib.sha256(process.encode()).hexdigest()[:16],
            "container": str(runtime_exec.get("container") or "unknown"),
            "workload_identity": identity,
            "correlation_method": "audit_identity_runtime_chain",
            "correlation_delta_ms": round((ordered[-1] - ordered[0]).total_seconds() * 1000),
        },
    }
    ocsf = to_ocsf_detection_finding(finding)
    techniques = [
        item["technique"]["uid"] for item in ocsf["finding_info"]["attacks"]
    ]
    owasp = [
        item["uid"] for item in ocsf["unmapped"]["security"]["owasp_agentic"]
    ]
    if techniques != ["T1098.006", "T1610"] or owasp != ["ASI03"]:
        raise ValueError("Kubernetes attack-chain threat mapping is incomplete.")

    return {
        "cluster": cluster,
        "finding_type": finding["finding_type"],
        "severity": finding["severity"],
        "actor": actor,
        "workload_identity": identity,
        "chain": {
            "rbac_grant": _audit_summary(role_grant),
            "pod_create": _audit_summary(pod_create),
            "pod_exec": _audit_summary(pod_exec),
            "runtime_exec": {
                "timestamp": ordered[-1].isoformat(),
                "source": "Tetragon process_exec",
                "target_fingerprint": finding["observation"]["target_fingerprint"],
            },
        },
        "correlation_delta_ms": finding["observation"]["correlation_delta_ms"],
        "owasp_agentic": owasp,
        "mitre_attack": techniques,
        "audit_events_scanned": len(audit_events),
        "tetragon_events_scanned": len(tetragon_events),
        "privacy": {
            "service_account_token_exported": False,
            "raw_process_arguments_exported": False,
            "audit_request_bodies_exported": False,
        },
        "ocsf": ocsf,
    }


def verify(audit: Path, inventory: Path, tetragon: Path, cluster: str) -> dict[str, Any]:
    return correlate(
        audit_events=load_json_lines(audit),
        tetragon_events=load_json_lines(tetragon),
        identities=load_pod_inventory(inventory, cluster),
        cluster=cluster,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--tetragon", type=Path, required=True)
    parser.add_argument("--cluster", default="arsl-phase8")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.audit, args.inventory, args.tetragon, args.cluster)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Kubernetes audit-chain verification failed: {exc}", file=sys.stderr)
        return 1
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
