"""Correlate real Kind/Tetragon process events with immutable Pod identities."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "agent-api"))
sys.path.insert(0, str(ROOT))

from app.ocsf import to_ocsf_detection_finding  # noqa: E402
from app.runtime import RuntimeMonitor  # noqa: E402
from sensor.kubernetes_identity import load_pod_inventory  # noqa: E402
from sensor.tetragon_adapter import normalize_tetragon_event  # noqa: E402


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            events.append(item)
    return events


def find_exec(
    events: list[dict[str, Any]],
    identities: dict[tuple[str, str, str], dict[str, str]],
    pod_name: str,
) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for event in events:
        payload = normalize_tetragon_event(
            event,
            "phase7-intent",
            pod_identities=identities,
        )
        if not payload or payload.get("event_type") != "process_exec":
            continue
        identity = payload.get("workload_identity") or {}
        if identity.get("pod_name") == pod_name and payload["process"] == "/bin/echo":
            matches.append(payload)
    if not matches:
        raise ValueError(f"No /bin/echo Tetragon event found for Pod {pod_name}.")
    return matches[-1]


def verify(inventory: Path, events_path: Path, cluster: str) -> dict[str, Any]:
    identities = load_pod_inventory(inventory, cluster)
    events = load_events(events_path)
    approved = find_exec(events, identities, "approved-tool")
    shadow = find_exec(events, identities, "shadow-runner")

    monitor = RuntimeMonitor(max_records=20)
    monitor.register_intent(
        intent_id="phase7-intent",
        tool="kubernetes_job",
        actor="lab-security-agent",
        policy_action="allow",
        executed=True,
        container="tool",
        workload_identity=approved["workload_identity"],
    )
    approved_finding = monitor.ingest(approved)
    shadow_finding = monitor.ingest(shadow)
    shadow_without_intent = dict(shadow)
    shadow_without_intent["intent_id"] = ""
    orphan_finding = monitor.ingest(shadow_without_intent)
    ocsf = to_ocsf_detection_finding(shadow_finding)

    if not approved_finding["matched"]:
        raise ValueError("Approved Pod identity did not match its intent.")
    if shadow_finding["finding_type"] != "workload_identity_mismatch":
        raise ValueError("Shadow Pod did not produce a workload identity mismatch.")
    if shadow_finding["severity"] != "Critical":
        raise ValueError("Workload identity mismatch was not Critical.")
    if orphan_finding["finding_type"] != "orphan_runtime_activity":
        raise ValueError("Unbound shadow execution did not produce an orphan finding.")

    owasp_ids = [
        item["uid"] for item in ocsf["unmapped"]["security"]["owasp_agentic"]
    ]
    mitre_ids = [
        item["technique"]["uid"] for item in ocsf["finding_info"]["attacks"]
    ]
    if owasp_ids != ["ASI03"] or mitre_ids != ["T1078"]:
        raise ValueError("Workload identity threat mapping is incomplete.")

    return {
        "cluster": cluster,
        "event_source": "Tetragon process_exec",
        "events_scanned": len(events),
        "approved": {
            "pod": approved["workload_identity"]["pod_name"],
            "pod_uid": approved["workload_identity"]["pod_uid"],
            "service_account": approved["workload_identity"]["service_account"],
            "finding_type": approved_finding["finding_type"],
            "matched": approved_finding["matched"],
        },
        "shadow": {
            "pod": shadow["workload_identity"]["pod_name"],
            "pod_uid": shadow["workload_identity"]["pod_uid"],
            "service_account": shadow["workload_identity"]["service_account"],
            "finding_type": shadow_finding["finding_type"],
            "severity": shadow_finding["severity"],
            "owasp_agentic": owasp_ids,
            "mitre_attack": mitre_ids,
        },
        "orphan_detection": orphan_finding["finding_type"],
        "raw_process_arguments_exported": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--cluster", default="arsl-phase7")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.inventory, args.events, args.cluster)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Kubernetes identity verification failed: {exc}", file=sys.stderr)
        return 1
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
