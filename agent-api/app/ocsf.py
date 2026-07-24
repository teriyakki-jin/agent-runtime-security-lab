from __future__ import annotations

from datetime import datetime
from typing import Any

from app.threat import classify_finding


OCSF_VERSION = "1.8.0"
PRODUCT_VERSION = "0.8.0"
OCSF_CATEGORY_UID = 6
OCSF_CLASS_UID = 6003


def _activity_id(tool: str) -> int:
    if tool == "read_document":
        return 2
    return 99


def _severity(risk_score: int) -> tuple[int, str]:
    if risk_score >= 90:
        return 5, "Critical"
    if risk_score >= 70:
        return 4, "High"
    if risk_score >= 40:
        return 3, "Medium"
    if risk_score >= 20:
        return 2, "Low"
    return 1, "Informational"


def _status(event: dict[str, Any]) -> tuple[int, str]:
    action = event["decision"]["action"]
    if event["executed"]:
        return 1, "Success"
    if action == "review":
        return 0, "Pending Review"
    return 2, "Failure"


def to_ocsf_api_activity(event: dict[str, Any]) -> dict[str, Any]:
    activity_id = _activity_id(event["tool"])
    severity_id, severity = _severity(event["decision"]["risk_score"])
    status_id, status = _status(event)
    event_time = datetime.fromisoformat(event["timestamp"])
    approval_id = event.get("approval_id")

    return {
        "activity_id": activity_id,
        "activity_name": "Read" if activity_id == 2 else "Other",
        "category_uid": OCSF_CATEGORY_UID,
        "category_name": "Application Activity",
        "class_uid": OCSF_CLASS_UID,
        "class_name": "API Activity",
        "type_uid": OCSF_CLASS_UID * 100 + activity_id,
        "time": int(event_time.timestamp() * 1000),
        "severity_id": severity_id,
        "severity": severity,
        "status_id": status_id,
        "status": status,
        "message": f"MCP tool {event['tool']} policy action: {event['decision']['action']}",
        "metadata": {
            "version": OCSF_VERSION,
            "profiles": ["ai_operation"],
            "product": {
                "name": "Agent Runtime Security Lab",
                "vendor_name": "teriyakki-jin",
                "version": PRODUCT_VERSION,
            },
            "uid": event["event_id"],
        },
        "actor": {"user": {"name": event["actor"]}},
        "api": {
            "operation": f"tools/call:{event['tool']}",
            "service": {"name": "mcp-tool-server"},
        },
        "src_endpoint": {"hostname": "agent-gateway"},
        "message_context": {
            "ai_role_id": 4,
            "ai_role": "Agent",
            "application": "Agent Runtime Security Lab",
            "service": "agent-gateway",
            "uid": event["event_id"],
        },
        "unmapped": {
            "security": {
                "argument_fingerprint": event["argument_fingerprint"],
                "argument_keys": event["argument_keys"],
                "approval_id": approval_id,
                "executed": event["executed"],
                "policy_action": event["decision"]["action"],
                "policy_reasons": event["decision"]["reasons"],
                "risk_score": event["decision"]["risk_score"],
                "scenario_id": event.get("scenario_id"),
            }
        },
    }


def to_ocsf_detection_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Map intent/runtime correlation results to OCSF 1.8 Detection Finding."""
    event_time = datetime.fromisoformat(finding["timestamp"])
    observation = finding["observation"]
    matched = finding["matched"]
    classification = classify_finding(finding)
    workload_identity = observation.get("workload_identity")
    return {
        "activity_id": 1,
        "activity_name": "Create",
        "category_uid": 2,
        "category_name": "Findings",
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "type_uid": 200401,
        "time": int(event_time.timestamp() * 1000),
        "severity_id": finding["severity_id"],
        "severity": finding["severity"],
        "status_id": 2 if matched else 1,
        "status": "Resolved" if matched else "New",
        "is_alert": not matched,
        "message": finding["title"],
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "Agent Runtime Security Lab",
                "vendor_name": "teriyakki-jin",
                "version": PRODUCT_VERSION,
            },
            "uid": finding["finding_id"],
        },
        "finding_info": {
            "uid": finding["finding_id"],
            "title": finding["title"],
            "desc": finding["reason"],
            "types": [finding["finding_type"]],
            "attacks": classification["mitre_attacks"],
        },
        "analytic": {
            "name": "Agent Intent Runtime Correlator",
            "type_id": 1,
            "type": "Rule",
        },
        "resources": [
            {
                "name": observation["container"],
                "type": "Container",
            }
        ],
        "unmapped": {
            "security": {
                "intent_id": finding["intent_id"],
                "matched": matched,
                "observation_id": observation["observation_id"],
                "observation_source": observation["source"],
                "event_type": observation["event_type"],
                "correlation_method": observation.get("correlation_method"),
                "correlation_delta_ms": observation.get("correlation_delta_ms"),
                "target_fingerprint": observation["target_fingerprint"],
                "tool": finding["tool"],
                "policy_action": finding["policy_action"],
                "owasp_agentic": classification["owasp_agentic"],
                "workload_identity": workload_identity,
            }
        },
    }
