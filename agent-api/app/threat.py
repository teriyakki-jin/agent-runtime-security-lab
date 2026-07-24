from __future__ import annotations

from copy import deepcopy
from typing import Any


OWASP_AGENTIC_2026: dict[str, dict[str, str]] = {
    "ASI01": {"uid": "ASI01", "name": "Agent Goal Hijack", "version": "2026"},
    "ASI02": {
        "uid": "ASI02",
        "name": "Tool Misuse & Exploitation",
        "version": "2026",
    },
    "ASI03": {
        "uid": "ASI03",
        "name": "Identity & Privilege Abuse",
        "version": "2026",
    },
    "ASI05": {
        "uid": "ASI05",
        "name": "Unexpected Code Execution (RCE)",
        "version": "2026",
    },
    "ASI10": {"uid": "ASI10", "name": "Rogue Agents", "version": "2026"},
}

MITRE_ATTACK: dict[str, dict[str, Any]] = {
    "file_access": {
        "tactic": {"uid": "TA0009", "name": "Collection"},
        "technique": {
            "uid": "T1005",
            "name": "Data from Local System",
            "src_url": "https://attack.mitre.org/techniques/T1005/",
        },
    },
    "process_exec": {
        "tactic": {"uid": "TA0002", "name": "Execution"},
        "technique": {
            "uid": "T1059",
            "name": "Command and Scripting Interpreter",
            "src_url": "https://attack.mitre.org/techniques/T1059/",
        },
    },
    "network_connect": {
        "tactic": {"uid": "TA0010", "name": "Exfiltration"},
        "technique": {
            "uid": "T1041",
            "name": "Exfiltration Over C2 Channel",
            "src_url": "https://attack.mitre.org/techniques/T1041/",
        },
    },
}

WORKLOAD_IDENTITY_ATTACK: dict[str, Any] = {
    "tactic": {"uid": "TA0004", "name": "Privilege Escalation"},
    "technique": {
        "uid": "T1078",
        "name": "Valid Accounts",
        "src_url": "https://attack.mitre.org/techniques/T1078/",
    },
}


def classify_finding(finding: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Return deterministic threat-framework mappings for an alertable finding."""
    if finding["matched"]:
        return {"owasp_agentic": [], "mitre_attacks": []}

    event_type = finding["observation"]["event_type"]
    owasp_ids: list[str] = []
    if finding["finding_type"] == "workload_identity_mismatch":
        return {
            "owasp_agentic": [deepcopy(OWASP_AGENTIC_2026["ASI03"])],
            "mitre_attacks": [deepcopy(WORKLOAD_IDENTITY_ATTACK)],
        }
    if finding["finding_type"] == "orphan_runtime_activity":
        owasp_ids.append("ASI10")
    if event_type == "process_exec":
        owasp_ids.extend(("ASI05", "ASI02"))
    elif event_type == "network_connect":
        owasp_ids.append("ASI02")
    elif event_type == "file_access":
        owasp_ids.append("ASI01")

    # Preserve order while preventing repeated framework entries.
    unique_owasp = list(dict.fromkeys(owasp_ids))
    attack = MITRE_ATTACK.get(event_type)
    return {
        "owasp_agentic": [deepcopy(OWASP_AGENTIC_2026[item]) for item in unique_owasp],
        "mitre_attacks": [deepcopy(attack)] if attack else [],
    }
