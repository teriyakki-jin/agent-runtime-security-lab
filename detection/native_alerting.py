from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from detection.esql_runner import load_rule_pack


CONNECTOR_ID = "arsl-soc-notifications"
NOTIFICATION_INDEX = "arsl-notifications-v1"


def connector_payload() -> dict[str, Any]:
    return {
        "name": "ARSL SOC Notification Index",
        "connector_type_id": ".index",
        "config": {"index": NOTIFICATION_INDEX, "refresh": True},
        "secrets": {},
    }


def native_rule_id(rule_id: str) -> str:
    return f"arsl-native-{rule_id.removeprefix('arsl-')}"


def native_rule_payload(rule: dict[str, Any]) -> dict[str, Any]:
    notification = {
        "@timestamp": "{{date}}",
        "alert_id": "{{alert.id}}",
        "channel": "elastic-index",
        "rule_id": "{{rule.id}}",
        "rule_name": "{{rule.name}}",
        "status": "new",
    }
    return {
        "rule_id": native_rule_id(rule["id"]),
        "name": f"ARSL Native - {rule['name']}",
        "description": rule["description"],
        "type": "esql",
        "language": "esql",
        "query": rule["query"],
        "severity": rule["severity"],
        "risk_score": rule["risk_score"],
        "interval": rule.get("interval", "1m"),
        "from": rule.get("from", "now-2m"),
        "enabled": True,
        "tags": [*rule["tags"], "Phase 11", "Native ES|QL"],
        "version": 1,
        "author": ["Agent Runtime Security Lab"],
        "false_positives": [],
        "references": [],
        "max_signals": 100,
        "actions": [
            {
                "id": CONNECTOR_ID,
                "action_type_id": ".index",
                "group": "default",
                "params": {"documents": [notification]},
                "frequency": {
                    "summary": False,
                    "notifyWhen": "onActiveAlert",
                    "throttle": None,
                },
            }
        ],
    }


def request_json(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    *,
    not_found_ok: bool = False,
) -> dict[str, Any] | None:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json", "kbn-xsrf": "arsl-phase11"},
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and not_found_ok:
            return None
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"Kibana returned HTTP {exc.code}: {detail}") from exc


def require_basic_connector(kibana: str) -> dict[str, Any]:
    types = request_json("GET", f"{kibana}/api/actions/connector_types")
    assert isinstance(types, list)
    connector = next((item for item in types if item.get("id") == ".index"), None)
    if not connector or not connector.get("enabled"):
        raise RuntimeError("The Basic-license Elastic index connector is unavailable.")
    return {
        "type": ".index",
        "enabled": True,
        "minimum_license": connector.get("minimum_license_required", "unknown"),
    }


def upsert_connector(kibana: str) -> dict[str, Any]:
    current = request_json(
        "GET",
        f"{kibana}/api/actions/connector/{CONNECTOR_ID}",
        not_found_ok=True,
    )
    method = "PUT" if current else "POST"
    url = f"{kibana}/api/actions/connector/{CONNECTOR_ID}"
    payload = connector_payload()
    if current:
        payload.pop("connector_type_id")
    result = request_json(method, url, payload)
    assert isinstance(result, dict)
    return result


def upsert_rule(kibana: str, rule: dict[str, Any]) -> dict[str, Any]:
    payload = native_rule_payload(rule)
    query = urllib.parse.urlencode({"rule_id": payload["rule_id"]})
    current = request_json(
        "GET", f"{kibana}/api/detection_engine/rules?{query}", not_found_ok=True
    )
    method = "PUT" if current else "POST"
    result = request_json(method, f"{kibana}/api/detection_engine/rules", payload)
    assert isinstance(result, dict)
    return result


def sync(pack: dict[str, Any], kibana: str) -> dict[str, Any]:
    root = kibana.rstrip("/")
    license_result = require_basic_connector(root)
    connector = upsert_connector(root)
    rules = [upsert_rule(root, rule) for rule in pack["rules"]]
    return {
        "connector": {
            "id": connector["id"],
            "type": connector["connector_type_id"],
            **license_result,
        },
        "rules": [
            {
                "id": item["id"],
                "rule_id": item["rule_id"],
                "enabled": item["enabled"],
                "interval": item["interval"],
                "from": item["from"],
                "action_type": item["actions"][0]["action_type_id"],
            }
            for item in rules
        ],
    }


def parse_args() -> argparse.Namespace:
    root = Path(__file__).parents[1]
    parser = argparse.ArgumentParser(description="Sync ARSL rules to Elastic Security.")
    parser.add_argument(
        "--rules",
        type=Path,
        default=root / "deploy/elastic/detection-rules/agent-runtime-rules.json",
    )
    parser.add_argument(
        "--kibana",
        default=os.getenv("ARSL_KIBANA_URL", "http://127.0.0.1:15601"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = sync(load_rule_pack(args.rules), args.kibana)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"native alerting sync failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
