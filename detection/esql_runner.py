from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_RULE_FIELDS = {
    "id",
    "name",
    "description",
    "severity",
    "risk_score",
    "tags",
    "owasp_agentic",
    "mitre_attack",
    "query",
}


def load_rule_pack(path: Path) -> dict[str, Any]:
    pack = json.loads(path.read_text(encoding="utf-8"))
    rules = pack.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("Detection pack must contain at least one rule.")

    seen: set[str] = set()
    for rule in rules:
        missing = REQUIRED_RULE_FIELDS - set(rule)
        if missing:
            raise ValueError(f"Rule is missing required fields: {sorted(missing)}")
        rule_id = rule["id"]
        if rule_id in seen:
            raise ValueError(f"Duplicate detection rule ID: {rule_id}")
        seen.add(rule_id)
        query = rule["query"]
        if not query.lstrip().upper().startswith("FROM ARSL-OCSF-*"):
            raise ValueError(f"Rule {rule_id} queries an unexpected index.")
        if "METADATA _id" not in query or "| LIMIT " not in query:
            raise ValueError(f"Rule {rule_id} must retain _id and set a result limit.")
    return pack


def rows_from_esql(response: dict[str, Any]) -> list[dict[str, Any]]:
    columns = [item["name"] for item in response.get("columns", [])]
    return [dict(zip(columns, values, strict=True)) for values in response.get("values", [])]


def alert_id(rule_id: str, source_id: str) -> str:
    return hashlib.sha256(f"{rule_id}:{source_id}".encode()).hexdigest()


def build_alert(
    rule: dict[str, Any],
    row: dict[str, Any],
    *,
    created_at: str | None = None,
) -> tuple[str, dict[str, Any]]:
    source_id = str(row.get("metadata.uid") or row["_id"])
    document_id = alert_id(rule["id"], source_id)
    timestamp = (
        row.get("@timestamp") or created_at or datetime.now(timezone.utc).isoformat()
    )
    finding_type = row.get("finding_info.types")
    if isinstance(finding_type, list):
        finding_type = finding_type[0] if finding_type else None
    document = {
        "@timestamp": timestamp,
        "message": f"{rule['name']}: {finding_type or 'runtime finding'}",
        "status": "active",
        "event": {
            "kind": "alert",
            "category": ["intrusion_detection"],
            "type": ["indicator"],
        },
        "rule": {
            "id": rule["id"],
            "name": rule["name"],
            "version": 1,
            "severity": rule["severity"],
            "risk_score": rule["risk_score"],
            "tags": rule["tags"],
        },
        "source": {"uid": source_id, "document_id": str(row["_id"])},
        "finding": {
            "type": finding_type,
            "event_type": row.get("unmapped.security.event_type"),
            "policy_action": row.get("unmapped.security.policy_action"),
            "intent_id": row.get("unmapped.security.intent_id"),
            "severity": row.get("severity"),
        },
        "threat": {
            "owasp_agentic": rule["owasp_agentic"],
            "mitre_attack": rule["mitre_attack"],
        },
    }
    return document_id, document


def request_json(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"Elasticsearch returned HTTP {exc.code}: {detail}") from exc


def execute_pack(
    pack: dict[str, Any],
    elasticsearch: str,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    summaries: list[dict[str, Any]] = []
    total_alerts = 0
    for rule in pack["rules"]:
        response = request_json(
            "POST",
            f"{elasticsearch.rstrip('/')}/_query",
            {"query": rule["query"]},
        )
        rows = rows_from_esql(response)
        for row in rows:
            document_id, document = build_alert(rule, row)
            if not dry_run:
                request_json(
                    "PUT",
                    f"{elasticsearch.rstrip('/')}/arsl-alerts-v1/_doc/{document_id}",
                    document,
                )
        total_alerts += len(rows)
        summaries.append({"rule_id": rule["id"], "matches": len(rows)})
    if not dry_run and total_alerts:
        request_json(
            "POST",
            f"{elasticsearch.rstrip('/')}/arsl-alerts-v1/_refresh",
        )
    return {"rules": summaries, "alerts": total_alerts, "dry_run": dry_run}


def parse_args() -> argparse.Namespace:
    default_rules = (
        Path(__file__).parents[1]
        / "deploy"
        / "elastic"
        / "detection-rules"
        / "agent-runtime-rules.json"
    )
    parser = argparse.ArgumentParser(description="Execute the ARSL ES|QL detection pack.")
    parser.add_argument("--rules", type=Path, default=default_rules)
    parser.add_argument(
        "--elasticsearch",
        default=os.getenv("ARSL_ELASTICSEARCH_URL", "http://127.0.0.1:19200"),
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        pack = load_rule_pack(args.rules)
        result = execute_pack(pack, args.elasticsearch, dry_run=args.dry_run)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"detection runner failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
