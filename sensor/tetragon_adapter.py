#!/usr/bin/env python3
"""Normalize Tetragon JSONL and submit signed runtime observations."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import urllib.request
from pathlib import Path
from typing import Any, TextIO

from sensor.kubernetes_identity import load_pod_inventory


def _process(event: dict[str, Any]) -> dict[str, Any]:
    process = event.get("process") or {}
    pod = process.get("pod") or {}
    container = pod.get("container") or {}
    return {
        "process": str(process.get("binary") or "unknown"),
        "container": str(
            process.get("docker")
            or container.get("name")
            or pod.get("name")
            or "unknown"
        ),
        "pod_namespace": str(pod.get("namespace") or ""),
        "pod_name": str(pod.get("name") or ""),
        "container_name": str(container.get("name") or ""),
    }


def _workload_identity(
    identity: dict[str, str],
    pod_identities: dict[tuple[str, str, str], dict[str, str]],
) -> dict[str, str] | None:
    key = (
        identity["pod_namespace"],
        identity["pod_name"],
        identity["container_name"],
    )
    workload = pod_identities.get(key)
    if not workload:
        return None
    return {
        key: value
        for key, value in workload.items()
        if key != "node_name"
    }


def _container_alias(container_id: str, aliases: dict[str, str]) -> str:
    matches = [
        (prefix, name)
        for prefix, name in aliases.items()
        if container_id.startswith(prefix) or prefix.startswith(container_id)
    ]
    if not matches:
        return container_id or "unknown"
    return max(matches, key=lambda item: len(item[0]))[1]


def normalize_tetragon_event(
    event: dict[str, Any],
    intent_id: str | None,
    container_aliases: dict[str, str] | None = None,
    pod_identities: dict[tuple[str, str, str], dict[str, str]] | None = None,
) -> dict[str, Any] | None:
    aliases = container_aliases or {}
    identities = pod_identities or {}
    timestamp = event.get("time")
    if "process_exec" in event:
        data = event["process_exec"]
        identity = _process(data)
        payload = {
            "source": "tetragon",
            "timestamp": timestamp,
            "event_type": "process_exec",
            "process": identity["process"],
            "target": identity["process"],
            "container": _container_alias(identity["container"], aliases),
        }
        if intent_id:
            payload["intent_id"] = intent_id
        workload = _workload_identity(identity, identities)
        if workload:
            payload["workload_identity"] = workload
        return payload

    data = event.get("process_kprobe")
    if not isinstance(data, dict):
        return None
    function_name = str(data.get("function_name") or "")
    identity = _process(data)
    args = data.get("args") or []

    if function_name == "security_file_permission":
        file_arg = next(
            (item.get("file_arg") for item in args if item.get("file_arg")), {}
        )
        target = str(file_arg.get("path") or file_arg.get("name") or "unknown")
        event_type = "file_access"
    elif function_name in {"tcp_connect", "security_socket_connect"}:
        sock_arg = next(
            (item.get("sock_arg") for item in args if item.get("sock_arg")), {}
        )
        address = sock_arg.get("daddr") or sock_arg.get("destination") or "unknown"
        port = sock_arg.get("dport") or sock_arg.get("port")
        target = f"{address}:{port}" if port is not None else str(address)
        event_type = "network_connect"
    else:
        return None

    payload = {
        "source": "tetragon",
        "timestamp": timestamp,
        "event_type": event_type,
        "process": identity["process"],
        "target": target,
        "container": _container_alias(identity["container"], aliases),
    }
    if intent_id:
        payload["intent_id"] = intent_id
    workload = _workload_identity(identity, identities)
    if workload:
        payload["workload_identity"] = workload
    return payload


def canonical_payload(payload: dict[str, Any]) -> bytes:
    clean = {key: value for key, value in payload.items() if value is not None}
    return json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")


def submit(payload: dict[str, Any], gateway: str, secret: str) -> None:
    body = canonical_payload(payload)
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        f"{gateway.rstrip('/')}/api/runtime/observations",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Sensor-Signature": signature,
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError(f"Gateway rejected observation: HTTP {response.status}")


def process_stream(
    stream: TextIO,
    *,
    intent_id: str | None,
    gateway: str,
    secret: str,
    dry_run: bool,
    container_aliases: dict[str, str] | None = None,
    container_name: str | None = None,
    include_event_types: set[str] | None = None,
    max_events: int = 0,
    pod_identities: dict[tuple[str, str, str], dict[str, str]] | None = None,
) -> int:
    submitted = 0
    for line_number, line in enumerate(stream, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"line {line_number}: invalid JSON: {exc}", file=sys.stderr)
            continue
        payload = normalize_tetragon_event(
            event, intent_id, container_aliases, pod_identities
        )
        if payload is None:
            continue
        if container_name and payload["container"] != container_name:
            continue
        if include_event_types and payload["event_type"] not in include_event_types:
            continue
        if dry_run:
            print(canonical_payload(payload).decode())
        else:
            submit(payload, gateway, secret)
        submitted += 1
        if max_events and submitted >= max_events:
            break
    return submitted


def parse_container_aliases(values: list[str]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for value in values:
        prefix, separator, name = value.partition("=")
        if not separator or len(prefix) < 12 or not name:
            raise ValueError(
                "Container aliases must use a Docker ID prefix of 12+ characters: ID=name"
            )
        aliases[prefix] = name
    return aliases


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--intent-id",
        help="Optional gateway intent ID; omit for container/time auto-correlation",
    )
    parser.add_argument("--input", default="-", help="Tetragon JSONL file or - for stdin")
    parser.add_argument("--gateway", default="http://127.0.0.1:8080")
    parser.add_argument(
        "--container-alias",
        action="append",
        default=[],
        metavar="ID=NAME",
        help="Map a Tetragon Docker ID prefix to the gateway container name",
    )
    parser.add_argument("--container-name", help="Only submit events for this container")
    parser.add_argument(
        "--pod-inventory",
        type=Path,
        help="kubectl Pod list JSON used to resolve Pod UID and ServiceAccount",
    )
    parser.add_argument(
        "--cluster-name",
        default="unknown-cluster",
        help="Cluster identity assigned to enriched workload events",
    )
    parser.add_argument(
        "--include-event-type",
        action="append",
        choices=["process_exec", "file_access", "network_connect"],
    )
    parser.add_argument(
        "--max-events", type=int, default=0, help="Stop after N submitted events"
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    secret = os.getenv("RUNTIME_SENSOR_HMAC_KEY", "")
    if not args.dry_run and len(secret) < 32:
        parser.error("RUNTIME_SENSOR_HMAC_KEY must contain at least 32 characters")

    try:
        aliases = parse_container_aliases(args.container_alias)
    except ValueError as exc:
        parser.error(str(exc))
    event_types = set(args.include_event_type or [])
    pod_identities = (
        load_pod_inventory(args.pod_inventory, args.cluster_name)
        if args.pod_inventory
        else {}
    )

    common = {
        "intent_id": args.intent_id,
        "gateway": args.gateway,
        "secret": secret,
        "dry_run": args.dry_run,
        "container_aliases": aliases,
        "container_name": args.container_name,
        "include_event_types": event_types,
        "max_events": max(0, args.max_events),
        "pod_identities": pod_identities,
    }
    if args.input == "-":
        count = process_stream(
            sys.stdin,
            **common,
        )
    else:
        with open(args.input, encoding="utf-8") as stream:
            count = process_stream(
                stream,
                **common,
            )
    print(f"normalized observations: {count}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
