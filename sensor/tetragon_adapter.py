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
from typing import Any, TextIO


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
    }


def normalize_tetragon_event(
    event: dict[str, Any], intent_id: str
) -> dict[str, Any] | None:
    timestamp = event.get("time")
    if "process_exec" in event:
        data = event["process_exec"]
        identity = _process(data)
        return {
            "intent_id": intent_id,
            "source": "tetragon",
            "timestamp": timestamp,
            "event_type": "process_exec",
            "process": identity["process"],
            "target": identity["process"],
            "container": identity["container"],
        }

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

    return {
        "intent_id": intent_id,
        "source": "tetragon",
        "timestamp": timestamp,
        "event_type": event_type,
        "process": identity["process"],
        "target": target,
        "container": identity["container"],
    }


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
    stream: TextIO, *, intent_id: str, gateway: str, secret: str, dry_run: bool
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
        payload = normalize_tetragon_event(event, intent_id)
        if payload is None:
            continue
        if dry_run:
            print(canonical_payload(payload).decode())
        else:
            submit(payload, gateway, secret)
        submitted += 1
    return submitted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intent-id", required=True, help="Gateway intent/event ID")
    parser.add_argument("--input", default="-", help="Tetragon JSONL file or - for stdin")
    parser.add_argument("--gateway", default="http://127.0.0.1:8080")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    secret = os.getenv("RUNTIME_SENSOR_HMAC_KEY", "")
    if not args.dry_run and len(secret) < 32:
        parser.error("RUNTIME_SENSOR_HMAC_KEY must contain at least 32 characters")

    if args.input == "-":
        count = process_stream(
            sys.stdin,
            intent_id=args.intent_id,
            gateway=args.gateway,
            secret=secret,
            dry_run=args.dry_run,
        )
    else:
        with open(args.input, encoding="utf-8") as stream:
            count = process_stream(
                stream,
                intent_id=args.intent_id,
                gateway=args.gateway,
                secret=secret,
                dry_run=args.dry_run,
            )
    print(f"normalized observations: {count}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
