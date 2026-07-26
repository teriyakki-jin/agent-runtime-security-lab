from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
import time
from typing import Any


_consumed_approval_ids: set[str] = set()
_consumption_lock = threading.Lock()


def _decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _fingerprint(arguments: dict[str, Any]) -> str:
    payload = json.dumps(
        arguments,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def consume_capability(token: str, tool: str, arguments: dict[str, Any]) -> str:
    secret = os.getenv("APPROVAL_HMAC_KEY", "")
    if len(secret) < 32:
        raise ValueError("Approval capability verification is unavailable.")
    if not token or len(token) > 4096:
        raise ValueError("A valid approval capability is required.")

    try:
        encoded, supplied_signature = token.split(".", 1)
        expected_signature = hmac.new(
            secret.encode(), encoded.encode(), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected_signature, _decode(supplied_signature)):
            raise ValueError("Approval capability signature is invalid.")
        claims = json.loads(_decode(encoded))
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Approval capability is malformed.") from exc

    if claims.get("version") != 1:
        raise ValueError("Approval capability version is unsupported.")
    if claims.get("tool") != tool:
        raise ValueError("Approval capability is bound to another tool.")
    if claims.get("argument_fingerprint") != _fingerprint(arguments):
        raise ValueError("Approval capability is bound to different arguments.")
    if not isinstance(claims.get("expires_at"), int) or claims["expires_at"] < int(time.time()):
        raise ValueError("Approval capability has expired.")
    approval_id = claims.get("approval_id")
    if not isinstance(approval_id, str) or not approval_id:
        raise ValueError("Approval capability has no approval identifier.")

    with _consumption_lock:
        if approval_id in _consumed_approval_ids:
            raise ValueError("Approval capability has already been consumed.")
        _consumed_approval_ids.add(approval_id)
    return approval_id
