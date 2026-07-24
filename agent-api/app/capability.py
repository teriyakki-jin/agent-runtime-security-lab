from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Any


def argument_fingerprint(arguments: dict[str, Any]) -> str:
    payload = json.dumps(
        arguments,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def issue_capability(
    tool: str,
    arguments: dict[str, Any],
    approval_id: str,
    expires_at: int,
) -> str:
    secret = os.getenv("APPROVAL_HMAC_KEY", "")
    if len(secret) < 32:
        raise RuntimeError("APPROVAL_HMAC_KEY must contain at least 32 characters.")

    claims = {
        "version": 1,
        "tool": tool,
        "argument_fingerprint": argument_fingerprint(arguments),
        "approval_id": approval_id,
        "expires_at": expires_at,
    }
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=")
    signature = hmac.new(secret.encode(), encoded, hashlib.sha256).digest()
    return f"{encoded.decode()}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"
