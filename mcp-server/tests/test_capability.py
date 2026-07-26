import base64
import hashlib
import hmac
import json
import os
import time
import unittest
from unittest.mock import patch

from app.capability import consume_capability


SECRET = "b" * 32


def make_token(
    tool: str,
    arguments: dict[str, str],
    expires_at: int,
    approval_id: str,
) -> str:
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":")).encode()
    claims = {
        "version": 1,
        "tool": tool,
        "argument_fingerprint": hashlib.sha256(canonical).hexdigest()[:16],
        "approval_id": approval_id,
        "expires_at": expires_at,
    }
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=")
    signature = hmac.new(SECRET.encode(), encoded, hashlib.sha256).digest()
    return f"{encoded.decode()}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"


class CapabilityVerifierTests(unittest.TestCase):
    def test_valid_capability_is_accepted(self) -> None:
        arguments = {"url": "https://external.example/upload"}
        token = make_token(
            "mock_http_request", arguments, int(time.time()) + 60, "valid-approval"
        )
        with patch.dict(os.environ, {"APPROVAL_HMAC_KEY": SECRET}):
            self.assertEqual(
                consume_capability(token, "mock_http_request", arguments),
                "valid-approval",
            )
            with self.assertRaises(ValueError):
                consume_capability(token, "mock_http_request", arguments)

    def test_capability_cannot_be_rebound_to_other_arguments(self) -> None:
        token = make_token(
            "mock_http_request",
            {"url": "https://approved.example/upload"},
            int(time.time()) + 60,
            "rebind-approval",
        )
        with patch.dict(os.environ, {"APPROVAL_HMAC_KEY": SECRET}):
            with self.assertRaises(ValueError):
                consume_capability(
                    token,
                    "mock_http_request",
                    {"url": "https://attacker.example/upload"},
                )

    def test_expired_capability_is_rejected(self) -> None:
        arguments = {"url": "https://external.example/upload"}
        token = make_token(
            "mock_http_request", arguments, int(time.time()) - 1, "expired-approval"
        )
        with patch.dict(os.environ, {"APPROVAL_HMAC_KEY": SECRET}):
            with self.assertRaises(ValueError):
                consume_capability(token, "mock_http_request", arguments)
