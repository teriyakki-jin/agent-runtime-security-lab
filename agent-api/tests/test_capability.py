import base64
import json
import os
import unittest
from unittest.mock import patch

from app.capability import argument_fingerprint, issue_capability


class CapabilityIssuerTests(unittest.TestCase):
    def test_capability_contains_only_bound_metadata(self) -> None:
        arguments = {"url": "https://sensitive.example/upload"}
        with patch.dict(os.environ, {"APPROVAL_HMAC_KEY": "a" * 32}):
            token = issue_capability("mock_http_request", arguments, "approval-1", 9999999999)

        encoded, _ = token.split(".", 1)
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual(payload["tool"], "mock_http_request")
        self.assertEqual(payload["argument_fingerprint"], argument_fingerprint(arguments))
        self.assertNotIn("arguments", payload)
        self.assertNotIn("sensitive.example", token)

    def test_short_secret_is_rejected(self) -> None:
        with patch.dict(os.environ, {"APPROVAL_HMAC_KEY": "short"}):
            with self.assertRaises(RuntimeError):
                issue_capability("tool", {}, "approval-1", 9999999999)
