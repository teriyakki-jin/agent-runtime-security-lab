import time
import unittest
from unittest.mock import patch

from mcp.server.auth.provider import AccessToken

from app.oauth import require_tool_scope


class ToolScopeTests(unittest.TestCase):
    def test_required_tool_scope_is_accepted(self) -> None:
        token = AccessToken(
            token="redacted-test-token",
            client_id="phase9-test",
            scopes=["mcp:access", "mcp:read_document"],
            expires_at=int(time.time()) + 60,
            resource="http://mcp-server:8000/mcp",
            subject="lab-analyst",
        )
        with patch("app.oauth.get_access_token", return_value=token):
            self.assertEqual(require_tool_scope("mcp:read_document").client_id, "phase9-test")

    def test_missing_tool_scope_is_rejected(self) -> None:
        token = AccessToken(
            token="redacted-test-token",
            client_id="phase9-test",
            scopes=["mcp:access", "mcp:read_document"],
        )
        with patch("app.oauth.get_access_token", return_value=token):
            with self.assertRaises(PermissionError):
                require_tool_scope("mcp:mock_http_request")

    def test_missing_access_token_is_rejected(self) -> None:
        with patch("app.oauth.get_access_token", return_value=None):
            with self.assertRaises(PermissionError):
                require_tool_scope("mcp:read_document")
