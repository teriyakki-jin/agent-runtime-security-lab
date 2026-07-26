import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from mcp.server.auth.provider import AccessToken

from app.oauth import RevocationClient, require_tool_scope


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


class RevocationClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_active_introspection_result_is_accepted(self) -> None:
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"active": True, "jti": "token-jti"}
        client = AsyncMock()
        client.post.return_value = response
        client.__aenter__.return_value = client
        client.__aexit__.return_value = None

        with patch("app.oauth.httpx.AsyncClient", return_value=client):
            active = await RevocationClient(
                url="http://auth-server:9000/introspect",
                client_secret="i" * 32,
            ).is_active("signed-token")

        self.assertTrue(active)

    async def test_inactive_or_unavailable_introspection_fails_closed(self) -> None:
        inactive_response = MagicMock()
        inactive_response.raise_for_status.return_value = None
        inactive_response.json.return_value = {"active": False}
        inactive_client = AsyncMock()
        inactive_client.post.return_value = inactive_response
        inactive_client.__aenter__.return_value = inactive_client
        inactive_client.__aexit__.return_value = None

        with patch("app.oauth.httpx.AsyncClient", return_value=inactive_client):
            self.assertFalse(
                await RevocationClient(
                    url="http://auth-server:9000/introspect",
                    client_secret="i" * 32,
                ).is_active("revoked-token")
            )

        inactive_response.json.return_value = []
        with patch("app.oauth.httpx.AsyncClient", return_value=inactive_client):
            self.assertFalse(
                await RevocationClient(
                    url="http://auth-server:9000/introspect",
                    client_secret="i" * 32,
                ).is_active("malformed-response-token")
            )

        failing_client = AsyncMock()
        failing_client.__aenter__.side_effect = RuntimeError("auth server unavailable")
        with patch("app.oauth.httpx.AsyncClient", return_value=failing_client):
            self.assertFalse(
                await RevocationClient(
                    url="http://auth-server:9000/introspect",
                    client_secret="i" * 32,
                ).is_active("signed-token")
            )
