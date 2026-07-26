import os
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from app.oauth import ServiceTokenProvider


class ServiceTokenProviderTests(unittest.IsolatedAsyncioTestCase):
    async def test_requests_audience_restricted_scoped_token_and_caches_it(self) -> None:
        response = httpx.Response(
            200,
            json={"access_token": "signed-token", "expires_in": 300},
            request=httpx.Request("POST", "http://auth-server:9000/token"),
        )
        client = AsyncMock()
        client.post.return_value = response
        provider = ServiceTokenProvider(client)
        with patch.dict(os.environ, {"MCP_OAUTH_CLIENT_SECRET": "s" * 32}):
            first = await provider.get_token(["mcp:read_document"])
            second = await provider.get_token(["mcp:read_document"])
        self.assertEqual(first, "signed-token")
        self.assertEqual(second, "signed-token")
        self.assertEqual(client.post.await_count, 1)
        data = client.post.await_args.kwargs["data"]
        self.assertEqual(data["resource"], "http://mcp-server:8000/mcp")
        self.assertEqual(data["scope"], "mcp:access mcp:read_document")

    async def test_rejects_missing_client_secret_before_network(self) -> None:
        client = AsyncMock()
        provider = ServiceTokenProvider(client)
        with patch.dict(os.environ, {"MCP_OAUTH_CLIENT_SECRET": ""}):
            with self.assertRaises(ValueError):
                await provider.get_token(["mcp:read_document"])
        client.post.assert_not_awaited()
