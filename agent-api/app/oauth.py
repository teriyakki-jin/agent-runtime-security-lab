from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass

import httpx


TOKEN_URL = os.getenv("MCP_OAUTH_TOKEN_URL", "http://auth-server:9000/token")
MCP_RESOURCE = os.getenv("MCP_RESOURCE", "http://mcp-server:8000/mcp")
CLIENT_ID = "arsl-agent-gateway"


@dataclass
class CachedToken:
    value: str
    expires_at: float


class ServiceTokenProvider:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client
        self._cache: dict[tuple[str, ...], CachedToken] = {}
        self._lock = asyncio.Lock()

    async def get_token(self, scopes: list[str]) -> str:
        key = tuple(sorted(set(scopes) | {"mcp:access"}))
        cached = self._cache.get(key)
        if cached and cached.expires_at > time.monotonic() + 15:
            return cached.value
        async with self._lock:
            cached = self._cache.get(key)
            if cached and cached.expires_at > time.monotonic() + 15:
                return cached.value
            secret = os.getenv("MCP_OAUTH_CLIENT_SECRET", "")
            if len(secret) < 32:
                raise ValueError("MCP_OAUTH_CLIENT_SECRET must contain at least 32 characters.")
            response = await self.client.post(
                TOKEN_URL,
                data={
                    "grant_type": "client_credentials",
                    "client_id": CLIENT_ID,
                    "client_secret": secret,
                    "scope": " ".join(key),
                    "resource": MCP_RESOURCE,
                },
            )
            response.raise_for_status()
            payload = response.json()
            token = str(payload["access_token"])
            expires_in = min(int(payload.get("expires_in", 300)), 300)
            self._cache[key] = CachedToken(token, time.monotonic() + expires_in)
            return token
