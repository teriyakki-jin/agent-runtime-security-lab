from __future__ import annotations

import os
import time
from typing import Any

import httpx
import jwt
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from pydantic import AnyHttpUrl


OAUTH_ISSUER = os.getenv("OAUTH_ISSUER", "http://auth-server:9000").rstrip("/")
MCP_RESOURCE = os.getenv("MCP_RESOURCE", "http://mcp-server:8000/mcp")
JWKS_URL = os.getenv("OAUTH_JWKS_URL", f"{OAUTH_ISSUER}/jwks.json")


class JwtTokenVerifier(TokenVerifier):
    def __init__(self, cache_seconds: int = 300) -> None:
        self.cache_seconds = cache_seconds
        self._jwks: dict[str, Any] | None = None
        self._loaded_at = 0.0

    async def _load_jwks(self, force: bool = False) -> dict[str, Any]:
        if not force and self._jwks and time.monotonic() - self._loaded_at < self.cache_seconds:
            return self._jwks
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(JWKS_URL)
            response.raise_for_status()
            jwks = response.json()
        if not isinstance(jwks.get("keys"), list) or not jwks["keys"]:
            raise ValueError("Authorization server returned no signing keys.")
        self._jwks = jwks
        self._loaded_at = time.monotonic()
        return jwks

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not header.get("kid"):
                return None
            jwks = await self._load_jwks()
            key_data = next((item for item in jwks["keys"] if item.get("kid") == header["kid"]), None)
            if key_data is None:
                jwks = await self._load_jwks(force=True)
                key_data = next((item for item in jwks["keys"] if item.get("kid") == header["kid"]), None)
            if key_data is None:
                return None
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
            claims = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=MCP_RESOURCE,
                issuer=OAUTH_ISSUER,
                options={"require": ["iss", "sub", "aud", "exp", "iat", "client_id", "scope", "jti"]},
            )
            scopes = sorted(set(str(claims["scope"]).split()))
            return AccessToken(
                token=token,
                client_id=str(claims["client_id"]),
                scopes=scopes,
                expires_at=int(claims["exp"]),
                resource=MCP_RESOURCE,
                subject=str(claims["sub"]),
                claims={"iss": claims["iss"], "jti": claims["jti"]},
            )
        except (httpx.HTTPError, jwt.PyJWTError, KeyError, TypeError, ValueError):
            return None


def require_tool_scope(scope: str) -> AccessToken:
    access_token = get_access_token()
    if access_token is None or scope not in access_token.scopes:
        raise PermissionError(f"OAuth scope required: {scope}")
    return access_token


AUTH_SETTINGS = AuthSettings(
    issuer_url=AnyHttpUrl(OAUTH_ISSUER),
    resource_server_url=AnyHttpUrl(MCP_RESOURCE),
    required_scopes=["mcp:access"],
)
