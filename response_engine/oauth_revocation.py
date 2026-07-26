from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from urllib.error import URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


class OAuthRevocationError(RuntimeError):
    """Raised when a token cannot be safely revoked."""


class OAuthTokenRevoker:
    """Keep bearer material in memory and revoke it by privacy-safe jti lookup."""

    def __init__(
        self,
        *,
        endpoint: str,
        client_secret: str,
        opener: Callable[[Request, float], Any] = urlopen,
    ) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme != "http" or parsed.hostname not in {
            "127.0.0.1",
            "localhost",
            "auth-server",
        }:
            raise OAuthRevocationError("revocation endpoint must be a local lab service")
        if len(client_secret) < 32:
            raise OAuthRevocationError("response client secret must contain 32 characters")
        self.endpoint = endpoint
        self._client_secret = client_secret
        self._opener = opener
        self._tokens: dict[str, str] = {}
        self.revoked_jtis: set[str] = set()

    def __repr__(self) -> str:
        return (
            f"OAuthTokenRevoker(endpoint={self.endpoint!r}, "
            f"registered={len(self._tokens)}, revoked={len(self.revoked_jtis)})"
        )

    def register(self, token_jti: str, token: str) -> None:
        if not token_jti or len(token_jti) > 256:
            raise OAuthRevocationError("token jti is invalid")
        if not token or len(token) > 16384:
            raise OAuthRevocationError("access token is invalid")
        self._tokens[token_jti] = token

    def has_token(self, token_jti: str) -> bool:
        return token_jti in self._tokens

    def revoke(self, token_jti: str) -> None:
        if token_jti in self.revoked_jtis:
            return
        token = self._tokens.get(token_jti)
        if token is None:
            raise OAuthRevocationError("token jti is not registered")
        body = urlencode(
            {
                "token": token,
                "client_id": "arsl-response-orchestrator",
                "client_secret": self._client_secret,
            }
        ).encode()
        request = Request(
            self.endpoint,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with self._opener(request, timeout=5.0) as response:
                result = json.loads(response.read())
        except (OSError, TimeoutError, URLError, ValueError, json.JSONDecodeError) as exc:
            raise OAuthRevocationError("OAuth revocation endpoint failed") from exc
        if not isinstance(result, dict) or result.get("revoked") is not True:
            raise OAuthRevocationError("OAuth revocation was not acknowledged")
        self._tokens.pop(token_jti, None)
        self.revoked_jtis.add(token_jti)
