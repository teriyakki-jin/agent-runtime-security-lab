import base64
import hashlib
import os
import unittest
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

import jwt
from fastapi.testclient import TestClient

from app.main import (
    CLI_CLIENT_ID,
    CLI_REDIRECT_URI,
    MCP_RESOURCE,
    app,
    authorization_codes,
)


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


class OAuthServerTests(unittest.TestCase):
    def setUp(self) -> None:
        authorization_codes.clear()
        self.client = TestClient(app)

    def authorize(self, verifier: str, scope: str = "mcp:access mcp:read_document") -> str:
        response = self.client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": CLI_CLIENT_ID,
                "redirect_uri": CLI_REDIRECT_URI,
                "scope": scope,
                "state": "state-bound-to-client",
                "code_challenge": pkce_challenge(verifier),
                "code_challenge_method": "S256",
                "resource": MCP_RESOURCE,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        query = parse_qs(urlparse(response.headers["location"]).query)
        self.assertEqual(query["state"], ["state-bound-to-client"])
        return query["code"][0]

    def test_metadata_advertises_pkce_and_scopes(self) -> None:
        metadata = self.client.get("/.well-known/oauth-authorization-server").json()
        self.assertEqual(metadata["code_challenge_methods_supported"], ["S256"])
        self.assertIn("mcp:read_document", metadata["scopes_supported"])

    def test_authorization_code_is_pkce_bound_and_single_use(self) -> None:
        verifier = "v" * 64
        code = self.authorize(verifier)
        response = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLI_CLIENT_ID,
                "code": code,
                "redirect_uri": CLI_REDIRECT_URI,
                "code_verifier": verifier,
                "resource": MCP_RESOURCE,
            },
        )
        self.assertEqual(response.status_code, 200)
        claims = jwt.decode(response.json()["access_token"], options={"verify_signature": False})
        self.assertEqual(claims["aud"], MCP_RESOURCE)
        self.assertEqual(claims["scope"], "mcp:access mcp:read_document")
        replay = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLI_CLIENT_ID,
                "code": code,
                "redirect_uri": CLI_REDIRECT_URI,
                "code_verifier": verifier,
                "resource": MCP_RESOURCE,
            },
        )
        self.assertEqual(replay.status_code, 400)

    def test_wrong_pkce_verifier_and_resource_are_rejected(self) -> None:
        verifier = "a" * 64
        code = self.authorize(verifier)
        wrong_verifier = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLI_CLIENT_ID,
                "code": code,
                "redirect_uri": CLI_REDIRECT_URI,
                "code_verifier": "b" * 64,
                "resource": MCP_RESOURCE,
            },
        )
        self.assertEqual(wrong_verifier.status_code, 400)
        valid_exchange = self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLI_CLIENT_ID,
                "code": code,
                "redirect_uri": CLI_REDIRECT_URI,
                "code_verifier": verifier,
                "resource": MCP_RESOURCE,
            },
        )
        self.assertEqual(valid_exchange.status_code, 200)
        wrong_resource = self.client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "arsl-agent-gateway",
                "client_secret": "s" * 32,
                "scope": "mcp:access mcp:read_document",
                "resource": "https://wrong-resource.example/mcp",
            },
        )
        self.assertEqual(wrong_resource.status_code, 400)

    def test_service_client_is_limited_to_registered_scopes(self) -> None:
        with patch.dict(os.environ, {"MCP_OAUTH_CLIENT_SECRET": "s" * 32}):
            response = self.client.post(
                "/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": "arsl-agent-gateway",
                    "client_secret": "s" * 32,
                    "scope": "mcp:access mcp:run_command",
                    "resource": MCP_RESOURCE,
                },
            )
        self.assertEqual(response.status_code, 400)
