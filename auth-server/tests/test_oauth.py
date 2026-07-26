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
    revoked_tokens,
)


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


class OAuthServerTests(unittest.TestCase):
    def setUp(self) -> None:
        authorization_codes.clear()
        revoked_tokens.clear()
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

    def issue_service_token(self, scopes: str = "mcp:access mcp:read_document") -> str:
        with patch.dict(os.environ, {"MCP_OAUTH_CLIENT_SECRET": "s" * 32}):
            response = self.client.post(
                "/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": "arsl-agent-gateway",
                    "client_secret": "s" * 32,
                    "scope": scopes,
                    "resource": MCP_RESOURCE,
                },
            )
        self.assertEqual(response.status_code, 200)
        return response.json()["access_token"]

    def test_metadata_advertises_revocation_introspection_and_token_exchange(self) -> None:
        metadata = self.client.get("/.well-known/oauth-authorization-server").json()
        self.assertTrue(metadata["revocation_endpoint"].endswith("/revoke"))
        self.assertTrue(metadata["introspection_endpoint"].endswith("/introspect"))
        self.assertIn(
            "urn:ietf:params:oauth:grant-type:token-exchange",
            metadata["grant_types_supported"],
        )

    def test_revoked_jti_becomes_inactive_immediately(self) -> None:
        token = self.issue_service_token()
        environment = {
            "MCP_OAUTH_INTROSPECTION_SECRET": "i" * 32,
            "INCIDENT_RESPONSE_CLIENT_SECRET": "r" * 32,
        }
        with patch.dict(os.environ, environment):
            active = self.client.post(
                "/introspect",
                data={
                    "token": token,
                    "client_id": "arsl-mcp-server",
                    "client_secret": "i" * 32,
                },
            )
            revoked = self.client.post(
                "/revoke",
                data={
                    "token": token,
                    "client_id": "arsl-response-orchestrator",
                    "client_secret": "r" * 32,
                },
            )
            inactive = self.client.post(
                "/introspect",
                data={
                    "token": token,
                    "client_id": "arsl-mcp-server",
                    "client_secret": "i" * 32,
                },
            )

        self.assertTrue(active.json()["active"])
        self.assertEqual(revoked.status_code, 200)
        self.assertFalse(inactive.json()["active"])

    def test_revocation_requires_dedicated_responder_identity(self) -> None:
        token = self.issue_service_token()
        with patch.dict(os.environ, {"INCIDENT_RESPONSE_CLIENT_SECRET": "r" * 32}):
            response = self.client.post(
                "/revoke",
                data={
                    "token": token,
                    "client_id": "arsl-agent-gateway",
                    "client_secret": "r" * 32,
                },
            )
        self.assertEqual(response.status_code, 401)

    def test_token_exchange_binds_parent_and_narrows_scope(self) -> None:
        root_token = self.issue_service_token(
            "mcp:access mcp:read_document mcp:mock_http_request"
        )
        with patch.dict(os.environ, {"MCP_OAUTH_CLIENT_SECRET": "s" * 32}):
            response = self.client.post(
                "/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "client_id": "arsl-agent-gateway",
                    "client_secret": "s" * 32,
                    "subject_token": root_token,
                    "requested_subject": "agent:researcher",
                    "scope": "mcp:access mcp:read_document",
                    "resource": MCP_RESOURCE,
                },
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["issued_token_type"],
            "urn:ietf:params:oauth:token-type:access_token",
        )
        root_claims = jwt.decode(root_token, options={"verify_signature": False})
        child_claims = jwt.decode(
            response.json()["access_token"], options={"verify_signature": False}
        )
        self.assertEqual(child_claims["parent_jti"], root_claims["jti"])
        self.assertEqual(child_claims["delegation_depth"], 1)
        self.assertEqual(child_claims["agent_id"], "agent:researcher")
        self.assertEqual(child_claims["scope"], "mcp:access mcp:read_document")

    def test_token_exchange_rejects_scope_escalation(self) -> None:
        root_token = self.issue_service_token("mcp:access mcp:read_document")
        with patch.dict(os.environ, {"MCP_OAUTH_CLIENT_SECRET": "s" * 32}):
            response = self.client.post(
                "/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "client_id": "arsl-agent-gateway",
                    "client_secret": "s" * 32,
                    "subject_token": root_token,
                    "requested_subject": "agent:researcher",
                    "scope": "mcp:access mcp:run_command",
                    "resource": MCP_RESOURCE,
                },
            )
        self.assertEqual(response.status_code, 400)

    def test_revoking_parent_invalidates_delegated_child(self) -> None:
        root_token = self.issue_service_token("mcp:access mcp:read_document")
        environment = {
            "MCP_OAUTH_CLIENT_SECRET": "s" * 32,
            "MCP_OAUTH_INTROSPECTION_SECRET": "i" * 32,
            "INCIDENT_RESPONSE_CLIENT_SECRET": "r" * 32,
        }
        with patch.dict(os.environ, environment):
            child = self.client.post(
                "/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "client_id": "arsl-agent-gateway",
                    "client_secret": "s" * 32,
                    "subject_token": root_token,
                    "requested_subject": "agent:researcher",
                    "scope": "mcp:access mcp:read_document",
                    "resource": MCP_RESOURCE,
                },
            ).json()["access_token"]
            self.client.post(
                "/revoke",
                data={
                    "token": root_token,
                    "client_id": "arsl-response-orchestrator",
                    "client_secret": "r" * 32,
                },
            )
            child_state = self.client.post(
                "/introspect",
                data={
                    "token": child,
                    "client_id": "arsl-mcp-server",
                    "client_secret": "i" * 32,
                },
            )

        self.assertFalse(child_state.json()["active"])
