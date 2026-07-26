from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
from urllib.parse import parse_qs, urlparse

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from app.threat import classify_finding


AUTH_SERVER_URL = os.getenv("MCP_OAUTH_SERVER_URL", "http://auth-server:9000")
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://mcp-server:8000/mcp")
MCP_RESOURCE = os.getenv("MCP_RESOURCE", MCP_SERVER_URL)
CLIENT_ID = "arsl-phase9-cli"
REDIRECT_URI = "http://127.0.0.1:19191/callback"


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


async def acquire_token(client: httpx.AsyncClient, scopes: list[str]) -> str:
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(24)
    response = await client.get(
        f"{AUTH_SERVER_URL}/authorize",
        params={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": " ".join(sorted(set(scopes) | {"mcp:access"})),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": MCP_RESOURCE,
        },
        follow_redirects=False,
    )
    if response.status_code != 302:
        raise RuntimeError(f"Authorization endpoint returned HTTP {response.status_code}.")
    query = parse_qs(urlparse(response.headers["location"]).query)
    if query.get("state") != [state]:
        raise RuntimeError("OAuth state binding failed.")
    token_response = await client.post(
        f"{AUTH_SERVER_URL}/token",
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": query["code"][0],
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
            "resource": MCP_RESOURCE,
        },
    )
    token_response.raise_for_status()
    return str(token_response.json()["access_token"])


async def call_tool(token: str, tool: str, arguments: dict[str, str]) -> tuple[bool, str]:
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"}, timeout=20.0
    ) as mcp_http:
        async with streamable_http_client(MCP_SERVER_URL, http_client=mcp_http) as streams:
            read_stream, write_stream, _ = streams
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.call_tool(tool, arguments)
                text = " ".join(getattr(item, "text", "") for item in result.content)
                return bool(result.isError), text


async def run() -> dict[str, object]:
    async with httpx.AsyncClient(timeout=10.0) as client:
        metadata = (
            await client.get(f"{AUTH_SERVER_URL}/.well-known/oauth-authorization-server")
        ).json()
        unauthenticated = await client.post(
            MCP_SERVER_URL,
            headers={"Accept": "application/json, text/event-stream"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "phase9-probe", "version": "0.9.0"},
                },
            },
        )
        read_token = await acquire_token(client, ["mcp:read_document"])
        scope_error, scope_message = await call_tool(
            read_token,
            "mock_http_request",
            {"url": "https://docs.example.local/security"},
        )
        read_error, read_message = await call_tool(
            read_token, "read_document", {"path": "public/guide.txt"}
        )
        wrong_resource = await client.post(
            f"{AUTH_SERVER_URL}/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "arsl-agent-gateway",
                "client_secret": os.getenv("MCP_OAUTH_CLIENT_SECRET", ""),
                "scope": "mcp:access mcp:read_document",
                "resource": "https://wrong-resource.example/mcp",
            },
        )

    checks = {
        "protected_resource_requires_token": unauthenticated.status_code == 401,
        "authorization_server_supports_pkce_s256": metadata.get(
            "code_challenge_methods_supported"
        )
        == ["S256"],
        "wrong_resource_rejected": wrong_resource.status_code == 400,
        "under_scoped_tool_call_blocked": scope_error
        and "mcp:mock_http_request" in scope_message,
        "correctly_scoped_tool_call_allowed": not read_error
        and "Agent Runtime Security Lab" in read_message,
    }
    finding = {
        "matched": False,
        "finding_type": "mcp_oauth_scope_violation",
        "severity": "High",
        "observation": {"event_type": "oauth_token_use"},
    }
    finding["threat"] = classify_finding(finding)
    return {
        "phase": 9,
        "result": "passed" if all(checks.values()) else "failed",
        "resource": MCP_RESOURCE,
        "client_id": CLIENT_ID,
        "token_fingerprint": hashlib.sha256(read_token.encode()).hexdigest()[:16],
        "token_exported": False,
        "checks": checks,
        "finding": finding,
    }


if __name__ == "__main__":
    result = asyncio.run(run())
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["result"] == "passed" else 1)
