from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, Header, HTTPException, Query
from fastapi.responses import RedirectResponse


ISSUER = os.getenv("OAUTH_ISSUER", "http://auth-server:9000").rstrip("/")
MCP_RESOURCE = os.getenv("MCP_RESOURCE", "http://mcp-server:8000/mcp")
AGENT_CLIENT_ID = "arsl-agent-gateway"
CLI_CLIENT_ID = "arsl-phase9-cli"
CLI_REDIRECT_URI = "http://127.0.0.1:19191/callback"
TOKEN_TTL_SECONDS = 300
CODE_TTL_SECONDS = 60
ALL_SCOPES = {
    "mcp:access",
    "mcp:read_document",
    "mcp:mock_http_request",
    "mcp:run_command",
}


@dataclass
class AuthorizationCodeRecord:
    client_id: str
    redirect_uri: str
    code_challenge: str
    scopes: list[str]
    resource: str
    expires_at: int


private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
public_der = public_key.public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
key_id = hashlib.sha256(public_der).hexdigest()[:16]
authorization_codes: dict[str, AuthorizationCodeRecord] = {}

app = FastAPI(
    title="ARSL OAuth 2.1 Lab Authorization Server",
    version="0.9.0",
    description="Local-only OAuth authorization server for MCP security validation.",
)


def _b64uint(value: int) -> str:
    size = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()


def _parse_scopes(scope: str) -> list[str]:
    scopes = sorted(set(scope.split()))
    if not scopes or not set(scopes).issubset(ALL_SCOPES):
        raise HTTPException(status_code=400, detail="invalid_scope")
    if "mcp:access" not in scopes:
        raise HTTPException(status_code=400, detail="mcp:access scope is required")
    return scopes


def _validate_resource(resource: str | None) -> str:
    if resource != MCP_RESOURCE:
        raise HTTPException(status_code=400, detail="invalid_target_resource")
    return resource


def _issue_access_token(client_id: str, scopes: list[str], subject: str) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": subject,
        "aud": MCP_RESOURCE,
        "client_id": client_id,
        "scope": " ".join(scopes),
        "iat": now,
        "nbf": now,
        "exp": now + TOKEN_TTL_SECONDS,
        "jti": secrets.token_urlsafe(18),
    }
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": key_id})


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "arsl-oauth-server", "version": "0.9.0"}


@app.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata() -> dict[str, object]:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "jwks_uri": f"{ISSUER}/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "scopes_supported": sorted(ALL_SCOPES),
    }


@app.get("/jwks.json")
async def jwks() -> dict[str, list[dict[str, str]]]:
    numbers = public_key.public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": key_id,
                "n": _b64uint(numbers.n),
                "e": _b64uint(numbers.e),
            }
        ]
    }


@app.get("/authorize")
async def authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(...),
    state: str = Query(...),
    code_challenge: str = Query(..., min_length=43, max_length=128),
    code_challenge_method: str = Query(...),
    resource: str = Query(...),
) -> RedirectResponse:
    if response_type != "code" or client_id != CLI_CLIENT_ID:
        raise HTTPException(status_code=400, detail="unauthorized_client")
    if redirect_uri != CLI_REDIRECT_URI:
        raise HTTPException(status_code=400, detail="invalid_redirect_uri")
    if code_challenge_method != "S256":
        raise HTTPException(status_code=400, detail="PKCE S256 is required")
    scopes = _parse_scopes(scope)
    target = _validate_resource(resource)
    now = int(time.time())
    expired_codes = [
        existing_code
        for existing_code, record in authorization_codes.items()
        if record.expires_at < now
    ]
    for expired_code in expired_codes:
        authorization_codes.pop(expired_code, None)
    if len(authorization_codes) >= 200:
        raise HTTPException(status_code=503, detail="authorization_code_capacity_reached")
    code = secrets.token_urlsafe(32)
    authorization_codes[code] = AuthorizationCodeRecord(
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        scopes=scopes,
        resource=target,
        expires_at=int(time.time()) + CODE_TTL_SECONDS,
    )
    query = urlencode({"code": code, "state": state})
    return RedirectResponse(f"{redirect_uri}?{query}", status_code=302)


@app.post("/token")
async def token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str | None = Form(default=None),
    scope: str = Form(default=""),
    resource: str | None = Form(default=None),
    code: str | None = Form(default=None),
    redirect_uri: str | None = Form(default=None),
    code_verifier: str | None = Form(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    del authorization
    target = _validate_resource(resource)
    if grant_type == "client_credentials":
        expected_secret = os.getenv("MCP_OAUTH_CLIENT_SECRET", "")
        if (
            client_id != AGENT_CLIENT_ID
            or len(expected_secret) < 32
            or not secrets.compare_digest(client_secret or "", expected_secret)
        ):
            raise HTTPException(status_code=401, detail="invalid_client")
        scopes = _parse_scopes(scope)
        allowed = {"mcp:access", "mcp:read_document", "mcp:mock_http_request"}
        if not set(scopes).issubset(allowed):
            raise HTTPException(status_code=400, detail="invalid_scope")
        access_token = _issue_access_token(client_id, scopes, client_id)
    elif grant_type == "authorization_code":
        if client_id != CLI_CLIENT_ID or not code or not code_verifier:
            raise HTTPException(status_code=400, detail="invalid_grant")
        record = authorization_codes.get(code)
        if (
            record is None
            or record.expires_at < int(time.time())
            or record.client_id != client_id
            or record.redirect_uri != redirect_uri
            or record.resource != target
        ):
            raise HTTPException(status_code=400, detail="invalid_grant")
        digest = hashlib.sha256(code_verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        if not secrets.compare_digest(challenge, record.code_challenge):
            raise HTTPException(status_code=400, detail="invalid_grant")
        authorization_codes.pop(code, None)
        scopes = record.scopes
        access_token = _issue_access_token(client_id, scopes, "lab-analyst")
    else:
        raise HTTPException(status_code=400, detail="unsupported_grant_type")

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL_SECONDS,
        "scope": " ".join(scopes),
        "resource": target,
    }
