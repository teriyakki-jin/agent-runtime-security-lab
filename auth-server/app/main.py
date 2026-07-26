from __future__ import annotations

import base64
import hashlib
import os
import re
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
MCP_SERVER_CLIENT_ID = "arsl-mcp-server"
RESPONSE_CLIENT_ID = "arsl-response-orchestrator"
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
revoked_tokens: dict[str, int] = {}

app = FastAPI(
    title="ARSL OAuth 2.1 Lab Authorization Server",
    version="0.14.0",
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


def _issue_access_token(
    client_id: str,
    scopes: list[str],
    subject: str,
    *,
    parent_claims: dict[str, object] | None = None,
) -> str:
    now = int(time.time())
    jti = secrets.token_urlsafe(18)
    delegation_chain: list[dict[str, str]] = []
    delegation_depth = 0
    expires_at = now + TOKEN_TTL_SECONDS
    if parent_claims is not None:
        inherited = parent_claims.get("delegation_chain", [])
        if not isinstance(inherited, list):
            raise HTTPException(status_code=400, detail="invalid_subject_token")
        delegation_chain = [*inherited]
        delegation_chain.append(
            {
                "jti": str(parent_claims["jti"]),
                "subject": str(parent_claims["sub"]),
                "client_id": str(parent_claims["client_id"]),
            }
        )
        delegation_depth = int(parent_claims.get("delegation_depth", 0)) + 1
        expires_at = min(expires_at, int(parent_claims["exp"]))
    claims = {
        "iss": ISSUER,
        "sub": subject,
        "aud": MCP_RESOURCE,
        "client_id": client_id,
        "scope": " ".join(scopes),
        "iat": now,
        "nbf": now,
        "exp": expires_at,
        "jti": jti,
        "agent_id": subject,
        "delegation_depth": delegation_depth,
        "delegation_chain": delegation_chain,
    }
    if parent_claims is not None:
        claims["parent_jti"] = str(parent_claims["jti"])
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": key_id})


def _authenticate_client(
    *,
    client_id: str,
    client_secret: str | None,
    expected_client_id: str,
    secret_env: str,
) -> None:
    expected_secret = os.getenv(secret_env, "")
    if (
        client_id != expected_client_id
        or len(expected_secret) < 32
        or not secrets.compare_digest(client_secret or "", expected_secret)
    ):
        raise HTTPException(status_code=401, detail="invalid_client")


def _decode_access_token(token: str, *, verify_exp: bool = True) -> dict[str, object]:
    try:
        return jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=MCP_RESOURCE,
            issuer=ISSUER,
            options={
                "require": [
                    "iss",
                    "sub",
                    "aud",
                    "exp",
                    "iat",
                    "client_id",
                    "scope",
                    "jti",
                    "agent_id",
                    "delegation_depth",
                    "delegation_chain",
                ],
                "verify_exp": verify_exp,
            },
        )
    except (jwt.PyJWTError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="invalid_token") from exc


def _prune_revocations() -> None:
    now = int(time.time())
    for jti, expires_at in list(revoked_tokens.items()):
        if expires_at <= now:
            revoked_tokens.pop(jti, None)


def _is_revoked(jti: str) -> bool:
    _prune_revocations()
    return jti in revoked_tokens


def _is_claims_revoked(claims: dict[str, object]) -> bool:
    if _is_revoked(str(claims["jti"])):
        return True
    delegation_chain = claims.get("delegation_chain", [])
    if not isinstance(delegation_chain, list):
        return True
    for ancestor in delegation_chain:
        if not isinstance(ancestor, dict):
            return True
        ancestor_jti = ancestor.get("jti")
        if not isinstance(ancestor_jti, str) or not ancestor_jti:
            return True
        if _is_revoked(ancestor_jti):
            return True
    return False


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "arsl-oauth-server", "version": "0.14.0"}


@app.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata() -> dict[str, object]:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "revocation_endpoint": f"{ISSUER}/revoke",
        "introspection_endpoint": f"{ISSUER}/introspect",
        "jwks_uri": f"{ISSUER}/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_post"],
        "introspection_endpoint_auth_methods_supported": ["client_secret_post"],
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
    subject_token: str | None = Form(default=None),
    requested_subject: str | None = Form(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    del authorization
    target = _validate_resource(resource)
    if grant_type == "client_credentials":
        _authenticate_client(
            client_id=client_id,
            client_secret=client_secret,
            expected_client_id=AGENT_CLIENT_ID,
            secret_env="MCP_OAUTH_CLIENT_SECRET",
        )
        scopes = _parse_scopes(scope)
        allowed = {"mcp:access", "mcp:read_document", "mcp:mock_http_request"}
        if not set(scopes).issubset(allowed):
            raise HTTPException(status_code=400, detail="invalid_scope")
        access_token = _issue_access_token(client_id, scopes, client_id)
    elif grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
        _authenticate_client(
            client_id=client_id,
            client_secret=client_secret,
            expected_client_id=AGENT_CLIENT_ID,
            secret_env="MCP_OAUTH_CLIENT_SECRET",
        )
        if not subject_token or not requested_subject:
            raise HTTPException(status_code=400, detail="invalid_request")
        if not re.fullmatch(r"agent:[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", requested_subject):
            raise HTTPException(status_code=400, detail="invalid_requested_subject")
        parent_claims = _decode_access_token(subject_token)
        if _is_claims_revoked(parent_claims):
            raise HTTPException(status_code=400, detail="invalid_subject_token")
        if parent_claims["client_id"] != client_id:
            raise HTTPException(status_code=400, detail="invalid_subject_token")
        if int(parent_claims.get("delegation_depth", 0)) >= 3:
            raise HTTPException(status_code=400, detail="delegation_depth_exceeded")
        scopes = _parse_scopes(scope)
        parent_scopes = set(str(parent_claims["scope"]).split())
        if not set(scopes).issubset(parent_scopes):
            raise HTTPException(status_code=400, detail="delegation_scope_escalation")
        access_token = _issue_access_token(
            client_id,
            scopes,
            requested_subject,
            parent_claims=parent_claims,
        )
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

    issued_claims = jwt.decode(access_token, options={"verify_signature": False})
    payload: dict[str, object] = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": max(0, int(issued_claims["exp"]) - int(time.time())),
        "scope": " ".join(scopes),
        "resource": target,
    }
    if grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
        payload["issued_token_type"] = (
            "urn:ietf:params:oauth:token-type:access_token"
        )
    return payload


@app.post("/introspect")
async def introspect(
    token: str = Form(...),
    client_id: str = Form(...),
    client_secret: str | None = Form(default=None),
) -> dict[str, object]:
    _authenticate_client(
        client_id=client_id,
        client_secret=client_secret,
        expected_client_id=MCP_SERVER_CLIENT_ID,
        secret_env="MCP_OAUTH_INTROSPECTION_SECRET",
    )
    try:
        claims = _decode_access_token(token)
    except HTTPException:
        return {"active": False}
    if _is_claims_revoked(claims):
        return {"active": False}
    return {
        "active": True,
        "iss": claims["iss"],
        "aud": claims["aud"],
        "iat": claims["iat"],
        "client_id": claims["client_id"],
        "sub": claims["sub"],
        "agent_id": claims["agent_id"],
        "scope": claims["scope"],
        "exp": claims["exp"],
        "jti": claims["jti"],
        "parent_jti": claims.get("parent_jti"),
        "delegation_depth": claims["delegation_depth"],
    }


@app.post("/revoke")
async def revoke(
    token: str = Form(...),
    client_id: str = Form(...),
    client_secret: str | None = Form(default=None),
) -> dict[str, bool]:
    _authenticate_client(
        client_id=client_id,
        client_secret=client_secret,
        expected_client_id=RESPONSE_CLIENT_ID,
        secret_env="INCIDENT_RESPONSE_CLIENT_SECRET",
    )
    try:
        claims = _decode_access_token(token, verify_exp=False)
    except HTTPException:
        return {"revoked": True}
    _prune_revocations()
    if len(revoked_tokens) >= 5000:
        raise HTTPException(status_code=503, detail="revocation_capacity_reached")
    revoked_tokens[str(claims["jti"])] = int(claims["exp"])
    return {"revoked": True}
