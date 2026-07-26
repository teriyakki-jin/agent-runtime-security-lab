from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from app.capability import consume_capability
from app.oauth import AUTH_SETTINGS, JwtTokenVerifier, require_tool_scope


def configure_tracing() -> trace.Tracer:
    provider = TracerProvider(
        resource=Resource.create(
            {"service.name": os.getenv("OTEL_SERVICE_NAME", "mcp-tool-server")}
        )
    )
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if endpoint:
        provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, insecure=True))
        )
    trace.set_tracer_provider(provider)
    return trace.get_tracer(__name__)


tracer = configure_tracing()
document_root = Path("/app/documents").resolve()
mcp = FastMCP(
    "Agent Runtime Security Lab Tools",
    instructions="Isolated tools used to validate agent security policies.",
    host="0.0.0.0",
    port=8000,
    json_response=True,
    token_verifier=JwtTokenVerifier(),
    auth=AUTH_SETTINGS,
)


def resolve_document_path(path: str) -> Path:
    if not path or len(path) > 256:
        raise ValueError("Document path must be between 1 and 256 characters.")
    candidate = (document_root / path).resolve()
    if candidate != document_root and document_root not in candidate.parents:
        raise ValueError("Document path escapes the isolated workspace.")
    if not candidate.is_file():
        raise ValueError("Document does not exist.")
    return candidate


@mcp.tool()
def read_document(path: str) -> str:
    """Read a UTF-8 document from the isolated public workspace."""
    access_token = require_tool_scope("mcp:read_document")
    with tracer.start_as_current_span("execute_tool read_document") as span:
        span.set_attribute("gen_ai.operation.name", "execute_tool")
        span.set_attribute("gen_ai.tool.name", "read_document")
        span.set_attribute("enduser.id", access_token.subject or access_token.client_id)
        span.set_attribute("security.oauth.client_id", access_token.client_id)
        safe_path = resolve_document_path(path)
        span.set_attribute("security.workspace.relative_path", path)
        return safe_path.read_text(encoding="utf-8")


@mcp.tool()
def mock_http_request(url: str, capability: str = "") -> dict[str, str | int]:
    """Return an isolated response; external destinations require signed approval."""
    access_token = require_tool_scope("mcp:mock_http_request")
    with tracer.start_as_current_span("execute_tool mock_http_request") as span:
        span.set_attribute("gen_ai.operation.name", "execute_tool")
        span.set_attribute("gen_ai.tool.name", "mock_http_request")
        span.set_attribute("enduser.id", access_token.subject or access_token.client_id)
        span.set_attribute("security.oauth.client_id", access_token.client_id)
        if url.startswith("https://docs.example.local/"):
            span.set_attribute("server.address", "docs.example.local")
            return {
                "status": 200,
                "url": url,
                "body": "isolated documentation response",
            }

        approval_id = consume_capability(
            capability,
            "mock_http_request",
            {"url": url},
        )
        span.set_attribute("security.approval.id", approval_id)
        span.set_attribute("security.network.mode", "simulation_only")
        return {
            "status": 202,
            "url": url,
            "body": "approved external request simulated; no network traffic was sent",
        }


@mcp.tool()
def run_command(command: str) -> dict[str, str]:
    """Demonstrate a high-risk tool without invoking a shell."""
    access_token = require_tool_scope("mcp:run_command")
    with tracer.start_as_current_span("execute_tool run_command") as span:
        span.set_attribute("gen_ai.operation.name", "execute_tool")
        span.set_attribute("gen_ai.tool.name", "run_command")
        span.set_attribute("enduser.id", access_token.subject or access_token.client_id)
        span.set_attribute("security.oauth.client_id", access_token.client_id)
        span.set_attribute("security.control", "defense_in_depth")
        return {
            "status": "blocked",
            "command": command[:64],
            "message": "Command execution is disabled inside the MCP server.",
            "time": datetime.now(UTC).isoformat(),
        }


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
