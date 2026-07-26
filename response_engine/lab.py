from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Callable

from response_engine.causal import CausalAttackGraph, SecurityEvent
from response_engine.docker_isolation import DockerIsolationAdapter
from response_engine.identity import DelegationVerifier
from response_engine.oauth_revocation import OAuthTokenRevoker
from response_engine.orchestrator import (
    Detection,
    IsolationAdapter,
    ResponseOrchestrator,
    TokenRevoker,
)


class ScenarioClock:
    def __init__(self, fixed_time: datetime | None = None) -> None:
        self.fixed_time = fixed_time
        self.offset = timedelta()

    def __call__(self) -> datetime:
        base = self.fixed_time or datetime.now(timezone.utc)
        return base + self.offset

    def advance(self, seconds: int) -> None:
        self.offset += timedelta(seconds=seconds)


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _was_revoked(token_revoker: TokenRevoker, token_jti: str) -> bool:
    revoked = getattr(token_revoker, "revoked_jtis", None)
    if isinstance(revoked, set):
        return token_jti in revoked
    revoked = getattr(token_revoker, "revoked", None)
    return isinstance(revoked, set) and token_jti in revoked


def run_phase14_scenario(
    *,
    root_jti: str,
    child_jti: str,
    root_subject: str,
    child_subject: str,
    issuer: str,
    audience: str,
    target: str,
    isolation: IsolationAdapter,
    token_revoker: TokenRevoker,
    clock: ScenarioClock,
) -> dict[str, object]:
    started_at = clock()
    identity = DelegationVerifier(
        trusted_issuer=issuer,
        audience=audience,
        max_depth=3,
    ).verify(
        [
            {
                "jti": root_jti,
                "parent_jti": None,
                "issuer": issuer,
                "subject": root_subject,
                "audience": audience,
                "scopes": ["mcp:access", "mcp:read_document"],
                "issued_at": (started_at - timedelta(seconds=2)).isoformat(),
                "expires_at": (started_at + timedelta(seconds=300)).isoformat(),
            },
            {
                "jti": child_jti,
                "parent_jti": root_jti,
                "issuer": issuer,
                "subject": child_subject,
                "audience": audience,
                "scopes": ["mcp:access", "mcp:read_document"],
                "issued_at": (started_at - timedelta(seconds=1)).isoformat(),
                "expires_at": (started_at + timedelta(seconds=180)).isoformat(),
            },
        ],
        required_scopes={"mcp:read_document"},
        now=started_at,
    )

    graph = CausalAttackGraph()
    graph.add(
        SecurityEvent(
            "event-scope",
            "scope_violation",
            identity.agent_id,
            audience,
            (),
            started_at,
        )
    )
    graph.add(
        SecurityEvent(
            "event-tool",
            "tool_call",
            identity.agent_id,
            audience,
            ("event-scope",),
            started_at + timedelta(milliseconds=1),
        )
    )
    graph.add(
        SecurityEvent(
            "event-runtime",
            "runtime_mismatch",
            identity.agent_id,
            audience,
            ("event-tool",),
            started_at + timedelta(milliseconds=2),
        )
    )
    causal_path = graph.match_sequence(
        "event-runtime", ("scope_violation", "tool_call", "runtime_mismatch")
    )

    time_only = CausalAttackGraph()
    for event_id, kind, offset in (
        ("near-1", "scope_violation", 0),
        ("near-2", "tool_call", 1),
        ("near-3", "runtime_mismatch", 2),
    ):
        time_only.add(
            SecurityEvent(
                event_id,
                kind,
                identity.agent_id,
                audience,
                (),
                started_at + timedelta(milliseconds=offset),
            )
        )
    time_only_path = time_only.match_sequence(
        "near-3", ("scope_violation", "tool_call", "runtime_mismatch")
    )

    orchestrator = ResponseOrchestrator(
        isolation=isolation,
        token_revoker=token_revoker,
        clock=clock,
        authorized_reviewers={"soc-lead"},
    )
    detection = Detection(
        incident_id="phase14-causal-attack",
        rule_id="causal-agent-takeover",
        root_event_id=causal_path[0].event_id,
        agent_id=identity.agent_id,
        token_jti=identity.token_jti,
        target=target,
        severity="Critical",
        detected_at=started_at,
    )
    first = orchestrator.handle(detection, ttl_seconds=1)
    isolated_state = first.action.state == "isolated"
    networks = tuple(getattr(first.action.isolation_snapshot, "networks", ()))
    duplicate = orchestrator.handle(detection, ttl_seconds=1)
    clock.advance(2)
    ttl_restored = orchestrator.reconcile() == [first.action.action_id]

    second = orchestrator.handle(
        Detection(
            incident_id="phase14-human-override",
            rule_id=detection.rule_id,
            root_event_id="event-human-override",
            agent_id=identity.agent_id,
            token_jti=identity.token_jti,
            target=target,
            severity="Critical",
            detected_at=clock(),
        ),
        ttl_seconds=1,
    ).action
    orchestrator.human_override(
        second.action_id,
        actor="soc-lead",
        decision="hold",
        reason="Validate containment before recovery",
    )
    clock.advance(2)
    hold_prevented_restore = orchestrator.reconcile() == []
    restored = orchestrator.human_override(
        second.action_id,
        actor="soc-lead",
        decision="restore",
        reason="Validated and approved for recovery",
    )

    checks = {
        "delegated_identity_verified": identity.delegation_depth == 1,
        "causal_path_matched": len(causal_path) == 3,
        "time_only_correlation_rejected": time_only_path == [],
        "oauth_token_revoked": _was_revoked(token_revoker, identity.token_jti),
        "container_isolation_applied": isolated_state,
        "network_isolation_applied": len(networks) > 0,
        "duplicate_response_suppressed": duplicate.duplicate,
        "ttl_auto_recovery_completed": ttl_restored,
        "human_hold_prevented_recovery": hold_prevented_restore,
        "human_override_restored_target": restored.state == "restored",
        "mttr_measured": first.action.mttr_ms is not None,
    }
    privacy = {
        "access_token_exported": False,
        "client_secret_exported": False,
        "raw_jti_exported": False,
        "raw_tool_arguments_exported": False,
    }
    return {
        "phase": 14,
        "result": "passed" if all(checks.values()) else "failed",
        "identity": {
            "agent_id": identity.agent_id,
            "root_subject": identity.root_subject,
            "delegation_depth": identity.delegation_depth,
            "token_fingerprint": _fingerprint(identity.token_jti),
        },
        "causal_graph": {
            "explicit_edge_count": 2,
            "matched_sequence": [item.kind for item in causal_path],
            "timestamp_only_match": False,
        },
        "response": {
            "target": target,
            "networks_detached": len(networks),
            "duplicates_suppressed": 1,
            "ttl_seconds": 1,
            "final_state": restored.state,
            "token_remains_revoked_after_restore": _was_revoked(
                token_revoker, identity.token_jti
            ),
        },
        "mttr": {
            "detect_to_block_ms": first.action.mttr_ms,
            "slo_ms": 5000,
            "within_slo": (first.action.mttr_ms or 0) <= 5000,
        },
        "checks": checks,
        "privacy": privacy,
    }


def _required_env(name: str) -> str:
    value = os.getenv(name, "")
    if not value:
        raise ValueError(f"missing required environment: {name}")
    return value


def main() -> int:
    try:
        child_jti = _required_env("PHASE14_CHILD_JTI")
        revoker = OAuthTokenRevoker(
            endpoint=os.getenv(
                "PHASE14_REVOCATION_ENDPOINT", "http://127.0.0.1:19000/revoke"
            ),
            client_secret=_required_env("INCIDENT_RESPONSE_CLIENT_SECRET"),
        )
        revoker.register(child_jti, _required_env("PHASE14_ACCESS_TOKEN"))
        evidence = run_phase14_scenario(
            root_jti=_required_env("PHASE14_ROOT_JTI"),
            child_jti=child_jti,
            root_subject=_required_env("PHASE14_ROOT_SUBJECT"),
            child_subject=_required_env("PHASE14_CHILD_SUBJECT"),
            issuer=os.getenv("PHASE14_ISSUER", "http://auth-server:9000"),
            audience=os.getenv(
                "PHASE14_AUDIENCE", "http://mcp-server:8000/mcp"
            ),
            target=os.getenv("PHASE14_TARGET", "arsl-mcp-server"),
            isolation=DockerIsolationAdapter(),
            token_revoker=revoker,
            clock=ScenarioClock(),
        )
        print(json.dumps(evidence, indent=2, sort_keys=True))
        return 0 if evidence["result"] == "passed" else 2
    except Exception as exc:
        print(
            json.dumps(
                {
                    "phase": 14,
                    "result": "failed",
                    "reason": type(exc).__name__,
                },
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
