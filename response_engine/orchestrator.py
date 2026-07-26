from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol
from uuid import uuid4


class ResponseError(RuntimeError):
    """Raised when an incident response action is unsafe or unauthorized."""


@dataclass(frozen=True)
class Detection:
    incident_id: str
    rule_id: str
    root_event_id: str
    agent_id: str
    token_jti: str
    target: str
    severity: str
    detected_at: datetime


@dataclass
class ResponseAction:
    action_id: str
    response_key: str
    incident_id: str
    token_jti: str
    target: str
    state: str
    detected_at: datetime
    blocked_at: datetime | None
    expires_at: datetime | None
    mttr_ms: int | None
    isolation_snapshot: object | None = field(repr=False)
    human_hold: bool = False
    overrides: list[dict[str, str]] = field(default_factory=list)


@dataclass(frozen=True)
class ResponseDecision:
    action: ResponseAction
    duplicate: bool


class IsolationAdapter(Protocol):
    def isolate(self, target: str) -> object: ...

    def restore(self, snapshot: object) -> None: ...


class TokenRevoker(Protocol):
    def revoke(self, token_jti: str) -> None: ...


class InMemoryTokenRevoker:
    def __init__(self) -> None:
        self.revoked: set[str] = set()
        self.calls = 0

    def revoke(self, token_jti: str) -> None:
        self.calls += 1
        self.revoked.add(token_jti)


class InMemoryIsolationAdapter:
    def __init__(self) -> None:
        self.isolated: dict[str, object] = {}
        self.isolate_calls = 0
        self.restore_calls = 0

    def isolate(self, target: str) -> object:
        self.isolate_calls += 1
        snapshot = {"target": target}
        self.isolated[target] = snapshot
        return snapshot

    def restore(self, snapshot: object) -> None:
        self.restore_calls += 1
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("target"), str):
            raise ResponseError("invalid isolation snapshot")
        self.isolated.pop(snapshot["target"], None)


class ResponseOrchestrator:
    """Idempotent, reversible response coordinator for explicit causal findings."""

    def __init__(
        self,
        *,
        isolation: IsolationAdapter,
        token_revoker: TokenRevoker,
        clock: Callable[[], datetime] | None = None,
        authorized_reviewers: set[str] | None = None,
    ) -> None:
        self.isolation = isolation
        self.token_revoker = token_revoker
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.authorized_reviewers = frozenset(authorized_reviewers or set())
        self._by_key: dict[str, ResponseAction] = {}
        self._by_id: dict[str, ResponseAction] = {}

    @staticmethod
    def _response_key(detection: Detection) -> str:
        material = "\x1f".join(
            (detection.rule_id, detection.root_event_id, detection.target)
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def handle(self, detection: Detection, *, ttl_seconds: int) -> ResponseDecision:
        if ttl_seconds < 1 or ttl_seconds > 3600:
            raise ResponseError("isolation TTL must be between 1 and 3600 seconds")
        key = self._response_key(detection)
        existing = self._by_key.get(key)
        if existing is not None:
            return ResponseDecision(action=existing, duplicate=True)

        now = self.clock()
        if detection.detected_at.tzinfo is None or now.tzinfo is None:
            raise ResponseError("response timestamps must be timezone-aware")
        if detection.severity != "Critical":
            action = ResponseAction(
                action_id=str(uuid4()),
                response_key=key,
                incident_id=detection.incident_id,
                token_jti=detection.token_jti,
                target=detection.target,
                state="review_required",
                detected_at=detection.detected_at,
                blocked_at=None,
                expires_at=None,
                mttr_ms=None,
                isolation_snapshot=None,
            )
        else:
            self.token_revoker.revoke(detection.token_jti)
            try:
                snapshot = self.isolation.isolate(detection.target)
            except Exception as exc:
                raise ResponseError("token revoked but target isolation failed") from exc
            blocked_at = self.clock()
            mttr_ms = max(
                0, round((blocked_at - detection.detected_at).total_seconds() * 1000)
            )
            action = ResponseAction(
                action_id=str(uuid4()),
                response_key=key,
                incident_id=detection.incident_id,
                token_jti=detection.token_jti,
                target=detection.target,
                state="isolated",
                detected_at=detection.detected_at,
                blocked_at=blocked_at,
                expires_at=blocked_at + timedelta(seconds=ttl_seconds),
                mttr_ms=mttr_ms,
                isolation_snapshot=snapshot,
            )

        self._by_key[key] = action
        self._by_id[action.action_id] = action
        return ResponseDecision(action=action, duplicate=False)

    def get(self, action_id: str) -> ResponseAction:
        try:
            return self._by_id[action_id]
        except KeyError as exc:
            raise ResponseError("response action does not exist") from exc

    def _restore(self, action: ResponseAction) -> None:
        if action.state != "isolated" or action.isolation_snapshot is None:
            raise ResponseError("response action is not restorable")
        self.isolation.restore(action.isolation_snapshot)
        action.state = "restored"
        action.human_hold = False

    def reconcile(self) -> list[str]:
        now = self.clock()
        restored: list[str] = []
        for action in self._by_id.values():
            if (
                action.state == "isolated"
                and not action.human_hold
                and action.expires_at is not None
                and action.expires_at <= now
            ):
                self._restore(action)
                restored.append(action.action_id)
        return restored

    def human_override(
        self,
        action_id: str,
        *,
        actor: str,
        decision: str,
        reason: str,
        ttl_seconds: int | None = None,
    ) -> ResponseAction:
        if actor not in self.authorized_reviewers:
            raise ResponseError("human reviewer is not authorized")
        if not reason.strip() or len(reason) > 256:
            raise ResponseError("override reason is required and must be bounded")
        action = self.get(action_id)
        if decision == "hold":
            if action.state != "isolated":
                raise ResponseError("only active isolation can be held")
            action.human_hold = True
        elif decision == "restore":
            self._restore(action)
        elif decision == "extend":
            if action.state != "isolated" or ttl_seconds is None:
                raise ResponseError("active isolation and TTL are required for extension")
            if ttl_seconds < 1 or ttl_seconds > 3600:
                raise ResponseError("extension TTL must be between 1 and 3600 seconds")
            action.expires_at = self.clock() + timedelta(seconds=ttl_seconds)
            action.human_hold = False
        else:
            raise ResponseError("unsupported human override decision")
        action.overrides.append(
            {
                "actor": actor,
                "decision": decision,
                "reason": reason.strip(),
                "timestamp": self.clock().isoformat(),
            }
        )
        return action
