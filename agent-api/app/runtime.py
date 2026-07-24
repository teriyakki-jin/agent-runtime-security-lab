from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections import deque
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


EVENT_TYPES = {"process_exec", "file_access", "network_connect"}


def canonical_sensor_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_sensor_signature(raw_payload: bytes, signature: str) -> bool:
    secret = os.getenv("RUNTIME_SENSOR_HMAC_KEY", "")
    if len(secret) < 32 or not signature:
        return False
    expected = hmac.new(secret.encode(), raw_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _timestamp(value: Any) -> str:
    if value is None or value == "":
        return datetime.now(timezone.utc).isoformat()
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Runtime observation timestamp must be an ISO-8601 string.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Runtime observation timestamp is not valid ISO-8601.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


class RuntimeMonitor:
    """Correlate policy intent with kernel/runtime sensor observations."""

    def __init__(
        self, max_records: int = 200, auto_correlation_window_seconds: float = 15.0
    ) -> None:
        self.max_records = max_records
        self.auto_correlation_window_seconds = auto_correlation_window_seconds
        self.intents: dict[str, dict[str, Any]] = {}
        self.observations: deque[dict[str, Any]] = deque(maxlen=max_records)
        self.findings: deque[dict[str, Any]] = deque(maxlen=max_records)

    def register_intent(
        self,
        *,
        intent_id: str,
        tool: str,
        actor: str,
        policy_action: str,
        executed: bool,
        container: str = "arsl-mcp-server",
    ) -> dict[str, Any]:
        expected_events: list[str] = []
        expected_target_prefix: str | None = None
        if executed and tool == "read_document":
            expected_events = ["file_access"]
            expected_target_prefix = "/app/documents/public/"

        intent = {
            "intent_id": intent_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "tool": tool,
            "policy_action": policy_action,
            "executed": executed,
            "container": container,
            "expected_event_types": expected_events,
            "expected_target_prefix": expected_target_prefix,
        }
        if len(self.intents) >= self.max_records:
            del self.intents[next(iter(self.intents))]
        self.intents[intent_id] = intent
        return intent

    def ingest(self, raw_observation: dict[str, Any]) -> dict[str, Any]:
        event_type = str(raw_observation.get("event_type", ""))
        if event_type not in EVENT_TYPES:
            raise ValueError(f"Unsupported runtime event type: {event_type}")

        target = str(raw_observation.get("target", ""))[:512]
        supplied_intent_id = str(raw_observation.get("intent_id", ""))[:64]
        observation = {
            "observation_id": str(raw_observation.get("observation_id") or uuid4()),
            "timestamp": _timestamp(raw_observation.get("timestamp")),
            "intent_id": supplied_intent_id,
            "source": str(raw_observation.get("source", "unknown"))[:32],
            "event_type": event_type,
            "process": str(raw_observation.get("process", "unknown"))[:256],
            "target": target,
            "target_fingerprint": _fingerprint(target),
            "container": str(raw_observation.get("container", "unknown"))[:128],
            "correlation_method": "explicit" if supplied_intent_id else "none",
            "correlation_delta_ms": None,
        }
        if not supplied_intent_id:
            correlated = self._auto_correlate(observation)
            if correlated:
                observation["intent_id"], delta_ms = correlated
                observation["correlation_method"] = "container_time_window"
                observation["correlation_delta_ms"] = delta_ms
        self.observations.appendleft(observation)
        finding = self._analyze(observation)
        self.findings.appendleft(finding)
        return finding

    def _auto_correlate(
        self, observation: dict[str, Any]
    ) -> tuple[str, int] | None:
        observed_at = datetime.fromisoformat(observation["timestamp"])
        candidates: list[tuple[float, str]] = []
        for intent in reversed(list(self.intents.values())):
            if intent["container"] != observation["container"]:
                continue
            intent_at = datetime.fromisoformat(intent["timestamp"])
            delta = (observed_at - intent_at).total_seconds()
            if -1.0 <= delta <= self.auto_correlation_window_seconds:
                candidates.append((abs(delta), intent["intent_id"]))
        if not candidates:
            return None
        delta, intent_id = min(candidates)
        return intent_id, round(delta * 1000)

    def _analyze(self, observation: dict[str, Any]) -> dict[str, Any]:
        intent = self.intents.get(observation["intent_id"])
        if intent is None:
            return self._finding(
                observation,
                None,
                matched=False,
                finding_type="orphan_runtime_activity",
                severity_id=4,
                severity="High",
                title="Runtime activity has no matching agent intent",
                reason="The sensor event could not be correlated to an authorized tool intent.",
            )

        expected_types = intent["expected_event_types"]
        event_type = observation["event_type"]
        target_prefix = intent["expected_target_prefix"]
        type_matches = event_type in expected_types
        target_matches = not target_prefix or observation["target"].startswith(target_prefix)

        if type_matches and target_matches:
            return self._finding(
                observation,
                intent,
                matched=True,
                finding_type="intent_runtime_match",
                severity_id=1,
                severity="Informational",
                title="Observed runtime activity matches agent intent",
                reason="The event type and target are within the intent allowlist.",
            )

        if not intent["executed"]:
            reason = (
                f"Policy action {intent['policy_action']} marked the tool as non-executed, "
                "but runtime activity was observed."
            )
        elif event_type in {"process_exec", "network_connect"}:
            reason = f"{event_type} is not expected for the isolated {intent['tool']} tool."
        elif type_matches:
            reason = "The observed target is outside the intent target allowlist."
        else:
            reason = "The observed event type is not declared by the authorized intent."

        critical = event_type in {"process_exec", "network_connect"} or not intent[
            "executed"
        ]
        severity_id = 5 if critical else 4
        severity = "Critical" if severity_id == 5 else "High"
        return self._finding(
            observation,
            intent,
            matched=False,
            finding_type="policy_runtime_mismatch",
            severity_id=severity_id,
            severity=severity,
            title="Observed runtime behavior violates agent intent",
            reason=reason,
        )

    @staticmethod
    def _finding(
        observation: dict[str, Any],
        intent: dict[str, Any] | None,
        *,
        matched: bool,
        finding_type: str,
        severity_id: int,
        severity: str,
        title: str,
        reason: str,
    ) -> dict[str, Any]:
        return {
            "finding_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "intent_id": observation["intent_id"],
            "finding_type": finding_type,
            "title": title,
            "reason": reason,
            "severity_id": severity_id,
            "severity": severity,
            "matched": matched,
            "tool": intent["tool"] if intent else None,
            "policy_action": intent["policy_action"] if intent else None,
            "expected_event_types": intent["expected_event_types"] if intent else [],
            "observation": observation,
        }

    def intent_list(self) -> list[dict[str, Any]]:
        return list(reversed(self.intents.values()))

    def observation_list(self) -> list[dict[str, Any]]:
        return list(self.observations)

    def finding_list(self) -> list[dict[str, Any]]:
        return list(self.findings)

    def status(self) -> dict[str, Any]:
        source_counts: dict[str, int] = {}
        auto_correlated = 0
        for observation in self.observations:
            source = observation["source"]
            source_counts[source] = source_counts.get(source, 0) + 1
            if observation["correlation_method"] == "container_time_window":
                auto_correlated += 1
        latest = self.observations[0]["timestamp"] if self.observations else None
        return {
            "sensor_mode": "tetragon" if source_counts.get("tetragon") else "simulator",
            "last_observation_at": latest,
            "source_counts": source_counts,
            "auto_correlated": auto_correlated,
            "correlation_window_seconds": self.auto_correlation_window_seconds,
        }
