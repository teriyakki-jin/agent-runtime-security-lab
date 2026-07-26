from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from response_engine.orchestrator import (
    Detection,
    InMemoryIsolationAdapter,
    InMemoryTokenRevoker,
    ResponseError,
    ResponseOrchestrator,
)


class MutableClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 7, 26, 6, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now


class ResponseOrchestratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = MutableClock()
        self.isolation = InMemoryIsolationAdapter()
        self.revoker = InMemoryTokenRevoker()
        self.orchestrator = ResponseOrchestrator(
            isolation=self.isolation,
            token_revoker=self.revoker,
            clock=self.clock,
            authorized_reviewers={"soc-lead"},
        )

    def detection(self, **changes: object) -> Detection:
        values: dict[str, object] = {
            "incident_id": "incident-001",
            "rule_id": "causal-agent-takeover",
            "root_event_id": "event-001",
            "agent_id": "agent:researcher",
            "token_jti": "token-jti-001",
            "target": "arsl-phase14-agent",
            "severity": "Critical",
            "detected_at": self.clock.now - timedelta(milliseconds=125),
        }
        values.update(changes)
        return Detection(**values)

    def test_critical_detection_revokes_and_isolates_with_mttr(self) -> None:
        decision = self.orchestrator.handle(self.detection(), ttl_seconds=60)

        self.assertFalse(decision.duplicate)
        self.assertEqual(decision.action.state, "isolated")
        self.assertEqual(decision.action.mttr_ms, 125)
        self.assertIn("token-jti-001", self.revoker.revoked)
        self.assertIn("arsl-phase14-agent", self.isolation.isolated)

    def test_same_response_key_is_idempotent(self) -> None:
        first = self.orchestrator.handle(self.detection(), ttl_seconds=60)
        second = self.orchestrator.handle(self.detection(), ttl_seconds=60)

        self.assertEqual(first.action.action_id, second.action.action_id)
        self.assertTrue(second.duplicate)
        self.assertEqual(self.revoker.calls, 1)
        self.assertEqual(self.isolation.isolate_calls, 1)

    def test_noncritical_detection_requires_human_review(self) -> None:
        decision = self.orchestrator.handle(
            self.detection(severity="High"), ttl_seconds=60
        )
        self.assertEqual(decision.action.state, "review_required")
        self.assertFalse(self.revoker.revoked)
        self.assertFalse(self.isolation.isolated)

    def test_ttl_restores_isolation_but_token_stays_revoked(self) -> None:
        decision = self.orchestrator.handle(self.detection(), ttl_seconds=60)
        self.clock.now += timedelta(seconds=61)

        restored = self.orchestrator.reconcile()

        self.assertEqual(restored, [decision.action.action_id])
        self.assertNotIn("arsl-phase14-agent", self.isolation.isolated)
        self.assertIn("token-jti-001", self.revoker.revoked)
        self.assertEqual(self.orchestrator.get(decision.action.action_id).state, "restored")

    def test_authorized_human_can_hold_and_restore(self) -> None:
        action = self.orchestrator.handle(self.detection(), ttl_seconds=60).action
        held = self.orchestrator.human_override(
            action.action_id,
            actor="soc-lead",
            decision="hold",
            reason="Active investigation",
        )
        self.assertTrue(held.human_hold)
        self.clock.now += timedelta(seconds=61)
        self.assertEqual(self.orchestrator.reconcile(), [])

        restored = self.orchestrator.human_override(
            action.action_id,
            actor="soc-lead",
            decision="restore",
            reason="Investigation complete",
        )
        self.assertEqual(restored.state, "restored")

    def test_unauthorized_or_empty_override_is_rejected(self) -> None:
        action = self.orchestrator.handle(self.detection(), ttl_seconds=60).action
        for actor, reason in (("unknown", "reason"), ("soc-lead", "")):
            with self.subTest(actor=actor, reason=reason):
                with self.assertRaises(ResponseError):
                    self.orchestrator.human_override(
                        action.action_id,
                        actor=actor,
                        decision="restore",
                        reason=reason,
                    )


if __name__ == "__main__":
    unittest.main()
