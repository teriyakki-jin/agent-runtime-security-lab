from __future__ import annotations

import json
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone

from response_engine.lab import ScenarioClock, run_phase14_scenario
from response_engine.orchestrator import InMemoryTokenRevoker


@dataclass(frozen=True)
class Snapshot:
    target: str
    networks: tuple[str, ...]


class RecordingIsolation:
    def __init__(self) -> None:
        self.restored = False

    def isolate(self, target: str) -> Snapshot:
        return Snapshot(target, ("agent_net", "egress_net"))

    def restore(self, snapshot: object) -> None:
        self.assert_snapshot(snapshot)
        self.restored = True

    @staticmethod
    def assert_snapshot(snapshot: object) -> None:
        if not isinstance(snapshot, Snapshot):
            raise TypeError("unexpected snapshot")


class Phase14LabTests(unittest.TestCase):
    def test_scenario_produces_sanitized_complete_evidence(self) -> None:
        clock = ScenarioClock(datetime(2026, 7, 26, 6, 0, tzinfo=timezone.utc))
        isolation = RecordingIsolation()
        revoker = InMemoryTokenRevoker()

        evidence = run_phase14_scenario(
            root_jti="root-jti-secret",
            child_jti="child-jti-secret",
            root_subject="arsl-agent-gateway",
            child_subject="agent:researcher",
            issuer="http://auth-server:9000",
            audience="http://mcp-server:8000/mcp",
            target="arsl-mcp-server",
            isolation=isolation,
            token_revoker=revoker,
            clock=clock,
        )

        self.assertEqual(evidence["result"], "passed")
        self.assertTrue(all(evidence["checks"].values()))
        self.assertTrue(isolation.restored)
        serialized = json.dumps(evidence)
        self.assertNotIn("root-jti-secret", serialized)
        self.assertNotIn("child-jti-secret", serialized)
        self.assertFalse(any(evidence["privacy"].values()))


if __name__ == "__main__":
    unittest.main()
