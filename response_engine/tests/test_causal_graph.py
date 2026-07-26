from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from response_engine.causal import CausalAttackGraph, CausalGraphError, SecurityEvent


BASE = datetime(2026, 7, 26, 6, 0, tzinfo=timezone.utc)


def event(
    event_id: str,
    kind: str,
    *,
    parents: tuple[str, ...] = (),
    seconds: int = 0,
    agent_id: str = "agent:researcher",
    resource_id: str = "mcp:tool-server",
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        kind=kind,
        agent_id=agent_id,
        resource_id=resource_id,
        parent_event_ids=parents,
        observed_at=BASE + timedelta(seconds=seconds),
    )


class CausalAttackGraphTests(unittest.TestCase):
    def test_explicit_edges_form_attack_path(self) -> None:
        graph = CausalAttackGraph()
        graph.add(event("e1", "scope_violation"))
        graph.add(event("e2", "tool_call", parents=("e1",), seconds=1))
        graph.add(event("e3", "runtime_mismatch", parents=("e2",), seconds=2))

        path = graph.match_sequence(
            "e3", ("scope_violation", "tool_call", "runtime_mismatch")
        )
        self.assertEqual([item.event_id for item in path], ["e1", "e2", "e3"])

    def test_close_timestamps_without_edges_do_not_correlate(self) -> None:
        graph = CausalAttackGraph()
        graph.add(event("e1", "scope_violation"))
        graph.add(event("e2", "tool_call", seconds=1))
        graph.add(event("e3", "runtime_mismatch", seconds=2))

        self.assertEqual(
            graph.match_sequence("e3", ("scope_violation", "tool_call", "runtime_mismatch")),
            [],
        )

    def test_unknown_parent_is_rejected(self) -> None:
        graph = CausalAttackGraph()
        with self.assertRaisesRegex(CausalGraphError, "unknown parent"):
            graph.add(event("e2", "tool_call", parents=("missing",)))

    def test_cross_agent_or_resource_edge_is_rejected(self) -> None:
        graph = CausalAttackGraph()
        graph.add(event("e1", "scope_violation"))
        with self.assertRaises(CausalGraphError):
            graph.add(event("e2", "tool_call", parents=("e1",), agent_id="agent:other"))
        with self.assertRaises(CausalGraphError):
            graph.add(event("e3", "tool_call", parents=("e1",), resource_id="mcp:other"))

    def test_parent_must_not_occur_after_child(self) -> None:
        graph = CausalAttackGraph()
        graph.add(event("e1", "scope_violation", seconds=10))
        with self.assertRaisesRegex(CausalGraphError, "after child"):
            graph.add(event("e2", "tool_call", parents=("e1",), seconds=2))


if __name__ == "__main__":
    unittest.main()
