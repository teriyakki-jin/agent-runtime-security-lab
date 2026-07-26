from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


class CausalGraphError(ValueError):
    """Raised when a causal edge is missing or violates graph identity."""


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    kind: str
    agent_id: str
    resource_id: str
    parent_event_ids: tuple[str, ...]
    observed_at: datetime


class CausalAttackGraph:
    """Correlate events only through explicit parent edges, never timestamps alone."""

    def __init__(self, max_events: int = 1000) -> None:
        self.max_events = max_events
        self._events: dict[str, SecurityEvent] = {}

    def add(self, event: SecurityEvent) -> None:
        if not event.event_id or len(event.event_id) > 128:
            raise CausalGraphError("event_id is invalid")
        if event.event_id in self._events:
            raise CausalGraphError("event_id already exists")
        if len(self._events) >= self.max_events:
            raise CausalGraphError("causal graph capacity reached")
        for parent_id in event.parent_event_ids:
            parent = self._events.get(parent_id)
            if parent is None:
                raise CausalGraphError(f"unknown parent event: {parent_id}")
            if parent.agent_id != event.agent_id:
                raise CausalGraphError("causal edge crosses agent identity")
            if parent.resource_id != event.resource_id:
                raise CausalGraphError("causal edge crosses protected resource")
            if parent.observed_at > event.observed_at:
                raise CausalGraphError("parent event occurred after child")
        self._events[event.event_id] = event

    def get(self, event_id: str) -> SecurityEvent | None:
        return self._events.get(event_id)

    def match_sequence(
        self, terminal_event_id: str, expected_kinds: tuple[str, ...]
    ) -> list[SecurityEvent]:
        if not expected_kinds:
            return []
        terminal = self._events.get(terminal_event_id)
        if terminal is None or terminal.kind != expected_kinds[-1]:
            return []

        def find(event: SecurityEvent, index: int) -> list[SecurityEvent] | None:
            if event.kind != expected_kinds[index]:
                return None
            if index == 0:
                return [event]
            for parent_id in event.parent_event_ids:
                parent = self._events[parent_id]
                matched = find(parent, index - 1)
                if matched is not None:
                    return [*matched, event]
            return None

        return find(terminal, len(expected_kinds) - 1) or []
