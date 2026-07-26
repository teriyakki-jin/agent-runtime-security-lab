from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from typing import Callable


class IsolationError(RuntimeError):
    """Raised when a target is unsafe or a Docker isolation action fails."""


@dataclass(frozen=True)
class IsolationSnapshot:
    target: str
    container_id: str
    networks: tuple[str, ...]
    was_paused: bool


CommandRunner = Callable[[list[str]], str]
CONTAINER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def run_command(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise IsolationError(f"Docker command failed: {command[1]}") from exc
    return completed.stdout


class DockerIsolationAdapter:
    """Pause and detach only explicitly managed Phase 14 lab containers."""

    def __init__(
        self,
        *,
        runner: CommandRunner = run_command,
        expected_project: str = "agent-runtime-security-lab",
    ) -> None:
        self.runner = runner
        self.expected_project = expected_project

    @staticmethod
    def _validate_target(target: str) -> None:
        if not CONTAINER_NAME.fullmatch(target):
            raise IsolationError("container target contains unsafe characters")

    def _inspect(self, target: str) -> IsolationSnapshot:
        self._validate_target(target)
        try:
            payload = json.loads(self.runner(["docker", "container", "inspect", target]))
            if not isinstance(payload, list) or len(payload) != 1:
                raise ValueError("expected one container")
            item = payload[0]
            container_id = item["Id"]
            if not isinstance(container_id, str) or not re.fullmatch(
                r"[a-f0-9]{64}", container_id
            ):
                raise ValueError("invalid container id")
            labels = item["Config"]["Labels"] or {}
            networks = tuple((item["NetworkSettings"]["Networks"] or {}).keys())
            paused = bool(item["State"]["Paused"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IsolationError("container inspection returned invalid data") from exc
        if labels.get("com.arsl.phase14.managed") != "true":
            raise IsolationError("container is not managed by Phase 14")
        if labels.get("com.docker.compose.project") != self.expected_project:
            raise IsolationError("container belongs to another Compose project")
        return IsolationSnapshot(
            target=target,
            container_id=container_id,
            networks=networks,
            was_paused=paused,
        )

    def isolate(self, target: str) -> IsolationSnapshot:
        snapshot = self._inspect(target)
        disconnected: list[str] = []
        container_id = snapshot.container_id
        try:
            for network in snapshot.networks:
                self.runner(
                    ["docker", "network", "disconnect", network, container_id]
                )
                disconnected.append(network)
            if not snapshot.was_paused:
                self.runner(["docker", "container", "pause", container_id])
        except Exception as exc:
            for network in disconnected:
                try:
                    self.runner(
                        ["docker", "network", "connect", network, container_id]
                    )
                except Exception:
                    pass
            if isinstance(exc, IsolationError):
                raise
            raise IsolationError("container isolation failed") from exc
        return snapshot

    def restore(self, snapshot: IsolationSnapshot) -> None:
        self._validate_target(snapshot.target)
        current = self._inspect(snapshot.container_id)
        if current.container_id != snapshot.container_id:
            raise IsolationError("container identity changed before restoration")
        try:
            if current.was_paused and not snapshot.was_paused:
                self.runner(
                    ["docker", "container", "unpause", snapshot.container_id]
                )
            for network in snapshot.networks:
                self.runner(
                    ["docker", "network", "connect", network, snapshot.container_id]
                )
        except Exception as exc:
            if isinstance(exc, IsolationError):
                raise
            raise IsolationError("container restoration failed") from exc
