from __future__ import annotations

import json
import unittest

from response_engine.docker_isolation import DockerIsolationAdapter, IsolationError


class FakeRunner:
    def __init__(self, labels: dict[str, str] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.labels = labels or {
            "com.arsl.phase14.managed": "true",
            "com.docker.compose.project": "agent-runtime-security-lab",
        }
        self.container_id = "a" * 64
        self.paused = False
        self.fail_connect_once = False

    def __call__(self, command: list[str]) -> str:
        self.calls.append(command)
        if command[1:3] == ["container", "inspect"]:
            return json.dumps(
                [
                    {
                        "Id": self.container_id,
                        "Config": {"Labels": self.labels},
                        "State": {"Paused": self.paused},
                        "NetworkSettings": {
                            "Networks": {"arsl_agent_net": {}, "arsl_egress_net": {}}
                        },
                    }
                ]
            )
        if command[1:3] == ["container", "pause"]:
            self.paused = True
        elif command[1:3] == ["container", "unpause"]:
            self.paused = False
        elif command[1:3] == ["network", "connect"] and self.fail_connect_once:
            self.fail_connect_once = False
            raise RuntimeError("transient reconnect failure")
        return ""


class DockerIsolationAdapterTests(unittest.TestCase):
    def test_isolation_disconnects_networks_then_pauses(self) -> None:
        runner = FakeRunner()
        adapter = DockerIsolationAdapter(runner=runner)

        snapshot = adapter.isolate("arsl-phase14-agent")

        self.assertEqual(snapshot.networks, ("arsl_agent_net", "arsl_egress_net"))
        self.assertEqual(
            runner.calls[1:],
            [
                ["docker", "network", "disconnect", "arsl_agent_net", "a" * 64],
                ["docker", "network", "disconnect", "arsl_egress_net", "a" * 64],
                ["docker", "container", "pause", "a" * 64],
            ],
        )

    def test_restore_unpauses_then_reconnects_saved_networks(self) -> None:
        runner = FakeRunner()
        adapter = DockerIsolationAdapter(runner=runner)
        snapshot = adapter.isolate("arsl-phase14-agent")

        adapter.restore(snapshot)

        self.assertEqual(
            runner.calls[-3:],
            [
                ["docker", "container", "unpause", "a" * 64],
                ["docker", "network", "connect", "arsl_agent_net", "a" * 64],
                ["docker", "network", "connect", "arsl_egress_net", "a" * 64],
            ],
        )

    def test_restore_rejects_replaced_container_identity(self) -> None:
        runner = FakeRunner()
        adapter = DockerIsolationAdapter(runner=runner)
        snapshot = adapter.isolate("arsl-phase14-agent")
        runner.container_id = "b" * 64

        with self.assertRaisesRegex(IsolationError, "identity changed"):
            adapter.restore(snapshot)

    def test_restore_can_retry_after_partial_network_failure(self) -> None:
        runner = FakeRunner()
        adapter = DockerIsolationAdapter(runner=runner)
        snapshot = adapter.isolate("arsl-phase14-agent")
        runner.fail_connect_once = True

        with self.assertRaises(IsolationError):
            adapter.restore(snapshot)
        adapter.restore(snapshot)

        unpause_calls = [
            call for call in runner.calls if call[1:3] == ["container", "unpause"]
        ]
        self.assertEqual(len(unpause_calls), 1)

    def test_unmanaged_or_wrong_project_container_is_rejected(self) -> None:
        for labels in (
            {"com.docker.compose.project": "agent-runtime-security-lab"},
            {
                "com.arsl.phase14.managed": "true",
                "com.docker.compose.project": "other-project",
            },
        ):
            with self.subTest(labels=labels):
                with self.assertRaises(IsolationError):
                    DockerIsolationAdapter(runner=FakeRunner(labels)).isolate(
                        "arsl-phase14-agent"
                    )

    def test_container_name_cannot_inject_shell_syntax(self) -> None:
        runner = FakeRunner()
        with self.assertRaises(IsolationError):
            DockerIsolationAdapter(runner=runner).isolate("agent;Remove-Item")
        self.assertEqual(runner.calls, [])


if __name__ == "__main__":
    unittest.main()
