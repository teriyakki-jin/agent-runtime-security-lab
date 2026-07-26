from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from portfolio_release.runner import (
    assemble_portfolio_evidence,
    benchmark_policy,
    evaluate_fixture,
    inspect_teardown,
    load_fixture_catalog,
)


class FixtureRunnerTests(unittest.TestCase):
    def test_catalog_rejects_unknown_kind_or_nonboolean_label(self) -> None:
        for fixture in (
            {"id": "bad", "kind": "shell", "scenario": "x", "expected_attack": True},
            {"id": "bad", "kind": "policy", "scenario": "x", "expected_attack": "yes"},
        ):
            with self.subTest(fixture=fixture), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "fixtures.json"
                path.write_text(json.dumps({"schema_version": 1, "fixtures": [fixture]}))
                with self.assertRaises(ValueError):
                    load_fixture_catalog(path)

    def test_policy_and_runtime_fixtures_are_classified_from_live_response(self) -> None:
        requested: list[str] = []

        def requester(url: str, body: dict[str, object]) -> dict[str, object]:
            requested.append(url)
            self.assertEqual(body, {})
            if "/runtime/" in url:
                return {"finding": {"matched": False, "severity": "Critical"}}
            return {"decision": {"action": "allow"}}

        ticks = iter((1.0, 1.015, 2.0, 2.025))
        policy = evaluate_fixture(
            {"id": "normal", "kind": "policy", "scenario": "safe_document", "expected_attack": False},
            agent_base_url="http://127.0.0.1:8080",
            requester=requester,
            clock=lambda: next(ticks),
        )
        runtime = evaluate_fixture(
            {"id": "attack", "kind": "runtime", "scenario": "denied_process_bypass", "expected_attack": True},
            agent_base_url="http://127.0.0.1:8080",
            requester=requester,
            clock=lambda: next(ticks),
        )
        self.assertFalse(policy.detected)
        self.assertEqual(policy.detection_ms, 15.0)
        self.assertTrue(runtime.detected)
        self.assertEqual(runtime.detection_ms, 25.0)
        self.assertEqual(
            requested,
            [
                "http://127.0.0.1:8080/api/scenarios/safe_document",
                "http://127.0.0.1:8080/api/runtime/scenarios/denied_process_bypass",
            ],
        )

    def test_malformed_fixture_response_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            evaluate_fixture(
                {"id": "attack", "kind": "policy", "scenario": "tool_misuse", "expected_attack": True},
                agent_base_url="http://127.0.0.1:8080",
                requester=lambda _url, _body: {"unexpected": True},
                clock=lambda: 1.0,
            )


class LiveBenchmarkTests(unittest.TestCase):
    def test_policy_benchmark_alternates_allow_and_deny_inputs(self) -> None:
        bodies: list[dict[str, object]] = []

        def requester(_url: str, body: dict[str, object]) -> dict[str, object]:
            bodies.append(body)
            tool = body["input"]["tool"]
            return {"result": {"action": "deny" if tool == "run_command" else "allow"}}

        tick_values: list[float] = []
        for index in range(1, 11):
            tick_values.extend((float(index), float(index) + index / 1000))
        ticks = iter(tick_values)
        samples = benchmark_policy(
            opa_url="http://127.0.0.1:8181/v1/data/agent_security/decision",
            requester=requester,
            clock=lambda: next(ticks),
            iterations=10,
        )
        self.assertEqual(samples, [float(index) for index in range(1, 11)])
        self.assertEqual(
            [body["input"]["tool"] for body in bodies],
            ["read_document", "run_command"] * 5,
        )

    def test_policy_benchmark_rejects_short_runs_or_wrong_decisions(self) -> None:
        with self.assertRaises(ValueError):
            benchmark_policy(
                opa_url="http://opa",
                requester=lambda _url, _body: {"result": {"action": "allow"}},
                clock=lambda: 1.0,
                iterations=9,
            )
        ticks = iter((1.0, 1.1) * 10)
        with self.assertRaises(ValueError):
            benchmark_policy(
                opa_url="http://opa",
                requester=lambda _url, _body: {"result": {"action": "allow"}},
                clock=lambda: next(ticks),
                iterations=10,
            )

    def test_teardown_is_true_only_when_all_project_resources_are_absent(self) -> None:
        outputs = iter(("", "", ""))
        clean = inspect_teardown(lambda _command: next(outputs))
        self.assertTrue(all(clean.values()))
        outputs = iter(("container-id\n", "", "volume-name\n"))
        dirty = inspect_teardown(lambda _command: next(outputs))
        self.assertEqual(
            dirty,
            {"containers_removed": False, "networks_removed": True, "volumes_removed": False},
        )


class EvidenceAssemblyTests(unittest.TestCase):
    def test_evidence_contains_three_control_stages_and_sanitized_artifacts(self) -> None:
        raw = {
            "policy_latencies_ms": [1.0] * 20,
            "fixture_results": [
                {"fixture_id": "normal", "expected_attack": False, "detected": False, "detection_ms": 2.0},
                {"fixture_id": "attack", "expected_attack": True, "detected": True, "detection_ms": 3.0},
            ],
            "resource_samples": [
                {"container": "arsl-agent-api", "cpu_percent": 2.0, "memory_mib": 128.0}
            ],
            "response_mttr_ms": 900.0,
            "tests": {"passed": 19, "failed": 0, "coverage_percent": 90.0},
        }
        evidence = assemble_portfolio_evidence(
            raw,
            teardown={"containers_removed": True, "networks_removed": True, "volumes_removed": True},
            generated_at="2026-07-26T00:00:00Z",
        )
        self.assertEqual(evidence["result"], "passed")
        self.assertEqual(set(evidence["control_stages"]), {"before", "during", "after"})
        self.assertGreaterEqual(len(evidence["control_stages"]["before"]), 3)
        self.assertGreaterEqual(len(evidence["control_stages"]["during"]), 3)
        self.assertGreaterEqual(len(evidence["control_stages"]["after"]), 3)
        self.assertTrue(evidence["checks"]["test_coverage_sufficient"])
        self.assertEqual(evidence["tests"]["passed"], 19)
        serialized = json.dumps(evidence)
        self.assertNotIn("container-id", serialized)
        self.assertNotIn("Bearer ", serialized)
        self.assertNotIn("eyJ", serialized)


if __name__ == "__main__":
    unittest.main()
