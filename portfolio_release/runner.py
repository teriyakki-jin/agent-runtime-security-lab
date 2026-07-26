from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from collections.abc import Callable
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from portfolio_release.metrics import (
    FixtureResult,
    ResourceSample,
    build_release_evidence,
    parse_docker_stats,
)


JsonRequester = Callable[[str, dict[str, object]], dict[str, object]]
CommandRunner = Callable[[list[str]], str]


def load_fixture_catalog(path: Path) -> list[dict[str, object]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        fixtures = payload["fixtures"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("fixture catalog is malformed") from exc
    if payload.get("schema_version") != 1 or not isinstance(fixtures, list):
        raise ValueError("fixture catalog schema is unsupported")
    validated: list[dict[str, object]] = []
    identifiers: set[str] = set()
    for item in fixtures:
        if not isinstance(item, dict):
            raise ValueError("fixture must be an object")
        identifier = item.get("id")
        kind = item.get("kind")
        scenario = item.get("scenario")
        expected_attack = item.get("expected_attack")
        if (
            not isinstance(identifier, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", identifier)
            or identifier in identifiers
            or kind not in {"policy", "runtime"}
            or not isinstance(scenario, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", scenario)
            or not isinstance(expected_attack, bool)
        ):
            raise ValueError("fixture fields are invalid")
        identifiers.add(identifier)
        validated.append(dict(item))
    if not validated:
        raise ValueError("fixture catalog is empty")
    return validated


def _validate_local_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in {
        "127.0.0.1",
        "localhost",
    }:
        raise ValueError("benchmark endpoint must be a local HTTP service")
    return url.rstrip("/")


def evaluate_fixture(
    fixture: dict[str, object],
    *,
    agent_base_url: str,
    requester: JsonRequester,
    clock: Callable[[], float],
) -> FixtureResult:
    identifier = fixture.get("id")
    kind = fixture.get("kind")
    scenario = fixture.get("scenario")
    expected_attack = fixture.get("expected_attack")
    if (
        not isinstance(identifier, str)
        or kind not in {"policy", "runtime"}
        or not isinstance(scenario, str)
        or not isinstance(expected_attack, bool)
    ):
        raise ValueError("fixture is invalid")
    base_url = _validate_local_url(agent_base_url)
    path = (
        f"/api/scenarios/{scenario}"
        if kind == "policy"
        else f"/api/runtime/scenarios/{scenario}"
    )
    started_at = clock()
    response = requester(f"{base_url}{path}", {})
    finished_at = clock()
    try:
        if kind == "policy":
            action = response["decision"]["action"]
            if action not in {"allow", "review", "deny"}:
                raise ValueError("policy fixture returned an invalid action")
            detected = action == "deny"
        else:
            finding = response["finding"]
            matched = finding["matched"]
            severity = finding["severity"]
            if not isinstance(matched, bool) or not isinstance(severity, str):
                raise ValueError("runtime fixture returned an invalid finding")
            detected = not matched and severity in {"High", "Critical"}
    except (KeyError, TypeError) as exc:
        raise ValueError("fixture response is malformed") from exc
    elapsed_ms = (finished_at - started_at) * 1000
    if elapsed_ms < 0:
        raise ValueError("fixture clock moved backwards")
    return FixtureResult(
        fixture_id=identifier,
        expected_attack=expected_attack,
        detected=detected,
        detection_ms=round(elapsed_ms, 3),
    )


def benchmark_policy(
    *,
    opa_url: str,
    requester: JsonRequester,
    clock: Callable[[], float],
    iterations: int,
) -> list[float]:
    if iterations < 10 or iterations > 10_000:
        raise ValueError("policy benchmark iterations must be between 10 and 10000")
    endpoint = _validate_local_url(opa_url)
    samples: list[float] = []
    for index in range(iterations):
        deny = index % 2 == 1
        policy_input: dict[str, object] = (
            {"tool": "run_command", "arguments": {"command": "blocked-fixture"}}
            if deny
            else {"tool": "read_document", "arguments": {"path": "public/guide.txt"}}
        )
        started_at = clock()
        response = requester(endpoint, {"input": policy_input})
        finished_at = clock()
        try:
            action = response["result"]["action"]
        except (KeyError, TypeError) as exc:
            raise ValueError("OPA benchmark response is malformed") from exc
        expected_action = "deny" if deny else "allow"
        if action != expected_action:
            raise ValueError("OPA benchmark returned an unexpected decision")
        elapsed_ms = (finished_at - started_at) * 1000
        if elapsed_ms < 0:
            raise ValueError("benchmark clock moved backwards")
        samples.append(round(elapsed_ms, 3))
    return samples


def inspect_teardown(runner: CommandRunner) -> dict[str, bool]:
    project_filter = "label=com.docker.compose.project=agent-runtime-security-lab"
    containers = runner(["docker", "ps", "-aq", "--filter", project_filter])
    networks = runner(["docker", "network", "ls", "-q", "--filter", project_filter])
    volumes = runner(["docker", "volume", "ls", "-q", "--filter", project_filter])
    return {
        "containers_removed": not containers.strip(),
        "networks_removed": not networks.strip(),
        "volumes_removed": not volumes.strip(),
    }


def assemble_portfolio_evidence(
    raw: dict[str, Any],
    *,
    teardown: dict[str, bool],
    generated_at: str,
) -> dict[str, object]:
    try:
        policy_latencies = [float(value) for value in raw["policy_latencies_ms"]]
        fixture_results = [FixtureResult(**item) for item in raw["fixture_results"]]
        resource_samples = [ResourceSample(**item) for item in raw["resource_samples"]]
        response_mttr_ms = float(raw["response_mttr_ms"])
        tests = raw["tests"]
        tests_passed = int(tests["passed"])
        tests_failed = int(tests["failed"])
        coverage_percent = float(tests["coverage_percent"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("raw portfolio benchmark is malformed") from exc
    if tests_passed < 1 or tests_failed < 0 or not 0 <= coverage_percent <= 100:
        raise ValueError("portfolio test evidence is invalid")
    evidence = build_release_evidence(
        policy_latencies_ms=policy_latencies,
        fixture_results=fixture_results,
        resource_samples=resource_samples,
        response_mttr_ms=response_mttr_ms,
        teardown=teardown,
    )
    evidence.update(
        {
            "generated_at": generated_at,
            "control_stages": {
                "before": [
                    "Cosign keyless admission",
                    "signed MCP tool manifest",
                    "prompt provenance and OAuth scope",
                ],
                "during": [
                    "OPA execution boundary",
                    "Tetragon runtime identity",
                    "causal multi-agent detection",
                ],
                "after": [
                    "OCSF and Elastic alert evidence",
                    "OAuth token revocation",
                    "reversible container isolation",
                ],
            },
            "artifacts": {
                "report": "docs/PHASE15.md",
                "screenshot": "docs/screenshots/phase15-portfolio-release.png",
                "demo_video": "docs/demo/phase15-integrated-attack.mp4",
                "demo_duration_seconds": 140,
            },
            "tests": {
                "passed": tests_passed,
                "failed": tests_failed,
                "coverage_percent": round(coverage_percent, 2),
            },
        }
    )
    evidence["checks"]["test_coverage_sufficient"] = (
        tests_failed == 0 and coverage_percent >= 80
    )
    evidence["result"] = (
        "passed" if all(evidence["checks"].values()) else "failed"
    )
    return evidence


def _request_json(url: str, body: dict[str, object]) -> dict[str, object]:
    encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
    request = Request(
        url,
        data=encoded,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=30.0) as response:
            payload = json.loads(response.read())
    except (OSError, TimeoutError, URLError, json.JSONDecodeError) as exc:
        raise RuntimeError("local benchmark request failed") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("local benchmark response must be an object")
    return payload


def _run_command(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"command failed: {command[0]}") from exc
    return completed.stdout


def _capture_resource_samples() -> list[ResourceSample]:
    output = _run_command(
        [
            "docker",
            "stats",
            "--no-stream",
            "--format",
            "{{json .}}",
            "arsl-opa",
            "arsl-agent-api",
            "arsl-auth-server",
            "arsl-mcp-server",
            "arsl-jaeger",
        ]
    )
    return parse_docker_stats(line for line in output.splitlines() if line.strip())


def collect_live(project_root: Path, output_path: Path) -> None:
    fixtures = load_fixture_catalog(
        project_root / "portfolio_release" / "fixtures" / "phase15" / "scenarios.json"
    )
    resource_samples = _capture_resource_samples()
    policy_latencies = benchmark_policy(
        opa_url="http://127.0.0.1:8181/v1/data/agent_security/decision",
        requester=_request_json,
        clock=time.perf_counter,
        iterations=60,
    )
    fixture_results = [
        evaluate_fixture(
            fixture,
            agent_base_url="http://127.0.0.1:8080",
            requester=_request_json,
            clock=time.perf_counter,
        )
        for fixture in fixtures
    ]
    resource_samples.extend(_capture_resource_samples())
    phase14 = json.loads(
        (project_root / "docs" / "evidence" / "phase14-safe-response.json").read_text(
            encoding="utf-8"
        )
    )
    raw = {
        "policy_latencies_ms": policy_latencies,
        "fixture_results": [asdict(item) for item in fixture_results],
        "resource_samples": [asdict(item) for item in resource_samples],
        "response_mttr_ms": phase14["mttr"]["detect_to_block_ms"],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")


def finalize(project_root: Path, input_path: Path, output_path: Path) -> None:
    raw = json.loads(input_path.read_text(encoding="utf-8"))
    evidence = assemble_portfolio_evidence(
        raw,
        teardown=inspect_teardown(_run_command),
        generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    if evidence["result"] != "passed":
        raise RuntimeError("Phase 15 release gate failed")


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 15 portfolio release benchmark")
    subparsers = parser.add_subparsers(dest="command", required=True)
    collect_parser = subparsers.add_parser("collect")
    collect_parser.add_argument("--output", type=Path, required=True)
    finalize_parser = subparsers.add_parser("finalize")
    finalize_parser.add_argument("--input", type=Path, required=True)
    finalize_parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    project_root = Path(__file__).resolve().parents[1]
    if arguments.command == "collect":
        collect_live(project_root, arguments.output.resolve())
    else:
        finalize(project_root, arguments.input.resolve(), arguments.output.resolve())


if __name__ == "__main__":
    main()
