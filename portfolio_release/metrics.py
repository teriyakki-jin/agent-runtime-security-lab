from __future__ import annotations

import json
import math
import re
from dataclasses import asdict
from dataclasses import dataclass
from typing import Iterable, Sequence


@dataclass(frozen=True)
class FixtureResult:
    fixture_id: str
    expected_attack: bool
    detected: bool
    detection_ms: float


@dataclass(frozen=True)
class ResourceSample:
    container: str
    cpu_percent: float
    memory_mib: float


@dataclass(frozen=True)
class ReleaseThresholds:
    policy_p95_ms: float = 250.0
    policy_p99_ms: float = 500.0
    detection_p95_ms: float = 1000.0
    response_mttr_ms: float = 5000.0
    minimum_recall: float = 0.95
    maximum_fpr: float = 0.05
    maximum_container_cpu_percent: float = 200.0
    maximum_container_memory_mib: float = 1024.0


def percentile(samples: Sequence[float], quantile: float) -> float:
    values = [float(value) for value in samples]
    if not values:
        raise ValueError("percentile requires at least one sample")
    if not 0.0 <= quantile <= 1.0:
        raise ValueError("quantile must be between zero and one")
    if any(not math.isfinite(value) for value in values):
        raise ValueError("percentile samples must be finite")
    values.sort()
    position = (len(values) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return values[lower]
    weight = position - lower
    return values[lower] + (values[upper] - values[lower]) * weight


def summarize_latency(samples: Sequence[float]) -> dict[str, float | int]:
    values = [float(value) for value in samples]
    if any(value < 0 for value in values):
        raise ValueError("latency samples must not be negative")
    return {
        "sample_count": len(values),
        "p50_ms": round(percentile(values, 0.50), 3),
        "p95_ms": round(percentile(values, 0.95), 3),
        "p99_ms": round(percentile(values, 0.99), 3),
        "max_ms": round(max(values), 3),
    }


def classification_metrics(
    results: Sequence[FixtureResult],
) -> dict[str, float | int]:
    if not results:
        raise ValueError("classification requires fixture results")
    identifiers = [result.fixture_id for result in results]
    if any(not identifier for identifier in identifiers) or len(identifiers) != len(
        set(identifiers)
    ):
        raise ValueError("fixture identifiers must be non-empty and unique")
    if any(
        result.detection_ms < 0 or not math.isfinite(result.detection_ms)
        for result in results
    ):
        raise ValueError("fixture detection latency must be finite and nonnegative")
    attack_count = sum(result.expected_attack for result in results)
    normal_count = len(results) - attack_count
    if attack_count == 0 or normal_count == 0:
        raise ValueError("classification requires normal and attack fixtures")

    true_positive = sum(
        result.expected_attack and result.detected for result in results
    )
    false_positive = sum(
        not result.expected_attack and result.detected for result in results
    )
    true_negative = sum(
        not result.expected_attack and not result.detected for result in results
    )
    false_negative = sum(
        result.expected_attack and not result.detected for result in results
    )
    precision_denominator = true_positive + false_positive
    return {
        "fixture_count": len(results),
        "attack_count": attack_count,
        "normal_count": normal_count,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "true_negative": true_negative,
        "false_negative": false_negative,
        "recall": round(true_positive / attack_count, 6),
        "precision": round(
            true_positive / precision_denominator if precision_denominator else 0.0,
            6,
        ),
        "false_positive_rate": round(false_positive / normal_count, 6),
    }


_MEMORY_PATTERN = re.compile(r"^([0-9]+(?:\.[0-9]+)?)(B|KiB|MiB|GiB|KB|MB|GB)$")
_MEMORY_TO_MIB = {
    "B": 1 / (1024 * 1024),
    "KiB": 1 / 1024,
    "MiB": 1.0,
    "GiB": 1024.0,
    "KB": 1000 / (1024 * 1024),
    "MB": 1_000_000 / (1024 * 1024),
    "GB": 1_000_000_000 / (1024 * 1024),
}


def _memory_to_mib(raw: str) -> float:
    matched = _MEMORY_PATTERN.fullmatch(raw.strip())
    if matched is None:
        raise ValueError("Docker memory value is malformed")
    return float(matched.group(1)) * _MEMORY_TO_MIB[matched.group(2)]


def parse_docker_stats(lines: Iterable[str]) -> list[ResourceSample]:
    samples: list[ResourceSample] = []
    for line in lines:
        try:
            payload = json.loads(line)
            name = payload["Name"]
            cpu_raw = payload["CPUPerc"]
            memory_raw = payload["MemUsage"].split("/", 1)[0]
            if not isinstance(name, str) or not name.strip():
                raise ValueError("container name is missing")
            if not isinstance(cpu_raw, str) or not cpu_raw.endswith("%"):
                raise ValueError("Docker CPU value is malformed")
            cpu_percent = float(cpu_raw[:-1])
            memory_mib = _memory_to_mib(memory_raw)
            if (
                cpu_percent < 0
                or memory_mib < 0
                or not math.isfinite(cpu_percent)
                or not math.isfinite(memory_mib)
            ):
                raise ValueError("Docker resource values must be finite and nonnegative")
        except (AttributeError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("Docker stats line is malformed") from exc
        samples.append(
            ResourceSample(
                container=name.strip(),
                cpu_percent=cpu_percent,
                memory_mib=memory_mib,
            )
        )
    if not samples:
        raise ValueError("Docker stats must contain at least one sample")
    return samples


def summarize_resources(
    samples: Sequence[ResourceSample],
) -> dict[str, object]:
    if not samples:
        raise ValueError("resource summary requires samples")
    grouped: dict[str, list[ResourceSample]] = {}
    for sample in samples:
        if (
            not sample.container
            or sample.cpu_percent < 0
            or sample.memory_mib < 0
            or not math.isfinite(sample.cpu_percent)
            or not math.isfinite(sample.memory_mib)
        ):
            raise ValueError("resource sample is invalid")
        grouped.setdefault(sample.container, []).append(sample)

    containers: dict[str, dict[str, float | int]] = {}
    for name in sorted(grouped):
        container_samples = grouped[name]
        containers[name] = {
            "samples": len(container_samples),
            "average_cpu_percent": round(
                sum(item.cpu_percent for item in container_samples)
                / len(container_samples),
                3,
            ),
            "peak_cpu_percent": round(
                max(item.cpu_percent for item in container_samples), 3
            ),
            "peak_memory_mib": round(
                max(item.memory_mib for item in container_samples), 3
            ),
        }
    return {
        "sample_count": len(samples),
        "container_count": len(containers),
        "peak_cpu_percent": round(max(item.cpu_percent for item in samples), 3),
        "peak_memory_mib": round(max(item.memory_mib for item in samples), 3),
        "containers": containers,
    }


def build_release_evidence(
    *,
    policy_latencies_ms: Sequence[float],
    fixture_results: Sequence[FixtureResult],
    resource_samples: Sequence[ResourceSample],
    response_mttr_ms: float,
    teardown: dict[str, bool],
    thresholds: ReleaseThresholds | None = None,
) -> dict[str, object]:
    selected_thresholds = thresholds or ReleaseThresholds()
    if response_mttr_ms < 0 or not math.isfinite(response_mttr_ms):
        raise ValueError("response MTTR must be finite and nonnegative")
    expected_teardown_keys = {
        "containers_removed",
        "networks_removed",
        "volumes_removed",
    }
    if set(teardown) != expected_teardown_keys or any(
        not isinstance(value, bool) for value in teardown.values()
    ):
        raise ValueError("teardown must contain exact boolean cleanup checks")

    policy = summarize_latency(policy_latencies_ms)
    quality = classification_metrics(fixture_results)
    attack_latencies = [
        item.detection_ms for item in fixture_results if item.expected_attack
    ]
    detection_latency = summarize_latency(attack_latencies)
    resources = summarize_resources(resource_samples)
    checks = {
        "policy_tail_within_slo": (
            policy["p95_ms"] <= selected_thresholds.policy_p95_ms
            and policy["p99_ms"] <= selected_thresholds.policy_p99_ms
        ),
        "detection_latency_within_slo": (
            detection_latency["p95_ms"] <= selected_thresholds.detection_p95_ms
        ),
        "detection_quality_within_slo": (
            quality["recall"] >= selected_thresholds.minimum_recall
            and quality["false_positive_rate"] <= selected_thresholds.maximum_fpr
        ),
        "response_mttr_within_slo": (
            response_mttr_ms <= selected_thresholds.response_mttr_ms
        ),
        "resource_budget_within_slo": (
            resources["peak_cpu_percent"]
            <= selected_thresholds.maximum_container_cpu_percent
            and resources["peak_memory_mib"]
            <= selected_thresholds.maximum_container_memory_mib
        ),
        "teardown_complete": all(teardown.values()),
        "privacy_safe": True,
    }
    return {
        "phase": 15,
        "result": "passed" if all(checks.values()) else "failed",
        "checks": checks,
        "thresholds": asdict(selected_thresholds),
        "policy_latency": policy,
        "detection_latency": detection_latency,
        "response": {"detect_to_block_ms": round(response_mttr_ms, 3)},
        "quality": quality,
        "resources": resources,
        "teardown": dict(teardown),
        "privacy": {
            "access_token_exported": False,
            "client_secret_exported": False,
            "raw_tool_arguments_exported": False,
            "container_id_exported": False,
        },
    }
