from __future__ import annotations

import json
import math
import unittest
from pathlib import Path

from portfolio_release.metrics import (
    FixtureResult,
    ReleaseThresholds,
    ResourceSample,
    build_release_evidence,
    classification_metrics,
    parse_docker_stats,
    percentile,
    summarize_latency,
    summarize_resources,
)


class PercentileTests(unittest.TestCase):
    def test_linear_percentiles_are_calculated_from_sorted_samples(self) -> None:
        samples = [4.0, 1.0, 3.0, 2.0]
        self.assertEqual(percentile(samples, 0.0), 1.0)
        self.assertEqual(percentile(samples, 0.5), 2.5)
        self.assertAlmostEqual(percentile(samples, 0.95), 3.85)
        self.assertEqual(percentile(samples, 1.0), 4.0)

    def test_percentile_rejects_empty_nonfinite_or_invalid_quantile(self) -> None:
        for samples, quantile in (([], 0.5), ([math.inf], 0.5), ([1.0], 1.1)):
            with self.subTest(samples=samples, quantile=quantile):
                with self.assertRaises(ValueError):
                    percentile(samples, quantile)

    def test_latency_summary_contains_tail_percentiles(self) -> None:
        summary = summarize_latency([1.1111, 2.2222, 3.3333, 4.4444])
        self.assertEqual(summary["sample_count"], 4)
        self.assertEqual(summary["p50_ms"], 2.778)
        self.assertEqual(summary["p95_ms"], 4.278)
        self.assertEqual(summary["p99_ms"], 4.411)
        self.assertEqual(summary["max_ms"], 4.444)


class DetectionQualityTests(unittest.TestCase):
    def test_confusion_matrix_fpr_precision_and_recall(self) -> None:
        results = [
            FixtureResult("attack-hit", True, True, 8.0),
            FixtureResult("attack-miss", True, False, 9.0),
            FixtureResult("normal-fp", False, True, 5.0),
            FixtureResult("normal-tn", False, False, 4.0),
        ]
        metrics = classification_metrics(results)
        self.assertEqual(
            {name: metrics[name] for name in ("true_positive", "false_positive", "true_negative", "false_negative")},
            {"true_positive": 1, "false_positive": 1, "true_negative": 1, "false_negative": 1},
        )
        self.assertEqual(metrics["recall"], 0.5)
        self.assertEqual(metrics["precision"], 0.5)
        self.assertEqual(metrics["false_positive_rate"], 0.5)

    def test_quality_requires_unique_balanced_fixtures_and_nonnegative_latency(self) -> None:
        invalid_sets = (
            [FixtureResult("only-normal", False, False, 1.0)],
            [FixtureResult("only-attack", True, True, 1.0)],
            [FixtureResult("same", True, True, 1.0), FixtureResult("same", False, False, 1.0)],
            [FixtureResult("attack", True, True, -1.0), FixtureResult("normal", False, False, 1.0)],
        )
        for fixtures in invalid_sets:
            with self.subTest(fixtures=fixtures):
                with self.assertRaises(ValueError):
                    classification_metrics(fixtures)


class ResourceMetricTests(unittest.TestCase):
    def test_docker_stats_are_parsed_without_container_ids(self) -> None:
        lines = [
            json.dumps({"Name": "arsl-agent-api", "CPUPerc": "1.25%", "MemUsage": "128MiB / 1GiB"}),
            json.dumps({"Name": "arsl-opa", "CPUPerc": "0.10%", "MemUsage": "1.5GiB / 2GiB"}),
        ]
        samples = parse_docker_stats(lines)
        self.assertEqual(samples[0], ResourceSample("arsl-agent-api", 1.25, 128.0))
        self.assertEqual(samples[1], ResourceSample("arsl-opa", 0.1, 1536.0))

    def test_docker_stats_reject_malformed_or_negative_values(self) -> None:
        invalid_lines = (
            ["not-json"],
            [json.dumps({"Name": "", "CPUPerc": "1%", "MemUsage": "1MiB / 2MiB"})],
            [json.dumps({"Name": "arsl-api", "CPUPerc": "-1%", "MemUsage": "1MiB / 2MiB"})],
        )
        for lines in invalid_lines:
            with self.subTest(lines=lines):
                with self.assertRaises(ValueError):
                    parse_docker_stats(lines)

    def test_resource_summary_groups_samples_and_reports_peaks(self) -> None:
        summary = summarize_resources(
            [
                ResourceSample("arsl-api", 1.0, 100.0),
                ResourceSample("arsl-api", 3.0, 120.0),
                ResourceSample("arsl-opa", 2.0, 50.0),
            ]
        )
        self.assertEqual(summary["sample_count"], 3)
        self.assertEqual(summary["peak_cpu_percent"], 3.0)
        self.assertEqual(summary["peak_memory_mib"], 120.0)
        self.assertEqual(summary["containers"]["arsl-api"]["samples"], 2)
        self.assertEqual(summary["containers"]["arsl-api"]["average_cpu_percent"], 2.0)


class ReleaseEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = [10.0, 20.0, 30.0, 40.0, 50.0]
        self.fixtures = [
            FixtureResult("normal-1", False, False, 4.0),
            FixtureResult("normal-2", False, False, 5.0),
            FixtureResult("attack-1", True, True, 10.0),
            FixtureResult("attack-2", True, True, 12.0),
        ]
        self.resources = [
            ResourceSample("arsl-api", 2.5, 128.0),
            ResourceSample("arsl-opa", 1.0, 64.0),
        ]
        self.teardown = {
            "containers_removed": True,
            "networks_removed": True,
            "volumes_removed": True,
        }

    def test_release_evidence_passes_only_when_all_slos_and_cleanup_pass(self) -> None:
        evidence = build_release_evidence(
            policy_latencies_ms=self.policy,
            fixture_results=self.fixtures,
            resource_samples=self.resources,
            response_mttr_ms=900.0,
            teardown=self.teardown,
        )
        self.assertEqual(evidence["phase"], 15)
        self.assertEqual(evidence["result"], "passed")
        self.assertTrue(all(evidence["checks"].values()))
        self.assertEqual(evidence["quality"]["recall"], 1.0)
        self.assertEqual(evidence["quality"]["false_positive_rate"], 0.0)
        self.assertFalse(any(evidence["privacy"].values()))

    def test_release_evidence_fails_closed_for_bad_tail_recall_or_teardown(self) -> None:
        fixtures = [
            FixtureResult("normal", False, False, 5.0),
            FixtureResult("attack", True, False, 10.0),
        ]
        evidence = build_release_evidence(
            policy_latencies_ms=[1.0, 2.0, 1000.0],
            fixture_results=fixtures,
            resource_samples=self.resources,
            response_mttr_ms=9000.0,
            teardown={**self.teardown, "volumes_removed": False},
        )
        self.assertEqual(evidence["result"], "failed")
        self.assertFalse(evidence["checks"]["policy_tail_within_slo"])
        self.assertFalse(evidence["checks"]["detection_quality_within_slo"])
        self.assertFalse(evidence["checks"]["response_mttr_within_slo"])
        self.assertFalse(evidence["checks"]["teardown_complete"])

    def test_custom_thresholds_are_included_in_machine_readable_evidence(self) -> None:
        thresholds = ReleaseThresholds(minimum_recall=0.8, maximum_fpr=0.2)
        evidence = build_release_evidence(
            policy_latencies_ms=self.policy,
            fixture_results=self.fixtures,
            resource_samples=self.resources,
            response_mttr_ms=900.0,
            teardown=self.teardown,
            thresholds=thresholds,
        )
        self.assertEqual(evidence["thresholds"]["minimum_recall"], 0.8)
        self.assertEqual(evidence["thresholds"]["maximum_fpr"], 0.2)


class FixtureCatalogTests(unittest.TestCase):
    def test_fixture_catalog_is_unique_balanced_and_has_no_raw_secrets(self) -> None:
        path = Path(__file__).parents[1] / "fixtures" / "phase15" / "scenarios.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        fixtures = payload["fixtures"]
        identifiers = [item["id"] for item in fixtures]
        labels = [item["expected_attack"] for item in fixtures]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertGreaterEqual(labels.count(True), 5)
        self.assertGreaterEqual(labels.count(False), 5)
        self.assertNotIn("token", json.dumps(payload).lower())
        self.assertNotIn("secret", json.dumps(payload).lower())


if __name__ == "__main__":
    unittest.main()
