from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def _component_licenses(component: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for entry in component.get("licenses", []):
        if not isinstance(entry, dict):
            continue
        license_data = entry.get("license")
        if isinstance(license_data, dict):
            value = license_data.get("id") or license_data.get("name")
            if isinstance(value, str):
                result.add(value)
        expression = entry.get("expression")
        if isinstance(expression, str):
            result.add(expression)
    return result


def evaluate_sbom_policy(
    sbom: dict[str, Any], vulnerability_report: dict[str, Any], policy: dict[str, Any]
) -> dict[str, Any]:
    reasons: list[str] = []
    components = sbom.get("components")
    if not isinstance(components, list):
        components = []
        reasons.append("invalid_sbom")
    matches = vulnerability_report.get("matches")
    if not isinstance(matches, list):
        matches = []
        reasons.append("invalid_vulnerability_report")

    observed_severities: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    vulnerability_ids: list[str] = []
    scoped_package_types = {
        item.lower()
        for item in policy.get("vulnerability_package_types", [])
        if isinstance(item, str)
    }
    for match in matches:
        vulnerability = match.get("vulnerability", {}) if isinstance(match, dict) else {}
        artifact = match.get("artifact", {}) if isinstance(match, dict) else {}
        severity = vulnerability.get("severity")
        identifier = vulnerability.get("id")
        if isinstance(severity, str):
            normalized_severity = severity.lower()
            observed_severities[normalized_severity] += 1
            artifact_type = artifact.get("type") if isinstance(artifact, dict) else None
            in_scope = not scoped_package_types or (
                isinstance(artifact_type, str)
                and artifact_type.lower() in scoped_package_types
            )
            if in_scope:
                severities[normalized_severity] += 1
                if isinstance(identifier, str):
                    vulnerability_ids.append(identifier)

    maximum = policy.get("maximum_vulnerabilities", {})
    for severity in ("critical", "high"):
        limit = maximum.get(severity, 0) if isinstance(maximum, dict) else 0
        if severities[severity] > limit:
            reasons.append(f"{severity}_vulnerability_limit_exceeded")

    maximum_observed = policy.get("maximum_observed_vulnerabilities", {})
    for severity in ("critical", "high"):
        limit = (
            maximum_observed.get(severity)
            if isinstance(maximum_observed, dict)
            else None
        )
        if isinstance(limit, int) and observed_severities[severity] > limit:
            reasons.append(f"observed_{severity}_baseline_exceeded")

    names = {
        item.get("name", "").lower()
        for item in components
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    required = {
        item.lower()
        for item in policy.get("required_components", [])
        if isinstance(item, str)
    }
    missing_components = sorted(required - names)
    if missing_components:
        reasons.append("required_component_missing")

    denied_policy = {
        item
        for item in policy.get("denied_licenses", [])
        if isinstance(item, str)
    }
    license_purl_types = {
        item.lower()
        for item in policy.get("license_purl_types", [])
        if isinstance(item, str)
    }
    observed_licenses: set[str] = set()
    for component in components:
        if isinstance(component, dict):
            purl = component.get("purl")
            in_scope = not license_purl_types or (
                isinstance(purl, str)
                and any(purl.lower().startswith(f"pkg:{kind}/") for kind in license_purl_types)
            )
            if in_scope:
                observed_licenses.update(_component_licenses(component))
    denied_licenses = sorted(observed_licenses & denied_policy)
    if denied_licenses:
        reasons.append("denied_license_detected")

    return {
        "allow": not reasons,
        "observed_critical": observed_severities["critical"],
        "observed_high": observed_severities["high"],
        "critical": severities["critical"],
        "high": severities["high"],
        "vulnerability_ids": sorted(set(vulnerability_ids)),
        "denied_licenses": denied_licenses,
        "missing_components": missing_components,
        "component_count": len(components),
        "reason_codes": reasons,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Apply the Phase 13 SBOM policy.")
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--vulnerabilities", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = evaluate_sbom_policy(
        json.loads(args.sbom.read_text(encoding="utf-8")),
        json.loads(args.vulnerabilities.read_text(encoding="utf-8")),
        json.loads(args.policy.read_text(encoding="utf-8")),
    )
    serialized = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(serialized, encoding="utf-8")
    print(serialized)
    return 0 if result["allow"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
