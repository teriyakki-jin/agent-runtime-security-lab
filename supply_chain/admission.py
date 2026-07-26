from __future__ import annotations

import hashlib
import json
import re
from typing import Any


DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


class AdmissionError(RuntimeError):
    pass


def tool_schema_sha256(schema: dict[str, Any]) -> str:
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def compare_tool_inventory(
    manifest: dict[str, Any], actual_tools: list[dict[str, Any]]
) -> dict[str, Any]:
    expected = {
        item["name"]: item.get("input_schema_sha256")
        for item in manifest.get("tools", [])
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    actual: dict[str, str] = {}
    duplicates: set[str] = set()
    for item in actual_tools:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        name = item["name"]
        if name in actual:
            duplicates.add(name)
        schema = item.get("inputSchema")
        if not isinstance(schema, dict):
            schema = {}
        actual[name] = tool_schema_sha256(schema)

    expected_names = set(expected)
    actual_names = set(actual)
    schema_drift = sorted(
        name
        for name in expected_names & actual_names
        if expected[name] != actual[name]
    )
    unexpected = sorted(actual_names - expected_names)
    missing = sorted(expected_names - actual_names)
    return {
        "matched": not (unexpected or missing or schema_drift or duplicates),
        "expected_count": len(expected),
        "actual_count": len(actual_tools),
        "unexpected_tools": unexpected,
        "missing_tools": missing,
        "schema_drift": schema_drift,
        "duplicate_tools": sorted(duplicates),
    }


def _repository(reference: str) -> str:
    if "@" in reference:
        return reference.rsplit("@", 1)[0]
    last_slash = reference.rfind("/")
    last_colon = reference.rfind(":")
    return reference[:last_colon] if last_colon > last_slash else reference


def admitted_digest_reference(requested: str, gate_result: dict[str, Any]) -> str:
    if gate_result.get("result") != "passed":
        raise AdmissionError("gate_did_not_pass")
    image = gate_result.get("image")
    if not isinstance(image, dict):
        raise AdmissionError("invalid_gate_output")
    repository = image.get("repository")
    digest = image.get("digest")
    if not isinstance(repository, str) or not isinstance(digest, str):
        raise AdmissionError("invalid_gate_output")
    if _repository(requested) != repository or not DIGEST.fullmatch(digest):
        raise AdmissionError("gate_output_reference_mismatch")
    return f"{repository}@{digest}"


def build_hardened_runtime_command(image: str, name: str) -> list[str]:
    if "@" not in image or not DIGEST.fullmatch(image.rsplit("@", 1)[1]):
        raise AdmissionError("runtime_image_must_be_digest_pinned")
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--network",
        "none",
        image,
    ]
