from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

from supply_chain.admission import AdmissionError, admitted_digest_reference


def validate_admission_bundle(
    requested_image: str,
    gate_result: dict[str, Any],
    inventory_result: dict[str, Any],
    sbom_policy_result: dict[str, Any],
) -> str:
    admitted = admitted_digest_reference(requested_image, gate_result)
    inventory = inventory_result.get("inventory")
    if (
        inventory_result.get("result") != "passed"
        or not isinstance(inventory, dict)
        or inventory.get("matched") is not True
    ):
        raise AdmissionError("runtime_tool_inventory_not_verified")
    if sbom_policy_result.get("allow") is not True:
        raise AdmissionError("sbom_policy_not_satisfied")
    return admitted


def runtime_command(
    image: str, *, docker: str, name: str, network: str, detach: bool
) -> list[str]:
    command = [docker, "run", "--rm"]
    if detach:
        command.append("-d")
    command.extend(
        [
            "--name",
            name,
            f"--network={network}",
            "--read-only",
            "--tmpfs=/tmp:size=16m,mode=1777",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=256",
            "--memory=512m",
            image,
        ]
    )
    return command


def _load(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AdmissionError("invalid_admission_artifact")
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Launch only the digest emitted by the Phase 13 admission gate."
    )
    parser.add_argument("--requested-image", required=True)
    parser.add_argument("--gate-result", type=Path, required=True)
    parser.add_argument("--inventory-result", type=Path, required=True)
    parser.add_argument("--sbom-policy-result", type=Path, required=True)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--name", default="arsl-mcp-server-admitted")
    parser.add_argument("--network", default="none")
    parser.add_argument("--foreground", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        image = validate_admission_bundle(
            args.requested_image,
            _load(args.gate_result),
            _load(args.inventory_result),
            _load(args.sbom_policy_result),
        )
        command = runtime_command(
            image,
            docker=args.docker,
            name=args.name,
            network=args.network,
            detach=not args.foreground,
        )
        if args.dry_run:
            print(json.dumps({"result": "passed", "admitted_image": image}))
            return 0
        completed = subprocess.run(
            command, check=False, capture_output=True, text=True, timeout=120
        )
        if completed.returncode != 0:
            raise AdmissionError("admitted_runtime_start_failed")
        print(
            json.dumps(
                {
                    "result": "started",
                    "admitted_image": image,
                    "container_id": completed.stdout.strip()[:64],
                }
            )
        )
        return 0
    except (AdmissionError, OSError, ValueError, json.JSONDecodeError) as exc:
        reason = str(exc) if isinstance(exc, AdmissionError) else "admission_failed"
        print(json.dumps({"result": "blocked", "reason_code": reason}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
