from __future__ import annotations

import argparse
import asyncio
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from supply_chain.admission import compare_tool_inventory
from supply_chain.gate import VerificationError, load_manifest, pinned_image


@dataclass(frozen=True)
class ProbeParameters:
    command: str
    args: list[str]
    env: dict[str, str]


def build_probe_parameters(
    image: str,
    *,
    docker: str = "docker",
    environment: Mapping[str, str] | None = None,
) -> ProbeParameters:
    try:
        pinned_image(image)
    except VerificationError as exc:
        raise ValueError("probe_image_must_be_digest_pinned") from exc
    source_environment = environment if environment is not None else os.environ
    allowed_environment = {
        key: source_environment[key]
        for key in (
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "DOCKER_HOST",
            "DOCKER_API_VERSION",
        )
        if key in source_environment
    }
    return ProbeParameters(
        command=docker,
        args=[
            "run",
            "--rm",
            "-i",
            "--network=none",
            "--read-only",
            "--tmpfs=/tmp:size=16m,mode=1777",
            "--cap-drop=ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit=128",
            "--memory=256m",
            image,
            "python",
            "-m",
            "app.pre_admission",
        ],
        env=allowed_environment,
    )


async def probe_actual_tools(image: str, *, docker: str = "docker") -> list[dict[str, Any]]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    probe = build_probe_parameters(image, docker=docker)
    parameters = StdioServerParameters(
        command=probe.command, args=probe.args, env=probe.env
    )
    async with stdio_client(parameters) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            response = await session.list_tools()
    return [tool.model_dump(by_alias=True, exclude_none=True) for tool in response.tools]


async def _run(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    tools = await probe_actual_tools(args.image, docker=args.docker)
    decision = compare_tool_inventory(manifest, tools)
    payload = {
        "result": "passed" if decision["matched"] else "blocked",
        "image": args.image,
        "isolation": {
            "network": "none",
            "read_only": True,
            "capabilities_dropped": "ALL",
            "no_new_privileges": True,
        },
        "inventory": decision,
    }
    serialized = json.dumps(payload, indent=2)
    if args.output:
        args.output.write_text(serialized, encoding="utf-8")
    print(serialized)
    return 0 if decision["matched"] else 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Interrogate the actual MCP tools/list surface before admission."
    )
    parser.add_argument("--image", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    return asyncio.run(_run(parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
