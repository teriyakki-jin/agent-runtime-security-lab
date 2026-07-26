from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence


TOOL_MANIFEST_LABEL = "org.opencontainers.image.arsl.tool-manifest-sha256"
TOOL_MANIFEST_PREDICATE = (
    "https://agent-runtime-security.dev/attestations/mcp-tool-manifest/v1"
)
DIGEST_PATTERN = re.compile(r"^(?P<repository>.+)@(?P<digest>sha256:[a-f0-9]{64})$")
TOOL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class VerificationError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def load_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    validate_manifest(payload)
    return payload


def validate_manifest(payload: dict[str, Any]) -> None:
    schema_version = payload.get("schema_version")
    if schema_version not in (1, 2):
        raise VerificationError("unsupported_manifest_schema")
    server = payload.get("server")
    policy = payload.get("policy")
    tools = payload.get("tools")
    if not isinstance(server, dict) or not isinstance(policy, dict):
        raise VerificationError("invalid_manifest")
    if not isinstance(tools, list) or not tools:
        raise VerificationError("invalid_tool_inventory")
    maximum = policy.get("maximum_tools")
    if not isinstance(maximum, int) or maximum < 1 or len(tools) > maximum:
        raise VerificationError("tool_inventory_limit_exceeded")
    names: list[str] = []
    for tool in tools:
        if not isinstance(tool, dict):
            raise VerificationError("invalid_tool_entry")
        name = tool.get("name")
        scope = tool.get("oauth_scope")
        if not isinstance(name, str) or not TOOL_NAME_PATTERN.fullmatch(name):
            raise VerificationError("invalid_tool_name")
        if scope != f"mcp:{name}":
            raise VerificationError("invalid_tool_scope_binding")
        names.append(name)
        if schema_version == 2:
            schema_hash = tool.get("input_schema_sha256")
            if not isinstance(schema_hash, str) or not re.fullmatch(
                r"[a-f0-9]{64}", schema_hash
            ):
                raise VerificationError("invalid_tool_schema_hash")
    if names != sorted(names) or len(names) != len(set(names)):
        raise VerificationError("noncanonical_tool_inventory")
    for requirement in (
        "deny_unlisted_tools",
        "require_signature",
        "require_sbom_attestation",
    ):
        if policy.get(requirement) is not True:
            raise VerificationError("weakened_manifest_policy")
    if schema_version == 2:
        for requirement in (
            "require_tool_manifest_attestation",
            "require_runtime_inventory",
        ):
            if policy.get(requirement) is not True:
                raise VerificationError("weakened_manifest_policy")


def canonical_manifest_sha256(payload: dict[str, Any]) -> str:
    validate_manifest(payload)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def pinned_image(image: str) -> tuple[str, str]:
    match = DIGEST_PATTERN.fullmatch(image)
    if not match:
        raise VerificationError("unpinned_image_reference")
    return match.group("repository"), match.group("digest")


def _run(command: Sequence[str], failure_code: str) -> str:
    try:
        completed = subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VerificationError(failure_code) from exc
    if completed.returncode != 0:
        raise VerificationError(failure_code)
    return completed.stdout


def _json_output(raw: str, failure_code: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise VerificationError(failure_code) from exc


def cosign_claims_match(payload: Any, expected_digest: str) -> bool:
    entries = payload if isinstance(payload, list) else [payload]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        critical = entry.get("critical") or entry.get("Critical") or {}
        image = critical.get("image") or critical.get("Image") or {}
        digest = image.get("docker-manifest-digest") or image.get(
            "Docker-manifest-digest"
        )
        if digest == expected_digest:
            return True
    return False


def inspect_manifest_label(payload: Any) -> tuple[str, list[str]]:
    if not isinstance(payload, list) or len(payload) != 1:
        raise VerificationError("image_inspection_failed")
    item = payload[0]
    labels = ((item.get("Config") or {}).get("Labels") or {})
    repo_digests = item.get("RepoDigests") or []
    label = labels.get(TOOL_MANIFEST_LABEL)
    if not isinstance(label, str) or not isinstance(repo_digests, list):
        raise VerificationError("tool_manifest_label_missing")
    return label, repo_digests


def attestation_predicates(raw: str, predicate_type: str) -> list[dict[str, Any]]:
    payload = _json_output(raw, "invalid_attestation_payload")
    entries = payload if isinstance(payload, list) else [payload]
    predicates: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("payload"), str):
            continue
        try:
            statement = json.loads(base64.b64decode(entry["payload"], validate=True))
        except (ValueError, json.JSONDecodeError):
            continue
        if (
            isinstance(statement, dict)
            and statement.get("predicateType") == predicate_type
            and isinstance(statement.get("predicate"), dict)
        ):
            predicates.append(statement["predicate"])
    return predicates


def verify_supply_chain(
    *,
    image: str,
    manifest: dict[str, Any],
    public_key: Path | None,
    cosign: str,
    docker: str,
    allow_insecure_registry: bool,
    offline_verification: bool = False,
    certificate_identity: str | None = None,
    certificate_oidc_issuer: str | None = None,
) -> dict[str, Any]:
    repository, digest = pinned_image(image)
    expected_manifest = canonical_manifest_sha256(manifest)
    insecure = ["--allow-insecure-registry"] if allow_insecure_registry else []
    offline_log = ["--insecure-ignore-tlog"] if offline_verification else []
    if public_key is not None:
        if certificate_identity or certificate_oidc_issuer:
            raise VerificationError("ambiguous_signature_identity")
        trust = ["--key", str(public_key)]
        identity_verified = False
    elif certificate_identity and certificate_oidc_issuer:
        if offline_verification:
            raise VerificationError("keyless_verification_requires_rekor")
        trust = [
            f"--certificate-identity={certificate_identity}",
            f"--certificate-oidc-issuer={certificate_oidc_issuer}",
        ]
        identity_verified = True
    else:
        raise VerificationError("signature_identity_required")

    signature_raw = _run(
        [
            cosign,
            "verify",
            *trust,
            *insecure,
            *offline_log,
            "--output",
            "json",
            image,
        ],
        "signature_verification_failed",
    )
    signature_payload = _json_output(signature_raw, "invalid_signature_payload")
    if not cosign_claims_match(signature_payload, digest):
        raise VerificationError("signature_digest_mismatch")

    _run(
        [
            cosign,
            "verify-attestation",
            *trust,
            "--type",
            "cyclonedx",
            *insecure,
            *offline_log,
            "--output",
            "json",
            image,
        ],
        "sbom_attestation_verification_failed",
    )

    signed_manifest_verified = False
    if manifest.get("schema_version") == 2:
        manifest_raw = _run(
            [
                cosign,
                "verify-attestation",
                *trust,
                "--type",
                TOOL_MANIFEST_PREDICATE,
                *insecure,
                *offline_log,
                "--output",
                "json",
                image,
            ],
            "tool_manifest_attestation_verification_failed",
        )
        predicates = attestation_predicates(manifest_raw, TOOL_MANIFEST_PREDICATE)
        matching_predicate = False
        for predicate in predicates:
            try:
                matching_predicate = (
                    canonical_manifest_sha256(predicate) == expected_manifest
                )
            except VerificationError:
                matching_predicate = False
            if matching_predicate:
                break
        if not matching_predicate:
            raise VerificationError("signed_tool_manifest_mismatch")
        signed_manifest_verified = True

    inspect_raw = _run(
        [docker, "image", "inspect", image],
        "image_inspection_failed",
    )
    label, repo_digests = inspect_manifest_label(
        _json_output(inspect_raw, "invalid_image_inspection_payload")
    )
    if label != expected_manifest:
        raise VerificationError("tool_manifest_digest_mismatch")
    if not any(item.endswith(f"@{digest}") for item in repo_digests):
        raise VerificationError("local_image_digest_mismatch")

    return {
        "result": "passed",
        "image": {"repository": repository, "digest": digest},
        "manifest_sha256": expected_manifest,
        "controls": {
            "signature_verified": True,
            "digest_pinned": True,
            "sbom_attestation_verified": True,
            "tool_manifest_verified": True,
            **(
                {
                    "signed_tool_manifest_verified": signed_manifest_verified,
                    **(
                        {
                            "github_oidc_identity_verified": True,
                            "rekor_inclusion_verified": True,
                        }
                        if identity_verified
                        else {}
                    ),
                }
                if manifest.get("schema_version") == 2
                else {}
            ),
        },
        "tool_count": len(manifest["tools"]),
    }


def parse_args() -> argparse.Namespace:
    root = Path(__file__).parents[1]
    parser = argparse.ArgumentParser(description="Verify a signed MCP server image.")
    parser.add_argument("--image", required=True)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=root / "deploy/supply-chain/trusted-mcp-tools.json",
    )
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--certificate-identity")
    parser.add_argument("--certificate-oidc-issuer")
    parser.add_argument("--cosign", default="cosign")
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--allow-insecure-registry", action="store_true")
    parser.add_argument(
        "--offline-verification",
        action="store_true",
        help="Skip transparency-log verification for the isolated local lab only.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = verify_supply_chain(
            image=args.image,
            manifest=load_manifest(args.manifest),
            public_key=args.public_key,
            cosign=args.cosign,
            docker=args.docker,
            allow_insecure_registry=args.allow_insecure_registry,
            offline_verification=args.offline_verification,
            certificate_identity=args.certificate_identity,
            certificate_oidc_issuer=args.certificate_oidc_issuer,
        )
    except (OSError, ValueError, VerificationError, json.JSONDecodeError) as exc:
        code = exc.code if isinstance(exc, VerificationError) else "verification_failed"
        payload = json.dumps({"result": "blocked", "reason_code": code})
        if args.output:
            args.output.write_text(payload, encoding="utf-8")
        print(payload)
        return 2
    payload = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
