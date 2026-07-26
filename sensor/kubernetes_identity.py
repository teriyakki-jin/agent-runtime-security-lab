"""Resolve immutable Kubernetes workload identities from a Pod inventory snapshot."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def identities_from_pod_list(
    document: dict[str, Any], cluster: str
) -> dict[tuple[str, str, str], dict[str, str]]:
    if document.get("kind") != "List" or not isinstance(document.get("items"), list):
        raise ValueError("Pod inventory must be a Kubernetes List object.")
    identities: dict[tuple[str, str, str], dict[str, str]] = {}
    for pod in document["items"]:
        metadata = pod.get("metadata") or {}
        spec = pod.get("spec") or {}
        namespace = str(metadata.get("namespace") or "default")
        pod_name = str(metadata.get("name") or "")
        pod_uid = str(metadata.get("uid") or "")
        service_account = str(spec.get("serviceAccountName") or "default")
        node_name = str(spec.get("nodeName") or "unknown")
        if not pod_name or not pod_uid:
            continue
        for container in spec.get("containers") or []:
            container_name = str(container.get("name") or "")
            if not container_name:
                continue
            identities[(namespace, pod_name, container_name)] = {
                "cluster": cluster,
                "namespace": namespace,
                "pod_name": pod_name,
                "pod_uid": pod_uid,
                "service_account": service_account,
                "container_name": container_name,
                "node_name": node_name,
            }
    return identities


def load_pod_inventory(
    path: Path, cluster: str
) -> dict[tuple[str, str, str], dict[str, str]]:
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    return identities_from_pod_list(document, cluster)
