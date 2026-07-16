"""Shared supply-chain evidence metadata helpers."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import platform as platform_module
import subprocess
from urllib.parse import quote

from tapio_build_tools.config import Product


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git_commit(project: Path) -> str:
    if value := os.environ.get("GITHUB_SHA"):
        return value
    try:
        result = subprocess.run(
            ["git", "-C", str(project), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return result.stdout.strip()


def target_platform() -> str:
    if value := os.environ.get("RUNNER_OS"):
        return value.lower()
    return platform_module.system().lower() or "unknown"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def product_component(product: Product, organization: str, version: str) -> dict:
    purl = f"pkg:generic/{quote(product.id, safe='.-_')}@{quote(version, safe='.+-_')}"
    component: dict = {
        "type": product.component_type,
        "bom-ref": purl,
        "name": product.name,
        "version": version,
        "publisher": organization,
        "purl": purl,
    }
    if product.license_id:
        component["licenses"] = [{"license": {"id": product.license_id}}]
    elif product.license_name:
        component["licenses"] = [{"license": {"name": product.license_name}}]
    references = []
    if product.website:
        references.append({"type": "website", "url": product.website})
    if product.repository:
        references.append({"type": "vcs", "url": product.repository})
    if references:
        component["externalReferences"] = references
    return component


def upsert_property(properties: list[dict[str, str]], name: str, value: str) -> None:
    for item in properties:
        if item.get("name") == name:
            item["value"] = value
            return
    properties.append({"name": name, "value": value})
