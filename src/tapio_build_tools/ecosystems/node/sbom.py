"""CycloneDX evidence generation for Node/npm products."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile

from tapio_build_tools.config import Config, Product
from tapio_build_tools.cyclonedx import validate_json
from tapio_build_tools.evidence import (
    git_commit,
    product_component,
    target_platform,
    upsert_property,
    utc_now,
)


class SbomError(RuntimeError):
    """npm SBOM generation failed."""


def _run_npm(project: Path) -> dict:
    command = [
        "npm",
        "sbom",
        "--package-lock-only",
        "--sbom-format",
        "cyclonedx",
        "--sbom-type",
        "application",
    ]
    try:
        result = subprocess.run(
            command,
            cwd=project,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SbomError("npm sbom failed") from exc
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SbomError("npm sbom produced invalid JSON") from exc
    if not isinstance(value, dict):
        raise SbomError("npm sbom produced invalid CycloneDX JSON")
    return value


def _stamp(
    bom: dict,
    *,
    config: Config,
    product: Product,
    version: str,
    commit_sha: str,
    build_platform: str,
    build_timestamp: str,
) -> None:
    node = config.require_node()
    metadata = bom.setdefault("metadata", {})
    original_component = metadata.get("component") or {}
    original_ref = original_component.get("bom-ref")
    if not original_ref:
        raise SbomError("npm SBOM has no root component reference")

    dependencies = bom.setdefault("dependencies", [])
    original_root = next((item for item in dependencies if item.get("ref") == original_ref), None)
    if original_root is None or not original_root.get("dependsOn"):
        raise SbomError("npm SBOM has no root dependency graph")

    component = product_component(product, config.organization.name, version)
    if properties := original_component.get("properties"):
        component["properties"] = properties
    metadata["timestamp"] = build_timestamp
    metadata["component"] = component

    properties = metadata.setdefault("properties", [])
    upsert_property(properties, "tapio:sbom:commit-sha", commit_sha)
    upsert_property(properties, "tapio:sbom:platform", build_platform)
    upsert_property(
        properties,
        "tapio:sbom:package-file",
        str(node.package.relative_to(config.project)),
    )
    upsert_property(
        properties,
        "tapio:sbom:lock-file",
        str(node.lock.relative_to(config.project)),
    )
    upsert_property(properties, "tapio:sbom:generator", "npm")

    dependencies[:] = [item for item in dependencies if item.get("ref") != original_ref]
    dependencies.append(
        {"ref": component["bom-ref"], "dependsOn": sorted(set(original_root["dependsOn"]))}
    )


def _validate_semantics(bom: dict, product: Product) -> None:
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.5":
        raise SbomError("npm did not produce a CycloneDX 1.5 BOM")
    if not bom.get("components"):
        raise SbomError("generated CycloneDX BOM has no components")
    component = (bom.get("metadata") or {}).get("component") or {}
    if component.get("name") != product.name:
        raise SbomError("generated CycloneDX BOM has wrong root component")
    root = next(
        (item for item in bom.get("dependencies", []) if item.get("ref") == component.get("bom-ref")),
        None,
    )
    if root is None or not root.get("dependsOn"):
        raise SbomError("generated CycloneDX BOM has no root dependency graph")


def generate_sbom(
    config: Config,
    *,
    product_id: str | None,
    output: str | Path,
    version: str,
    commit_sha: str | None = None,
    build_platform: str | None = None,
    build_timestamp: str | None = None,
) -> Path:
    product = config.product(product_id)
    node = config.require_node()
    output_path = Path(output)
    if not output_path.is_absolute():
        output_path = config.project / output_path
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    bom = _run_npm(node.package.parent)
    _stamp(
        bom,
        config=config,
        product=product,
        version=version,
        commit_sha=commit_sha or git_commit(config.project),
        build_platform=build_platform or target_platform(),
        build_timestamp=build_timestamp or utc_now(),
    )
    _validate_semantics(bom, product)
    serialized = json.dumps(bom, indent=2, sort_keys=True) + "\n"
    validate_json(serialized, bom["specVersion"])

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.write_text(serialized, encoding="utf-8")
        os.replace(temporary, output_path)
    finally:
        temporary.unlink(missing_ok=True)
    return output_path
