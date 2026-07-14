"""CycloneDX evidence generation for Python products."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform as platform_module
import re
import subprocess
import sys
import tempfile
from urllib.parse import quote

from packaging.requirements import Requirement

from tapio_build_tools.config import Config, Product
from tapio_build_tools.cyclonedx import validate_json


class SbomError(RuntimeError):
    """SBOM generation failed."""


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


def normalized_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def direct_requirement_names(path: Path) -> set[str]:
    names: set[str] = set()
    logical_line = ""
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.split("#", 1)[0].strip()
        if not stripped or (stripped.startswith("-") and not logical_line):
            continue
        logical_line += stripped.removesuffix("\\").strip()
        if stripped.endswith("\\"):
            continue
        try:
            names.add(normalized_name(Requirement(logical_line).name))
        except ValueError as exc:
            raise SbomError(f"cannot parse direct requirement: {raw_line}") from exc
        logical_line = ""
    if logical_line:
        raise SbomError(f"unterminated requirement continuation in {path}")
    return names


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _pyinstaller_version(explicit: str | None) -> str:
    if explicit:
        return explicit
    try:
        return importlib.metadata.version("pyinstaller")
    except importlib.metadata.PackageNotFoundError as exc:
        raise SbomError(
            "PyInstaller must be installed or --pyinstaller-version supplied for artifact evidence"
        ) from exc


def _upsert_property(properties: list[dict[str, str]], name: str, value: str) -> None:
    for item in properties:
        if item.get("name") == name:
            item["value"] = value
            return
    properties.append({"name": name, "value": value})


def _product_component(product: Product, organization: str, version: str) -> dict:
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


def add_pyinstaller_components(bom: dict, version: str) -> tuple[str, str]:
    python_version = platform_module.python_version()
    python_ref = f"pkg:generic/python@{python_version}"
    bootloader_ref = f"pkg:generic/pyinstaller-bootloader@{version}"
    bom.setdefault("components", []).extend(
        [
            {
                "type": "framework",
                "bom-ref": python_ref,
                "name": "Python",
                "version": python_version,
                "purl": python_ref,
                "properties": [{"name": "tapio:sbom:embedded-part", "value": "interpreter"}],
            },
            {
                "type": "framework",
                "bom-ref": bootloader_ref,
                "name": "PyInstaller bootloader",
                "version": version,
                "purl": bootloader_ref,
                "externalReferences": [
                    {"type": "vcs", "url": "https://github.com/pyinstaller/pyinstaller"}
                ],
                "properties": [{"name": "tapio:sbom:embedded-part", "value": "bootloader"}],
            },
        ]
    )
    dependencies = bom.setdefault("dependencies", [])
    existing = {item.get("ref") for item in dependencies}
    for reference in (python_ref, bootloader_ref):
        if reference not in existing:
            dependencies.append({"ref": reference})
    return python_ref, bootloader_ref


def connect_root_dependencies(
    bom: dict,
    root_ref: str,
    direct_names: set[str] | None,
    additional_refs: tuple[str, ...] = (),
) -> None:
    components = bom.get("components", [])
    if direct_names is None:
        direct_refs = [component["bom-ref"] for component in components]
    else:
        direct_refs = [
            component["bom-ref"]
            for component in components
            if normalized_name(component.get("name", "")) in direct_names
        ]
        found = {
            normalized_name(component.get("name", ""))
            for component in components
            if component.get("bom-ref") in direct_refs
        }
        missing = direct_names - found
        if missing:
            raise SbomError(
                "direct requirements missing from generated SBOM: " + ", ".join(sorted(missing))
            )
    dependencies = bom.setdefault("dependencies", [])
    root = next((item for item in dependencies if item.get("ref") == root_ref), None)
    if root is None:
        root = {"ref": root_ref}
        dependencies.append(root)
    root["dependsOn"] = sorted({*direct_refs, *additional_refs})


def _run_cyclonedx(lock: Path, output: Path, spec_version: str, project: Path) -> None:
    command = [
        sys.executable,
        "-m",
        "cyclonedx_py",
        "requirements",
        str(lock),
        "--spec-version",
        spec_version,
        "--output-format",
        "JSON",
        "--output-file",
        str(output),
        "--validate",
    ]
    try:
        subprocess.run(command, cwd=project, check=True)
    except subprocess.CalledProcessError as exc:
        raise SbomError("cyclonedx-py failed") from exc


def _stamp(
    bom: dict,
    *,
    config: Config,
    product: Product,
    group_name: str,
    version: str,
    commit_sha: str,
    build_platform: str,
    build_timestamp: str,
    artifact: Path | None,
    pyinstaller_version: str | None,
) -> None:
    group = config.python.requirement(group_name)
    metadata = bom.setdefault("metadata", {})
    metadata["timestamp"] = build_timestamp
    component = _product_component(product, config.organization.name, version)
    metadata["component"] = component

    embedded: tuple[str, ...] = ()
    if artifact is not None:
        component["hashes"] = [{"alg": "SHA-256", "content": sha256_file(artifact)}]
        embedded = add_pyinstaller_components(bom, _pyinstaller_version(pyinstaller_version))

    properties = metadata.setdefault("properties", [])
    _upsert_property(properties, "tapio:sbom:commit-sha", commit_sha)
    _upsert_property(properties, "tapio:sbom:platform", build_platform)
    _upsert_property(
        properties,
        "tapio:sbom:requirements-file",
        str(group.lock.relative_to(config.project)),
    )
    _upsert_property(properties, "tapio:sbom:generator", "cyclonedx-py")
    if artifact is not None:
        _upsert_property(properties, "tapio:sbom:artifact-name", artifact.name)
        _upsert_property(properties, "tapio:sbom:artifact-size", str(artifact.stat().st_size))

    direct_names = direct_requirement_names(group.input) if group.input else None
    connect_root_dependencies(bom, component["bom-ref"], direct_names, embedded)


def _validate_semantics(bom: dict, product: Product, *, artifact: bool) -> None:
    if bom.get("bomFormat") != "CycloneDX" or not bom.get("specVersion"):
        raise SbomError("generated file is not a versioned CycloneDX BOM")
    if not bom.get("components"):
        raise SbomError("generated CycloneDX BOM has no components")
    component = (bom.get("metadata") or {}).get("component") or {}
    if component.get("name") != product.name:
        raise SbomError("generated CycloneDX BOM has wrong root component")
    if bool(component.get("hashes")) != artifact:
        raise SbomError("artifact hash metadata does not match generation mode")
    root = next(
        (item for item in bom.get("dependencies", []) if item.get("ref") == component.get("bom-ref")),
        None,
    )
    if root is None or not root.get("dependsOn"):
        raise SbomError("generated CycloneDX BOM has no root dependency graph")


def generate_sbom(
    config: Config,
    *,
    group_name: str,
    product_id: str | None,
    output: str | Path,
    version: str,
    commit_sha: str | None = None,
    build_platform: str | None = None,
    build_timestamp: str | None = None,
    spec_version: str = "1.6",
    artifact: str | Path | None = None,
    artifact_kind: str | None = None,
    pyinstaller_version: str | None = None,
) -> Path:
    if spec_version not in {"1.6", "1.7"}:
        raise SbomError(f"unsupported CycloneDX specification version: {spec_version}")
    if (artifact is None) != (artifact_kind is None):
        raise SbomError("--artifact and --artifact-kind must be supplied together")
    if artifact_kind not in {None, "pyinstaller"}:
        raise SbomError(f"unsupported artifact kind: {artifact_kind}")

    product = config.product(product_id)
    group = config.python.requirement(group_name)
    artifact_path = Path(artifact).resolve() if artifact is not None else None
    if artifact_path is not None and not artifact_path.is_file():
        raise SbomError(f"artifact does not exist: {artifact_path}")
    output_path = Path(output)
    if not output_path.is_absolute():
        output_path = config.project / output_path
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        _run_cyclonedx(group.lock, temporary, spec_version, config.project)
        try:
            bom = json.loads(temporary.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise SbomError("cyclonedx-py produced invalid JSON") from exc
        _stamp(
            bom,
            config=config,
            product=product,
            group_name=group_name,
            version=version,
            commit_sha=commit_sha or git_commit(config.project),
            build_platform=build_platform or target_platform(),
            build_timestamp=build_timestamp or utc_now(),
            artifact=artifact_path,
            pyinstaller_version=pyinstaller_version,
        )
        _validate_semantics(bom, product, artifact=artifact_path is not None)
        serialized = json.dumps(bom, indent=2, sort_keys=True) + "\n"
        validate_json(serialized, bom["specVersion"])
        temporary.write_text(serialized, encoding="utf-8")
        os.replace(temporary, output_path)
    finally:
        temporary.unlink(missing_ok=True)
    return output_path

