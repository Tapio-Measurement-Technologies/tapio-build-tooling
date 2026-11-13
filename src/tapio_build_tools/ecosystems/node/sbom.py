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


_PATH_PROPERTY = "cdx:npm:package:path"
_DEVELOPMENT_PROPERTY = "cdx:npm:package:development"
# The strongest scope first: a version one install path needs at run time is
# required, whatever its other copies are.
_SCOPES = ("required", "optional", "excluded")
# The lock fields npm draws a package's dependency edges from. Development
# edges count only for a package outside node_modules: the project, its
# workspaces and other linked directories.
_EDGE_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")
_TOP_EDGE_FIELDS = (*_EDGE_FIELDS, "devDependencies")


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


def _by_ref(items: list, key: str) -> dict[str, list[dict]]:
    """*items* grouped by their *key* reference, in the order each first appears."""
    groups: dict[str, list[dict]] = {}
    for item in items:
        ref = item.get(key) if isinstance(item, dict) else None
        if not isinstance(ref, str):
            raise SbomError(f"npm SBOM has an entry without a {key}")
        groups.setdefault(ref, []).append(item)
    return groups


def _merge_component(ref: str, copies: list[dict]) -> dict:
    """One component for a version npm lists once per install path."""

    def described(component: dict) -> dict:
        return {
            key: value for key, value in component.items() if key not in ("scope", "properties")
        }

    first = copies[0]
    if any(described(copy) != described(first) for copy in copies[1:]):
        raise SbomError(f"npm SBOM describes {ref} differently at its install paths")
    merged = dict(first)
    scopes = {copy.get("scope", "required") for copy in copies}
    merged["scope"] = next((scope for scope in _SCOPES if scope in scopes), first.get("scope"))
    # CycloneDX properties may repeat a name, so every install path is kept.
    # Any other property, such as cdx:npm:package:development, holds for the
    # version only if it holds at every path.
    paths = sorted(
        {
            item["value"]
            for copy in copies
            for item in copy.get("properties") or []
            if item.get("name") == _PATH_PROPERTY
        }
    )
    shared = [
        item
        for item in first.get("properties") or []
        if item.get("name") != _PATH_PROPERTY
        and all(item in (copy.get("properties") or []) for copy in copies[1:])
    ]
    merged["properties"] = [{"name": _PATH_PROPERTY, "value": path} for path in paths] + shared
    return merged


def _merge_install_paths(bom: dict) -> None:
    """List each package version once, however many paths install it.

    npm 10 writes a component and a dependency entry for every path in the
    lock, each under the reference name@version. A version nested under two
    parents, because another version holds the top-level slot npm would
    dedupe it into, is then listed twice under one reference, and the BOM
    fails the schema's unique dependencies. Its copies are merged: one
    component, required if any path needs it, and one dependency entry that
    depends on everything any copy resolves to, sorted. A child is named by
    its own name@version, so an edge to a nested copy still names the version
    nested there. Entries already listed once are left as npm wrote them;
    npm 11 lists each version once itself, and _correct_from_lock restores
    what its single copy leaves out.
    """
    components = _by_ref(bom.get("components") or [], "bom-ref")
    bom["components"] = [
        copies[0] if len(copies) == 1 else _merge_component(ref, copies)
        for ref, copies in components.items()
    ]
    dependencies = _by_ref(bom.get("dependencies") or [], "ref")
    bom["dependencies"] = [
        entries[0]
        if len(entries) == 1
        else {
            **entries[0],
            "dependsOn": sorted(
                {child for entry in entries for child in entry.get("dependsOn") or []}
            ),
        }
        for entries in dependencies.values()
    ]


def _read_lock(lock: Path) -> dict[str, dict]:
    """The lock's packages table: each install path's entry."""
    try:
        text = lock.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SbomError(f"cannot read {lock.name}") from exc
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SbomError(f"{lock.name} is not valid JSON") from exc
    packages = document.get("packages") if isinstance(document, dict) else None
    if not isinstance(packages, dict):
        raise SbomError(f"{lock.name} has no packages table; npm lockfileVersion 2 or 3 is needed")
    return {path: entry for path, entry in packages.items() if isinstance(entry, dict)}


def _locked_ref(path: str, entry: dict) -> str | None:
    """The name@version npm lists the package installed at *path* under."""
    # The lock records a name only where it differs from the directory's,
    # as for an alias; npm's reference uses the package's own name.
    name = entry.get("name") or path.rsplit("node_modules/", 1)[-1]
    version = entry.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        return None
    return f"{name}@{version}"


def _resolve(packages: dict[str, dict], path: str, name: str) -> str | None:
    """The install path that *name*, required from the package at *path*, loads.

    Node looks for node_modules/<name> in the package's own directory, then in
    each directory above it, skipping directories that are themselves
    node_modules. A link loads the directory it points to.
    """
    parts = path.split("/") if path else []
    while True:
        if not parts or parts[-1] != "node_modules":
            candidate = "/".join([*parts, "node_modules", name])
            entry = packages.get(candidate)
            if entry is not None:
                if not entry.get("link"):
                    return candidate
                target = entry.get("resolved")
                return target if isinstance(target, str) and target in packages else None
        if not parts:
            return None
        parts.pop()


def _correct_from_lock(bom: dict, packages: dict[str, dict]) -> None:
    """Give a version installed at several lock paths the scope and edges of every path.

    npm 11 lists such a version once, as the first of its install paths has
    it: that path's scope, development flag and dependency edges, and nothing
    of the other paths. A version nested under both a development and a
    production parent is then marked optional and development when the
    development copy comes first, and the edges the other copies resolve to
    are lost. The lock still has every path, so:

    - the component is required if any path is not dev, optional or
      devOptional, and keeps cdx:npm:package:development only if every path
      is dev, as npm 10's copies merge;
    - its dependency entry also depends on whatever each path's dependencies
      resolve to from that path, if npm lists it.

    A scope is only ever raised and an edge only ever added. Versions installed
    at one path, and entries that already agree with the lock, such as npm 10's
    merged copies, are left as they are. A changed dependency list is sorted.
    """
    paths: dict[str, list[str]] = {}
    for path, entry in packages.items():
        # npm lists neither the project itself nor a link, only its target.
        if not path or entry.get("link"):
            continue
        if (ref := _locked_ref(path, entry)) is not None:
            paths.setdefault(ref, []).append(path)
    nested = {ref: found for ref, found in paths.items() if len(found) > 1}
    if not nested:
        return

    components = bom.get("components") or []
    listed = {component.get("bom-ref") for component in components}
    for component in components:
        found = nested.get(component.get("bom-ref"))
        if found is None:
            continue
        entries = [packages[path] for path in found]
        needed = any(
            not (entry.get("dev") or entry.get("optional") or entry.get("devOptional"))
            for entry in entries
        )
        if needed and component.get("scope", "required") != "required":
            component["scope"] = "required"
        properties = component.get("properties") or []
        if not all(entry.get("dev") for entry in entries):
            kept = [item for item in properties if item.get("name") != _DEVELOPMENT_PROPERTY]
            if len(kept) != len(properties):
                component["properties"] = kept

    for dependency in bom.get("dependencies") or []:
        found = nested.get(dependency.get("ref"))
        if found is None:
            continue
        written = dependency.get("dependsOn") or []
        edges = set(written)
        for path in found:
            entry = packages[path]
            fields = _EDGE_FIELDS if "node_modules" in path.split("/") else _TOP_EDGE_FIELDS
            for field in fields:
                wanted = entry.get(field)
                for name in wanted if isinstance(wanted, dict) else ():
                    target = _resolve(packages, path, name)
                    child = None if target is None else _locked_ref(target, packages[target])
                    # npm drops an edge to a package it does not list.
                    if child in listed:
                        edges.add(child)
        if edges != set(written):
            dependency["dependsOn"] = sorted(edges)


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
    _merge_install_paths(bom)
    _correct_from_lock(bom, _read_lock(node.lock))
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
