"""Configuration parsing and validation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from string import Template
import tomllib
from typing import Any


class ConfigError(ValueError):
    """Invalid build tooling configuration."""


# The operating systems a download page knows how to name, and how it names them.
OPERATING_SYSTEMS = {"windows": "Windows", "linux": "Linux", "macos": "macOS"}
ARCHITECTURES = ("x86_64", "aarch64")
ARCHIVES = ("zip", "tar.gz", "none")
# A bare executable is wrapped so that it downloads as a file the browser does
# not try to run, and so that a Linux binary keeps its executable bit.
DEFAULT_ARCHIVE = {"windows": "zip", "linux": "tar.gz", "macos": "tar.gz"}
# A slug is a path segment in a bucket and a prefix of every file name under it.
SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*$")
VERSION_PLACEHOLDER = "version"


@dataclass(frozen=True)
class Organization:
    name: str
    website: str | None = None


@dataclass(frozen=True)
class Product:
    id: str
    name: str
    repository: str | None = None
    website: str | None = None
    license_id: str | None = None
    license_name: str | None = None
    component_type: str = "application"


@dataclass(frozen=True)
class RequirementGroup:
    name: str
    lock: Path
    input: Path | None = None


@dataclass(frozen=True)
class PythonEcosystem:
    version: str
    requirements: tuple[RequirementGroup, ...]

    def requirement(self, name: str) -> RequirementGroup:
        for group in self.requirements:
            if group.name == name:
                return group
        names = ", ".join(group.name for group in self.requirements)
        raise ConfigError(f"unknown requirement group {name!r}; configured: {names}")


@dataclass(frozen=True)
class NodeEcosystem:
    version: str
    package: Path
    lock: Path


@dataclass(frozen=True)
class DownloadAsset:
    """One downloadable build of a program: where the build leaves it, and for what."""

    os: str
    arch: str
    glob: str
    archive: str
    sbom: str | None = None

    @property
    def os_name(self) -> str:
        return OPERATING_SYSTEMS[self.os]


@dataclass(frozen=True)
class DownloadProgram:
    """A program with a download page of its own.

    One product can ship as several programs - one executable per
    measurement, say - and each gets its own prefix in the bucket.
    """

    id: str
    product: Product
    slug: str
    name: str
    contact: str
    assets: tuple[DownloadAsset, ...]
    notes: str | None = None
    indexable: bool = False
    source_package: bool = False


@dataclass(frozen=True)
class Downloads:
    programs: dict[str, DownloadProgram]
    logo: Path | None = None

    def program(self, program_id: str) -> DownloadProgram:
        try:
            return self.programs[program_id]
        except KeyError as exc:
            names = ", ".join(self.programs)
            raise ConfigError(f"unknown program {program_id!r}; configured: {names}") from exc


@dataclass(frozen=True)
class Config:
    project: Path
    path: Path
    organization: Organization
    products: dict[str, Product]
    python: PythonEcosystem | None
    node: NodeEcosystem | None
    downloads: Downloads | None = None

    def require_python(self) -> PythonEcosystem:
        if self.python is None:
            raise ConfigError("Python ecosystem is not configured")
        return self.python

    def require_node(self) -> NodeEcosystem:
        if self.node is None:
            raise ConfigError("Node ecosystem is not configured")
        return self.node

    def require_downloads(self) -> Downloads:
        if self.downloads is None:
            raise ConfigError("downloads are not configured")
        return self.downloads

    def product(self, product_id: str | None) -> Product:
        if product_id is None:
            if len(self.products) == 1:
                return next(iter(self.products.values()))
            raise ConfigError("--product is required when multiple products are configured")
        try:
            return self.products[product_id]
        except KeyError as exc:
            names = ", ".join(self.products)
            raise ConfigError(f"unknown product {product_id!r}; configured: {names}") from exc


def _table(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be a table")
    return value


def _keys(table: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise ConfigError(f"unknown {label} key(s): {', '.join(unknown)}")


def _required_string(table: dict[str, Any], key: str, label: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label}.{key} must be a non-empty string")
    return value


def _optional_string(table: dict[str, Any], key: str, label: str) -> str | None:
    value = table.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label}.{key} must be a non-empty string")
    return value


def _project_path(project: Path, value: str, label: str, *, must_exist: bool) -> Path:
    configured = Path(value)
    if configured.is_absolute():
        raise ConfigError(f"{label} must be relative to project root")
    resolved = (project / configured).resolve()
    if not resolved.is_relative_to(project):
        raise ConfigError(f"{label} escapes project root: {value}")
    if must_exist and not resolved.is_file():
        raise ConfigError(f"{label} does not exist: {value}")
    return resolved


def load_config(
    project: str | Path = ".",
    config_path: str | Path = "build-tooling.toml",
    *,
    require_lock_files: bool = True,
) -> Config:
    project_root = Path(project).resolve()
    path_arg = Path(config_path)
    path = path_arg.resolve() if path_arg.is_absolute() else (project_root / path_arg).resolve()
    if not path.is_file():
        raise ConfigError(f"configuration does not exist: {path}")

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc

    _keys(
        data, {"schema-version", "organization", "products", "ecosystems", "downloads"}, "top-level"
    )
    if data.get("schema-version") != 1:
        raise ConfigError(f"unsupported schema-version: {data.get('schema-version')!r}")

    organization_data = _table(data.get("organization"), "organization")
    _keys(organization_data, {"name", "website"}, "organization")
    organization = Organization(
        name=_required_string(organization_data, "name", "organization"),
        website=_optional_string(organization_data, "website", "organization"),
    )

    products_data = _table(data.get("products"), "products")
    if not products_data:
        raise ConfigError("at least one product must be configured")
    products: dict[str, Product] = {}
    product_keys = {
        "name", "repository", "website", "license-id", "license-name", "component-type"
    }
    for product_id, raw_product in products_data.items():
        label = f"products.{product_id}"
        product_data = _table(raw_product, label)
        _keys(product_data, product_keys, label)
        license_id = _optional_string(product_data, "license-id", label)
        license_name = _optional_string(product_data, "license-name", label)
        if license_id and license_name:
            raise ConfigError(f"{label} cannot define both license-id and license-name")
        component_type = _optional_string(product_data, "component-type", label) or "application"
        if component_type not in {"application", "firmware", "library"}:
            raise ConfigError(f"{label}.component-type is invalid: {component_type}")
        products[product_id] = Product(
            id=product_id,
            name=_required_string(product_data, "name", label),
            repository=_optional_string(product_data, "repository", label),
            website=_optional_string(product_data, "website", label),
            license_id=license_id,
            license_name=license_name,
            component_type=component_type,
        )

    ecosystems_data = _table(data.get("ecosystems"), "ecosystems")
    _keys(ecosystems_data, {"python", "node"}, "ecosystems")
    if not ecosystems_data:
        raise ConfigError("at least one ecosystem must be configured")

    python: PythonEcosystem | None = None
    if "python" in ecosystems_data:
        python_data = _table(ecosystems_data["python"], "ecosystems.python")
        _keys(python_data, {"version", "requirements"}, "ecosystems.python")
        version = _required_string(python_data, "version", "ecosystems.python")
        raw_groups = python_data.get("requirements")
        if not isinstance(raw_groups, list) or not raw_groups:
            raise ConfigError("ecosystems.python.requirements must be a non-empty array")

        groups: list[RequirementGroup] = []
        names: set[str] = set()
        for index, raw_group in enumerate(raw_groups):
            label = f"ecosystems.python.requirements[{index}]"
            group_data = _table(raw_group, label)
            _keys(group_data, {"name", "input", "lock"}, label)
            name = _required_string(group_data, "name", label)
            if name in names:
                raise ConfigError(f"duplicate requirement group: {name}")
            names.add(name)
            lock_value = _required_string(group_data, "lock", label)
            input_value = _optional_string(group_data, "input", label)
            groups.append(
                RequirementGroup(
                    name=name,
                    lock=_project_path(
                        project_root,
                        lock_value,
                        f"{label}.lock",
                        must_exist=require_lock_files,
                    ),
                    input=(
                        _project_path(project_root, input_value, f"{label}.input", must_exist=True)
                        if input_value is not None
                        else None
                    ),
                )
            )
        python = PythonEcosystem(version=version, requirements=tuple(groups))

    node: NodeEcosystem | None = None
    if "node" in ecosystems_data:
        node_data = _table(ecosystems_data["node"], "ecosystems.node")
        _keys(node_data, {"version", "package", "lock"}, "ecosystems.node")
        package = _project_path(
            project_root,
            _required_string(node_data, "package", "ecosystems.node"),
            "ecosystems.node.package",
            must_exist=True,
        )
        lock = _project_path(
            project_root,
            _required_string(node_data, "lock", "ecosystems.node"),
            "ecosystems.node.lock",
            must_exist=require_lock_files,
        )
        if package.name != "package.json":
            raise ConfigError("ecosystems.node.package must reference package.json")
        if lock.name != "package-lock.json":
            raise ConfigError("ecosystems.node.lock must reference package-lock.json")
        if package.parent != lock.parent:
            raise ConfigError("ecosystems.node.package and ecosystems.node.lock must share a directory")
        node = NodeEcosystem(
            version=_required_string(node_data, "version", "ecosystems.node"),
            package=package,
            lock=lock,
        )

    downloads: Downloads | None = None
    if "downloads" in data:
        downloads = _load_downloads(project_root, data["downloads"], products)

    return Config(
        project=project_root,
        path=path,
        organization=organization,
        products=products,
        python=python,
        node=node,
        downloads=downloads,
    )


def _optional_bool(table: dict[str, Any], key: str, label: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{label}.{key} must be true or false")
    return value


def _choice(table: dict[str, Any], key: str, label: str, allowed: tuple[str, ...], default: str | None) -> str:
    value = table.get(key, default)
    if value not in allowed:
        raise ConfigError(f"{label}.{key} is invalid: {value}; supported: {', '.join(allowed)}")
    return value


def _contact(table: dict[str, Any], label: str) -> str | None:
    contact = _optional_string(table, "contact", label)
    if contact is not None and "@" not in contact:
        raise ConfigError(f"{label}.contact must be an email address")
    return contact


def _asset_pattern(project: Path, table: dict[str, Any], key: str, label: str) -> str:
    """A project-relative path that may name the version as ${version}.

    Only checked for shape here: the file exists once the build has run, which
    is after the configuration was validated.
    """
    value = _required_string(table, key, label)
    template = Template(value)
    if not template.is_valid():
        raise ConfigError(f"{label}.{key} is not a valid pattern: {value}")
    unknown = sorted(set(template.get_identifiers()) - {VERSION_PLACEHOLDER})
    if unknown:
        raise ConfigError(
            f"{label}.{key} uses unknown placeholder(s) {', '.join(unknown)};"
            f" only ${{{VERSION_PLACEHOLDER}}} is substituted"
        )
    _project_path(project, value, f"{label}.{key}", must_exist=False)
    return value


def _load_asset(project: Path, raw_asset: Any, label: str) -> DownloadAsset:
    asset_data = _table(raw_asset, label)
    _keys(asset_data, {"os", "arch", "glob", "archive", "sbom"}, label)
    operating_system = _choice(asset_data, "os", label, tuple(OPERATING_SYSTEMS), None)
    return DownloadAsset(
        os=operating_system,
        arch=_choice(asset_data, "arch", label, ARCHITECTURES, ARCHITECTURES[0]),
        glob=_asset_pattern(project, asset_data, "glob", label),
        archive=_choice(asset_data, "archive", label, ARCHIVES, DEFAULT_ARCHIVE[operating_system]),
        sbom=(
            _asset_pattern(project, asset_data, "sbom", label)
            if asset_data.get("sbom") is not None
            else None
        ),
    )


def _load_downloads(project: Path, raw: Any, products: dict[str, Product]) -> Downloads:
    data = _table(raw, "downloads")
    _keys(data, {"contact", "logo", "programs"}, "downloads")
    default_contact = _contact(data, "downloads")
    logo: Path | None = None
    if (logo_value := _optional_string(data, "logo", "downloads")) is not None:
        logo = _project_path(project, logo_value, "downloads.logo", must_exist=True)
        if logo.suffix.lower() not in {".png", ".svg"}:
            raise ConfigError("downloads.logo must be a .png or .svg file")

    programs_data = _table(data.get("programs"), "downloads.programs")
    if not programs_data:
        raise ConfigError("downloads.programs must configure at least one program")
    programs: dict[str, DownloadProgram] = {}
    slugs: dict[str, str] = {}
    program_keys = {
        "product", "slug", "name", "notes", "contact", "indexable", "source-package", "assets"
    }
    for program_id, raw_program in programs_data.items():
        label = f"downloads.programs.{program_id}"
        program_data = _table(raw_program, label)
        _keys(program_data, program_keys, label)

        product_id = _optional_string(program_data, "product", label)
        if product_id is None:
            if len(products) != 1:
                raise ConfigError(f"{label}.product is required when multiple products are configured")
            product = next(iter(products.values()))
        elif product_id in products:
            product = products[product_id]
        else:
            raise ConfigError(f"{label}.product is unknown: {product_id}; configured: {', '.join(products)}")

        slug = _required_string(program_data, "slug", label)
        if not SLUG_PATTERN.match(slug):
            raise ConfigError(f"{label}.slug must be lower-case letters, digits and hyphens: {slug}")
        if slug in slugs:
            raise ConfigError(f"{label}.slug duplicates downloads.programs.{slugs[slug]}: {slug}")
        slugs[slug] = program_id

        contact = _contact(program_data, label) or default_contact
        if contact is None:
            raise ConfigError(f"{label}.contact is required when downloads.contact is not set")

        source_package = _optional_bool(program_data, "source-package", label, False)
        if source_package and not product.license_id:
            raise ConfigError(
                f"{label}.source-package needs products.{product.id}.license-id, which the page names"
            )

        raw_assets = program_data.get("assets")
        if not isinstance(raw_assets, list) or not raw_assets:
            raise ConfigError(f"{label}.assets must be a non-empty array")
        assets: list[DownloadAsset] = []
        targets: set[tuple[str, str]] = set()
        for index, raw_asset in enumerate(raw_assets):
            asset = _load_asset(project, raw_asset, f"{label}.assets[{index}]")
            if (asset.os, asset.arch) in targets:
                raise ConfigError(f"{label} configures {asset.os} {asset.arch} twice")
            targets.add((asset.os, asset.arch))
            assets.append(asset)

        programs[program_id] = DownloadProgram(
            id=program_id,
            product=product,
            slug=slug,
            name=_required_string(program_data, "name", label),
            contact=contact,
            assets=tuple(assets),
            notes=_optional_string(program_data, "notes", label),
            indexable=_optional_bool(program_data, "indexable", label, False),
            source_package=source_package,
        )
    return Downloads(programs=programs, logo=logo)
